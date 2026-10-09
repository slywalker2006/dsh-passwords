#!/usr/bin/env node
// Initialize only the dsh-passwords gateway state. dsh is managed separately.
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function nonEmpty(value, fallback) {
  return (value ?? '').trim() || fallback;
}

function envValue(contents, name) {
  for (const line of contents.split(/\r?\n/)) {
    const match = new RegExp(`^\\s*${name}\\s*=\\s*(.*?)\\s*$`).exec(line);
    if (match && !line.trimStart().startsWith('#')) {
      return match[1].replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '').trim();
    }
  }
  return '';
}

function hasEnvKey(contents, name) {
  return contents.split(/\r?\n/).some((line) =>
    new RegExp(`^\\s*${name}\\s*=`).test(line) && !line.trimStart().startsWith('#'),
  );
}

function secureFile(file) {
  if (process.platform !== 'win32') chmodSync(file, 0o600);
}

function appendMissingEnv(file, values) {
  const raw = readFileSync(file, 'utf8');
  const missing = Object.entries(values)
    .filter(([name]) => !hasEnvKey(raw, name))
    .map(([name, value]) => `${name}=${value}`);
  if (missing.length > 0) {
    writeFileSync(file, `${raw.replace(/\s*$/, '')}\n${missing.join('\n')}\n`, 'utf8');
    secureFile(file);
  }
}

/**
 * Creates persistent gateway configuration and a one-time setup key.
 * dsh, its profile, and its remote-settings patch are managed outside this image.
 */
export function initializeDocker({
  env = process.env,
  log = console.log,
  error = console.error,
} = {}) {
  const envFile = nonEmpty(env.DSH_PASSWORDS_ENV_FILE, '/data/dsh-passwords/.env');
  const stateDir = path.dirname(envFile);
  const dbPath = nonEmpty(env.MCP_DB_PATH, path.join(stateDir, 'platform.db'));
  const upstream = nonEmpty(env.MCP_GATEWAY_UPSTREAM, 'http://127.0.0.1:3080');
  const setupKeyFile = path.join(stateDir, 'setup-key.txt');
  // 用户通过 -e SETUP_KEY=... 传入的初始密钥优先，绝不能让它与卷内 .env 里
  // 生成的随机值分叉：Docker 运行时环境变量优先，去掉该 env 重启后就会锁死。
  const providedSetupKey = nonEmpty(env.SETUP_KEY, '');

  mkdirSync(stateDir, { recursive: true });
  mkdirSync(path.dirname(dbPath), { recursive: true });

  let firstInitialization = false;
  let setupKey = '';
  let setupKeyFromEnv = false;
  if (existsSync(envFile)) {
    secureFile(envFile);
    setupKey = envValue(readFileSync(envFile, 'utf8'), 'SETUP_KEY');
    if (setupKey === '') {
      // A volume can contain a partially written .env after an interrupted
      // first boot. Keep all existing state and add only the missing key.
      if (providedSetupKey !== '') {
        setupKey = providedSetupKey;
        setupKeyFromEnv = true;
      } else {
        setupKey = randomBytes(24).toString('hex');
      }
      appendMissingEnv(envFile, { SETUP_KEY: setupKey });
      firstInitialization = true;
      log(`[dsh-passwords] ${envFile} had no usable SETUP_KEY; ${setupKeyFromEnv ? 'adopted SETUP_KEY from the container environment' : 'generated one'} without replacing existing configuration`);
    }
    // 旧卷可能已经用 SETUP_KEY 派生密钥加密数据库。已有数据库且未显式提供
    // MCP_DB_ENC_KEY 时不能随机补写新密钥，否则下一次启动将无法解密旧数据。
    // 新数据库才生成并固化独立密钥；显式环境变量仍由运行时优先使用。
    const existingDb = existsSync(dbPath);
    const providedDbEncKey = nonEmpty(env.MCP_DB_ENC_KEY, '');
    const dbEncKey = existingDb ? providedDbEncKey : providedDbEncKey || randomBytes(32).toString('hex');
    appendMissingEnv(envFile, {
      ...(dbEncKey === '' ? {} : { MCP_DB_ENC_KEY: dbEncKey }),
      MCP_DB_PATH: dbPath,
      MCP_GATEWAY_AUTO_TLS: '0',
      MCP_GATEWAY_HOST: '0.0.0.0',
      MCP_GATEWAY_PORT: '3088',
      MCP_GATEWAY_UPSTREAM: upstream,
      MCP_DSH_RESTART_SERVICE: '',
      DSH_PASSWORDS_RUNTIME: 'docker',
    });
  } else {
    firstInitialization = true;
    if (providedSetupKey !== '') {
      setupKey = providedSetupKey;
      setupKeyFromEnv = true;
    } else {
      setupKey = randomBytes(24).toString('hex');
    }
    const dbEncKey = randomBytes(32).toString('hex');
    writeFileSync(
      envFile,
      [
        `SETUP_KEY=${setupKey}`,
        `MCP_DB_ENC_KEY=${dbEncKey}`,
        `MCP_DB_PATH=${dbPath}`,
        'DSH_PASSWORDS_RUNTIME=docker',
        'MCP_GATEWAY_AUTO_TLS=0',
        'MCP_GATEWAY_HOST=0.0.0.0',
        'MCP_GATEWAY_PORT=3088',
        `MCP_GATEWAY_UPSTREAM=${upstream}`,
        'MCP_DSH_RESTART_SERVICE=',
        '',
      ].join('\n'),
      { encoding: 'utf8', mode: 0o600 },
    );
    secureFile(envFile);
    log(`[dsh-passwords] created persistent configuration: ${envFile}${setupKeyFromEnv ? ' (SETUP_KEY taken from the container environment)' : ''}`);
  }

  // 由环境变量提供的密钥用户已经知道，不再落一份明文 setup-key.txt；
  // 随机生成时才写，供用户 docker exec 读取。
  if (firstInitialization && !setupKeyFromEnv && !existsSync(setupKeyFile)) {
    writeFileSync(setupKeyFile, `${setupKey}\n`, { encoding: 'utf8', mode: 0o600 });
    secureFile(setupKeyFile);
    log(`[dsh-passwords] first-time setup key written to ${setupKeyFile}`);
  }

  return true;
}

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  process.exit(initializeDocker() ? 0 : 1);
}
