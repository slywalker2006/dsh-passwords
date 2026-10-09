// Issue #33（附带项「.env 修改不生效」）的机制与契约测试。
//
// 机制：dotenv 默认 override:false，而 dsh 是常驻进程——它在启动时把部署 .env 的
// 值灌进自身 process.env，并在拉起网关子进程时原样继承（plugin.ts spawn 的
// env: {...process.env}）。于是修改 .env 后只重启网关子进程，旧值仍压过文件。
//
// 插件拉起的网关与插件初始配置共享部署文件；直接运行 CLI 和 Docker 注入保持环境变量优先。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { deploymentGatewayEnv, resolveRemoteMuxConfig } from '../src/config.ts';
import type { PlatformConfig, RemoteMuxConfig } from '../src/config.ts';
import {
  GATEWAY_CONFIG_DRIFT_MAX_RETRIES,
  gatewayConfigDrift,
  gatewayDriftDecision,
} from '../src/plugin.ts';

const projectRoot = path.resolve(import.meta.dirname, '..');
const configUrl = pathToFileURL(path.join(projectRoot, 'src', 'config.ts')).href;

/** Remote mux 调优的默认解析结果（与 REMOTE_MUX_DEFAULTS 的值一致）。 */
const MUX_DEFAULT: RemoteMuxConfig = {
  fragmentBytes: 131_072,
  pingIntervalMs: 2_000,
  pongTimeoutMs: 30_000,
  writeStallMs: 30_000,
};

/** 在同步回调内捕获 console.warn，便于断言非法值回退时恰好告警一次。 */
function captureWarnings(run: () => void): string[] {
  const messages: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { messages.push(args.map(String).join(' ')); };
  try {
    run();
  } finally {
    console.warn = original;
  }
  return messages;
}

/** 在全新进程里导入 config.ts 并调用 loadConfig()，避开 ESM 模块缓存。 */
function loadConfigInChild(env: NodeJS.ProcessEnv): { setupKey: string; port: number } {
  const script =
    `const { loadConfig } = await import(${JSON.stringify(configUrl)});` +
    `const c = loadConfig();` +
    `console.log(JSON.stringify({ setupKey: c.setupKey, port: c.gateway.port }));`;
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
    cwd: projectRoot,
    env,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `child exit=${String(result.status)}\n${result.stdout}\n${result.stderr}`);
  const lines = result.stdout.trim().split(/\r?\n/);
  return JSON.parse(lines[lines.length - 1]!) as { setupKey: string; port: number };
}

function writeDeploymentEnv(dir: string, setupKey: string, port: string): string {
  const file = path.join(dir, '.env');
  writeFileSync(file, [`SETUP_KEY=${setupKey}`, `MCP_GATEWAY_PORT=${port}`, 'MCP_GATEWAY_AUTO_TLS=0', ''].join('\n'));
  return file;
}

/** 模拟 dsh 常驻进程固化进自身环境、再继承给网关子进程的陈旧值。 */
function staleEnv(envFile: string, parentPid?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    DSH_PASSWORDS_ENV_FILE: envFile,
    SETUP_KEY: 'env-key',
    MCP_GATEWAY_PORT: '2222',
    MCP_GATEWAY_AUTO_TLS: '0',
    LANG: 'en_US.UTF-8',
  };
  delete env.DSH_GATEWAY_PARENT_PID;
  if (parentPid !== undefined) env.DSH_GATEWAY_PARENT_PID = parentPid;
  return env;
}

test('未由插件拉起时：显式环境变量优先于部署 .env（守住 cli.ts 的三层优先级）', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = writeDeploymentEnv(dir, 'file-key', '1111');
    assert.deepEqual(loadConfigInChild(staleEnv(file)), { setupKey: 'env-key', port: 2222 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('无陈旧继承值时：全新进程正常读取部署 .env', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = writeDeploymentEnv(dir, 'file-key', '1111');
    const env = staleEnv(file);
    delete env.SETUP_KEY;
    delete env.MCP_GATEWAY_PORT;
    assert.deepEqual(loadConfigInChild(env), { setupKey: 'file-key', port: 1111 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Windows 未显式配置 systemd 服务时默认手动重启', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = writeDeploymentEnv(dir, 'file-key', '1111');
    const env = staleEnv(file);
    delete env.MCP_DSH_RESTART_SERVICE;
    const script = `const { loadConfig } = await import(${JSON.stringify(configUrl)});` +
      'console.log(JSON.stringify({ restartService: loadConfig().patch.restartService }));';
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: projectRoot, env, encoding: 'utf8',
    });
    assert.equal(result.status, 0);
    const output = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') as { restartService?: string };
    assert.equal(output.restartService, process.platform === 'win32' ? '' : 'dsh-web');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('插件拉起的 Docker 网关仍以容器环境变量为准', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = writeDeploymentEnv(dir, 'file-key', '1111');
    assert.deepEqual(loadConfigInChild({ ...staleEnv(file, '12345'), DSH_PASSWORDS_RUNTIME: 'docker' }),
      { setupKey: 'env-key', port: 2222 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Docker 空值遮蔽：compose 注入的空串 secret 不覆盖卷内 .env，非空环境变量仍优先', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-empty-'));
  try {
    const file = path.join(dir, '.env');
    writeFileSync(file, [
      'SETUP_KEY=file-key',
      'MCP_DB_ENC_KEY=file-db-enc',
      'MCP_JWT_SECRET=file-jwt',
      'MCP_INTERNAL_SECRET=file-internal',
      'MCP_GATEWAY_AUTO_TLS=0',
      '',
    ].join('\n'));
    const script =
      `const { loadConfig } = await import(${JSON.stringify(configUrl)});` +
      'console.log(JSON.stringify(loadConfig()));';
    // 模拟 docker compose 的 `${VAR:-}`：未设置的 secret 以空串进入容器环境。
    const read = (extra: NodeJS.ProcessEnv): PlatformConfig => {
      const env: NodeJS.ProcessEnv = {
        ...staleEnv(file, '12345'),
        DSH_PASSWORDS_RUNTIME: 'docker',
        SETUP_KEY: '',
        MCP_DB_ENC_KEY: '',
        MCP_JWT_SECRET: '',
        MCP_INTERNAL_SECRET: '',
        ...extra,
      };
      const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
        cwd: projectRoot, env, encoding: 'utf8',
      });
      assert.equal(result.status, 0, `child exit=${String(result.status)}\n${result.stdout}\n${result.stderr}`);
      return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') as PlatformConfig;
    };

    // 空串必须回落到卷内 .env 的值，否则容器会因 SETUP_KEY 判空而拒绝启动。
    const fromFile = read({});
    assert.equal(fromFile.setupKey, 'file-key');
    assert.equal(fromFile.dbEncKey, 'file-db-enc');
    assert.equal(fromFile.jwtSecret, 'file-jwt');
    assert.equal(fromFile.internalSecret, 'file-internal');

    // 显式非空环境变量（docker/.env 透传或 `-e VAR=...`）仍然优先。
    const fromEnv = read({
      SETUP_KEY: 'env-key',
      MCP_DB_ENC_KEY: 'env-db-enc',
      MCP_JWT_SECRET: 'env-jwt',
      MCP_INTERNAL_SECRET: 'env-internal',
    });
    assert.equal(fromEnv.setupKey, 'env-key');
    assert.equal(fromEnv.dbEncKey, 'env-db-enc');
    assert.equal(fromEnv.jwtSecret, 'env-jwt');
    assert.equal(fromEnv.internalSecret, 'env-internal');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('插件子进程仍保留仅通过环境变量提供的设置', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = path.join(dir, '.env');
    writeFileSync(file, 'SETUP_KEY=file-key\nMCP_GATEWAY_AUTO_TLS=0\n');
    assert.deepEqual(loadConfigInChild(staleEnv(file, '12345')), { setupKey: 'file-key', port: 2222 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('插件快照清理文件中已删除的键，文件消失时拒绝沿用旧值', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  const file = path.join(dir, '.env');
  try {
    writeFileSync(file, 'SETUP_KEY=file-key\nMCP_GATEWAY_PORT=1111\n');
    const inherited = { SETUP_KEY: 'old-key', MCP_GATEWAY_PORT: '2222', MCP_DSH_ROOT: 'environment-only' };
    const first = deploymentGatewayEnv(file, inherited);
    assert.equal(first.MCP_GATEWAY_PORT, '1111');
    writeFileSync(file, 'SETUP_KEY=file-key\n');
    const second = deploymentGatewayEnv(file, first);
    assert.equal(second.MCP_GATEWAY_PORT, undefined);
    assert.equal(second.MCP_DSH_ROOT, 'environment-only');
    rmSync(file);
    assert.throws(() => deploymentGatewayEnv(file, first), /部署环境文件已缺失/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Issue #33：插件拉起的子进程以部署文件为准，重启子进程读取新值', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  try {
    const file = writeDeploymentEnv(dir, 'file-key', '1111');
    assert.deepEqual(
      loadConfigInChild(staleEnv(file, '12345')),
      { setupKey: 'file-key', port: 1111 },
      '插件子进程必须读取部署文件',
    );

    // 修改 .env 后只重启网关子进程：文件中的新值要生效。
    writeDeploymentEnv(dir, 'file-key2', '3333');
    assert.deepEqual(
      loadConfigInChild(staleEnv(file, '12345')),
      { setupKey: 'file-key2', port: 3333 },
      '重启子进程后应重新读取部署文件',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MANAGED_ENV_KEYS 覆盖设置、超时与缓存开关，且随文件删除而清除', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-envprec-'));
  const file = path.join(dir, '.env');
  try {
    writeFileSync(file, [
      'SETUP_KEY=file-key',
      'MCP_DSH_SETTINGS_FILE=file-settings.yaml',
      'MCP_DSH_PATCH_ALLOW_BIND_ALL=1',
      'MCP_GATEWAY_UPSTREAM_TLS_VERIFY=0',
      'MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS=180000',
      'MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS=120000',
      'MCP_DSH_PASSWORDS_INVENTORY_TTL_MS=60000',
      'MCP_GATEWAY_MUX_FRAGMENT_BYTES=65536',
      'MCP_GATEWAY_MUX_PING_INTERVAL_MS=3000',
      'MCP_GATEWAY_MUX_PONG_TIMEOUT_MS=45000',
      'MCP_GATEWAY_MUX_WRITE_STALL_MS=15000',
      '',
    ].join('\n'));
    // 模拟 dsh 常驻进程继承下来的陈旧值：部署文件必须覆盖它们。
    const inherited = {
      SETUP_KEY: 'stale-key',
      MCP_DSH_SETTINGS_FILE: 'stale-settings.yaml',
      MCP_DSH_PATCH_ALLOW_BIND_ALL: '0',
      MCP_GATEWAY_UPSTREAM_TLS_VERIFY: '1',
      MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS: '60000',
      MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '10000',
      MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '0',
      MCP_GATEWAY_MUX_FRAGMENT_BYTES: '131072',
      MCP_GATEWAY_MUX_PING_INTERVAL_MS: '2000',
      MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '30000',
      MCP_GATEWAY_MUX_WRITE_STALL_MS: '30000',
      MCP_DSH_ROOT: 'environment-only',
    };
    const snapshot = deploymentGatewayEnv(file, inherited);
    assert.equal(snapshot.MCP_DSH_SETTINGS_FILE, 'file-settings.yaml');
    assert.equal(snapshot.MCP_DSH_PATCH_ALLOW_BIND_ALL, '1');
    assert.equal(snapshot.MCP_GATEWAY_UPSTREAM_TLS_VERIFY, '0');
    assert.equal(snapshot.MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS, '180000');
    assert.equal(snapshot.MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS, '120000');
    assert.equal(snapshot.MCP_DSH_PASSWORDS_INVENTORY_TTL_MS, '60000');
    assert.equal(snapshot.MCP_GATEWAY_MUX_FRAGMENT_BYTES, '65536');
    assert.equal(snapshot.MCP_GATEWAY_MUX_PING_INTERVAL_MS, '3000');
    assert.equal(snapshot.MCP_GATEWAY_MUX_PONG_TIMEOUT_MS, '45000');
    assert.equal(snapshot.MCP_GATEWAY_MUX_WRITE_STALL_MS, '15000');
    // 未纳入管理的键仍沿用环境变量。
    assert.equal(snapshot.MCP_DSH_ROOT, 'environment-only');

    // 运维从文件中删掉这些键后，插件快照必须清除旧值，
    // 否则网关子进程会继续沿用陈旧的安全开关（如 bindAll 或跳过上游校验）。
    writeFileSync(file, 'SETUP_KEY=file-key\n');
    const cleared = deploymentGatewayEnv(file, snapshot);
    assert.equal(cleared.MCP_DSH_SETTINGS_FILE, undefined);
    assert.equal(cleared.MCP_DSH_PATCH_ALLOW_BIND_ALL, undefined);
    assert.equal(cleared.MCP_GATEWAY_UPSTREAM_TLS_VERIFY, undefined);
    assert.equal(cleared.MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS, undefined);
    assert.equal(cleared.MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS, undefined);
    assert.equal(cleared.MCP_DSH_PASSWORDS_INVENTORY_TTL_MS, undefined);
    assert.equal(cleared.MCP_GATEWAY_MUX_FRAGMENT_BYTES, undefined);
    assert.equal(cleared.MCP_GATEWAY_MUX_PING_INTERVAL_MS, undefined);
    assert.equal(cleared.MCP_GATEWAY_MUX_PONG_TIMEOUT_MS, undefined);
    assert.equal(cleared.MCP_GATEWAY_MUX_WRITE_STALL_MS, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function driftConfig(overrides: Partial<PlatformConfig> = {}, gateway: Partial<PlatformConfig['gateway']> = {}): PlatformConfig {
  return {
    setupKey: 'key',
    dbPath: '/deploy/data/platform.db',
    dbEncKey: '',
    jwtSecret: 'jwt',
    internalSecret: 'internal',
    gateway: {
      host: '0.0.0.0', port: 8080, upstream: 'http://127.0.0.1:3080',
      tls: null, redirectPort: null, publicHost: '', domain: '', autoTls: false, acmeEmail: '', acmeStaging: false,
      ...gateway,
    },
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
    ...overrides,
  };
}

test('密钥/端口/上游漂移必须被识别，避免用旧快照误启网关', () => {
  const base = driftConfig();
  assert.deepEqual(gatewayConfigDrift(base, base), [], '完全一致时无漂移');
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({}, { port: 8443 })), ['MCP_GATEWAY_PORT']);
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({ jwtSecret: 'other' })), ['MCP_JWT_SECRET']);
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({ internalSecret: 'other' })), ['MCP_INTERNAL_SECRET']);
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({ setupKey: 'other' })), ['SETUP_KEY/MCP_DB_ENC_KEY']);
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({ dbEncKey: 'explicit' })), ['SETUP_KEY/MCP_DB_ENC_KEY']);
  assert.deepEqual(gatewayConfigDrift(base, driftConfig({ dbPath: '/other/platform.db' })), ['MCP_DB_PATH']);
  assert.deepEqual(
    gatewayConfigDrift(base, driftConfig({}, { upstream: 'http://127.0.0.1:9090' })),
    ['MCP_GATEWAY_UPSTREAM'],
  );
  assert.deepEqual(
    gatewayConfigDrift(base, driftConfig({}, { tls: { cert: 'a.pem', key: 'a.key' } })),
    ['MCP_GATEWAY_TLS_CERT/MCP_GATEWAY_TLS_KEY'],
  );
});

test('配置漂移重试有界：超过上限后转为已诊断停机而不是静默不启动', () => {
  assert.ok(Number.isInteger(GATEWAY_CONFIG_DRIFT_MAX_RETRIES) && GATEWAY_CONFIG_DRIFT_MAX_RETRIES > 0);
  for (let attempt = 1; attempt <= GATEWAY_CONFIG_DRIFT_MAX_RETRIES; attempt += 1) {
    assert.equal(gatewayDriftDecision(attempt), 'retry', `第 ${String(attempt)} 次应在界内重试`);
  }
  // 越界后必须明确停机（不退化为无限静默重试，也不误启）。
  assert.equal(gatewayDriftDecision(GATEWAY_CONFIG_DRIFT_MAX_RETRIES + 1), 'stopped');
  assert.equal(gatewayDriftDecision(GATEWAY_CONFIG_DRIFT_MAX_RETRIES + 100), 'stopped');
});

test('Compose 与 docker 模板透传四个 Remote mux 键（空值回退默认，不漏接）', () => {
  const compose = readFileSync(path.join(projectRoot, 'docker', 'docker-compose.yml'), 'utf8');
  const dockerEnvExample = readFileSync(path.join(projectRoot, 'docker', '.env.example'), 'utf8');
  const keys = [
    'MCP_GATEWAY_MUX_FRAGMENT_BYTES',
    'MCP_GATEWAY_MUX_PING_INTERVAL_MS',
    'MCP_GATEWAY_MUX_PONG_TIMEOUT_MS',
    'MCP_GATEWAY_MUX_WRITE_STALL_MS',
  ];
  for (const key of keys) {
    assert.match(compose, new RegExp(`${key}: \\$\\{${key}:-\\}`), `${key} 必须在 Compose 显式透传（空值回退默认）`);
    assert.match(dockerEnvExample, new RegExp(key), `${key} 必须在 docker/.env.example 列出`);
  }
});

test('Compose 以空值兜底透传四个卷内持久化密钥（空值由 config 视为未设置）', () => {
  const compose = readFileSync(path.join(projectRoot, 'docker', 'docker-compose.yml'), 'utf8');
  for (const key of ['SETUP_KEY', 'MCP_JWT_SECRET', 'MCP_INTERNAL_SECRET', 'MCP_DB_ENC_KEY']) {
    assert.match(compose, new RegExp(`${key}: \\$\\{${key}:-\\}`), `${key} 必须在 Compose 以空值兜底透传`);
  }
});

// ── Remote mux 大消息传输调优（MCP_GATEWAY_MUX_*）──────────────────────

test('Remote mux 调优：未设置/纯空白用默认且不告警', () => {
  const blank = {
    MCP_GATEWAY_MUX_FRAGMENT_BYTES: '',
    MCP_GATEWAY_MUX_PING_INTERVAL_MS: '   ',
    MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '',
    MCP_GATEWAY_MUX_WRITE_STALL_MS: '',
  };
  const warnings = captureWarnings(() => {
    assert.deepEqual(resolveRemoteMuxConfig({}), MUX_DEFAULT);
    assert.deepEqual(resolveRemoteMuxConfig(blank), MUX_DEFAULT);
  });
  assert.deepEqual(warnings, [], '未设置/空白不得告警');
});

test('Remote mux 调优：严格十进制整数且接受区间上下界（含 FRAGMENT_BYTES=0）', () => {
  const warnings = captureWarnings(() => {
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_FRAGMENT_BYTES: '0' }).fragmentBytes, 0);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_FRAGMENT_BYTES: '16384' }).fragmentBytes, 16_384);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_FRAGMENT_BYTES: '1048576' }).fragmentBytes, 1_048_576);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_PING_INTERVAL_MS: '250' }).pingIntervalMs, 250);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_PING_INTERVAL_MS: '60000', MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '600000' }).pingIntervalMs, 60_000);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '2000' }).pongTimeoutMs, 2_000);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '600000' }).pongTimeoutMs, 600_000);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_WRITE_STALL_MS: '5000' }).writeStallMs, 5_000);
    assert.equal(resolveRemoteMuxConfig({ MCP_GATEWAY_MUX_WRITE_STALL_MS: '600000' }).writeStallMs, 600_000);
  });
  assert.deepEqual(warnings, [], '合法值不得告警');
});

test('Remote mux 调优：非十进制整数/越界的值回退默认并恰好告警一次', () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '16383'],   // 低于下限且非 0
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '1048577'], // 高于上限
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '1.5'],     // 小数
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '1e3'],     // 科学计数法
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '0x4000'],  // 十六进制
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '-1'],      // 负数
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', '+4096'],   // 显式正号
    ['MCP_GATEWAY_MUX_FRAGMENT_BYTES', 'invalid'],
    ['MCP_GATEWAY_MUX_PING_INTERVAL_MS', '249'],
    ['MCP_GATEWAY_MUX_PING_INTERVAL_MS', '60001'],
    ['MCP_GATEWAY_MUX_PING_INTERVAL_MS', '0'],     // 除 FRAGMENT_BYTES 外 0 非法
    ['MCP_GATEWAY_MUX_PONG_TIMEOUT_MS', '1999'],
    ['MCP_GATEWAY_MUX_PONG_TIMEOUT_MS', '600001'],
    ['MCP_GATEWAY_MUX_WRITE_STALL_MS', '4999'],
    ['MCP_GATEWAY_MUX_WRITE_STALL_MS', '600001'],
  ];
  for (const [name, value] of cases) {
    const warnings = captureWarnings(() => {
      assert.deepEqual(resolveRemoteMuxConfig({ [name]: value }), MUX_DEFAULT, `${name}=${value} 应回退默认`);
    });
    assert.equal(warnings.length, 1, `${name}=${value} 应恰好告警一次`);
    assert.match(warnings[0]!, new RegExp(name));
  }
});

test('Remote mux 调优：PING_INTERVAL_MS 大于 PONG_TIMEOUT_MS 时照用并告警', () => {
  const warnings = captureWarnings(() => {
    const cfg = resolveRemoteMuxConfig({
      MCP_GATEWAY_MUX_PING_INTERVAL_MS: '60000',
      MCP_GATEWAY_MUX_PONG_TIMEOUT_MS: '2000',
    });
    assert.equal(cfg.pingIntervalMs, 60_000);
    assert.equal(cfg.pongTimeoutMs, 2_000);
  });
  assert.equal(warnings.length, 1, '仅应产生关系告警（两个值各自合法）');
  assert.match(warnings[0]!, /PING_INTERVAL_MS/);
});

test('loadConfig 通过托管环境解析 Remote mux 调优，非法值回退默认', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-muxcfg-'));
  try {
    const file = path.join(dir, '.env');
    writeFileSync(file, [
      'SETUP_KEY=file-key',
      'MCP_GATEWAY_AUTO_TLS=0',
      'MCP_GATEWAY_MUX_FRAGMENT_BYTES=0',
      'MCP_GATEWAY_MUX_PING_INTERVAL_MS=3000',
      'MCP_GATEWAY_MUX_PONG_TIMEOUT_MS=bogus',
      'MCP_GATEWAY_MUX_WRITE_STALL_MS=15000',
      '',
    ].join('\n'));
    const script =
      `const { loadConfig } = await import(${JSON.stringify(configUrl)});` +
      'console.log(JSON.stringify(loadConfig().mux));';
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], {
      cwd: projectRoot, env: staleEnv(file), encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    const parsed = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') as RemoteMuxConfig;
    // 文件中的三个合法值生效，非法 pong timeout 回退默认。
    assert.deepEqual(parsed, { fragmentBytes: 0, pingIntervalMs: 3_000, pongTimeoutMs: MUX_DEFAULT.pongTimeoutMs, writeStallMs: 15_000 });
    assert.match(result.stderr, /MCP_GATEWAY_MUX_PONG_TIMEOUT_MS/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
