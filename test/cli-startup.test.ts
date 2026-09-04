import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const projectRoot = path.resolve(import.meta.dirname, '..');
const cli = path.join(projectRoot, 'dist', 'cli.js');

function writeConfig(root: string, dshRoot: string): string {
  const envFile = path.join(root, '.env');
  writeFileSync(envFile, [
    'SETUP_KEY=test-setup-key',
    'MCP_DB_ENC_KEY=test-encryption-key',
    'MCP_GATEWAY_AUTO_TLS=0',
    'MCP_GATEWAY_PORT=19443',
    `MCP_DSH_ROOT=${dshRoot}`,
  ].join('\n') + '\n');
  return envFile;
}

function makeAlpha3Root(
  root: string,
  settings: string | null,
  connection: string,
  version = '0.1.2-alpha.5',
): string {
  const dshRoot = path.join(root, 'dsh');
  const settingsPath = path.join(dshRoot, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js');
  const connectionPath = path.join(dshRoot, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib', 'index.js');
  mkdirSync(path.dirname(settingsPath), { recursive: true });
  mkdirSync(path.dirname(connectionPath), { recursive: true });
  writeFileSync(path.join(dshRoot, 'package.json'), JSON.stringify({ version }) + '\n');
  if (settings === null) mkdirSync(settingsPath);
  else writeFileSync(settingsPath, settings);
  writeFileSync(connectionPath, connection);
  return dshRoot;
}

function startGateway(envFile: string) {
  return spawnSync(process.execPath, [cli, 'serve-gateway'], {
    cwd: projectRoot,
    env: { ...process.env, DSH_PASSWORDS_ENV_FILE: envFile, LANG: 'en_US.UTF-8' },
    encoding: 'utf8',
  });
}

test('gateway refuses startup when the explicitly configured DSH root is absent', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-cli-root-'));
  const envFile = writeConfig(root, path.join(root, 'missing-dsh'));
  try {
    const result = spawnSync(process.execPath, [cli, 'serve-gateway'], {
      cwd: projectRoot,
      env: { ...process.env, DSH_PASSWORDS_ENV_FILE: envFile, LANG: 'en_US.UTF-8' },
      encoding: 'utf8',
    });
    assert.equal(result.status, 34, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /MCP_DSH_ROOT/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('alpha.3 gateway refuses startup when the settings anchor cannot be patched', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-cli-settings-'));
  const dshRoot = makeAlpha3Root(root, 'export const persistence = "memory";\n', 'export class Connection {}\n');
  try {
    const result = startGateway(writeConfig(root, dshRoot));
    assert.equal(result.status, 35, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /patch target|settings/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('gateway refuses startup when the Cookie bridge is unavailable', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-cli-cookie-'));
  const settings = 'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";\n';
  const dshRoot = makeAlpha3Root(root, settings, 'export class Connection {}\n');
  try {
    const result = startGateway(writeConfig(root, dshRoot));
    assert.equal(result.status, 33, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /Cookie bridge/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('rc.1 gateway refuses startup when the Cookie bridge is unavailable', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-cli-rc1-cookie-'));
  const settings = 'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";\n';
  const dshRoot = makeAlpha3Root(root, settings, 'export class Connection {}\n', '0.1.2-rc.1');
  try {
    const result = startGateway(writeConfig(root, dshRoot));
    assert.equal(result.status, 33, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /Cookie bridge/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('gateway refuses startup when patch inspection throws', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-cli-patch-error-'));
  const dshRoot = makeAlpha3Root(root, null, 'export class Connection {}\n');
  try {
    const result = startGateway(writeConfig(root, dshRoot));
    assert.equal(result.status, 36, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stderr, /patch.*failed|EISDIR/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
