import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// install.sh 的 nonprivileged_tls_mode 必须与 scripts/install.mjs / src/config.ts 的
// autoTls 判定一致：证书值 trim 后同时非空才算自管证书（仅含空白不算）；只有 1/true/yes/auto
// 显式开启；无法识别的显式值在运行时按关闭处理（src/config.ts autoTlsValueIsKnown=false）。
// 首次安装判定（gate_first_install_root）与 scripts/install.mjs 的 isFirstInstall 同口径。
// 这里直接从 install.sh 提取这些函数并在 bash 中执行，避免复制一份会漂移的实现。
const projectRoot = path.resolve(import.meta.dirname, '..');
const installSh = readFileSync(path.join(projectRoot, 'install.sh'), 'utf8').replace(/\r\n/g, '\n');

function extractBashFunction(name: string): string {
  const start = installSh.indexOf(`${name}() {`);
  if (start === -1) return '';
  const end = installSh.indexOf('\n}', start);
  return end === -1 ? '' : installSh.slice(start, end + 2);
}

// require_root 依赖 err()；测试环境只关心退出码，用空实现代替真实输出。
const FN = [
  'err() { :; }',
  extractBashFunction('nonprivileged_tls_mode'),
  extractBashFunction('require_root'),
  extractBashFunction('env_file_for'),
  extractBashFunction('gate_first_install_root'),
].join('\n');

function bashAvailable(): boolean {
  const probe = spawnSync('bash', ['--version'], { stdio: 'ignore' });
  return probe.error === undefined && probe.status === 0;
}

function nonprivileged(vars: Record<string, string>): boolean {
  const script = `${FN}\nif nonprivileged_tls_mode; then printf '0'; else printf '1'; fi`;
  // 显式清空三个键，避免继承宿主环境造成判定漂移。
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    MCP_GATEWAY_TLS_CERT: vars.MCP_GATEWAY_TLS_CERT ?? '',
    MCP_GATEWAY_TLS_KEY: vars.MCP_GATEWAY_TLS_KEY ?? '',
    MCP_GATEWAY_AUTO_TLS: vars.MCP_GATEWAY_AUTO_TLS ?? '',
    DSH_PASSWORDS_RUNTIME: vars.DSH_PASSWORDS_RUNTIME ?? '',
  };
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env });
  assert.equal(result.status, 0, result.stderr ?? '');
  return result.stdout === '0';
}

test('install.sh nonprivileged_tls_mode 与 autoTls 一致，含空白 cert/key（fail-closed）', (t) => {
  if (!bashAvailable()) {
    t.skip('需要 bash');
    return;
  }
  assert.notEqual(FN, '', '未能从 install.sh 提取 nonprivileged_tls_mode');
  assert.equal(nonprivileged({}), false, '默认自动 HTTPS 仍要求 root');
  for (const value of ['0', 'false', 'no', 'FALSE', ' 0 ']) {
    assert.equal(nonprivileged({ MCP_GATEWAY_AUTO_TLS: value }), true, `AUTO_TLS=${value}`);
  }
  // 显式开启与空值（自动判断）仍需要 root。
  for (const value of ['1', 'true', 'yes', 'auto', '', '   ']) {
    assert.equal(nonprivileged({ MCP_GATEWAY_AUTO_TLS: value }), false, `AUTO_TLS=${value}`);
  }
  // 无法识别的显式值运行时 autoTls=false，安装器必须与运行时一致放行。
  for (const value of ['maybe', 'bogus', 'on', '2']) {
    assert.equal(nonprivileged({ MCP_GATEWAY_AUTO_TLS: value }), true, `AUTO_TLS=${value}`);
  }
  assert.equal(
    nonprivileged({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem', MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem' }),
    true,
  );
  assert.equal(
    nonprivileged({ MCP_GATEWAY_TLS_CERT: '  /etc/ssl/c.pem  ', MCP_GATEWAY_TLS_KEY: '\t/etc/ssl/k.pem\t' }),
    true,
    '有效证书前后空白应被 trim',
  );
  // 仅含空白不得视为自管证书。
  assert.equal(nonprivileged({ MCP_GATEWAY_TLS_CERT: '   ', MCP_GATEWAY_TLS_KEY: '   ' }), false);
  assert.equal(nonprivileged({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem', MCP_GATEWAY_TLS_KEY: '  ' }), false);
  assert.equal(nonprivileged({ MCP_GATEWAY_TLS_CERT: '  ', MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem' }), false);
  assert.equal(nonprivileged({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem' }), false, '只有一半证书不算');
  assert.equal(nonprivileged({ DSH_PASSWORDS_RUNTIME: 'docker' }), false, 'runtime 不是授权开关');
});

// 首次安装判定与 scripts/install.mjs 的 isFirstInstall（!exists(envPath)）同口径：目标 .env
// （DSH_PASSWORDS_ENV_FILE 优先，否则 <目标目录>/.env）存在则不是首次安装。修复前 install.sh 在
// “目录尚未下载” 分支无条件要求 root，导致 DSH_PASSWORDS_ENV_FILE 指向已存在外部 .env 的
// 部署被误判为首次安装。
test('install.sh 首次安装判定以目标 .env 为准（外部 DSH_PASSWORDS_ENV_FILE 与 install.mjs 对齐）', (t) => {
  if (!bashAvailable()) {
    t.skip('需要 bash');
    return;
  }
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('需要非 root 进程');
    return;
  }
  assert.notEqual(FN, '', '未能从 install.sh 提取门禁函数');
  const needsRoot = (target: string, vars: Record<string, string>): boolean => {
    const script = `${FN}\ngate_first_install_root "$1" "sudo bash install.sh"`;
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      MCP_GATEWAY_TLS_CERT: vars.MCP_GATEWAY_TLS_CERT ?? '',
      MCP_GATEWAY_TLS_KEY: vars.MCP_GATEWAY_TLS_KEY ?? '',
      MCP_GATEWAY_AUTO_TLS: vars.MCP_GATEWAY_AUTO_TLS ?? '',
      DSH_PASSWORDS_ENV_FILE: vars.DSH_PASSWORDS_ENV_FILE ?? '',
    };
    const result = spawnSync('bash', ['-c', script, 'bash', target], { encoding: 'utf8', env });
    // require_root 需要 root 时 exit 1；否则返回 0。
    assert.ok(result.status === 0 || result.status === 1, result.stderr ?? '');
    return result.status === 1;
  };

  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-sh-gate-'));
  try {
    const dest = path.join(dir, 'dest');
    mkdirSync(dest);
    // 目录无 .env、未设置外部 env → 首次安装，需要 root。
    assert.equal(needsRoot(dest, {}), true, '无 .env 的默认自动 HTTPS 首次安装需要 root');
    // 非特权模式（显式关闭或运行时未知值）放行。
    assert.equal(needsRoot(dest, { MCP_GATEWAY_AUTO_TLS: '0' }), false);
    assert.equal(needsRoot(dest, { MCP_GATEWAY_AUTO_TLS: 'maybe' }), false);
    assert.equal(needsRoot(dest, { MCP_GATEWAY_AUTO_TLS: '1' }), true, '显式开启仍需要 root');

    // 目标目录内已有 .env → 非首次安装，放行。
    writeFileSync(path.join(dest, '.env'), 'SETUP_KEY=x\n');
    assert.equal(needsRoot(dest, {}), false);

    // 外部 DSH_PASSWORDS_ENV_FILE 已存在、目标目录尚未下载 → 非首次安装，放行（issue 1 修复点）。
    const external = path.join(dir, 'data', '.env');
    mkdirSync(path.dirname(external), { recursive: true });
    writeFileSync(external, 'SETUP_KEY=x\n');
    const freshDest = path.join(dir, 'fresh');
    assert.equal(needsRoot(freshDest, { DSH_PASSWORDS_ENV_FILE: external }), false);

    // 外部 DSH_PASSWORDS_ENV_FILE 缺失 → 仍是首次安装，fail-closed 要求 root。
    assert.equal(needsRoot(freshDest, { DSH_PASSWORDS_ENV_FILE: path.join(dir, 'missing.env') }), true);
    assert.equal(
      needsRoot(freshDest, { DSH_PASSWORDS_ENV_FILE: path.join(dir, 'missing.env'), MCP_GATEWAY_AUTO_TLS: '0' }),
      false,
      '外部 env 缺失但显式非特权模式仍放行',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
