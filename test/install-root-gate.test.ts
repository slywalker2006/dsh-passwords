import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
// Issue #36：安装器在首次安装时无条件要求 Unix root，忽略 MCP_GATEWAY_AUTO_TLS=0；
// 当 DSH_PASSWORDS_ENV_FILE 指向尚不存在的文件时，非 root Docker/反代部署在插件
// 注册前退出。下面直接覆盖 scripts/install.mjs 导出的门禁纯逻辑，不启动真实网络/安装流程。
import {
  isExplicitNonPrivilegedTlsMode,
  firstInstallNeedsRoot,
  firstInstallEnvContent,
} from '../scripts/install-root-gate.mjs';

test('显式关闭自动 HTTPS 或提供自管证书 = 明确的非特权模式', () => {
  assert.equal(isExplicitNonPrivilegedTlsMode({}), false);
  for (const value of ['0', 'false', 'no', 'FALSE', ' No ', ' 0 ']) {
    assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_AUTO_TLS: value }), true, `AUTO_TLS=${value}`);
  }
  assert.equal(
    isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem', MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem' }),
    true,
  );
  // 有效证书值允许前后有空白（trim 后仍非空）。
  assert.equal(
    isExplicitNonPrivilegedTlsMode({
      MCP_GATEWAY_TLS_CERT: '  /etc/ssl/c.pem  ',
      MCP_GATEWAY_TLS_KEY: '\t/etc/ssl/k.pem\t',
    }),
    true,
  );
});

test('自动 HTTPS 默认/显式开启不是非特权模式，无法识别的值按运行时判定为关闭', () => {
  // 显式开启与空值（自动判断）都需要 root。
  for (const value of ['1', 'true', 'yes', 'auto', '', '   ']) {
    assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_AUTO_TLS: value }), false, `AUTO_TLS=${value}`);
  }
  // 与运行时一致：src/config.ts 对无法识别的显式值判定 autoTlsValueIsKnown=false ⇒ autoTls=false，
  // 不会绑定特权端口，因此安装器同样放行非 root 首次安装。
  for (const value of ['maybe', 'bogus', 'on', '2']) {
    assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_AUTO_TLS: value }), true, `AUTO_TLS=${value}`);
  }
  // 只给一半证书不算用户自管证书。
  assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem' }), false);
  assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem' }), false);
  // 仅含空白（trim 后为空）不得视为自管证书。
  assert.equal(isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_CERT: '   ', MCP_GATEWAY_TLS_KEY: '   ' }), false);
  assert.equal(
    isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem', MCP_GATEWAY_TLS_KEY: '  ' }),
    false,
  );
  assert.equal(
    isExplicitNonPrivilegedTlsMode({ MCP_GATEWAY_TLS_CERT: '  ', MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem' }),
    false,
  );
});

test('单独设置 DSH_PASSWORDS_RUNTIME=docker 不构成授权', () => {
  assert.equal(isExplicitNonPrivilegedTlsMode({ DSH_PASSWORDS_RUNTIME: 'docker' }), false);
  assert.equal(
    firstInstallNeedsRoot({ isWin: false, uid: 1000, env: { DSH_PASSWORDS_RUNTIME: 'docker' } }),
    true,
  );
});

test('非 root + 缺失外部 env + AUTO_TLS=0 时放行首次安装（Issue #36）', () => {
  const env = { MCP_GATEWAY_AUTO_TLS: '0', DSH_PASSWORDS_ENV_FILE: '/data/dsh-passwords/.env' };
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env }), false);
});

test('AUTO_TLS 无法识别的值按运行时放行非 root 首次安装', () => {
  // src/config.ts：未知/非法显式值 ⇒ autoTls=false（不绑定特权端口），安装器必须与运行时一致。
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env: { MCP_GATEWAY_AUTO_TLS: 'maybe' } }), false);
  // 未设置/显式开启仍要求 root。
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env: {} }), true);
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env: { MCP_GATEWAY_AUTO_TLS: 'auto' } }), true);
});

test('非 root + 默认自动 HTTPS 仍拒绝首次安装', () => {
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env: {} }), true);
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 1000, env: { MCP_GATEWAY_AUTO_TLS: '1' } }), true);
});

test('root 与 Windows 不受首次安装门禁约束', () => {
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: 0, env: {} }), false);
  assert.equal(firstInstallNeedsRoot({ isWin: true, uid: undefined, env: {} }), false);
  assert.equal(firstInstallNeedsRoot({ isWin: false, uid: null, env: {} }), false);
});

test('非特权首次安装的 .env 不写特权端口，并持久化非特权模式', () => {
  const off = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0' });
  assert.match(off, /^SETUP_KEY=K$/m);
  assert.match(off, /^MCP_DB_ENC_KEY=D$/m);
  assert.match(off, /^MCP_GATEWAY_AUTO_TLS=0$/m);
  assert.match(off, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m);
  assert.match(off, /^MCP_GATEWAY_PORT=8080$/m);
  assert.doesNotMatch(off, /MCP_GATEWAY_PORT=443/);
  assert.doesNotMatch(off, /MCP_GATEWAY_HOST=0\.0\.0\.0/);
  assert.doesNotMatch(off, /MCP_GATEWAY_REDIRECT_PORT/);

  const certs = firstInstallEnvContent('K', 'D', {
    MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem',
    MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem',
  });
  assert.match(certs, /^MCP_GATEWAY_TLS_CERT=\/etc\/ssl\/c\.pem$/m);
  assert.match(certs, /^MCP_GATEWAY_TLS_KEY=\/etc\/ssl\/k\.pem$/m);
  assert.match(certs, /^MCP_GATEWAY_PORT=8080$/m);
  assert.doesNotMatch(certs, /MCP_GATEWAY_AUTO_TLS/);

  const explicit = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0', MCP_GATEWAY_PORT: '3088' });
  assert.match(explicit, /^MCP_GATEWAY_PORT=3088$/m);
});

// 非 root 首次安装的明文 HTTP 网关不能默认监听 0.0.0.0：src/config.ts 在缺省
// MCP_GATEWAY_HOST 时回退 0.0.0.0，安装器必须显式写回环地址才不把明文服务暴露到所有网卡。
test('非特权首次安装的 .env 默认只监听回环，用户显式 host 优先', () => {
  const dflt = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0' });
  assert.match(dflt, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m, '无显式 host 时回环');
  assert.doesNotMatch(dflt, /MCP_GATEWAY_HOST=0\.0\.0\.0/, '不得默认为全网卡监听');

  // 仅含空白等同未设置，仍回落环。
  const blank = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0', MCP_GATEWAY_HOST: '   ' });
  assert.match(blank, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m);

  // 用户显式给定的监听地址原样保留（含 0.0.0.0 与内网地址），只做首尾 trim。
  const broadcast = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0', MCP_GATEWAY_HOST: '0.0.0.0' });
  assert.match(broadcast, /^MCP_GATEWAY_HOST=0\.0\.0\.0$/m);
  const lan = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: '0', MCP_GATEWAY_HOST: '  10.0.0.5  ' });
  assert.match(lan, /^MCP_GATEWAY_HOST=10\.0\.0\.5$/m);

  // 自管证书分支同属非特权模式，默认同回环，显式 host 优先。
  const certs = firstInstallEnvContent('K', 'D', {
    MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem',
    MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem',
  });
  assert.match(certs, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m);
  const certsExplicit = firstInstallEnvContent('K', 'D', {
    MCP_GATEWAY_TLS_CERT: '/etc/ssl/c.pem',
    MCP_GATEWAY_TLS_KEY: '/etc/ssl/k.pem',
    MCP_GATEWAY_HOST: '0.0.0.0',
  });
  assert.match(certsExplicit, /^MCP_GATEWAY_HOST=0\.0\.0\.0$/m);
});

test('自动 HTTPS 首次安装的 .env 保持原有 443/80 默认', () => {
  const dflt = firstInstallEnvContent('K', 'D', {});
  assert.match(dflt, /^MCP_GATEWAY_PORT=443$/m);
  assert.match(dflt, /^MCP_GATEWAY_REDIRECT_PORT=80$/m);
  assert.doesNotMatch(dflt, /MCP_GATEWAY_AUTO_TLS/);
  // 自动 HTTPS 面向公网，保持 0.0.0.0 隐式默认，不写 host（root gate 已要求特权）。
  assert.doesNotMatch(dflt, /MCP_GATEWAY_HOST/);
});

// 与 src/config.ts 对齐：未知/非法 AUTO_TLS 值运行时 autoTls=false，首次 .env 必须写入非特权配置，
// 否则非 root 安装会因写入 443/80 在运行时绑定特权端口而启动失败。
test('AUTO_TLS 无法识别的值 → 首次 .env 走非特权分支', () => {
  const env = firstInstallEnvContent('K', 'D', { MCP_GATEWAY_AUTO_TLS: 'maybe' });
  assert.match(env, /^MCP_GATEWAY_AUTO_TLS=0$/m, '未知值归一化为显式关闭');
  assert.match(env, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m);
  assert.match(env, /^MCP_GATEWAY_PORT=8080$/m);
  assert.doesNotMatch(env, /MCP_GATEWAY_PORT=443/);
});

// ── P1：非特权首次安装的目标目录 ──
// install.sh 的默认下载目录 /opt/dsh-passwords 对非 root 不可写；非特权首次安装（已通过
// root gate）会在 git clone 阶段因权限失败，并被通用报错误报成“下载失败/网络问题”。
// 下面直接提取 install.sh 的目录解析/可写判定函数在 bash 中执行，避免复制一份会漂移的实现。
const projectRoot = path.resolve(import.meta.dirname, '..');
const installSh = readFileSync(path.join(projectRoot, 'install.sh'), 'utf8').replace(/\r\n/g, '\n');

function extractBashFunction(name: string): string {
  const start = installSh.indexOf(`${name}() {`);
  if (start === -1) return '';
  const end = installSh.indexOf('\n}', start);
  return end === -1 ? '' : installSh.slice(start, end + 2);
}

const DEFAULT_DEST_FN = extractBashFunction('default_dest');
const DEST_WRITABLE_FN = extractBashFunction('dest_writable');

function bashAvailable(): boolean {
  const probe = spawnSync('bash', ['--version'], { stdio: 'ignore' });
  return probe.error === undefined && probe.status === 0;
}

test('install.sh 非 root 首次安装的默认目录改到用户可写路径（P1）', (t) => {
  if (!bashAvailable()) {
    t.skip('需要 bash');
    return;
  }
  assert.notEqual(DEFAULT_DEST_FN, '', '未能从 install.sh 提取 default_dest');
  const defaultDest = (uid: number, env: Record<string, string>): string => {
    // 需要“未设置”的键在 bash 内显式 unset，避免 Git Bash 用空/继承值填 HOME 造成判定漂移。
    const script = [
      DEFAULT_DEST_FN,
      env.HOME ? '' : 'unset HOME',
      env.DSH_PASSWORDS_DIR ? '' : 'unset DSH_PASSWORDS_DIR',
      `default_dest "${uid}"`,
    ].join('\n');
    const result = spawnSync('bash', ['-c', script], {
      encoding: 'utf8',
      env: { ...process.env, ...env },
    });
    assert.equal(result.status, 0, result.stderr ?? '');
    return result.stdout;
  };
  assert.equal(defaultDest(0, { HOME: '/root' }), '/opt/dsh-passwords', 'root 保持 /opt 默认');
  assert.equal(defaultDest(1000, { HOME: '/home/tester' }), '/home/tester/dsh-passwords', '非 root 改到 $HOME');
  assert.equal(
    defaultDest(1000, { HOME: '/home/tester', DSH_PASSWORDS_DIR: '/data/dsh-passwords' }),
    '/data/dsh-passwords',
    '显式 DSH_PASSWORDS_DIR 优先',
  );
  assert.equal(
    defaultDest(0, { HOME: '/root', DSH_PASSWORDS_DIR: '/data/dsh-passwords' }),
    '/data/dsh-passwords',
    'root 也尊重显式值',
  );
  assert.equal(defaultDest(1000, {}), '', '非 root 且无 HOME 交由调用方显式拒绝');
});

test('install.sh dest_writable 区分权限失败与下载失败（P1 前置检查）', (t) => {
  if (!bashAvailable()) {
    t.skip('需要 bash');
    return;
  }
  assert.notEqual(DEST_WRITABLE_FN, '', '未能从 install.sh 提取 dest_writable');
  const destWritable = (target: string): boolean => {
    const script = `${DEST_WRITABLE_FN}\nif dest_writable "$1"; then printf 'yes'; else printf 'no'; fi`;
    const result = spawnSync('bash', ['-c', script, 'bash', target], { encoding: 'utf8', env: process.env });
    assert.equal(result.status, 0, result.stderr ?? '');
    return result.stdout === 'yes';
  };
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-dest-'));
  try {
    assert.equal(destWritable(dir), true, '已存在且可写的目录');
    assert.equal(destWritable(path.join(dir, 'nested', 'app')), true, '父目录可写即可创建');
    const blocker = path.join(dir, 'blocker');
    writeFileSync(blocker, '');
    assert.equal(destWritable(path.join(blocker, 'child')), false, '祖先不是目录 → 不可写');
    // root 会绕过权限位，仅在非 root 下验证真正的不可写目录。
    if (typeof process.getuid === 'function' && process.getuid() !== 0) {
      const locked = path.join(dir, 'locked');
      mkdirSync(locked);
      chmodSync(locked, 0o555);
      assert.equal(destWritable(locked), false, '存在但不可写');
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('install.sh 在 git clone 前做可写检查，且移除 /opt 硬默认（P1 静态契约）', () => {
  assert.match(installSh, /default_dest\(\) \{/, '必须定义 default_dest');
  assert.match(installSh, /printf '%s\/dsh-passwords' "\$HOME"/, '非 root 默认目录应为 $HOME/dsh-passwords');
  assert.match(installSh, /dest_writable\(\) \{/, '必须定义 dest_writable');
  const writableAt = installSh.indexOf('dest_writable "$DEST"');
  const cloneAt = installSh.indexOf('git clone --depth 1');
  assert.ok(writableAt !== -1 && cloneAt !== -1 && writableAt < cloneAt, '可写检查必须前置于 git clone');
  assert.doesNotMatch(
    installSh,
    /DEST="\$\{DSH_PASSWORDS_DIR:-\/opt\/dsh-passwords\}"/,
    '旧的 /opt 硬默认必须移除',
  );
});
