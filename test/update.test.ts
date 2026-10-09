import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, rmdirSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import type { PlatformConfig } from '../src/config.ts';
import { isBackgroundUpdateRequest, systemdPurgeLaunchArgs } from '../src/gateway.ts';
import { resolveNpmCommand, windowsNpmShimArgs } from '../src/patch.ts';
import {
  compareVersions,
  detectRuntime,
  deploymentEnvFileRelativeEntry,
  isContainerRuntime,
  parseNpmPackageInfo,
  parseReleaseInfo,
  updateApplyHttpStatus,
  type UpdateEngineOps,
  type UpdateStore,
  UpdateEngine,
  UPDATE_DEFAULT_MAX_BPS,
  UPDATE_CHECK_MS,
  UPDATE_GATE_TTL_MS,
  UPDATE_IDLE_MS,
  npmGlobalInstallArgs,
} from '../src/update.ts';

function config(dbPath: string, restartService = 'dsh-web'): PlatformConfig {
  return {
    setupKey: 'test-setup-key', dbPath, dbEncKey: '', jwtSecret: 'test-jwt-secret', internalSecret: 'test-internal-secret',
    gateway: { host: '127.0.0.1', port: 9443, upstream: 'http://127.0.0.1:3080', tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false, acmeEmail: '', acmeStaging: false },
    patch: { dshRoot: '', restartService }, endpointRules: [],
  };
}

function store(): UpdateStore & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return { values, getSetting: (key) => values.get(key) ?? null, setSetting: (key, value) => values.set(key, value), audit: () => {} };
}

async function flushUpdates(count = 12): Promise<void> {
  for (let i = 0; i < count; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** 固定部署交换锁路径（与 UpdateEngine 同口径：部署目录同级的隐藏文件）。 */
function fixedDeploymentLockPath(root: string): string {
  return path.join(path.dirname(root), `.${path.basename(root)}.update.lock`);
}

/** 部署目录同级的临时残留（staging/backup/failed/lock），用于断言异常清理。 */
function deploymentSiblings(root: string): string[] {
  const prefix = `.${path.basename(root)}.`;
  return readdirSync(path.dirname(root)).filter((name) => name.startsWith(prefix));
}

/** 手动模式两阶段：下载 + 确认安装，与插件两次点击等价。 */
async function runManualInstall(engine: UpdateEngine): Promise<void> {
  await engine.checkNow();
  const downloaded = await engine.applyNow();
  assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
  await flushUpdates();
  const installed = await engine.applyNow();
  assert.equal(installed.code, 'INSTALL_STARTED');
  await flushUpdates();
}

function release(version = '2.6.3'): unknown { return { tag_name: `v${version}` }; }
function metadata(version = '2.6.3', payload = Buffer.from('verified package')): unknown {
  return { name: 'dsh-passwords', version, dist: { tarball: `https://registry.npmjs.org/dsh-passwords/-/dsh-passwords-${version}.tgz`, integrity: `sha512-${createHash('sha512').update(payload).digest('base64')}` } };
}

function setupDocker(root: string, autoEnabled: boolean, nowRef: { value: number }, results: { pull?: boolean; up?: boolean; ps?: boolean } = {}) {
  const composeDir = path.join(root, 'compose');
  mkdirSync(composeDir, { recursive: true });
  writeFileSync(path.join(composeDir, 'compose.yml'), 'services:\n  dsh-passwords:\n    image: skywalker237234/dsh-passwords:2.6.2\n');
  const calls: Array<{ command: string; args: string[]; cwd?: string }> = [];
  let installAudits = 0;
  const db = store();
  db.setSetting('auto_update_enabled', autoEnabled ? '1' : '0');
  const ops: UpdateEngineOps = {
    now: () => nowRef.value,
    fetchRelease: async () => release(),
    fetchNpmMetadata: async () => {
      throw new Error('Docker must not query npm metadata');
    },
    download: async () => {
      throw new Error('Docker must not download npm artifacts');
    },
    runInstall: async () => {
      throw new Error('Docker must not run npm install');
    },
    runCommand: async (command, args, cwd) => {
      calls.push({ command, args, cwd });
      if (command !== 'docker') return { ok: false, message: 'unexpected command' };
      if (args[0] !== 'compose') return { ok: false, message: 'unexpected docker command' };
      if (args.includes('pull')) return { ok: results.pull !== false, message: results.pull === false ? 'pull failed' : '' };
      if (args.includes('up')) return { ok: results.up !== false, message: results.up === false ? 'up failed' : '' };
      if (args.includes('ps')) return { ok: results.ps !== false, message: results.ps === false ? 'ps failed' : 'dsh-passwords' };
      if (args.some((arg) => arg.includes('package.json'))) return { ok: true, message: '2.6.3' };
      if (args.some((arg) => arg.includes('readyz'))) return { ok: true, message: '' };
      return { ok: false, message: 'unexpected compose command' };
    },
    restartWebService: async () => ({ ok: false, message: 'Docker must not restart systemd' }),
    log: () => {},
  };
  const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, {
    installRoot: root,
    env: {
      DSH_PASSWORDS_RUNTIME: 'docker',
      MCP_DSH_DOCKER_COMPOSE_DIR: composeDir,
      DSH_HOME: path.join(root, 'dsh-home'),
      MCP_DSH_DOCKER_SELF_UPDATE: '1',
      MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml',
      MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords',
    },
    dockerSelfUpdateAvailable: true,
  });
  const originalAudit = db.audit;
  db.audit = (...args) => { installAudits += 1; originalAudit(...args); };
  return { engine, db, ops, calls, installAudits: () => installAudits, composeDir };
}

// currentVersion = 部署中正在运行的旧版本；targetVersion = 线上/本地待升级到的版本。
// 默认值与历史契约保持一致，既有测试无需改动；2.7.7 → 本地 2.7.8 的回归用例显式覆盖它们。
function setup(root: string, autoEnabled: boolean, nowRef: { value: number }, restartOk = true, restartService = 'dsh-web', extraEnv: NodeJS.ProcessEnv = {}, inPlaceDeploymentSwap = true, currentVersion = '2.6.2', targetVersion = '2.6.3') {
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'dsh-passwords', version: currentVersion }));
  writeFileSync(path.join(root, 'obsolete-runtime.js'), 'old program file\n');
  const envFile = path.join(root, '.env');
  writeFileSync(envFile, 'SETUP_KEY=test-setup-key\n');
  mkdirSync(path.join(root, 'data'), { recursive: true });
  writeFileSync(path.join(root, 'data', 'platform.db'), 'user database\n');
  const dshHome = path.join(root, 'dsh-home');
  const globalRoot = path.join(root, 'global', 'node_modules');
  const calls: Array<{ command: string; args: string[] }> = [];
  let restarts = 0;
  let restartAllowed = restartOk;
  const payload = Buffer.from('verified package');
  const ops: UpdateEngineOps = {
    now: () => nowRef.value,
    fetchRelease: async () => release(targetVersion),
    fetchNpmMetadata: async () => metadata(targetVersion),
    download: async (_url, dest, maxBps, resumed, progress) => {
      assert.equal(resumed, 0);
      progress?.(payload.length, payload.length);
      writeFileSync(dest, payload);
      assert.ok(maxBps <= UPDATE_DEFAULT_MAX_BPS || maxBps > 1_000_000_000_000);
      return createHash('sha512').update(payload).digest('hex');
    },
    runInstall: async (args) => {
      if (args.includes('--prefix')) {
        assert.ok(args.includes('--omit=dev'));
        assert.ok(args.includes('--ignore-scripts'));
      }
      const prefixIndex = args.indexOf('--prefix');
      if (prefixIndex >= 0) {
        const stagingRoot = args[prefixIndex + 1];
        const packageRoot = path.join(stagingRoot, 'node_modules', 'dsh-passwords');
        mkdirSync(path.join(packageRoot, 'dist'), { recursive: true });
        mkdirSync(path.join(packageRoot, 'scripts'), { recursive: true });
        writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name: 'dsh-passwords', version: targetVersion }));
        writeFileSync(path.join(packageRoot, 'dist', 'cli.js'), 'export {};\n');
        writeFileSync(path.join(packageRoot, 'scripts', 'register-plugin.mjs'), 'export {};\n');
        writeFileSync(path.join(stagingRoot, 'node_modules', 'runtime-dependency.js'), 'export {};\n');
      }
      return { ok: true, message: '' };
    },
    runCommand: async (command, args, _cwd, env) => {
      calls.push({ command, args });
      if (args.includes('root') && args.includes('-g')) return { ok: true, message: globalRoot };
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        const packageRoot = path.resolve(path.dirname(args[0]), '..');
        const profile = path.join(env?.DSH_HOME ?? dshHome, 'profiles', 'web');
        mkdirSync(path.join(profile, 'node_modules'), { recursive: true });
        const linkPath = path.join(profile, 'node_modules', 'dsh-passwords');
        rmSync(linkPath, { recursive: true, force: true });
        symlinkSync(packageRoot, linkPath, process.platform === 'win32' ? 'junction' : 'dir');
        writeFileSync(path.join(profile, 'package.json'), JSON.stringify({ dependencies: { 'dsh-passwords': `link:${packageRoot}` } }));
      }
      return { ok: true, message: '' };
    },
    restartWebService: async () => { restarts += 1; return restartAllowed ? { ok: true, message: '' } : { ok: false, message: 'systemd unavailable' }; }, log: () => {},
  };
  const db = store();
  db.setSetting('auto_update_enabled', autoEnabled ? '1' : '0');
  const engine = new UpdateEngine(config(path.join(root, 'data', 'platform.db'), restartService), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: dshHome, DSH_PASSWORDS_ENV_FILE: envFile, ...extraEnv }, inPlaceDeploymentSwap });
  return { engine, db, ops, calls, restarts: () => restarts, setRestartAllowed: (allowed: boolean) => { restartAllowed = allowed; } };
}

test('update apply maps NOT_READY to an actionable 422 instead of HTTP 409', () => {
  assert.equal(updateApplyHttpStatus({ ok: false, code: 'NOT_READY', message: 'download pending' }), 422);
  assert.equal(updateApplyHttpStatus({ ok: false, code: 'RATE_LIMITED', message: 'try later' }), 429);
  assert.equal(updateApplyHttpStatus({ ok: false, code: 'DOWNLOAD_IN_PROGRESS' }), 202);
  assert.equal(updateApplyHttpStatus({ ok: false, code: 'INSTALL_IN_PROGRESS' }), 202);
  assert.equal(updateApplyHttpStatus({ ok: false, code: 'INSTALL_STARTED' }), 202);
  assert.equal(updateApplyHttpStatus({ ok: true, code: 'NO_UPDATE' }), 200);
});

// 2.7.7 → 本地 package 版本（当前 2.7.8）的固定部署升级回归。
// 复用既有 ops 夹具（不真实执行 npm install / 不连远程）：runInstall 只把目标版本写进 staging，
// 断言集中在升级必须保留的部署状态与 profile 指向，绝不声称为真实 npm/远程验收。
test('2.7.7 → 本地 package 版本固定部署升级：保留 .env、打开中的数据库句柄与 profile，并替换旧程序', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  // 升级链方向必须是 2.7.7 < 本地版本，且本地版本是 X.Y.Z 形态（compareVersions 只接受该形态）。
  assert.equal(compareVersions(pkg.version, '2.7.7'), 1, `本地版本 ${pkg.version} 必须高于 2.7.7`);
  const dbFile = path.join(root, 'data', 'platform.db');
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now, true, 'dsh-web', {}, true, '2.7.7', pkg.version);
    // 复刻真实前提：2.7.7 进程正打开部署内 SQLite 文件句柄（Windows 上会阻止 rename 部署目录）。
    rmSync(dbFile);
    const sqlite = new DatabaseSync(dbFile);
    sqlite.exec("CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('kept');");
    try {
      assert.match(readFileSync(path.join(root, '.env'), 'utf8'), /^SETUP_KEY=test-setup-key$/m);
      await runManualInstall(engine);
      assert.equal(restarts(), 1, '升级完成后应触发一次服务重启');
      // .env 保留原配置，并补写指向保留数据库的 MCP_DB_PATH。
      const envAfter = readFileSync(path.join(root, '.env'), 'utf8');
      assert.match(envAfter, /^SETUP_KEY=test-setup-key$/m);
      assert.match(envAfter, /^MCP_DB_PATH=.*platform\.db$/m);
      // 打开中的数据库句柄在升级后仍能读到原数据（data 目录未被移动）。
      assert.equal(sqlite.prepare('SELECT value FROM probe').get()?.value, 'kept');
      // 旧程序被替换为本地目标版本，旧程序文件不残留。
      assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, pkg.version);
      assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
      // profile 指向本部署目录，且链接到的包版本即升级目标。
      const profile = JSON.parse(readFileSync(path.join(root, 'dsh-home', 'profiles', 'web', 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
      assert.equal(profile.dependencies['dsh-passwords'], `link:${root}`);
      const linked = JSON.parse(readFileSync(path.join(root, 'dsh-home', 'profiles', 'web', 'node_modules', 'dsh-passwords', 'package.json'), 'utf8')) as { version: string };
      assert.equal(linked.version, pkg.version);
      assert.deepEqual(deploymentSiblings(root), [], '不应留下 staging/backup/failed/lock 残留');
      assert.equal(existsSync(path.join(root, 'update')), false, '下载临时目录应被清理');
    } finally {
      sqlite.close();
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('固定部署自定义 env 文件名：只保留部署目录内的相对路径，越界与分隔异常拒绝', () => {
  const root = path.join(tmpdir(), 'dshpw-env-scope');
  // 未显式指定：返回 null，保持 .env 默认行为。
  assert.equal(deploymentEnvFileRelativeEntry(root, ''), null);
  assert.equal(deploymentEnvFileRelativeEntry(root, '   '), null);
  // 部署目录内的相对路径按原样保留。
  assert.equal(deploymentEnvFileRelativeEntry(root, path.join(root, '.env')), '.env');
  assert.equal(deploymentEnvFileRelativeEntry(root, path.join(root, 'harness.env')), 'harness.env');
  assert.equal(deploymentEnvFileRelativeEntry(root, path.join(root, 'config', 'app.env')), path.join('config', 'app.env'));
  // 越界：等于部署目录本身，或位于其外部。
  assert.equal(deploymentEnvFileRelativeEntry(root, root), null);
  assert.equal(deploymentEnvFileRelativeEntry(root, path.join(root, '..', 'outside.env')), null);
  if (process.platform !== 'win32') {
    // POSIX 上反斜杠是合法文件名字符，下游会把它误当路径分隔符，必须拒绝。
    assert.equal(deploymentEnvFileRelativeEntry(root, path.join(root, 'nested\\app.env')), null);
  }
});

test('固定部署使用自定义 env 文件名（就地交换）：保留配置与打开的数据库句柄', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-envname-'));
  const envFile = path.join(root, 'harness.env');
  const dbFile = path.join(root, 'data', 'platform.db');
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now, true, 'dsh-web', { DSH_PASSWORDS_ENV_FILE: envFile }, true);
    writeFileSync(envFile, 'SETUP_KEY=custom-env-key\n');
    // 复刻真实前提：部署内 SQLite 文件句柄处于打开状态，数据目录不得被移动。
    rmSync(dbFile);
    const sqlite = new DatabaseSync(dbFile);
    sqlite.exec("CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES ('kept');");
    try {
      await runManualInstall(engine);
      assert.equal(restarts(), 1);
      const envAfter = readFileSync(envFile, 'utf8');
      assert.match(envAfter, /^SETUP_KEY=custom-env-key$/m, '自定义 env 文件必须原地保留');
      assert.match(envAfter, /^MCP_DB_PATH=.*platform\.db$/m);
      assert.equal(sqlite.prepare('SELECT value FROM probe').get()?.value, 'kept', '打开的数据库句柄必须原地保留');
      assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.3');
      assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
      assert.deepEqual(deploymentSiblings(root), [], '不应留下 staging/backup/failed/lock 残留');
    } finally {
      sqlite.close();
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('固定部署使用自定义 env 文件名（整目录交换）：保留配置与数据', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-envname-'));
  const envFile = path.join(root, 'harness.env');
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now, true, 'dsh-web', { DSH_PASSWORDS_ENV_FILE: envFile }, false);
    writeFileSync(envFile, 'SETUP_KEY=custom-env-key\n');
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    const envAfter = readFileSync(envFile, 'utf8');
    assert.match(envAfter, /^SETUP_KEY=custom-env-key$/m, '整目录交换后自定义 env 文件必须被移回部署目录');
    assert.match(envAfter, /^MCP_DB_PATH=.*platform\.db$/m);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
    assert.deepEqual(deploymentSiblings(root), [], '不应留下 staging/backup/failed/lock 残留');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('固定部署使用自定义 env 文件名时 profile 注册失败：回滚旧程序并保留配置', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-envname-'));
  const envFile = path.join(root, 'harness.env');
  try {
    const now = { value: 1_000_000 };
    const { engine, ops, restarts } = setup(root, false, now, true, 'dsh-web', { DSH_PASSWORDS_ENV_FILE: envFile }, false);
    writeFileSync(envFile, 'SETUP_KEY=custom-env-key\n');
    let registrations = 0;
    ops.runCommand = async (command, args) => {
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        registrations += 1;
        return { ok: false, message: 'register boom' };
      }
      return { ok: true, message: '' };
    };
    await runManualInstall(engine);
    assert.equal(restarts(), 0, '注册失败不得重启到未注册的新版本');
    assert.equal(registrations, 2, '回滚后应尝试重新注册旧 profile');
    assert.match(engine.status().lastError ?? '', /profile/);
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.2', '失败后必须回滚到旧程序');
    assert.match(readFileSync(envFile, 'utf8'), /^SETUP_KEY=custom-env-key$/m, '回滚必须保留自定义 env 文件');
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.deepEqual(deploymentSiblings(root), [], '回滚后不应留下 staging/backup/failed/lock');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('source archives without .git still use the npm update runtime', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-runtime-'));
  try {
    mkdirSync(path.join(root, 'src'));
    mkdirSync(path.join(root, 'scripts'));
    assert.equal(detectRuntime(root, { DSH_PASSWORDS_RUNTIME: '' }), 'git');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('detectRuntime 把调用方 env 传入 npm 探测子进程', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-runtime-env-'));
  try {
    const fakeNpm = path.join(dir, 'npm-cli.js');
    // 子进程只回显调用方注入的 env：漏传 env 时会继承宿主 process.env，输出为空。
    writeFileSync(fakeNpm, 'process.stdout.write(process.env.DSH_PW_RUNTIME_PROBE ?? "");\n');
    const globalRoot = path.join(dir, 'global-root');
    mkdirSync(globalRoot, { recursive: true });
    const installRoot = path.join(globalRoot, 'dsh-passwords');
    const env = { DSH_PASSWORDS_RUNTIME: '', npm_execpath: fakeNpm, DSH_PW_RUNTIME_PROBE: globalRoot };
    assert.equal(detectRuntime(installRoot, env), 'npm-global', '探测子进程必须拿到调用方 env（npm --prefix 等配置随之生效）');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('普通 npm 更新只安装生产依赖并跳过第三方脚本', () => {
  assert.deepEqual(npmGlobalInstallArgs('C:/cache/dsh-passwords-2.7.8.tgz'), [
    'install', '-g', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', 'C:/cache/dsh-passwords-2.7.8.tgz',
  ]);
});


test('container detection covers explicit runtime, data homes and standard container markers', () => {
  assert.equal(isContainerRuntime({ DSH_PASSWORDS_RUNTIME: 'docker' }, () => false), true);
  assert.equal(isContainerRuntime({ DSH_HOME: '/data/dsh' }, () => false), true);
  assert.equal(isContainerRuntime({}, (candidate) => candidate === '/.dockerenv'), true);
  assert.equal(isContainerRuntime({}, (candidate) => candidate === '/run/.containerenv'), true);
  assert.equal(isContainerRuntime({}, () => false), false);
});

test('Issue #33：npm 解析优先 node + npm-cli.js，Windows 上不再走无法 spawn 的 .cmd shim', () => {
  const resolved = resolveNpmCommand(['root', '-g']);
  assert.ok(resolved !== null, 'npm 调用方式应可解析');
  if (resolved.command === process.execPath) {
    assert.match(resolved.args[0] ?? '', /npm-cli\.js$/i, '应使用 npm-cli.js 入口');
    assert.deepEqual(resolved.args.slice(1), ['root', '-g'], 'npm 子命令参数必须排在入口之后');
  } else {
    assert.notEqual(process.platform, 'win32', 'Windows 上不能回退到 shell:false 无法执行的 .cmd shim');
    assert.equal(resolved.command, 'npm');
  }
  // 真实 Windows 路径上验证 node/npm-cli.js 或 cmd shim 都不会触发 .cmd EINVAL。
  const version = resolveNpmCommand(['--version']);
  assert.ok(version !== null);
  if (process.platform === 'win32') {
    const probe = spawnSync(version.command, version.args, { encoding: 'utf8', timeout: 30_000, shell: false, windowsHide: true });
    assert.equal(probe.error, undefined);
    assert.equal(probe.status, 0, `npm --version 应成功：${probe.stderr ?? ''}`);
    assert.match(String(probe.stdout ?? '').trim(), /^\d+\.\d+\.\d+/, '应输出 npm 版本号');
  }
});

test('Issue #33：npm_execpath 只采信 npm 自身入口，pnpm/yarn 或不存在时不误用', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-npm-cli-'));
  try {
    const fakeNpm = path.join(dir, 'npm-cli.js');
    writeFileSync(fakeNpm, 'console.log("ok");\n');
    assert.deepEqual(resolveNpmCommand(['x'], { npm_execpath: fakeNpm }), { command: process.execPath, args: [fakeNpm, 'x'] });
    const pnpmEntry = path.join(dir, 'pnpm.cjs');
    writeFileSync(pnpmEntry, 'console.log("ok");\n');
    const ignored = resolveNpmCommand(['x'], { npm_execpath: pnpmEntry });
    assert.notEqual(ignored?.args[0], pnpmEntry, 'pnpm 的 execpath 不能用来执行 npm 子命令');
    const missing = path.join(dir, 'npm-missing.js');
    const absent = resolveNpmCommand(['x'], { npm_execpath: missing });
    assert.notEqual(absent?.args[0], missing, '不存在的 npm_execpath 不能被采信');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Issue #33：Windows cmd 回退显式引用参数，含引号/换行时 fail-closed', () => {
  // 外层引号交给 cmd /s 剥离，剥离后剩下标准命令串（与 scripts/install.mjs 同口径）。
  assert.deepEqual(windowsNpmShimArgs(['install', '-g', 'C:\\a b\\dsh-passwords-2.7.5.tgz']), [
    '/d', '/s', '/c', '""npm.cmd" "install" "-g" "C:\\a b\\dsh-passwords-2.7.5.tgz""',
  ]);
  assert.equal(windowsNpmShimArgs(['install', 'C:\\evil" & calc.exe']), null, '双引号参数必须拒绝');
  assert.equal(windowsNpmShimArgs(['install', 'C:\\line\nbreak']), null, '换行参数必须拒绝');
  assert.equal(windowsNpmShimArgs(['install', 'C:\\100%TEMP%\\package.tgz']), null, 'cmd 环境变量展开参数必须拒绝');
});

test('systemd purge runner waits for helper exec before reporting a successful launch', () => {
  assert.deepEqual(systemdPurgeLaunchArgs('dsh-passwords-purge-test', '/usr/bin/node', '/tmp/purge.mjs', '/tmp/plan.json', '/tmp'), [
    '--unit', 'dsh-passwords-purge-test', '--collect', '--quiet', '--property=Type=exec', '--setenv=TMPDIR=/tmp',
    '/usr/bin/node', '/tmp/purge.mjs', '/tmp/plan.json',
  ]);
});

test('update metadata parser only accepts the expected npm package, version, registry and integrity', () => {
  assert.equal(compareVersions('2.6.10', '2.6.2'), 1);
  assert.equal(parseReleaseInfo({ tag_name: 'v2.6.3' })?.version, '2.6.3');
  assert.equal(parseNpmPackageInfo(metadata(), '2.6.3')?.version, '2.6.3');
  assert.equal(parseNpmPackageInfo({ name: 'dsh-passwords', version: '2.6.3', dist: { tarball: 'https://example.test/x.tgz', integrity: 'sha512-x' } }, '2.6.3'), null);
  assert.equal(parseNpmPackageInfo(metadata(), '2.6.2'), null);
});

test('automatic update downloads a verified npm package and installs only after idle', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, calls, restarts } = setup(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().phase, 'ready');
    assert.equal(engine.status().downloadMode, 'automatic');
    assert.equal(restarts(), 0);
    now.value += UPDATE_IDLE_MS;
    engine.tick();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(restarts(), 1);
    assert.equal(db.getSetting('update_downloaded_ready'), '');
    assert.equal(calls.some((call) => call.command === 'git'), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('manual mode checks without download, then requires download and installation confirmation', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, restarts } = setup(root, false, now);
    await engine.checkNow();
    assert.equal(engine.status().updateAvailable, true);
    assert.equal(engine.status().phase, 'idle');
    const first = await engine.applyNow();
    assert.equal(first.code, 'DOWNLOAD_STARTED');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(engine.status().phase, 'ready');
    assert.equal(engine.status().installConfirmationRequired, true);
    assert.equal(db.getSetting('update_download_mode'), 'manual');
    assert.equal(db.getSetting('update_install_confirmation_required'), '1');
    assert.ok(db.getSetting('update_last_notification_at'));
    assert.equal(restarts(), 0);
    const second = await engine.applyNow();
    assert.equal(second.ok, true);
    assert.equal(second.code, 'INSTALL_STARTED');
    assert.equal(second.phase, 'installing');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(restarts(), 1);
    assert.match(readFileSync(path.join(root, '.env'), 'utf8'), /MCP_DB_PATH=.*platform\.db/);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
    assert.equal(existsSync(path.join(root, 'update')), false);
    const profile = JSON.parse(readFileSync(path.join(root, 'dsh-home', 'profiles', 'web', 'package.json'), 'utf8')) as { dependencies: Record<string, string> };
    assert.equal(profile.dependencies['dsh-passwords'], `link:${root}`);
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test('Issue #33：部署目录内数据库句柄打开时固定部署替换仍成功（Windows 不得 rename 部署目录）', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const dbFile = path.join(root, 'data', 'platform.db');
  const now = { value: 1_000_000 };
  const { engine, restarts } = setup(root, false, now);
  // 用真实 node:sqlite 句柄覆盖报告中的 EPERM 前提。
  rmSync(dbFile);
  const sqlite = new DatabaseSync(dbFile);
  sqlite.exec('CREATE TABLE probe (value TEXT); INSERT INTO probe VALUES (\'user database\');');
  try {
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    assert.equal(sqlite.prepare('SELECT value FROM probe').get()?.value, 'user database', '打开的数据库必须原地保留');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false, '旧程序应被替换');
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.3');
    assert.deepEqual(deploymentSiblings(root), [], '不应留下 staging/backup/failed/lock 残留');
  } finally {
    sqlite.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test('Windows 数据目录大小写与配置不同仍原地保留', { skip: process.platform !== 'win32' }, async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    const data = path.join(root, 'data');
    const renamed = path.join(root, 'data-temp');
    const actual = path.join(root, 'Data');
    renameSync(data, renamed);
    renameSync(renamed, actual);
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    assert.equal(readFileSync(path.join(actual, 'platform.db'), 'utf8'), 'user database\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Issue #33：cwd 位于部署目录内时替换仍成功并恢复 cwd', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const originalCwd = process.cwd();
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    process.chdir(root);
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
    assert.equal(path.resolve(process.cwd()), path.resolve(root), '更新应恢复更新前的工作目录');
  } finally {
    process.chdir(originalCwd);
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：固定部署交换锁拒绝并发更新且不修改部署', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const lockPath = fixedDeploymentLockPath(root);
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    // 模拟另一个网关进程已持有交换锁。
    writeFileSync(lockPath, JSON.stringify({ pid: 1, startedAt: now.value }));
    await runManualInstall(engine);
    assert.equal(restarts(), 0);
    assert.match(engine.status().lastError ?? '', /占用|正在进行/);
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true, '被锁拒绝时旧程序必须原样保留');
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.2');
  } finally {
    rmSync(lockPath, { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：陈旧交换锁可被接管，不永久阻塞更新', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const lockPath = fixedDeploymentLockPath(root);
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    // 进程被强杀留下的旧锁：超过 TTL 后必须可接管。
    writeFileSync(lockPath, JSON.stringify({ pid: 999999, startedAt: -1_000_000_000 }));
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    assert.equal(existsSync(lockPath), false, '更新完成后必须释放锁');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), false);
    assert.deepEqual(deploymentSiblings(root), []);
  } finally {
    rmSync(lockPath, { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：临界区内崩溃残留的 .gate（写者 PID 已不存在）可被安全接管', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const lockPath = fixedDeploymentLockPath(root);
  const gatePath = `${lockPath}.gate`;
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    // 临界区内进程被杀：gate 残留，且写者 PID 已不存在（必不存在的极端 PID）。
    writeFileSync(gatePath, JSON.stringify({ pid: 2_147_483_647, startedAt: now.value, token: 'dead-gate' }));
    await runManualInstall(engine);
    assert.equal(restarts(), 1, '残留 gate 不得永久阻塞更新');
    assert.equal(existsSync(gatePath), false, 'gate 必须在退出时清理');
    assert.deepEqual(deploymentSiblings(root), [], '不得留下 gate 残留副本');
  } finally {
    rmSync(gatePath, { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：内容未写入即崩溃的空 .gate 超过 TTL 后也可接管', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const lockPath = fixedDeploymentLockPath(root);
  const gatePath = `${lockPath}.gate`;
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    // openSync('wx') 成功后、写入内容前进程被杀：文件为空且无时间戳，
    // 只能按文件 mtime + TTL 判定陈旧并接管。
    writeFileSync(gatePath, '');
    const past = new Date(Date.now() - UPDATE_GATE_TTL_MS - 60_000);
    utimesSync(gatePath, past, past);
    await runManualInstall(engine);
    assert.equal(restarts(), 1, '超过 TTL 的空 gate 必须可接管');
    assert.deepEqual(deploymentSiblings(root), []);
  } finally {
    rmSync(gatePath, { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：存活写者持有的新鲜 .gate 仍 fail-closed 拒绝并发更新', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const lockPath = fixedDeploymentLockPath(root);
  const gatePath = `${lockPath}.gate`;
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now);
    // 写者进程仍在运行且未超过 TTL：不得接管，必须拒绝本次更新。
    writeFileSync(gatePath, JSON.stringify({ pid: process.pid, startedAt: now.value, token: 'live-gate' }));
    await runManualInstall(engine);
    assert.equal(restarts(), 0);
    assert.equal(engine.status().phase, 'ready');
    assert.match(engine.status().lastError ?? '', /正在进行|进行中/);
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true, '被 gate 拒绝时旧程序必须原样保留');
  } finally {
    rmSync(lockPath, { force: true });
    rmSync(gatePath, { force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('POSIX 整目录替换仍保留数据库和配置并恢复 cwd', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const cwd = process.cwd();
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now, true, 'dsh-web', {}, false);
    mkdirSync(path.join(root, '.git'));
    writeFileSync(path.join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    writeFileSync(path.join(root, 'notes.txt'), 'keep local checkout files\n');
    process.chdir(root);
    await runManualInstall(engine);
    assert.equal(restarts(), 1);
    assert.equal(process.cwd(), root);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.equal(readFileSync(path.join(root, '.git', 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
    assert.equal(readFileSync(path.join(root, 'notes.txt'), 'utf8'), 'keep local checkout files\n');
    assert.deepEqual(deploymentSiblings(root), []);
  } finally {
    process.chdir(cwd);
    rmSync(root, { recursive: true, force: true });
  }
});

test('Issue #33：Git checkout 可原位更新且保留仓库元数据，非保留数据库路径拒绝更新', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const first = setup(root, false, now);
    mkdirSync(path.join(root, '.git'));
    writeFileSync(path.join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    await runManualInstall(first.engine);
    assert.equal(first.restarts(), 1);
    assert.equal(readFileSync(path.join(root, '.git', 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
    assert.equal(readFileSync(path.join(root, 'obsolete-runtime.js'), 'utf8'), 'old program file\n');
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    const second = setup(root, false, now);
    const customDb = path.join(root, 'private', 'platform.db');
    mkdirSync(path.dirname(customDb));
    writeFileSync(customDb, 'must survive\n');
    const guarded = new UpdateEngine(config(customDb), second.db, second.ops, {
      installRoot: root,
      env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: path.join(root, 'dsh-home'), DSH_PASSWORDS_ENV_FILE: path.join(root, '.env') },
      inPlaceDeploymentSwap: true,
    });
    await runManualInstall(guarded);
    assert.match(guarded.status().lastError ?? '', /数据库位于部署目录的非保留位置/);
    assert.equal(readFileSync(customDb, 'utf8'), 'must survive\n');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true);
    assert.equal(readFileSync(path.join(root, '.git', 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Git checkout 有本地改动时拒绝自动更新', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, ops, restarts } = setup(root, false, now);
    mkdirSync(path.join(root, '.git'));
    const runCommand = ops.runCommand;
    ops.runCommand = async (command, args, cwd, env) =>
      command === 'git' ? { ok: true, message: ' M src/update.ts' } : runCommand(command, args, cwd, env);
    await runManualInstall(engine);
    assert.equal(restarts(), 0);
    assert.match(engine.status().lastError ?? '', /Git 工作区包含未提交文件/);
    assert.equal(readFileSync(path.join(root, 'obsolete-runtime.js'), 'utf8'), 'old program file\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Issue #33：就地替换发现保留数据与新程序目录冲突时 fail-closed', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, restarts } = setup(root, false, now, true, 'dsh-web', { MCP_GATEWAY_TLS_CERT: 'dist/cert.pem' });
    await runManualInstall(engine);
    assert.equal(restarts(), 0);
    assert.match(engine.status().lastError ?? '', /保留数据目录冲突/);
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.2');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('Issue #33：profile 注册失败时固定部署替换回滚旧程序并保留用户数据', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, ops, restarts } = setup(root, false, now);
    let registrations = 0;
    ops.runCommand = async (command, args) => {
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        registrations += 1;
        return { ok: false, message: 'register boom' };
      }
      return { ok: true, message: '' };
    };
    await runManualInstall(engine);
    assert.equal(restarts(), 0);
    assert.equal(registrations, 2, '回滚后应尝试重新注册旧 profile');
    assert.match(engine.status().lastError ?? '', /profile/);
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.6.2', '失败后必须回滚到旧程序');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true, '旧程序文件应被移回');
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.deepEqual(deploymentSiblings(root), [], '回滚后不应留下 staging/backup/failed/lock');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// 2.7.7 → 本地 package 版本的注册失败恢复：新程序已进部署目录但 profile 切换失败时，
// 必须回滚到 2.7.7 旧程序、保留 .env/data，并如实用旧 profile 重注册（不谎报升级成功）。
test('2.7.7 → 本地版本升级时 profile 注册失败：回滚旧程序、保留 .env/data、二次注册旧 profile', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  assert.equal(compareVersions(pkg.version, '2.7.7'), 1, `本地版本 ${pkg.version} 必须高于 2.7.7`);
  try {
    const now = { value: 1_000_000 };
    // 用 inPlace=false 走整目录交换分支（Linux/systemd 非 git 固定部署的生产路径），
    // 与保留用例的就地分支互补。
    const { engine, ops, restarts } = setup(root, false, now, true, 'dsh-web', {}, false, '2.7.7', pkg.version);
    let registrations = 0;
    ops.runCommand = async (command, args) => {
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        registrations += 1;
        return { ok: false, message: 'register boom' };
      }
      return { ok: true, message: '' };
    };
    await runManualInstall(engine);
    assert.equal(restarts(), 0, '注册失败不得重启到未注册的新版本');
    assert.equal(registrations, 2, '回滚后应尝试重新注册旧 profile');
    assert.match(engine.status().lastError ?? '', /profile/);
    // 必须回滚到 2.7.7 旧程序，旧文件归位。
    assert.equal((JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as { version: string }).version, '2.7.7');
    assert.equal(existsSync(path.join(root, 'obsolete-runtime.js')), true);
    // 用户数据不受回滚影响。
    assert.match(readFileSync(path.join(root, '.env'), 'utf8'), /^SETUP_KEY=test-setup-key$/m);
    assert.equal(readFileSync(path.join(root, 'data', 'platform.db'), 'utf8'), 'user database\n');
    assert.deepEqual(deploymentSiblings(root), [], '回滚后不应留下 staging/backup/failed/lock');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// 回归：整目录交换回滚失败时，绝不能无条件删除仍含保留数据的 failedRoot。
// 正向注册故意失败触发回滚，并在旧程序备份里把已空的证书父目录换成同名文件，
// 让回滚把保留的 TLS 证书移回旧程序时确定性失败；此时 failedRoot 必须保留且证书完好。
test('固定部署回滚失败时保留仍含保留数据的 failedRoot 并记录可操作错误', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-rollback-'));
  const cert = path.join(root, 'certs', 'tls.crt');
  try {
    const now = { value: 1_000_000 };
    // inPlace=false 走整目录交换分支，才会退化到 rollbackFixedDeployment。
    const { engine, ops, restarts } = setup(root, false, now, true, 'dsh-web', { MCP_GATEWAY_TLS_CERT: cert }, false);
    mkdirSync(path.dirname(cert), { recursive: true });
    writeFileSync(cert, 'tls certificate\n');
    let registrations = 0;
    ops.runCommand = async (command, args) => {
      if (command === process.execPath && args[0]?.endsWith('register-plugin.mjs')) {
        registrations += 1;
        // 正向注册失败以触发回滚；同时把旧程序备份中已空的保留项父目录占成文件，
        // 使回滚 movePreservedEntries 重建 certs 目录时确定性抛错。
        const backupName = deploymentSiblings(root).find((name) => name.includes('.backup-'));
        assert.ok(backupName, '回滚前应存在旧程序备份目录');
        const blocker = path.join(path.dirname(root), backupName, 'certs');
        rmdirSync(blocker);
        writeFileSync(blocker, 'blocked\n');
        return { ok: false, message: 'register boom' };
      }
      return { ok: true, message: '' };
    };
    await runManualInstall(engine);
    assert.equal(restarts(), 0, '回滚失败不得重启到未注册的新版本');
    assert.equal(registrations, 1, '回滚移动保留项即失败，不应再注册旧 profile');
    assert.match(engine.status().lastError ?? '', /回滚未完成/);
    const failedName = deploymentSiblings(root).find((name) => name.includes('.failed-'));
    assert.ok(failedName, '回滚失败必须保留 failedRoot，而不是无条件删除');
    // 未移出的保留数据仍在 failedRoot 中，未被删除。
    assert.equal(readFileSync(path.join(path.dirname(root), failedName, 'certs', 'tls.crt'), 'utf8'), 'tls certificate\n');
    // 已移出的保留数据也不丢失，仍在旧程序备份里等待人工恢复。
    const backupName = deploymentSiblings(root).find((name) => name.includes('.backup-'));
    assert.ok(backupName, '回滚未完成时必须保留旧程序备份');
    assert.match(readFileSync(path.join(path.dirname(root), backupName, '.env'), 'utf8'), /^SETUP_KEY=test-setup-key$/m);
    assert.equal(readFileSync(path.join(path.dirname(root), backupName, 'data', 'platform.db'), 'utf8'), 'user database\n');
  } finally {
    for (const name of deploymentSiblings(root)) rmSync(path.join(path.dirname(root), name), { recursive: true, force: true });
    rmSync(root, { recursive: true, force: true });
  }
});

test('update status polling is background traffic, while user actions remain activity', () => {
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/status'), true);
  assert.equal(isBackgroundUpdateRequest('/gateway/internal/update'), true);
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/check'), false);
  assert.equal(isBackgroundUpdateRequest('/api/dsh-passwords/update/apply'), false);
  assert.equal(isBackgroundUpdateRequest('/gateway/api/overview'), false);
});

test('turning automatic updates off requires confirmation for an already downloaded package', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine } = setup(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().installConfirmationRequired, false);
    engine.setAutoUpdateEnabled(false);
    assert.equal(engine.status().installConfirmationRequired, true);
    assert.equal(engine.status().downloadMode, 'manual');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart failure is reported and does not claim a successful update', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine } = setup(root, false, now, false);
    await engine.checkNow();
    const downloaded = await engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    assert.equal(engine.status().phase, 'error');
    assert.match(engine.status().lastError ?? '', /重启失败/);
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.match(engine.status().lastError ?? '', /重启失败/);
    assert.equal(engine.status().phase, 'error');
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    // 已安装、等待重启的版本不再属于「有新版本可更新」：updateAvailable 必须与
    // restartPendingVersion 一致，否则状态页会提示可再次安装而已完成安装的版本。
    assert.equal(engine.status().currentVersion, '2.6.2');
    assert.equal(engine.status().latestVersion, '2.6.3');
    assert.equal(engine.status().updateAvailable, false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart failure can be retried immediately and clears the pending restart after recovery', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, setRestartAllowed } = setup(root, false, now, false);
    await engine.checkNow();
    const downloaded = await engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    const failed = await engine.applyNow();
    assert.equal(failed.code, 'RESTART_FAILED');
    setRestartAllowed(true);
    const retried = await engine.applyNow();
    assert.equal(retried.ok, true);
    assert.equal(engine.status().restartPendingVersion, null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('安装完成后进入重启待定期不得重复下载、安装或审计', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, ops, restarts, setRestartAllowed } = setup(root, true, now, false);
    let audits = 0;
    const originalAudit = db.audit;
    db.audit = (...args) => { audits += 1; originalAudit(...args); };
    let downloads = 0;
    const originalDownload = ops.download;
    ops.download = async (...args) => { downloads += 1; return originalDownload(...args); };
    let installs = 0;
    const originalInstall = ops.runInstall;
    ops.runInstall = async (...args) => { installs += 1; return originalInstall(...args); };

    // 自动模式：包就绪后平台空闲满 1 小时触发一次自动安装，重启失败进入待重启。
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().phase, 'ready');
    assert.equal(downloads, 1);
    now.value += UPDATE_IDLE_MS;
    engine.tick();
    await flushUpdates();
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.equal(installs, 1);
    assert.equal(audits, 1);
    assert.equal(restarts(), 1);

    // 24h 后再次自动检查/推进：待重启期间必须完全跳过，不得重复下载/安装/审计/重启。
    now.value += UPDATE_CHECK_MS + UPDATE_IDLE_MS;
    await engine.checkNow({ downloadIfAllowed: true });
    engine.tick();
    await flushUpdates();
    assert.equal(downloads, 1, '待重启期间不得重复下载');
    assert.equal(installs, 1, '待重启期间不得重复安装');
    assert.equal(audits, 1, '待重启期间不得重复写 update_applied 审计');
    assert.equal(restarts(), 1, '待重启期间不得重复触发重启');
    assert.equal(engine.status().pendingVersion, null);
    assert.equal(engine.status().phase, 'error');
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.equal(engine.status().updateAvailable, false);

    // 重启恢复后仍可正常完成，且不需要再次安装。
    setRestartAllowed(true);
    const recovered = await engine.applyNow();
    assert.equal(recovered.ok, true);
    assert.equal(engine.status().restartPendingVersion, null);
    assert.equal(installs, 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('restart pending state survives engine reconstruction and can be resumed', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const first = setup(root, false, now, false);
    await first.engine.checkNow();
    const downloaded = await first.engine.applyNow();
    assert.equal(downloaded.code, 'DOWNLOAD_STARTED');
    await flushUpdates();
    const started = await first.engine.applyNow();
    assert.equal(started.code, 'INSTALL_STARTED');
    await flushUpdates();
    assert.equal(first.db.getSetting('update_restart_pending_version'), '2.6.3');
    const second = setup(root, false, now, true);
    // setup's fresh store is replaced with the persisted settings to model a gateway restart.
    second.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'data', 'platform.db')), second.db, second.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: path.join(root, 'dsh-home'), DSH_PASSWORDS_ENV_FILE: path.join(root, '.env') } });
    assert.equal(restored.status().restartPendingVersion, '2.6.3');
    const retried = await restored.applyNow();
    assert.equal(retried.ok, true);
    assert.equal(restored.status().restartPendingVersion, null);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('手动重启后的新版本进程清除待重启标记', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, ops } = setup(root, false, now, true, '');
    await runManualInstall(engine);
    assert.equal(db.getSetting('update_restart_pending_version'), '2.6.3');
    const restarted = new UpdateEngine(config(path.join(root, 'data', 'platform.db'), ''), db, ops, {
      installRoot: root,
      env: { DSH_PASSWORDS_RUNTIME: 'git', DSH_HOME: path.join(root, 'dsh-home'), DSH_PASSWORDS_ENV_FILE: path.join(root, '.env') },
    });
    assert.equal(restarted.status().restartPendingVersion, null);
    assert.equal(db.getSetting('update_restart_pending_version'), '');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('服务重启器不支持当前平台时报告手动重启而不清理 pending', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db, ops } = setup(root, false, now);
    ops.restartWebService = async () => ({ ok: false, manual: true, message: '请手动重启 DeepSeek Harness' });
    await runManualInstall(engine);
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.match(engine.status().lastError ?? '', /手动重启/);
    const retry = await engine.applyNow();
    assert.equal(retry.requiresManualRestart, true);
    assert.equal(db.getSetting('update_restart_pending_version'), '2.6.3');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('manual restart mode reports manual action without persisting a failed restart', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, db } = setup(root, false, now, true, '');
    await engine.checkNow();
    await engine.applyNow();
    await flushUpdates();
    const result = await engine.applyNow();
    assert.equal(result.ok, true);
    assert.equal(result.code, 'INSTALL_STARTED');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(engine.status().phase, 'error');
    assert.equal(engine.status().restartPendingVersion, '2.6.3');
    assert.equal(db.getSetting('update_restart_pending_version'), '2.6.3');
    assert.match(engine.status().lastError ?? '', process.platform === 'win32' ? /重新启动 DeepSeek Harness/ : /重启 dsh-web 服务/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker manual update uses compose without npm or systemd', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, calls, installAudits, composeDir } = setupDocker(root, false, now);
    await engine.checkNow();
    assert.equal(engine.status().env, 'docker');
    assert.equal(engine.status().updateAvailable, true);
    const started = await engine.applyNow();
    assert.equal(started.ok, true);
    assert.equal(started.code, 'INSTALL_STARTED');
    assert.equal(started.phase, 'installing');
    await flushUpdates();
    assert.equal(calls.length, 5);
    assert.deepEqual(calls.slice(0, 3).map((call) => call.args.at(-1)), ['dsh-passwords', 'dsh-passwords', 'dsh-passwords']);
    assert.match(calls[0].args.join(' '), /compose -f compose\.yml -f \.dsh-passwords-update\.override\.yml pull dsh-passwords/);
    assert.ok(calls.some((call) => call.args.some((arg) => arg.includes('package.json'))));
    assert.ok(calls.some((call) => call.args.some((arg) => arg.includes('readyz'))));
    assert.ok(calls.every((call) => call.cwd === composeDir));
    assert.equal(installAudits(), 1);
    assert.equal(engine.status().phase, 'idle');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker automatic update waits for idle and never downloads npm', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, calls, installAudits } = setupDocker(root, true, now);
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(calls.length, 0);
    assert.equal(engine.status().updateAvailable, true);
    now.value += UPDATE_IDLE_MS;
    engine.tick();
    assert.equal(engine.status().phase, 'installing');
    await flushUpdates();
    assert.equal(calls.length, 5);
    assert.equal(installAudits(), 1);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker update failures stop the compose chain and enter error', async () => {
  for (const failure of ['pull', 'up', 'ps'] as const) {
    const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
    try {
      const now = { value: 1_000_000 };
      const { engine, calls, installAudits } = setupDocker(root, false, now, { [failure]: false });
      await engine.checkNow();
      const result = await engine.applyNow();
      assert.equal(result.code, 'INSTALL_STARTED');
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(engine.status().phase, 'error');
      assert.match(engine.status().lastError ?? '', new RegExp(`Docker .*${failure === 'pull' ? '拉取' : failure === 'up' ? '重启' : '健康检查'}`));
      assert.equal(installAudits(), 0);
      const commands = calls.map((call) => call.args.find((arg) => ['pull', 'up', 'ps'].includes(arg))).filter((arg): arg is string => arg !== undefined);
      if (failure === 'pull') assert.deepEqual(commands, ['pull']);
      if (failure === 'up') assert.deepEqual(commands, ['pull', 'up']);
      if (failure === 'ps') assert.deepEqual(commands, ['pull', 'up', 'ps']);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
});

test('docker update without compose directory is manual-only', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const db = store();
    db.setSetting('auto_update_enabled', '0');
    const ops: UpdateEngineOps = {
      now: () => 1_000_000,
      fetchRelease: async () => release(),
      fetchNpmMetadata: async () => { throw new Error('must not query npm'); },
      download: async () => { throw new Error('must not download npm'); },
      runInstall: async () => { throw new Error('must not install npm'); },
      runCommand: async () => { throw new Error('must not run docker'); },
      restartWebService: async () => ({ ok: false, message: 'must not restart' }),
      log: () => {},
    };
    const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker' } });
    await engine.checkNow();
    const result = await engine.applyNow();
    assert.equal(result.code, 'MANUAL_ONLY');
    assert.match(result.message, /MCP_DSH_DOCKER_COMPOSE_DIR/);
    assert.equal(engine.status().autoInstallSupported, false);
    assert.match(engine.status().manualCommand, /docker compose pull/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker update rejects duplicate apply while compose is running', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const composeDir = path.join(root, 'compose');
    mkdirSync(composeDir, { recursive: true });
    let releaseUp: (() => void) | null = null;
    const calls: string[] = [];
    const db = store();
    db.setSetting('auto_update_enabled', '0');
    const ops: UpdateEngineOps = {
      now: () => now.value,
      fetchRelease: async () => release(),
      fetchNpmMetadata: async () => { throw new Error('must not query npm'); },
      download: async () => { throw new Error('must not download npm'); },
      runInstall: async () => { throw new Error('must not install npm'); },
      runCommand: async (_command, args) => {
        const action = args.find((arg) => ['pull', 'up', 'ps'].includes(arg)) ?? '';
        calls.push(action);
        if (action === 'up') await new Promise<void>((resolve) => { releaseUp = resolve; });
        if (args.some((arg) => arg.includes('package.json'))) return { ok: true, message: '2.6.3' };
        if (args.some((arg) => arg.includes('readyz'))) return { ok: true, message: '' };
        return { ok: true, message: action === 'ps' ? 'dsh-passwords' : '' };
      },
      restartWebService: async () => ({ ok: false, message: 'must not restart' }),
      log: () => {},
    };
    writeFileSync(path.join(composeDir, 'compose.yml'), 'services:\n  dsh-passwords:\n    image: skywalker237234/dsh-passwords:2.6.2\n');
    const engine = new UpdateEngine(config(path.join(root, 'platform.db')), db, ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await engine.checkNow();
    const first = await engine.applyNow();
    assert.equal(first.code, 'INSTALL_STARTED');
    const second = await engine.applyNow();
    assert.equal(second.code, 'INSTALL_IN_PROGRESS');
    assert.deepEqual(calls, ['pull', 'up']);
    (releaseUp as (() => void) | null)!();
    await flushUpdates();
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker restart pending state recovers with a single health check', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const first = setupDocker(root, false, now);
    first.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'platform.db')), first.db, first.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: first.composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await flushUpdates();
    assert.equal(restored.status().phase, 'idle');
    assert.equal(restored.status().currentVersion, '2.6.3');
    assert.equal(first.db.getSetting('update_restart_pending_version'), '');
    assert.equal(first.db.getSetting('update_docker_applied_version'), '2.6.3');
    assert.ok(first.calls.some((call) => call.args.includes('ps')));
    assert.ok(first.calls.some((call) => call.args.some((arg) => arg.includes('package.json'))));
    assert.ok(first.calls.some((call) => call.args.some((arg) => arg.includes('readyz'))));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('docker restart recovery clears the pending marker when health check fails', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-docker-'));
  try {
    const now = { value: 1_000_000 };
    const first = setupDocker(root, false, now, { ps: false });
    first.db.setSetting('update_restart_pending_version', '2.6.3');
    const restored = new UpdateEngine(config(path.join(root, 'platform.db')), first.db, first.ops, { installRoot: root, env: { DSH_PASSWORDS_RUNTIME: 'docker', MCP_DSH_DOCKER_COMPOSE_DIR: first.composeDir, MCP_DSH_DOCKER_SELF_UPDATE: '1', MCP_DSH_DOCKER_COMPOSE_FILE: 'compose.yml', MCP_DSH_DOCKER_IMAGE: 'skywalker237234/dsh-passwords' }, dockerSelfUpdateAvailable: true });
    await flushUpdates();
    assert.equal(restored.status().phase, 'error');
    assert.equal(restored.status().restartPendingVersion, null);
    assert.equal(first.db.getSetting('update_restart_pending_version'), '');
    assert.match(restored.status().lastError ?? '', /恢复(健康检查|失败)/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('integrity mismatch discards the artifact and never installs', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  try {
    const now = { value: 1_000_000 };
    const { engine, ops, restarts } = setup(root, true, now);
    ops.fetchNpmMetadata = async () => metadata('2.6.3', Buffer.from('different integrity'));
    await engine.checkNow({ downloadIfAllowed: true });
    assert.equal(engine.status().phase, 'error');
    assert.match(engine.status().lastError ?? '', /sha512/);
    assert.equal(restarts(), 0);
    assert.equal(existsSync(path.join(root, 'update', 'dsh-passwords-2.6.3.tgz')), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('update engine start is idempotent and dispose keeps it stopped', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-update-'));
  const originalSetInterval = globalThis.setInterval;
  let created = 0;
  try {
    const now = { value: 1_000_000 };
    const { engine } = setup(root, false, now);
    globalThis.setInterval = ((handler: (...args: unknown[]) => void, timeout?: number) => {
      created += 1;
      return originalSetInterval(handler as (...args: unknown[]) => void, timeout);
    }) as unknown as typeof globalThis.setInterval;
    try {
      engine.start();
      engine.start();
      assert.equal(created, 1, '重复 start() 不得叠加轮询器');
      engine.dispose();
      engine.start();
      assert.equal(created, 1, 'dispose() 后 start() 必须保持停止');
    } finally {
      globalThis.setInterval = originalSetInterval;
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
