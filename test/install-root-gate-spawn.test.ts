import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { gzipSync, gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveNpmCommand } from '../src/patch.ts';

const projectRoot = path.resolve(import.meta.dirname, '..');
const installScript = path.join(projectRoot, 'scripts', 'install.mjs');
const packageJson = JSON.parse(readFileSync(path.join(projectRoot, 'package.json'), 'utf8')) as {
  name: string;
  version: string;
  dependencies: Record<string, string>;
};
const RUNTIME_DEPS = Object.keys(packageJson.dependencies);

type Fixture = {
  root: string;
  app: string;
  dshRoot: string;
  dshHome: string;
  deploy: string;
  bin: string;
  calls: string;
};

function createFixture(): Fixture {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-gate-'));
  const app = path.join(root, 'app');
  const scripts = path.join(app, 'scripts');
  const dshRoot = path.join(root, 'dsh');
  const dshHome = path.join(root, 'dsh-home');
  const deploy = path.join(root, 'deploy');
  const bin = path.join(root, 'bin');
  const calls = path.join(root, 'commands.log');
  mkdirSync(scripts, { recursive: true });
  mkdirSync(dshRoot, { recursive: true });
  mkdirSync(bin, { recursive: true });
  mkdirSync(path.join(app, 'dist'), { recursive: true });
  mkdirSync(path.join(root, 'node_modules'), { recursive: true });
  writeFileSync(path.join(app, 'package.json'), JSON.stringify(packageJson));
  writeFileSync(path.join(app, 'dist', 'cli.js'), '');
  writeFileSync(path.join(app, 'dist', 'client.js'), '');
  for (const dependency of RUNTIME_DEPS) {
    const dependencyRoot = path.join(root, 'node_modules', ...dependency.split('/'));
    mkdirSync(dependencyRoot, { recursive: true });
    writeFileSync(path.join(dependencyRoot, 'package.json'), JSON.stringify({ name: dependency, main: 'index.js' }));
    writeFileSync(path.join(dependencyRoot, 'index.js'), '');
  }
  writeFileSync(path.join(dshRoot, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh', version: '0.2.1-alpha.1' }));
  const fixtureInstaller = readFileSync(path.join(projectRoot, 'scripts', 'install.mjs'), 'utf8')
    .replace("const isWin = process.platform === 'win32';", "const isWin = false;")
    .replace("function commandPath(command) {", "function commandPath(command) { return command; }\nfunction unusedCommandPath(command) {")
    .replace("function spawnCommand(command, args, runOptions) {", "function spawnCommand(command, args, runOptions) {\n  if (process.env.DSH_TEST_COMMAND_SHIM) return spawnSync(process.execPath, [process.env.DSH_TEST_COMMAND_SHIM, command, ...args], runOptions);");
  writeFileSync(path.join(scripts, 'install.mjs'), fixtureInstaller);
  writeFileSync(path.join(scripts, 'command-shim.mjs'), [
    "import { appendFileSync } from 'node:fs';",
    "appendFileSync(process.env.DSH_TEST_COMMAND_LOG, `${process.argv.slice(2).join(' ')}\\n`);",
  ].join('\n'));
  cpSync(path.join(projectRoot, 'scripts', 'prebuilt-check.mjs'), path.join(scripts, 'prebuilt-check.mjs'));
  cpSync(path.join(projectRoot, 'scripts', 'install-root-gate.mjs'), path.join(scripts, 'install-root-gate.mjs'));
  writeFileSync(path.join(scripts, 'register-plugin.mjs'), "console.log('[fixture] plugin registered');\n");

  writeFileSync(path.join(bin, 'pnpm'), '#!/bin/sh\nprintf "pnpm %s\\n" "$*" >> "$DSH_TEST_COMMAND_LOG"\nexit 0\n', { mode: 0o755 });
  writeFileSync(path.join(bin, 'npm'), '#!/bin/sh\nprintf "npm %s\\n" "$*" >> "$DSH_TEST_COMMAND_LOG"\nexit 0\n', { mode: 0o755 });
  writeFileSync(path.join(bin, 'pnpm.cmd'), '@echo off\r\necho pnpm %*>>"%DSH_TEST_COMMAND_LOG%"\r\nexit /b 0\r\n');
  writeFileSync(path.join(bin, 'npm.cmd'), '@echo off\r\necho npm %*>>"%DSH_TEST_COMMAND_LOG%"\r\nexit /b 0\r\n');
  writeFileSync(path.join(dshRoot, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh', version: '0.2.1-alpha.1' }));
  return { root, app, dshRoot, dshHome, deploy, bin, calls };
}

function fixtureEnv(fixture: Fixture, overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const inheritedPath = process.env.Path ?? process.env.PATH ?? '';
  const nextPath = `${fixture.bin}${path.delimiter}${inheritedPath}`;
  return {
    ...process.env,
    PATH: nextPath,
    Path: nextPath,

    DSH_TEST_COMMAND_LOG: fixture.calls,
    DSH_TEST_COMMAND_SHIM: path.join(fixture.app, 'scripts', 'command-shim.mjs'),
    DSH_HOME: fixture.dshHome,
    MCP_DSH_ROOT: fixture.dshRoot,
    MCP_DSH_RESTART_SERVICE: '',
    DSH_PASSWORDS_ENV_FILE: path.join(fixture.deploy, '.env'),
    ...overrides,
  };
}

function runInstaller(fixture: Fixture, overrides: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, [path.join(fixture.app, 'scripts', 'install.mjs')], {
    cwd: fixture.root,
    encoding: 'utf8',
    timeout: 30_000,
    env: fixtureEnv(fixture, overrides),
  });
}

function outputOf(result: ReturnType<typeof runInstaller>): string {
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
}

function commandLog(fixture: Fixture): string {
  return existsSync(fixture.calls) ? readFileSync(fixture.calls, 'utf8') : '';
}

function cleanup(fixture: Fixture): void {
  rmSync(fixture.root, { recursive: true, force: true });
}

function extractTarball(tarball: string, destination: string): void {
  const tar = gunzipSync(readFileSync(tarball));
  for (let offset = 0; offset < tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
    const entryName = prefix ? `${prefix}/${name}` : name;
    const size = Number.parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/s, '').trim() || '0', 8);
    const type = header[156];
    if (entryName === '') break;
    const dataStart = offset + 512;
    if (type === 120 || type === 103) {
      offset = dataStart + Math.ceil(size / 512) * 512;
      continue;
    }
    const target = path.join(destination, entryName);
    if (type === 53) {
      mkdirSync(target, { recursive: true });
    } else if (type === 0 || type === 48) {
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, tar.subarray(dataStart, dataStart + size));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
}

test('root gate rejects before any npm/pnpm command or install artifact is touched', (t) => {
  if (process.platform === 'win32') {
    t.skip('Windows has no POSIX non-root gate');
    return;
  }
  if (typeof process.getuid !== 'function' || process.getuid() === 0) {
    t.skip('requires a non-root POSIX process');
    return;
  }
  const fixture = createFixture();
  try {
    const distBefore = readdirSync(path.join(fixture.app, 'dist')).sort();
    const result = runInstaller(fixture, {
      MCP_GATEWAY_AUTO_TLS: '',
      MCP_GATEWAY_TLS_CERT: '',
      MCP_GATEWAY_TLS_KEY: '',
    });
    const output = outputOf(result);
    assert.notEqual(result.status, 0, output);
    assert.match(output, /请使用 sudo 运行安装器/, output);
    assert.doesNotMatch(output, /注册 dsh 插件/, output);
    assert.equal(commandLog(fixture), '', 'neither npm nor pnpm may run before root gate');
    assert.equal(existsSync(fixture.deploy), false, 'deployment directory must not be created');
    assert.deepEqual(readdirSync(path.join(fixture.app, 'dist')).sort(), distBefore, 'fixture dist must remain untouched');
  } finally {
    cleanup(fixture);
  }
});

test('explicit nonprivileged mode passes the root gate and reaches plugin registration without installs', (t) => {
  if (process.platform !== 'win32' && (typeof process.getuid !== 'function' || process.getuid() === 0)) {
    t.skip('requires a non-root POSIX process');
    return;
  }
  const fixture = createFixture();
  try {
    const result = runInstaller(fixture, {
      MCP_GATEWAY_AUTO_TLS: '0',
      // 显式清空，避免宿主进程环境里的 host/证书影响断言。
      MCP_GATEWAY_HOST: '',
      MCP_GATEWAY_TLS_CERT: '',
      MCP_GATEWAY_TLS_KEY: '',
    });
    const output = outputOf(result);
    assert.match(output, /dsh 0\.2\.1-alpha\.1 ✓/, output);
    assert.match(output, /pnpm ✓/, output);
    assert.match(output, /检测到 npm 预构建包/, output);
    assert.match(output, /注册 dsh 插件/, output);
    assert.doesNotMatch(output, /请使用 sudo 运行安装器/, output);
    assert.match(commandLog(fixture), /^pnpm(?:\.cmd)? --version\r?$/m, 'prebuilt package must check pnpm');
    assert.doesNotMatch(commandLog(fixture), /^npm(?:\.cmd)? /m, 'prebuilt package must not invoke npm');
    const envFile = path.join(fixture.deploy, '.env');
    assert.equal(existsSync(envFile), true);
    const envContent = readFileSync(envFile, 'utf8');
    assert.match(envContent, /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m, '非特权首次安装默认只监听回环');
    assert.doesNotMatch(envContent, /MCP_GATEWAY_HOST=0\.0\.0\.0/, '不得默认为全网卡监听');
    assert.equal(existsSync(path.join(fixture.app, 'dist')), true);
  } finally {
    cleanup(fixture);
  }
});

test('packed npm tarball runs the prebuilt branch from an isolated extracted fixture', (t) => {
  if (process.platform !== 'win32' && (typeof process.getuid !== 'function' || process.getuid() === 0)) {
    t.skip('requires a non-root POSIX process');
    return;
  }
  const fixture = createFixture();
  try {
    const tarball = path.join(fixture.root, 'package.tgz');
    // 通过生产同款的 Node/npm 发现逻辑定位 npm 入口（npm_execpath 优先，其次
    // Windows `<node>/node_modules/npm` 与 POSIX `<node>/../lib/node_modules/npm`
    // 布局），避免写死 Windows 布局而在 Linux/CI 上找不到 npm-cli.js。
    const npmPack = resolveNpmCommand(['pack', '--silent', '--pack-destination', fixture.root, '--ignore-scripts']);
    assert.ok(npmPack !== null, 'npm CLI 不可用：npm-cli.js 与平台 shim 均无法解析');
    const pack = spawnSync(npmPack.command, npmPack.args, {
      cwd: projectRoot,
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, npm_config_ignore_scripts: 'true' },
    });
    assert.equal(pack.status, 0, `${pack.stdout ?? ''}\n${pack.stderr ?? ''}`);
    const producedName = pack.stdout.trim().split(/\r?\n/).at(-1) ?? '';
    const produced = path.isAbsolute(producedName) ? producedName : path.join(fixture.root, producedName);
    assert.equal(existsSync(produced), true, `npm pack tarball missing: ${pack.stdout}`);
    const copiedTarball = path.join(fixture.root, path.basename(produced));
    if (produced !== copiedTarball) cpSync(produced, copiedTarball);
    assert.equal(existsSync(copiedTarball), true);

    extractTarball(copiedTarball, fixture.root);
    const packageRoot = path.join(fixture.root, 'package');
    assert.equal(existsSync(path.join(packageRoot, 'scripts', 'install.mjs')), true);
    assert.equal(existsSync(path.join(packageRoot, 'scripts', 'install-root-gate.mjs')), true);
    assert.equal(existsSync(path.join(packageRoot, 'dist', 'cli.js')), true);
    assert.equal(existsSync(path.join(packageRoot, 'dist', 'client.js')), true);
    const packedManifest = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8')) as { files?: string[] };
    assert.equal(packedManifest.files?.includes('src/'), false, 'npm tarball manifest must omit source files');
    assert.equal(packedManifest.files?.includes('tsconfig.json'), false, 'npm tarball manifest must omit build-only tsconfig');

    const packageInstaller = readFileSync(path.join(packageRoot, 'scripts', 'install.mjs'), 'utf8')
      .replace("function spawnCommand(command, args, runOptions) {", "function spawnCommand(command, args, runOptions) {\n  if (process.env.DSH_TEST_COMMAND_SHIM) return spawnSync(process.execPath, [process.env.DSH_TEST_COMMAND_SHIM, command, ...args], runOptions);");
    writeFileSync(path.join(packageRoot, 'scripts', 'install.mjs'), packageInstaller);
    writeFileSync(path.join(packageRoot, 'scripts', 'register-plugin.mjs'), "console.log('[fixture] plugin registered');\n");

    const manifest = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const modules = path.join(fixture.root, 'node_modules');
    for (const dependency of Object.keys(manifest.dependencies)) {
      const dependencyRoot = path.join(modules, ...dependency.split('/'));
      mkdirSync(dependencyRoot, { recursive: true });
      writeFileSync(path.join(dependencyRoot, 'package.json'), JSON.stringify({ name: dependency, main: 'index.js' }));
      writeFileSync(path.join(dependencyRoot, 'index.js'), '');
    }
    writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify(manifest));

    const result = spawnSync(process.execPath, [path.join(packageRoot, 'scripts', 'install.mjs')], {
      cwd: packageRoot,
      encoding: 'utf8',
      timeout: 30_000,
      env: fixtureEnv({ ...fixture, app: packageRoot }, {
        DSH_TEST_COMMAND_SHIM: path.join(fixture.app, 'scripts', 'command-shim.mjs'),
        DSH_PASSWORDS_ENV_FILE: path.join(fixture.deploy, '.env'),
        DSH_HOME: fixture.dshHome,
        MCP_DSH_ROOT: fixture.dshRoot,
        MCP_GATEWAY_AUTO_TLS: '0',
        MCP_GATEWAY_HOST: '',
      }),
    });
    const output = outputOf(result as ReturnType<typeof runInstaller>);
    assert.match(output, /检测到 npm 预构建包/, output);
    assert.match(output, /注册 dsh 插件/, output);
    assert.doesNotMatch(output, /安装源码依赖|编译…|缺少完整的预构建产物/, output);
    assert.match(commandLog(fixture), /^pnpm(?:\.cmd)? --version\r?$/m);
    assert.doesNotMatch(commandLog(fixture), /^npm(?:\.cmd)? /m);
    const envFile = path.join(fixture.deploy, '.env');
    assert.equal(existsSync(envFile), true);
    assert.match(readFileSync(envFile, 'utf8'), /^MCP_GATEWAY_HOST=127\.0\.0\.1$/m, '打包安装同样默认回环');
    assert.equal(existsSync(path.join(packageRoot, 'dist', 'cli.js')), true);
  } finally {
    cleanup(fixture);
  }
});

// 永久补丁退出码（1/34-37，与 src/plugin.ts 的 PERMANENT_GATEWAY_EXIT_CODES 补丁子集一致）
// 表示密码门拒绝启动且不会自动重试；安装器不得打印“安装完成”，也不得暗示自动重试，
// 并以非零码退出，让 install.sh / install.bat 的退出码透传反映真实结果。
function runWithPatchExit(code: string): { status: number | null; output: string } {
  const fixture = createFixture();
  try {
    // 补丁步骤直接以 node dist/cli.js patch 运行（不经命令 shim）；用夹具 cli.js 控制退出码。
    writeFileSync(
      path.join(fixture.app, 'dist', 'cli.js'),
      "if (process.argv.includes('patch')) process.exit(Number(process.env.DSH_TEST_PATCH_EXIT || 0));\n",
    );
    const result = runInstaller(fixture, {
      MCP_GATEWAY_AUTO_TLS: '0',
      MCP_GATEWAY_HOST: '',
      MCP_GATEWAY_TLS_CERT: '',
      MCP_GATEWAY_TLS_KEY: '',
      DSH_TEST_PATCH_EXIT: code,
    });
    return { status: result.status, output: outputOf(result) };
  } finally {
    cleanup(fixture);
  }
}

test('永久补丁退出码：不打印“安装完成”，不暗示自动重试，且以非零退出', () => {
  for (const code of ['1', '34', '35', '36', '37']) {
    const { status, output } = runWithPatchExit(code);
    assert.notEqual(status, 0, `退出码 ${code}：${output}`);
    assert.doesNotMatch(output, /安装完成/, `退出码 ${code} 不得打印“安装完成”`);
    // 不得承诺自动重试（永久失败的信息是“不会自动重试”）。
    assert.doesNotMatch(output, /启动时会自动重试/, `退出码 ${code} 不得暗示自动重试`);
    assert.doesNotMatch(output, /暂时无法应用/, `退出码 ${code} 不得描述为暂时性失败`);
    assert.match(output, /补丁未应用（永久失败）/, output);
    assert.match(output, /安装未完成/, output);
    // 补丁是最后一步：前置步骤（插件注册）仍应完成。
    assert.match(output, /注册 dsh 插件/, output);
  }
});

test('非永久补丁退出码仍提示暂时失败并自动重试，安装照常完成', () => {
  const { status, output } = runWithPatchExit('42');
  assert.equal(status, 0, output);
  assert.match(output, /补丁暂时无法应用/, output);
  assert.match(output, /自动重试/, output);
  assert.match(output, /安装完成/, output);
  assert.doesNotMatch(output, /永久失败/, output);
});
