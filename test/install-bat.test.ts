// Windows 安装器（install.bat）主流程的自动化覆盖。
//
// install.bat 只是引导壳：真正的安装逻辑在 scripts/install.mjs（与 install.sh 同一入口）。
// 完整端到端（winget 装 Node/git、git clone、PATH 刷新）依赖网络与特权，无法在单测里跑，
// 见 docs/testing-gaps-docker-installer.md 的手动验收清单与 CI 方案。
//
// 这里覆盖可低成本自动化的部分：
//  1) 静态契约：版本门禁 / 幂等目录判定 / ASCII-only / 交接入口；
//  2) 真实 spawn：把 install.bat 复制到临时目录并放一个假 install.mjs，
//     在 Windows 上执行引导壳本体，验证目录定位、交接、退出码透传与收尾提示。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const projectRoot = path.resolve(import.meta.dirname, '..');
const read = (...parts: string[]) => readFileSync(path.join(projectRoot, ...parts), 'utf8');
const installBat = read('install.bat');
const installSh = read('install.sh');

test('install.bat 把所有安装动作交给 scripts/install.mjs（与 install.sh 同一入口）', () => {
  assert.match(installBat, /node "%SCRIPT_DIR%scripts\\install\.mjs"/, 'install.bat 必须交接给 install.mjs');
  assert.match(installSh, /exec node "\$SOURCE_DIR\/scripts\/install\.mjs"/, 'install.sh 必须走同一入口');
  // 引导壳不得自己跑项目依赖安装或构建——那会绕过 install.mjs 的幂等与预构建判定。
  // （全局安装 dsh 工具链 `npm install -g ...` 属引导阶段，允许。）
  assert.doesNotMatch(installBat, /npm ci/, 'install.bat 不得自行 npm ci');
  assert.doesNotMatch(installBat, /npm run build/, 'install.bat 不得自行构建');
});

test('install.bat Node 版本门禁与 install.sh / package.json engines 对齐（拒绝 <22、23、22.<19）', () => {
  assert.match(installBat, /if %NODE_MAJOR% LSS 22 \(/);
  assert.match(installBat, /if %NODE_MAJOR% EQU 23 \(/);
  assert.match(installBat, /if %NODE_MAJOR% EQU 22 if %NODE_MINOR% LSS 19 \(/);
  // install.sh 的等价拒绝规则：三条条件必须同时存在。
  assert.match(installSh, /"\$NODE_MAJOR" -lt 22/);
  assert.match(installSh, /"\$NODE_MAJOR" -eq 23/);
  assert.match(installSh, /"\$NODE_MAJOR" -eq 22 \] && \[ "\$NODE_MINOR" -lt 19/);
  const engines = (JSON.parse(read('package.json')) as { engines: { node: string } }).engines.node;
  assert.equal(engines, '^22.19.0 || >=24.0.0');
});

test('install.bat 幂等重跑：识别已有 dsh-passwords 安装并支持 DSH_PASSWORDS_DIR 覆盖', () => {
  assert.match(installBat, /set "DEST=%USERPROFILE%\\dsh-passwords"/, '默认安装目录');
  assert.match(installBat, /if defined DSH_PASSWORDS_DIR set "DEST=%DSH_PASSWORDS_DIR%"/, 'DSH_PASSWORDS_DIR 覆盖');
  // 已有安装必须按 package.json 的 name 精确识别后就地重跑，而不是覆盖或另建目录。
  assert.match(installBat, /findstr \/c:"\\"name\\": \\"dsh-passwords\\"" "%DEST%\\package\.json"/);
  assert.match(installBat, /resuming the idempotent installer/);
});

test('install.bat 保持 ASCII-only（cmd 以 OEM 代码页解析 .bat）', () => {
  const bytes = readFileSync(path.join(projectRoot, 'install.bat'));
  const nonAscii = bytes.findIndex((byte) => byte > 0x7f);
  assert.equal(nonAscii, -1, `install.bat 含非 ASCII 字节，位于偏移 ${nonAscii}（cmd 会乱码）`);
});

test('install.bat 收尾保留窗口并提示 setup-key.txt 位置', () => {
  assert.match(installBat, /pause >nul/, '双击场景需保留窗口');
  assert.match(installBat, /Install finished!/);
  assert.match(installBat, /setup-key\.txt \(auto-deleted after first-time setup\)/);
});

function commandEnvironment(): NodeJS.ProcessEnv {
  const inherited = process.env.Path ?? process.env.PATH ?? '';
  return { ...process.env, PATH: inherited, Path: inherited };
}

/** 在临时目录放置 install.bat 副本与一个假 install.mjs，真实执行引导壳的 :run 分支。 */
function runBootstrapWithFakeInstaller(exitCode: number) {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-bat-'));
  const scriptsDir = path.join(dir, 'scripts');
  mkdirSync(scriptsDir, { recursive: true });
  writeFileSync(path.join(dir, 'install.bat'), installBat);
  writeFileSync(
    path.join(scriptsDir, 'install.mjs'),
    `process.stdout.write('FAKE-INSTALL-RUN ' + process.argv[1] + '\\n');\nprocess.exit(${exitCode});\n`,
  );
  try {
    const result = spawnSync(process.env.ComSpec ?? 'cmd.exe', ['/c', path.join(dir, 'install.bat')], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 30_000,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: commandEnvironment(),
    });
    return { dir, result };
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
}

test('install.bat 引导壳：定位脚本目录、交接 install.mjs 并以 0 退出', (t) => {
  if (process.platform !== 'win32') {
    t.skip('需要 cmd.exe');
    return;
  }
  const { dir, result } = runBootstrapWithFakeInstaller(0);
  try {
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
    assert.equal(result.status, 0, output);
    assert.match(output, /FAKE-INSTALL-RUN .*scripts[\\/]install\.mjs/, '应真实调用 install.mjs');
    assert.match(output, /Install finished!/, '成功时打印收尾提示');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('install.bat 引导壳：install.mjs 失败时透传退出码且不谎报成功', (t) => {
  if (process.platform !== 'win32') {
    t.skip('需要 cmd.exe');
    return;
  }
  const { dir, result } = runBootstrapWithFakeInstaller(7);
  try {
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
    assert.equal(result.status, 7, output);
    assert.doesNotMatch(output, /Install finished!/, '失败时不得打印成功提示');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
