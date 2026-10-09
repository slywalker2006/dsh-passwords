#!/usr/bin/env node
// dsh-passwords 一键安装（跨平台核心逻辑；install.sh / install.bat 只是引导壳）
//
// 做的事：环境检查（node/dsh/pnpm）→ 装依赖 + 编译 → 生成随机 SETUP_KEY
// → 写 .env 和 setup-key.txt（用完即删）→ 精确注册为 dsh 插件
// （此后启动 dsh 会自动拉起密码门）→ 应用远程设置补丁。
// 幂等：已存在 .env 不覆盖，插件已注册不重复加。
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hasPrebuiltRuntime } from './prebuilt-check.mjs';
import { firstInstallNeedsRoot, firstInstallEnvContent } from './install-root-gate.mjs';

const isWin = process.platform === 'win32';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RUNTIME_DEPS = ['bcryptjs', 'dotenv', 'express', 'jsonwebtoken', 'ws'];
const CYAN = isWin ? '' : '\x1b[1;36m';
const RED = isWin ? '' : '\x1b[1;31m';
const RESET = isWin ? '' : '\x1b[0m';

const say = (msg) => console.log(`${CYAN}[dsh-passwords]${RESET} ${msg}`);
const err = (msg) => console.error(`${RED}[dsh-passwords]${RESET} ${msg}`);

/**
 * Unix 一律不经 shell：安装路径可能带空格/特殊字符，参数数组避免解析歧义与注入面。
 * Windows 的 npm/pnpm/dsh 是 .cmd shim，Node 无法直接执行；仅这三个固定命令走 cmd。
 * 所有传入参数均为安装器自身固定值或 Node 解析出的绝对路径，不拼接用户 shell 文本。
 */
const WINDOWS_SHIMS = new Set(['npm', 'pnpm', 'dsh']);
function commandPath(command) {
  return isWin && WINDOWS_SHIMS.has(command) ? `${command}.cmd` : command;
}

function spawnCommand(command, args, runOptions) {
  if (isWin && WINDOWS_SHIMS.has(command)) {
    // Windows 的 npm/pnpm/dsh 是 .cmd shim，只能由 cmd.exe 启动。
    // cmd /d /s /c 显式调用（不用 shell:true，避开 Node 22 的 DEP0190
    // "shell:true + 参数数组"弃用警告）；外部双引号让 /s 剥壳后
    // 留下 "npm.cmd" "install" ... 的标准命令串。
    const line = [commandPath(command), ...args].map((a) => `"${a}"`).join(' ');
    return spawnSync(
      process.env.ComSpec || 'cmd.exe',
      ['/d', '/s', '/c', `"${line}"`],
      runOptions,
    );
  }
  return spawnSync(commandPath(command), args, runOptions);
}

function run(command, args = [], { quiet = false, env } = {}) {
  const result = spawnCommand(command, args, {
    stdio: quiet ? 'ignore' : 'inherit',
    cwd: root,
    env: env ?? process.env,
  });
  if (result.error !== undefined) {
    // ENOENT（Unix 上命令不存在）等 spawn 错误：返回非零状态码，走调用方的
    // 友好错误路径——不能 throw，否则 mustRun 的"先检测后安装"分支
    // （缺 pnpm 时自动安装）永远不可达，安装器以未捕获异常崩溃。
    return 1;
  }
  return result.status ?? 1;
}

/** 捕获命令 stdout（读取 dsh --version 用）；命令缺失/非零退出/无输出时返回 null。 */
function capture(command, args) {
  const result = spawnCommand(command, args, {
    stdio: ['ignore', 'pipe', 'ignore'],
    cwd: root,
    env: process.env,
    encoding: 'utf8',
  });
  if (result.error !== undefined || result.status !== 0 || typeof result.stdout !== 'string') return null;
  return result.stdout;
}

/** Windows 无 POSIX 权限：用 icacls 收紧密钥文件 ACL（仅当前用户 + SYSTEM 可读写），
 *  防止同机其他用户/服务账号读取 .env 与 setup-key.txt（L-3）。
 *  失败不阻塞安装，但必须提示——否则用户以为已收紧。 */
function tightenWindowsAcl(file) {
  if (!isWin || !existsSync(file)) return;
  try {
    // 域环境用 DOMAIN\user 完整主体；本地账号 USERDOMAIN=机器名同样可用
    const account =
      process.env.USERDOMAIN && process.env.USERNAME
        ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
        : process.env.USERNAME;
    const args = [file, '/inheritance:r'];
    if (account) args.push('/grant:r', `${account}:F`);
    args.push('/grant:r', 'SYSTEM:F');
    const result = spawnSync('icacls', args, { stdio: 'ignore' });
    if (result.status !== 0 || result.error !== undefined) {
      say(`⚠ 无法收紧密钥文件 ACL（${file}），请检查目录权限`);
    }
  } catch {
    // 收紧失败不影响安装主流程
  }
}

function mustRun(command, args, failureMessage, options = {}) {
  if (run(command, args, options) === 0) return;
  err(failureMessage);
  process.exit(1);
}

// ── 0. 项目根目录必须完整（root 由脚本自身位置定位，不依赖 cwd；壳脚本保证 clone 到正确位置） ──
const pkgPath = path.join(root, 'package.json');
if (!existsSync(pkgPath)) {
  err(`未找到 ${pkgPath}，请先下载项目（git clone 或运行 install.bat/install.sh）`);
  process.exit(1);
}

// ── 1. Node.js（本包 engines ^22.19.0 || >=24.0.0；DSH 0.2.1-alpha.2 依赖树中的
//    @deepseek-ai/libreoffice-kit 声明 node >=22.19.0；DSH CLI 包自身未声明 engines） ──
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if ((nodeMajor === 22 && nodeMinor < 19) || nodeMajor < 22 || nodeMajor === 23) {
  err(`Node.js 版本不受支持（当前 v${process.versions.node}），需要 22.19+ 或 24+。`);
  err('  安装方法见 README「快速安装」一节。');
  process.exit(1);
}
say(`Node.js v${process.versions.node} ✓`);

// ── 2. dsh（DeepSeek Harness）版本窗口校验 ──
// 支持的补丁线：>=0.2.1-alpha.1 <0.2.2-0（与 src/cli.ts 的运行时门禁同一身份边界）。
// 0.2.1 的后续预发布（alpha.3/beta/rc）与稳定版共享同一 bundle/wire 契约，仍在窗口内；
// 0.1.x、0.2.0、0.2.1-alpha.0 以及 0.2.2+ 都不允许打补丁或公开监听，安装器必须同样失败。
const DSH_SUPPORTED_RANGE = '>=0.2.1-alpha.1 <0.2.2-0';
const DSH_SUPPORTED_CORE = '0.2.1';
const DSH_SUPPORTED_PRERELEASE_FLOOR = ['alpha', '1'];
const SEMVER_RE = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function stripBuildMetadata(version) {
  const plus = version.indexOf('+');
  return plus === -1 ? version : version.slice(0, plus);
}

/** SemVer 2.0 预发布优先级比较（数值标识低于字母数字标识，短列表低于其延长列表）。 */
function comparePrerelease(a, b) {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNumeric = /^\d+$/.test(x);
    const yNumeric = /^\d+$/.test(y);
    if (xNumeric && yNumeric) {
      if (Number(x) !== Number(y)) return Number(x) - Number(y);
    } else if (xNumeric) {
      return -1;
    } else if (yNumeric) {
      return 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

function isSupportedDshVersion(version) {
  if (typeof version !== 'string' || !SEMVER_RE.test(version)) return false;
  const stripped = stripBuildMetadata(version);
  const dash = stripped.indexOf('-');
  const core = dash === -1 ? stripped : stripped.slice(0, dash);
  const prerelease = dash === -1 ? [] : stripped.slice(dash + 1).split('.');
  if (core !== DSH_SUPPORTED_CORE) return false;
  return prerelease.length === 0 || comparePrerelease(prerelease, DSH_SUPPORTED_PRERELEASE_FLOOR) >= 0;
}

function assertSupportedDshVersion(version) {
  if (isSupportedDshVersion(version)) return;
  err(`不支持的 dsh 版本（当前 ${version}），本安装器仅支持 ${DSH_SUPPORTED_RANGE}。`);
  err('  请安装受支持版本后重试：npm install -g @deepseek-ai/dsh@0.2.1-alpha.2');
  err('  源码部署请将 MCP_DSH_ROOT 指向该版本所在的 dsh 目录。');
  process.exit(1);
}

// 版本来源优先采用 MCP_DSH_ROOT（网关补丁会以它为准），否则回退 dsh --version。
// 显式指定的安装根不可读时不回退全局 CLI——避免校验到与运行时不同的另一份 DSH。
const explicitDshRoot = process.env.MCP_DSH_ROOT?.trim();
if (explicitDshRoot) {
  const manifestPath = path.join(explicitDshRoot, 'package.json');
  let manifestVersion = null;
  try {
    manifestVersion = JSON.parse(readFileSync(manifestPath, 'utf8')).version;
  } catch {
    // 交由下方统一报错。
  }
  if (typeof manifestVersion !== 'string') {
    err(`无法从 MCP_DSH_ROOT 读取 dsh 版本（${manifestPath} 缺失或损坏）。`);
    err('  请把 MCP_DSH_ROOT 指向包含 package.json 的 dsh 安装目录，或取消该变量后重试。');
    process.exit(1);
  }
  assertSupportedDshVersion(manifestVersion);
  say(`dsh ${manifestVersion} ✓`);
} else {
  const versionOutput = capture('dsh', ['--version']);
  // dsh --version 可能带前缀/多行；取第一个 semver 形状的 token。
  const versionMatch = versionOutput === null
    ? null
    : versionOutput.match(/\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?/);
  if (versionMatch === null) {
    err('未找到 dsh（DeepSeek Harness）。请先安装：');
    err('  npm install -g @deepseek-ai/dsh@0.2.1-alpha.2');
    err('  然后确认 dsh --version 可读，或设置 MCP_DSH_ROOT 指向 dsh 安装目录后重试。');
    process.exit(1);
  }
  assertSupportedDshVersion(versionMatch[0]);
  say(`dsh ${versionMatch[0]} ✓`);
}

// 首次安装的特权检查必须在安装任何工具或依赖之前完成：非特权账号最终无法绑定自动 HTTPS 的 80/443，
// 不应让用户先修改全局 pnpm、下载或构建再失败。
// 部署文件路径：DSH_PASSWORDS_ENV_FILE 显式指定时跟随它（dsh 插件/网关进程读的就是这份），
// 否则仍写在包根。setup-key.txt 始终与 .env 同目录，保证引导文件与配置在一起。
const explicitEnvFile = process.env.DSH_PASSWORDS_ENV_FILE?.trim();
const envPath = explicitEnvFile ? path.resolve(explicitEnvFile) : path.join(root, '.env');
const keyFile = explicitEnvFile
  ? path.join(path.dirname(envPath), 'setup-key.txt')
  : path.join(root, 'setup-key.txt');
const isFirstInstall = !existsSync(envPath);
if (isFirstInstall && existsSync(keyFile)) {
  // .env 已丢失但旧引导文件还在：其 key 与即将生成的新 key 不可信地不一致。
  // 在写任何新文件之前失败，避免留下半成品配置。
  err(`检测到 ${keyFile}，但 ${envPath} 不存在。请先确认是否需要恢复旧配置；否则删除/备份该残留文件后重试。`);
  process.exit(1);
}
const uid = typeof process.getuid === 'function' ? process.getuid() : null;
if (isFirstInstall && firstInstallNeedsRoot({ isWin, uid, env: process.env })) {
  err('自动 HTTPS 需要监听 80 和 443；Unix/macOS 上请使用 sudo 运行安装器。');
  err('如必须非特权账号部署，请显式关闭自动 HTTPS（MCP_GATEWAY_AUTO_TLS=0/false/no）');
  err('或配置 MCP_GATEWAY_TLS_CERT/KEY 后重试，并按 README 设置高位端口与监听地址。');
  process.exit(1);
}
// 只有通过首次安装门禁后才创建显式部署目录；拒绝路径不得产生任何部署副作用。
if (isFirstInstall && explicitEnvFile) mkdirSync(path.dirname(envPath), { recursive: true });
if (isFirstInstall && !isWin && uid === 0) {
  // root 安装后，dsh 的 web profile（~/.dsh/profiles/web）将由 root 拥有；
  // 之后用普通用户跑 dsh 会因目录归属/权限读不到插件（M-2）。
  say('⚠ 检测到以 root 安装：dsh 的 web profile（~/.dsh）将由 root 拥有。');
  say('  若之后改用其他用户运行 dsh，请先执行 chown -R <用户> ~/.dsh，否则插件可能加载失败。');
}

// ── 3. pnpm（dsh 插件管理依赖）──
if (run('pnpm', ['--version'], { quiet: true }) !== 0) {
  say('未找到 pnpm（dsh 插件管理需要），正在安装…');
  mustRun(
    'npm',
    ['install', '-g', 'pnpm', '--no-audit', '--no-fund'],
    'pnpm 安装失败，请手动执行 npm install -g pnpm 后重试',
  );
}
say('pnpm ✓');

// ── 4. 依赖 + 编译（npm 包已预构建时自动跳过） ──
// 不能只看 node_modules 目录：中断安装会留下半残目录，之后直到首次运行才暴露 MODULE_NOT_FOUND。
// 运行时依赖用 Node 模块解析检测（兼容 npm --prefix 安装时依赖被提升到上层
// node_modules 的情况）；dist/cli.js 与 dist/client.js 均存在才视为已构建。
const hasSource = existsSync(path.join(root, 'tsconfig.json')) && existsSync(path.join(root, 'src'));
const prebuilt = hasPrebuiltRuntime(root, RUNTIME_DEPS);
if (prebuilt && !hasSource) {
  say('检测到 npm 预构建包，跳过依赖安装与编译');
} else if (hasSource) {
  say('安装源码依赖…');
  // 源码构建不执行依赖包脚本：本项目运行时不依赖 postinstall，DSH 的原生脚本
  // 由外部安装器单独按 allowlist 处理。这样 npm 11 的用户级 allow-scripts
  // 不会改变本项目 npm ci 的结果，也不会执行未审查的第三方脚本。
  const installArgs = existsSync(path.join(root, 'npm-shrinkwrap.json'))
    ? ['ci', '--include=optional', '--include=dev', '--ignore-scripts', '--no-audit', '--no-fund']
    : ['install', '--ignore-scripts', '--no-audit', '--no-fund'];
  mustRun('npm', installArgs, '依赖安装失败，请修复 npm 输出后重试');
  say('编译…');
  mustRun('npm', ['run', 'build'], '编译失败，请修复错误后重试');
} else {
  err('npm 包缺少完整的预构建产物，请重新安装 dsh-passwords');
  process.exit(1);
}

// ── 5. 生成/修复 .env（重跑不覆盖既有配置） ──
let setupKey = '';
let recoveredSetupKey = false;
if (!isFirstInstall && existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = /^\s*SETUP_KEY\s*=\s*(.*?)\s*$/.exec(line);
    if (match && !line.trimStart().startsWith('#')) {
      setupKey = match[1].replace(/\s+#.*$/, '').replace(/^['"]|['"]$/g, '').trim();
    }
  }
  if (setupKey === '') {
    // 旧版/中断安装可能留下没有 SETUP_KEY 的 .env。保留其余配置并只补齐
    // 缺项；直接拒绝会让安装器无法从这一可恢复状态继续执行。
    setupKey = randomBytes(24).toString('hex');
    writeFileSync(envPath, `${readFileSync(envPath, 'utf8').replace(/\s*$/, '')}\nSETUP_KEY=${setupKey}\n`);
    recoveredSetupKey = true;
    say('.env 缺少 SETUP_KEY，已保留现有配置并生成新的首次配置密钥');
  }
  if (!isWin) chmodSync(envPath, 0o600);
  tightenWindowsAcl(envPath);
  say('.env 已存在，沿用现有配置');
} else {
  setupKey = randomBytes(24).toString('hex');
  // DB 加密主密钥独立随机生成（不复用 SETUP_KEY）：SETUP_KEY 泄露/轮换
  // 不再连带削弱静态加密；hardenSecretsAfterSetup 会把它固化进 .env
  const dbEncKey = randomBytes(32).toString('hex');
  writeFileSync(
    envPath,
    firstInstallEnvContent(setupKey, dbEncKey, process.env),
    { encoding: 'utf8', mode: 0o600 },
  );
  if (!isWin) chmodSync(envPath, 0o600);
  tightenWindowsAcl(envPath);
  say('.env 已生成（含随机 SETUP_KEY 与独立 DB 加密密钥）');
}

// ── 6. 首次安装才写 setup-key.txt；绝不在重跑安装器时重新暴露密钥 ──
if (setupKey === '') {
  // 保护已有但损坏/注释掉 SETUP_KEY 的 .env，避免生成空密钥引导文件。
  err('未能读取 SETUP_KEY；请检查 .env 后重试');
  process.exit(1);
}
if (isFirstInstall || recoveredSetupKey) {
  writeFileSync(
    keyFile,
    [
      'dsh-passwords 首次配置密钥',
      '========================',
      '',
      `SETUP_KEY = ${setupKey}`,
      '',
      '用法：启动 dsh 后，浏览器打开 https://<你的服务器地址>',
      '（未初始化时会自动进入首次配置页），在「预设密钥」栏输入',
      '上面的值，创建主用户。',
      '',
      '注意：只用于第一次初始化。初始化完成后请删除本文件！',
      '',
    ].join('\n'),
    { encoding: 'utf8', mode: 0o600 },
  );
  if (!isWin) chmodSync(keyFile, 0o600);
  tightenWindowsAcl(keyFile);
  say(`首次配置密钥已写入 ${keyFile}（初始化完成后请删除）`);
} else {
  say('检测到已有 .env，不重复创建或打印首次配置密钥');
}

// ── 7. 注册为 dsh 插件（此后 dsh web 启动会自动拉起密码门） ──
say('注册 dsh 插件（profile: web）…');
mustRun(
  process.execPath,
  [path.join(root, 'scripts', 'register-plugin.mjs')],
  '插件注册失败（pnpm 安装 profile 依赖出错），可手动运行 scripts/register-plugin.mjs 排查',
);

// ── 8. 应用远程设置补丁（让经密码门登录的远程浏览器可用 dsh 设置） ──
say('应用远程设置补丁…');
const patchResult = spawnSync(
  process.execPath,
  [path.join(root, 'dist', 'cli.js'), 'patch'],
  {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, MCP_DSH_RESTART_SERVICE: '' },
  },
);
// 退出码由 dist/cli.js 的补丁命令定义（与 src/cli.ts 一致）；按原因给出可操作提示，
// 不再把任何失败都归为“未找到 dsh 安装目录”。
const PATCH_EXIT_REASONS = {
  34: '未找到 dsh 安装目录（请在 .env 设置 MCP_DSH_ROOT 或确保 dsh 已安装）',
  35: '当前 dsh 版本缺少可打补丁的目标文件',
  36: '补丁写入或校验失败（DSH 文件可能被其他工具改动）',
  37: `dsh 版本不受支持（仅支持 ${DSH_SUPPORTED_RANGE}）`,
};
// 永久失败退出码（与 src/plugin.ts 的 PERMANENT_GATEWAY_EXIT_CODES 中补丁相关子集一致）：
// 密码门在这些码上拒绝启动且不会自动重试，安装器必须同样终止，不得打印“安装完成”。
const PATCH_PERMANENT_EXIT_CODES = new Set([1, 34, 35, 36, 37]);
let patchPermanentFailure = false;
if (patchResult.error !== undefined) {
  say(`补丁暂时无法应用（执行失败：${patchResult.error.message}），密码门启动时会自动重试`);
} else if (patchResult.status === 0) {
  say('补丁已应用');
} else {
  const code = patchResult.status;
  const reason = PATCH_EXIT_REASONS[code]
    ?? `未知原因（退出码 ${code ?? 'signal'}）`;
  if (PATCH_PERMANENT_EXIT_CODES.has(code)) {
    patchPermanentFailure = true;
    err(`补丁未应用（永久失败）：${reason}；密码门将拒绝启动，不会自动重试`);
  } else {
    say(`补丁暂时无法应用（${reason}），密码门启动时会自动重试。若问题持续，请手动修复后重新运行安装器`);
  }
}

// ── 9. 完成 ──
// 永久补丁失败时密码门不会启动，安装并未完成：不得打印“安装完成”，并以非零码退出，
// 让 install.sh / install.bat 的退出码透传反映真实结果。
if (patchPermanentFailure) {
  err('安装未完成：远程设置补丁未应用，密码门将拒绝启动。请修复上述原因后重新运行安装器。');
  process.exit(1);
}
say('');
say('★ 安装完成！');
say('');
if (isFirstInstall || recoveredSetupKey) {
  say('  首次配置密钥（SETUP_KEY）：');
  say(`      ${setupKey}`);
  say(`      （同时保存在 ${keyFile}，初始化完成后请删除该文件）`);
  say('');
} else {
  say('  已沿用现有 .env；为避免重新暴露密钥，安装器不会打印 SETUP_KEY。');
  say('  若尚未初始化，请仅在受信任终端中从 .env 读取它。');
  say('');
}
say('  接下来 3 步：');
say('    1) 用平时的方式启动 dsh（例如：DEEPSEEK_API_KEY=sk-你的key dsh web）');
say('       ——密码门会被自动拉起，不需要额外启动命令');
say('    2) 浏览器打开 https://<服务器IP>.sslip.io');
say('       （首次会自动进入配置页），输入上面的 SETUP_KEY，创建主用户');
say('    3) 之后所有人访问 https://<服务器IP>.sslip.io 都会先过登录页');
say('');
say('  提示：');
say('    - 服务器防火墙和云安全组都要放行 80 和 443 端口');
say('      （80 用于证书验证和跳转，443 用于 HTTPS 访问）');
say('    - 有自己域名的话，在 .env 里加一行 MCP_GATEWAY_DOMAIN=你的域名');
say('      并把域名解析到本机，就能用域名访问（自动签该域名的证书）');
say('    - 证书签不出来（无公网 IP/纯内网）：见 README 的「HTTP 模式」一节');
