// 自动更新引擎：GitHub release 仅用于发现版本；npm registry 是 tarball 和
// sha512 integrity 的唯一下载信任源。自动更新先限速下载并校验，连续空闲满一小时
// 才安装；关闭自动更新时，主用户第一次点击只下载，第二次确认才安装。
//
// 原生 systemd 部署会把已校验包先装进同级临时目录，再替换固定部署目录中的程序文件；
// .env、data 和部署内证书会被保留，旧程序与下载临时文件在成功后立即清理。普通 npm
// 安装仍保留其全局/prefix 语义。
import { createHash, randomBytes } from 'node:crypto';
import {
  cpSync,
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
  chmodSync,
  closeSync,
  openSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { homedir } from 'node:os';
import { realpathSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import type { PlatformConfig } from './config.js';
import { restartDshWebChecked, resolveNpmCommand } from './patch.js';

const INSTALL_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** 空闲安装等待窗：连续 1 小时无任何用户活动才执行安装+重启 */
export const UPDATE_IDLE_MS = 60 * 60 * 1000;
/** 自动检查周期：启动时一次 + 之后每 24 小时 */
export const UPDATE_CHECK_MS = 24 * 60 * 60 * 1000;
/** 手动「立即安装重启」冷却（防反复重启 dsh，与补丁重载同口径） */
export const UPDATE_APPLY_COOLDOWN_MS = 10 * 60 * 1000;
/** 自动下载的硬上限：1MiB/s。环境变量只能再降低它，不能提高。 */
export const UPDATE_DEFAULT_MAX_BPS = 1024 * 1024;
const NPM_REGISTRY_HOSTS = new Set(['registry.npmjs.org']);
/** npm 校验/安装超时 */
const UPDATE_NPM_TIMEOUT_MS = 180 * 1000;
/** 固定部署目录交换锁 TTL：进程被强杀超过该时长视为陈旧锁可接管，避免永久阻塞更新。 */
const UPDATE_INSTALL_LOCK_TTL_MS = 60 * 60 * 1000;
/** 交换锁临界区 gate 的接管 TTL：临界区只做同步判定，写者崩溃残留后不应永久阻塞更新。 */
export const UPDATE_GATE_TTL_MS = 5 * 60 * 1000;
/** 版本标签合法格式（拒绝任意字符串标签） */
const RELEASE_TAG_RE = /^v?\d+\.\d+\.\d+$/;
/** npm 包下载地址白名单。GitHub API 仅用于发现版本，不下载其 release asset。 */
const ALLOWED_DOWNLOAD_HOSTS = NPM_REGISTRY_HOSTS;

export type UpdateRuntime = 'docker' | 'git' | 'npm-global' | 'npm-prefix' | 'unknown';
export type UpdatePhase = 'idle' | 'downloading' | 'ready' | 'installing' | 'restarting' | 'error';

export interface UpdateStatus {
  env: UpdateRuntime;
  /** 当前运行版本（package.json） */
  currentVersion: string;
  /** 最近一次检到的线上版本；未检过为 null */
  latestVersion: string | null;
  updateAvailable: boolean;
  checking: boolean;
  phase: UpdatePhase;
  /** npm 下载进度 0-100；Docker 安装没有真实字节进度时保持 null。 */
  downloadPercent: number | null;
  downloadMode: 'automatic' | 'manual' | null;
  downloadedBytes: number;
  totalBytes: number | null;
  /** 已下载并通过校验、等待空闲窗口或主用户确认安装的版本 */
  pendingVersion: string | null;
  /** 手动下载完成后必须由主用户第二次点击安装。 */
  installConfirmationRequired: boolean;
  /** 手动下载完成的持久化通知时间。 */
  lastNotificationAt: string | null;
  /** 距空闲窗剩余毫秒（pending install 时）；其余为 null */
  idleRemainingMs: number | null;
  /** 自动更新开关（数据库设置优先；部署级 MCP_DSH_AUTO_UPDATE=false 可强制关闭） */
  autoUpdateEnabled: boolean;
  /** 当前环境是否支持自动安装；Docker 需要配置 compose 目录，unknown 保持关闭 */
  autoInstallSupported: boolean;
  /** 环境不支持时给的手动命令；支持自动时为空串 */
  manualCommand: string;
  lastCheckedAt: string | null;
  lastError: string | null;
  /** 手动 apply 冷却剩余毫秒；0 = 可立即执行 */
  applyCooldownRemainingMs: number;
  /** 程序已替换但服务尚未成功重启的版本 */
  restartPendingVersion: string | null;
}

/**
 * 将更新引擎的业务结果映射为插件 HTTP 状态码。
 * 进行中是可轮询的受理状态；未就绪/不支持是可操作的业务错误，不能冒充冲突。
 */
export function updateApplyHttpStatus(body: { ok?: unknown; code?: unknown; message?: unknown; error?: unknown }): number {
  const code = typeof body.code === 'string' ? body.code : '';
  if (
    code === 'DOWNLOAD_STARTED' ||
    code === 'DOWNLOAD_IN_PROGRESS' ||
    code === 'INSTALL_STARTED' ||
    code === 'INSTALL_IN_PROGRESS'
  ) return 202;
  if (code === 'RATE_LIMITED') return 429;
  if (code === 'NOT_READY') return 422;
  return body.ok === false ? 422 : 200;
}

interface ReleaseInfo {
  version: string;
}

interface NpmPackageInfo {
  version: string;
  tarballUrl: string;
  integrity: string;
}

interface NpmInstallTarget {
  env: NodeJS.ProcessEnv;
  packageRoot: string;
  /** 固定部署目录；null 表示保持传统 npm-global/npm-prefix 安装方式。 */
  deploymentRoot: string | null;
}

export function npmGlobalInstallArgs(artifact: string): string[] {
  return ['install', '-g', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', artifact];
}

/** 只能保留部署状态，不能把旧包中的运行代码带进新包。 */
const PRESERVED_DEPLOYMENT_ENTRIES = ['.env', 'data', 'setup-key.txt'];

/**
 * 计算固定部署替换必须保留的实际 env 文件相对路径。DSH_PASSWORDS_ENV_FILE 可指向
 * 部署目录内的其它文件名（如 harness.env），只靠硬编码 .env 会在替换时丢失配置。
 * 仅当文件确实位于部署目录内、且路径分隔正常时返回相对路径；越界（部署目录本身或
 * 外部）与分隔异常的路径一律返回 null，避免交换时移动或错位保留范围外的条目。
 * 未显式指定时返回 null，交由默认 .env，保持既有行为。
 */
export function deploymentEnvFileRelativeEntry(deploymentRoot: string, configuredEnvFile: string): string | null {
  const raw = configuredEnvFile.trim();
  if (raw === '') return null;
  const relative = path.relative(deploymentRoot, path.resolve(raw));
  if (relative === '' || path.isAbsolute(relative)) return null;
  // 非本机分隔符混入相对路径，说明文件名被下游误当成子目录，拒绝以免交换错位。
  const foreignSeparator = path.sep === '\\' ? '/' : '\\';
  if (relative.includes(foreignSeparator)) return null;
  if (relative.split(path.sep).some((segment) => segment === '' || segment === '.' || segment === '..')) return null;
  return relative;
}

/** 版本号比较：'v2.6.0' / '2.5.10' → 数字逐级比较；格式非法返回 null */
export function compareVersions(a: string, b: string): number | null {
  const pa = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(a.trim());
  const pb = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(b.trim());
  if (!pa || !pb) return null;
  for (let i = 1; i <= 3; i++) {
    const x = Number(pa[i]);
    const y = Number(pb[i]);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** 容器判定由更新与紧急清理共用；任一可靠信号命中即按容器处理。 */
export function isContainerRuntime(
  env: NodeJS.ProcessEnv = process.env,
  exists: (candidate: string) => boolean = existsSync,
): boolean {
  if (env.DSH_PASSWORDS_RUNTIME?.trim().toLowerCase() === 'docker') return true;
  for (const marker of ['/.dockerenv', '/run/.containerenv']) {
    try {
      if (exists(marker)) return true;
    } catch {
      /* 只读挂载等环境读不到该标记时继续检查其他信号 */
    }
  }
  return (env.DSH_HOME?.trim().replace(/\\/g, '/') ?? '').startsWith('/data/');
}

/**
 * 识别当前运行环境。
 * - docker：容器标记存在、DSH_HOME 落在 /data/ 下、或显式
 *   DSH_PASSWORDS_RUNTIME=docker（Dockerfile 内置标记，最可靠）
 * - git：安装根含 .git（源码开发目录）
 * - npm-global：安装根恰为 `<npm root -g>` 的子目录
 * - npm-prefix：位于 `<prefix>/node_modules` 或 `<prefix>/lib/node_modules` 下
 * - 其余 → unknown（fail-closed：不猜安装目标）
 */
export function detectRuntime(installRoot: string, env: NodeJS.ProcessEnv = process.env): UpdateRuntime {
  const explicit = env.DSH_PASSWORDS_RUNTIME?.trim().toLowerCase() ?? '';
  if (explicit === 'docker' || explicit === 'git') return explicit;
  if (isContainerRuntime(env)) return 'docker';
  try {
    if (existsSync(path.join(installRoot, '.git'))) return 'git';
  } catch {
    /* best effort */
  }
  try {
    const npm = resolveNpmCommand(['root', '-g'], env);
    // 必须把调用方传入的 env 交给子进程：npm_config_prefix 等安装前缀配置决定
    // `npm root -g` 的输出，漏传会按宿主 process.env 误判运行环境。
    const result = npm === null
      ? null
      : spawnSync(npm.command, npm.args, { encoding: 'utf8', timeout: 8000, shell: false, windowsHide: true, env });
    const globalRoot = result !== null && result.status === 0 && typeof result.stdout === 'string' ? result.stdout.trim() : '';
    if (globalRoot !== '' && path.dirname(installRoot) === path.resolve(globalRoot)) return 'npm-global';
    if (resolveNpmPrefix(installRoot, globalRoot) !== null) return 'npm-prefix';
  } catch {
    /* npm 不可用时走下方兜底 */
  }
  // 原生源码部署可能通过 tar/安装脚本同步，没有 .git；明确的 dsh-passwords
  // 源码布局仍应走 npm tarball 更新路径，而不是错误降级为 unknown。
  if (existsSync(path.join(installRoot, 'src')) && existsSync(path.join(installRoot, 'scripts'))) return 'git';
  // 兜底：无 npm 时按目录布局推断
  const parent = path.basename(path.dirname(installRoot));
  if (parent === 'node_modules') return 'npm-prefix';
  if (parent === 'lib' && path.basename(path.dirname(path.dirname(installRoot))) === 'node_modules') {
    return 'npm-prefix';
  }
  return 'unknown';
}

/** 从 npm 目录布局反推 --prefix；推不出返回 null（fail-closed） */
export function resolveNpmPrefix(installRoot: string, globalRoot?: string): string | null {
  if (globalRoot !== undefined && globalRoot !== '' && path.dirname(installRoot) === path.resolve(globalRoot)) {
    return null; // 就是 npm-global，不是 prefix
  }
  const parent = path.dirname(installRoot);
  const base = path.basename(parent);
  if (base === 'node_modules') {
    // <prefix>/node_modules 或 <prefix>/lib/node_modules
    const grand = path.dirname(parent);
    return path.basename(grand) === 'lib' ? path.dirname(grand) : grand;
  }
  return null;
}

/** 解析 release 信息：tag 合法 + 存在目标 tgz 资产 + host 在 GitHub 官方域内，否则 null */
export function parseReleaseInfo(data: unknown, wantedVersion?: string): ReleaseInfo | null {
  if (typeof data !== 'object' || data === null) return null;
  const tag = (data as { tag_name?: unknown }).tag_name;
  if (typeof tag !== 'string' || !RELEASE_TAG_RE.test(tag)) return null;
  const version = tag.replace(/^v/, '');
  return wantedVersion !== undefined && wantedVersion !== version ? null : { version };
}

/** npm registry 是包下载与完整性校验的唯一信任源。 */
export function parseNpmPackageInfo(data: unknown, wantedVersion: string): NpmPackageInfo | null {
  if (typeof data !== 'object' || data === null) return null;
  const value = data as { name?: unknown; version?: unknown; dist?: { tarball?: unknown; integrity?: unknown } };
  if (value.name !== 'dsh-passwords' || value.version !== wantedVersion) return null;
  if (typeof value.dist?.tarball !== 'string' || typeof value.dist.integrity !== 'string' || value.dist.integrity === '') return null;
  try {
    const url = new URL(value.dist.tarball);
    if (url.protocol !== 'https:' || !NPM_REGISTRY_HOSTS.has(url.hostname)) return null;
  } catch {
    return null;
  }
  return { version: wantedVersion, tarballUrl: value.dist.tarball, integrity: value.dist.integrity };
}

/** 引擎持久化用最小接口（真实 Database 结构上满足；测试传假 store） */
export interface UpdateStore {
  getSetting(key: string): string | null;
  setSetting(key: string, value: string): void;
  audit(
    eventType: string,
    opts?: { username?: string | null; ip?: string | null; userAgent?: string | null; detail?: string | null },
  ): void;
}

/** 引擎依赖注入接口（测试替换真实网络/npm 调用） */
export interface UpdateEngineOps {
  now(): number;
  /** 拉取 GitHub release JSON（真实实现只请求受信任的 api.github.com） */
  fetchRelease(url: string): Promise<unknown>;
  /** 读取 npm 某版本的元数据（tarball URL + integrity）。 */
  fetchNpmMetadata(version: string): Promise<unknown>;
  /** 限速流式下载（内含 Range 续传 + 完成后整体 sha512），返回 hex */
  download(
    url: string,
    dest: string,
    maxBps: number,
    resumedBytes: number,
    onProgress?: (receivedBytes: number, totalBytes: number | null) => void,
  ): Promise<string>;

  /** 执行安装命令；返回 {ok, message（错误摘要）}，不得阻塞网关事件循环 */
  runInstall(args: string[], env: NodeJS.ProcessEnv, cwd?: string): Promise<{ ok: boolean; message: string }>;
  /** 执行外部子进程（Docker/npm/node 等）；不得经过 shell；成功时 message 保留 stdout。 */
  runCommand(command: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): Promise<{ ok: boolean; message: string }>;
  /** Docker readiness 重试等待；测试可注入无等待实现。 */
  wait?(ms: number): Promise<void>;
  /** 重启 dsh 网页服务（systemd）；返回真实命令结果 */
  restartWebService(service: string): Promise<{ ok: boolean; message: string; manual?: boolean }>;
  log(message: string): void;
}

function runProcess(command: string, args: string[], env: NodeJS.ProcessEnv, cwd?: string): Promise<{ ok: boolean; output: string }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      env,
      cwd,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    const append = (chunk: Buffer) => {
      if (size >= 8192) return;
      const slice = chunk.subarray(0, 8192 - size);
      chunks.push(slice);
      size += slice.length;
    };
    child.stdout.on('data', append);
    child.stderr.on('data', append);
    let killTimer: NodeJS.Timeout | null = null;
    const timer = setTimeout(() => {
      child.kill();
      killTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
    }, UPDATE_NPM_TIMEOUT_MS);
    const cleanup = () => {
      clearTimeout(timer);
      if (killTimer !== null) clearTimeout(killTimer);
    };
    child.on('error', (error) => {
      cleanup();
      resolve({ ok: false, output: error instanceof Error ? error.message : '命令启动失败' });
    });
    child.on('close', (code) => {
      cleanup();
      const output = Buffer.concat(chunks).toString('utf8').trim().slice(0, 800);
      resolve({ ok: code === 0, output });
    });
  });
}

// Windows 的 npm.cmd 在 Node >=22 上无法 shell:false 直接 spawn（Issue #33），
// 统一经 resolveNpmCommand 解析为 `node <npm-cli.js>`（详见 patch.ts）。
function runNpm(args: string[], env: NodeJS.ProcessEnv, cwd?: string): Promise<{ ok: boolean; output: string }> {
  const npm = resolveNpmCommand(args, env);
  if (npm === null) return Promise.resolve({ ok: false, output: 'npm 调用参数不安全，已拒绝执行' });
  return runProcess(npm.command, npm.args, env, cwd);
}

function testUpdateConfig(): { version: string; artifact: string } | null {
  if (process.env.MCP_DSH_UPDATE_TEST_MODE?.trim() !== '1') return null;
  const version = process.env.MCP_DSH_UPDATE_TEST_VERSION?.trim() ?? '';
  const artifact = process.env.MCP_DSH_UPDATE_TEST_ARTIFACT?.trim() ?? '';
  if (!RELEASE_TAG_RE.test(version) || !path.isAbsolute(artifact) || !existsSync(artifact)) return null;
  return { version, artifact };
}

function testUpdateMetadata(version: string, artifact: string): unknown {
  const integrity = createHash('sha512').update(readFileSync(artifact)).digest('base64');
  return {
    name: 'dsh-passwords',
    version,
    dist: {
      tarball: `https://registry.npmjs.org/dsh-passwords/-/dsh-passwords-${version}.tgz`,
      integrity: `sha512-${integrity}`,
    },
  };
}

async function downloadTestArtifact(artifact: string, dest: string, onProgress?: (received: number, total: number) => void): Promise<string> {
  const payload = readFileSync(artifact);
  mkdirSync(path.dirname(dest), { recursive: true });
  writeFileSync(dest, payload);
  onProgress?.(payload.length, payload.length);
  return createHash('sha512').update(payload).digest('hex');
}

const defaultOps: UpdateEngineOps = {
  now: () => Date.now(),
  fetchRelease: (url) => {
    const test = testUpdateConfig();
    return test === null ? fetchReleaseJson(url) : Promise.resolve({ tag_name: `v${test.version}` });
  },
  fetchNpmMetadata: (version) => {
    const test = testUpdateConfig();
    return test === null ? fetchJson(`https://registry.npmjs.org/dsh-passwords/${version}`, 'dsh-passwords-update-check') : Promise.resolve(test.version === version ? testUpdateMetadata(test.version, test.artifact) : null);
  },
  download: (url, dest, maxBps, resumed, onProgress) => {
    const test = testUpdateConfig();
    return test === null ? downloadThrottled(url, dest, maxBps, resumed, onProgress) : downloadTestArtifact(test.artifact, dest, onProgress);
  },
  runInstall: async (args, env, cwd) => {
    const result = await runNpm(args, env, cwd);
    return { ok: result.ok, message: result.ok ? '' : result.output || 'npm 命令失败' };
  },
  runCommand: async (command, args, cwd, env = process.env) => {
    const result = await runProcess(command, args, env, cwd);
    return { ok: result.ok, message: result.output || (result.ok ? '' : `${command} 命令失败`) };
  },
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  restartWebService: (service) => restartDshWebChecked(service, 800),
  log: (message) => console.log(`[dsh-passwords] ${message}`),
};

/** 读当前安装版本（package.json）；损坏按 0.0.0（不阻断引擎） */
function readCurrentVersion(installRoot: string): string {
  try {
    const pkg = JSON.parse(readFileSync(path.join(installRoot, 'package.json'), 'utf8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

function readMaxBps(): number {
  const raw = process.env.MCP_DSH_UPDATE_MAX_BPS?.trim() ?? '';
  if (raw === '') return UPDATE_DEFAULT_MAX_BPS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : UPDATE_DEFAULT_MAX_BPS;
}

function parseStoredDate(value: string | null): number | null {
  if (value === null || value === '') return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/** PID 是否仍在运行（信号 0 探测）；EPERM 表示存在但无权限，按存活处理。 */
function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** 引擎构造可注入项（测试用）：installRoot/env 覆盖真实安装位置与环境 */
export interface UpdateEngineInit {
  installRoot?: string;
  env?: NodeJS.ProcessEnv;
  /** 测试可在非 Windows 平台覆盖目录替换策略；生产默认按当前平台选择。 */
  inPlaceDeploymentSwap?: boolean;
  /** 测试替身：真实运行时仍必须确认 Docker socket 为 Unix socket。 */
  dockerSelfUpdateAvailable?: boolean;
}

/** 引擎（网关侧单实例）：空闲状态机 + 下载/安装执行 */
export class UpdateEngine {
  private readonly ops: UpdateEngineOps;
  private readonly config: PlatformConfig;
  private readonly db: UpdateStore;
  private readonly installRoot: string;
  private version: string;
  private readonly runtime: UpdateRuntime;
  private readonly env: NodeJS.ProcessEnv;
  private readonly dockerSelfUpdateAvailable: boolean;
  private readonly inPlaceDeploymentSwap: boolean;
  private readonly stateDir: string;
  private lastActivityAt: number;
  private lastCheckedAt: number | null;
  private latestVersion: string | null;
  private phase: UpdatePhase = 'idle';
  private downloadPercent: number | null = null;
  private downloadMode: 'automatic' | 'manual' | null = null;
  private downloadedBytes = 0;
  private totalBytes: number | null = null;
  private pendingVersion: string | null;
  private installConfirmationRequired: boolean;
  private lastNotificationAt: string | null;
  private pendingIntegrity: string | null;
  private restartPendingVersion: string | null;
  private lastError: string | null;
  private lastApplyAt = 0;
  private downloadRunning = false;
  private checkRunning = false;
  private checkPromise: Promise<void> | null = null;
  private installRunning = false;
  private disposed = false;
  private tickTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    config: PlatformConfig,
    db: UpdateStore,
    ops: UpdateEngineOps = defaultOps,
    init?: UpdateEngineInit,
  ) {
    this.ops = ops;
    this.config = config;
    this.db = db;
    const installRoot = init?.installRoot ?? INSTALL_ROOT;
    this.installRoot = installRoot;
    this.env = init?.env ?? process.env;
    this.runtime = detectRuntime(installRoot, this.env);
    const dockerSocket = this.env.MCP_DSH_DOCKER_SOCKET?.trim() || '/var/run/docker.sock';
    let dockerSocketAvailable = false;
    try {
      dockerSocketAvailable = statSync(dockerSocket).isSocket();
    } catch {
      dockerSocketAvailable = false;
    }
    this.dockerSelfUpdateAvailable = init?.dockerSelfUpdateAvailable ?? dockerSocketAvailable;
    this.inPlaceDeploymentSwap = init?.inPlaceDeploymentSwap ?? process.platform === 'win32';
    // Docker 也以当前容器内的 package.json 为准。持久化 marker 只表示已完成的
    // Compose 操作，不能替代对真实运行镜像版本的证明。
    this.version = readCurrentVersion(installRoot);
    this.stateDir = path.join(path.dirname(config.dbPath), 'update');
    // 恢复持久化状态（网关重启不丢「已检到的版本/已完成下载」）
    this.lastCheckedAt = parseStoredDate(db.getSetting('update_checked_at'));
    this.latestVersion = db.getSetting('update_latest_version') || null;
    this.lastError = db.getSetting('update_last_error') || null;
    this.pendingVersion = db.getSetting('update_downloaded_ready') || null;
    this.downloadMode = db.getSetting('update_download_mode') === 'manual' ? 'manual' : db.getSetting('update_download_mode') === 'automatic' ? 'automatic' : null;
    this.installConfirmationRequired = db.getSetting('update_install_confirmation_required') === '1';
    this.lastNotificationAt = db.getSetting('update_last_notification_at') || null;
    this.pendingIntegrity = db.getSetting('update_downloaded_integrity') || null;
    this.restartPendingVersion = db.getSetting('update_restart_pending_version') || null;
    // 新进程已经从切换后的包目录启动，说明之前持久化的待重启版本已生效。
    // Docker 不能用 package.json 判断镜像版本，改由下方 Compose 健康恢复流程收口。
    if (this.runtime !== 'docker' && this.restartPendingVersion === this.version) {
      this.restartPendingVersion = null;
      db.setSetting('update_restart_pending_version', '');
    }
    if (this.pendingVersion !== null) {
      if (existsSync(this.artifactPath(this.pendingVersion))) {
        this.phase = 'ready';
      } else {
        // 产物被手工删除：状态复位，等下次 check 重新下载
        this.pendingVersion = null;
        this.downloadMode = null;
        this.installConfirmationRequired = false;
        this.pendingIntegrity = null;
        db.setSetting('update_downloaded_ready', '');
        db.setSetting('update_download_mode', '');
        db.setSetting('update_install_confirmation_required', '');
        db.setSetting('update_downloaded_integrity', '');
      }
    }
    // 安装已完成但服务未成功重启时，待重启状态优先于普通下载状态。
    if (this.restartPendingVersion !== null) {
      this.phase = 'error';
      if (this.runtime === 'docker') {
        // compose up 可能在旧进程收到响应前杀掉它；新实例用持久化标记执行
        // 一次幂等健康检查，成功后清理 pending，不依赖旧进程继续运行。
        void this.recoverDockerInstall().catch((error) => {
          this.setError(`Docker 更新恢复失败：${error instanceof Error ? error.message : String(error)}`);
          this.phase = 'error';
        });
      }
    }
    // 空闲窗从网关启动时刻起算（启动本身不算用户活动）
    this.lastActivityAt = this.ops.now();
  }

  /** 用户活动刷新（网关中间件调用；内部通道调用不算） */
  bumpActivity(): void {
    this.lastActivityAt = this.ops.now();
  }

  activityAgeMs(): number {
    return Math.max(0, this.ops.now() - this.lastActivityAt);
  }

  start(): void {
    if (this.disposed || this.tickTimer !== null) return;
    // 空闲窗检查 + 24h 自动重检的推进刻度：每 15 秒一跳
    this.tickTimer = setInterval(() => this.tick(), 15_000);
    this.tickTimer.unref();
    // 启动即检查一次（自动更新开启时）；之后每 24h 由 tick 推进
    if (this.autoUpdateEnabled()) void this.checkNow({ downloadIfAllowed: true }).catch(() => undefined);
  }

  dispose(): void {
    this.disposed = true;
    if (this.tickTimer !== null) {
      clearInterval(this.tickTimer);
      this.tickTimer = null;
    }
  }

  /**
   * 部署环境可以用 false/0/no 作为总控关闭；否则 platform_settings 的开关生效。
   * 没有数据库记录时默认开启，兼容已有安装。
   */
  private autoUpdateEnabled(): boolean {
    const raw = this.env.MCP_DSH_AUTO_UPDATE?.trim().toLowerCase() ?? '';
    if (raw === '0' || raw === 'false' || raw === 'no') return false;
    return this.db.getSetting('auto_update_enabled') !== '0';
  }

  /** 持久化设置页中的自动更新开关；部署级关闭时仍报告实际生效状态。 */
  setAutoUpdateEnabled(enabled: boolean): boolean {
    this.db.setSetting('auto_update_enabled', enabled ? '1' : '0');
    // 切换开关必须同步 pending 包的安装语义：关闭后即使包由后台下载，
    // 也必须要求第二次人工确认；开启后才允许按空闲窗自动安装。
    const effectiveEnabled = this.autoUpdateEnabled();
    if (this.pendingVersion !== null && this.phase === 'ready') {
      this.installConfirmationRequired = !effectiveEnabled;
      this.downloadMode = effectiveEnabled ? 'automatic' : 'manual';
      this.db.setSetting('update_install_confirmation_required', this.installConfirmationRequired ? '1' : '');
      this.db.setSetting('update_download_mode', this.downloadMode);
    }
    // 旧 Git 更新器留下的错误与当前 npm 下载状态无关，切换开关时不再继续误导用户。
    if (this.lastError?.includes('Git 工作区有未提交修改')) {
      this.lastError = null;
      this.db.setSetting('update_last_error', '');
    }
    if (enabled && this.latestVersion !== null && this.pendingVersion === null && this.phase === 'idle') {
      void this.checkNow({ downloadIfAllowed: true }).catch(() => undefined);
    }
    return this.autoUpdateEnabled();
  }

  private autoInstallSupported(): boolean {
    if (this.runtime === 'npm-global' || this.runtime === 'npm-prefix' || this.runtime === 'git') return true;
    return this.dockerUpdateSupported();
  }

  private dockerComposeDir(): string | null {
    const dir = this.env.MCP_DSH_DOCKER_COMPOSE_DIR?.trim() ?? '';
    const resolved = dir === '' ? null : path.resolve(dir);
    return resolved !== null && existsSync(resolved) ? resolved : null;
  }

  private dockerComposeFile(): string | null {
    const raw = this.env.MCP_DSH_DOCKER_COMPOSE_FILE?.trim() ?? '';
    if (raw === '' || path.isAbsolute(raw) || raw.includes('..')) return null;
    const dir = this.dockerComposeDir();
    if (dir === null) return null;
    const file = path.resolve(dir, raw);
    return file.startsWith(`${dir}${path.sep}`) && existsSync(file) ? raw : null;
  }

  private dockerImageRepository(): string | null {
    const image = this.env.MCP_DSH_DOCKER_IMAGE?.trim() ?? '';
    return /^[a-z0-9][a-z0-9._/-]*$/i.test(image) ? image : null;
  }

  private dockerUpdateSupported(): boolean {
    const dir = this.dockerComposeDir();
    const file = this.dockerComposeFile();
    if (dir === null || file === null) return false;
    try {
      const compose = readFileSync(path.join(dir, file), 'utf8');
      return this.runtime === 'docker'
        && this.dockerSelfUpdateAvailable
        && /^\s*dsh-passwords:\s*$/m.test(compose)
        && this.dockerImageRepository() !== null
        && this.env.MCP_DSH_DOCKER_SELF_UPDATE?.trim() === '1';
    } catch {
      return false;
    }
  }

  private dockerManualMessage(): string {
    return 'Docker 应用内更新未启用：需配置 MCP_DSH_DOCKER_SELF_UPDATE=1、MCP_DSH_DOCKER_COMPOSE_DIR、MCP_DSH_DOCKER_COMPOSE_FILE、MCP_DSH_DOCKER_IMAGE，并向容器显式授予 Docker socket 访问；请由宿主机执行 docker compose pull && docker compose up -d';
  }

  private dockerBaseArgs(): string[] {
    const file = this.dockerComposeFile();
    return ['compose', '-f', file ?? 'docker-compose.yml'];
  }

  private dockerOverrideFile(): string {
    return '.dsh-passwords-update.override.yml';
  }

  private dockerUpdateArgs(...args: string[]): string[] {
    return [...this.dockerBaseArgs(), '-f', this.dockerOverrideFile(), ...args];
  }

  private writeDockerOverride(version: string): boolean {
    const dir = this.dockerComposeDir();
    const image = this.dockerImageRepository();
    if (dir === null || image === null) return false;
    const target = path.join(dir, this.dockerOverrideFile());
    const temporary = `${target}.tmp`;
    try {
      writeFileSync(temporary, `services:\n  dsh-passwords:\n    image: ${image}:${version}\n`);
      renameSync(temporary, target);
      return true;
    } catch (error) {
      this.setError(`无法写入 Docker 更新覆盖文件：${error instanceof Error ? error.message : String(error)}`);
      try { rmSync(temporary, { force: true }); } catch { /* best effort */ }
      return false;
    }
  }

  private artifactPath(version: string): string {
    return path.join(this.stateDir, `dsh-passwords-${version}.tgz`);
  }

  private setError(message: string): void {
    this.lastError = message;
    this.db.setSetting('update_last_error', message);
  }

  private dropPart(partFile: string): void {
    try {
      unlinkSync(partFile);
    } catch {
      /* best effort */
    }
  }

  /** 面向不支持自动安装的环境提供兜底命令。 */
  private manualCommand(version: string | null): string {
    const v = version ?? this.version;
    if (this.runtime === 'docker') return 'docker compose pull dsh-passwords && docker compose up -d dsh-passwords';
    return `npm install -g dsh-passwords@${v}`;
  }

  /** 每 15s 刻度：24h 自动重检 + 空闲窗就绪后的自动安装 */
  tick(): void {
    if (this.disposed) return;
    try {
      // 安装已完成但尚未成功重启（等待手动重启或重启失败）时必须先完成重启：
      // 期间禁止再次下载/安装/审计，否则会重复应用同一版本并重复记账。
      if (this.restartPendingVersion !== null) return;
      const now = this.ops.now();
      const checked = this.lastCheckedAt ?? 0;
      if (
        this.autoUpdateEnabled() &&
        !this.downloadRunning &&
        (checked === 0 || now - checked >= UPDATE_CHECK_MS)
      ) {
        void this.checkNow({ downloadIfAllowed: true }).catch(() => undefined);
        return;
      }
      // npm/native 只在包已校验就绪后自动安装；Docker 不下载 npm 包，改为
      // 在发现新版本且 Compose 目录已配置时直接执行 Compose 更新。
      const packageReady = this.pendingVersion !== null && this.phase === 'ready' && !this.installConfirmationRequired;
      const dockerReady = this.dockerUpdateSupported()
        && this.latestVersion !== null
        && compareVersions(this.latestVersion, this.version) !== null
        && compareVersions(this.latestVersion, this.version)! > 0;
      if (
        this.autoUpdateEnabled() &&
        !this.installRunning &&
        (packageReady || dockerReady) &&
        this.activityAgeMs() >= UPDATE_IDLE_MS &&
        now - this.lastApplyAt >= UPDATE_APPLY_COOLDOWN_MS
      ) {
        void this.performInstall().catch((error) => this.setError(error instanceof Error ? error.message : String(error)));
      }
    } catch (error) {
      this.setError(error instanceof Error ? error.message : String(error));
    }
  }

  /** 检查 GitHub release。只有后台自动检查明确传入时才启动限速下载。 */
  async checkNow(options: { downloadIfAllowed?: boolean } = {}): Promise<void> {
    if (this.checkPromise !== null) return this.checkPromise;
    this.checkPromise = this.checkNowInternal(options.downloadIfAllowed === true);
    try {
      await this.checkPromise;
    } finally {
      this.checkPromise = null;
    }
  }

  private async checkNowInternal(downloadIfAllowed: boolean): Promise<void> {
    if (this.downloadRunning) return;
    this.checkRunning = true;
    try {
      this.lastCheckedAt = this.ops.now();
      this.db.setSetting('update_checked_at', new Date(this.ops.now()).toISOString());
      const data = await this.ops.fetchRelease(
        'https://api.github.com/repos/slywalker2006/dsh-passwords/releases/latest',
      );
      const release = parseReleaseInfo(data);
      if (release === null) {
        this.setError('无法解析 GitHub 最新发布（tag 非法或缺少 dsh-passwords-<version>.tgz 资产）');
        return;
      }
      this.latestVersion = release.version;
      this.db.setSetting('update_latest_version', release.version);
      const cmp = compareVersions(release.version, this.version);
      if (cmp === null || cmp <= 0) {
        // 无新版本：清错误；若已下载的正是当前版本（装机后首次启动）→ 复位待装标记
        this.lastError = null;
        this.db.setSetting('update_last_error', '');
        if (this.pendingVersion !== null && this.pendingVersion === this.version) {
          this.pendingVersion = null;
          this.downloadMode = null;
          this.installConfirmationRequired = false;
          this.pendingIntegrity = null;
          this.phase = 'idle';
          this.db.setSetting('update_downloaded_ready', '');
          this.db.setSetting('update_download_mode', '');
          this.db.setSetting('update_install_confirmation_required', '');
          this.db.setSetting('update_downloaded_integrity', '');
        }
        return;
      }
      // 已下载就绪的正好是目标版本 → 无需重复下载。
      if (this.pendingVersion === release.version && this.phase === 'ready') return;
      // Docker 只能交给 compose 更新，关闭自动下载以避免写入临时容器层。
      if (!downloadIfAllowed || this.runtime === 'docker' || !this.autoInstallSupported() || !this.autoUpdateEnabled()) return;
      const metadata = parseNpmPackageInfo(await this.ops.fetchNpmMetadata(release.version), release.version);
      if (metadata === null) {
        this.setError(`无法读取 npm 包元数据（dsh-passwords@${release.version}）`);
        return;
      }
      await this.startDownload(metadata, 'automatic');
    } catch (error) {
      this.setError(error instanceof Error ? error.message : String(error));
    } finally {
      this.checkRunning = false;
    }
  }

  private async startDownload(pkg: NpmPackageInfo, mode: 'automatic' | 'manual'): Promise<void> {
    if (this.downloadRunning) return; // 单实例下载
    // 已有安装完成、等待重启的版本：不得重复下载覆盖，避免重启前重复应用。
    if (this.restartPendingVersion !== null) return;
    const previousVersion = this.pendingVersion;
    const previousIntegrity = this.pendingIntegrity;
    const previousMode = this.downloadMode;
    const previousConfirmation = this.installConfirmationRequired;
    const previousPhase = this.phase;
    this.downloadRunning = true;
    this.phase = 'downloading';
    this.downloadMode = mode;
    this.downloadPercent = 0;
    this.downloadedBytes = 0;
    this.totalBytes = null;
    try {
      mkdirSync(this.stateDir, { recursive: true });
      const maxBps = mode === 'automatic' ? Math.min(readMaxBps(), UPDATE_DEFAULT_MAX_BPS) : Number.MAX_SAFE_INTEGER;
      const finalFile = this.artifactPath(pkg.version);
      const partFile = `${finalFile}.part`;
      const resumed = existsSync(partFile) ? statSync(partFile).size : 0;
      this.ops.log(`update: 下载 dsh-passwords@${pkg.version}${mode === 'automatic' ? `（限速 <=${Math.round(maxBps / 1024)}KiB/s）` : '（手动不限速）'}`);
      const sha512 = await this.ops.download(pkg.tarballUrl, partFile, maxBps, resumed, (received, total) => {
        this.downloadedBytes = received;
        this.totalBytes = total;
        this.downloadPercent = total === null || total <= 0 ? null : Math.min(99, (received / total) * 100);
      });
      const expected = pkg.integrity.startsWith('sha512-') ? pkg.integrity.slice('sha512-'.length) : pkg.integrity;
      const actual = Buffer.from(sha512, 'hex').toString('base64');
      if (expected.trim() !== actual) {
        this.setError('下载产物 sha512 与 npm registry 不符，已丢弃（发布账号可能被劫持，勿装）');
        this.dropPart(partFile);
        if (previousVersion !== null && previousIntegrity !== null && existsSync(this.artifactPath(previousVersion))) {
          this.pendingVersion = previousVersion;
          this.pendingIntegrity = previousIntegrity;
          this.downloadMode = previousMode;
          this.installConfirmationRequired = previousConfirmation;
          this.phase = previousPhase === 'ready' ? 'ready' : 'error';
        } else {
          this.phase = 'error';
        }
        return;
      }
      renameSync(partFile, finalFile);
      this.pendingVersion = pkg.version;
      this.phase = 'ready';
      this.downloadPercent = 100;
      this.downloadedBytes = this.totalBytes ?? this.downloadedBytes;
      const effectiveMode = mode === 'manual' || !this.autoUpdateEnabled() ? 'manual' : 'automatic';
      this.installConfirmationRequired = effectiveMode === 'manual';
      this.lastNotificationAt = effectiveMode === 'manual' ? new Date(this.ops.now()).toISOString() : null;
      this.lastError = null;
      this.pendingIntegrity = actual;
      this.db.setSetting('update_downloaded_ready', pkg.version);
      this.db.setSetting('update_download_mode', effectiveMode);
      this.db.setSetting('update_downloaded_integrity', actual);
      this.db.setSetting('update_install_confirmation_required', this.installConfirmationRequired ? '1' : '');
      this.db.setSetting('update_last_notification_at', this.lastNotificationAt ?? '');
      this.db.setSetting('update_last_error', '');
      this.ops.log(`update: dsh-passwords@${pkg.version} 下载完成并校验通过${effectiveMode === 'automatic' ? '，等待平台空闲 1 小时后安装' : '，等待主用户再次确认安装'}`);
    } catch (error) {
      this.setError(`下载失败：${error instanceof Error ? error.message : String(error)}`);
      // 新版本失败不能遮蔽此前已经校验完成的可安装包。
      if (previousVersion !== null && existsSync(this.artifactPath(previousVersion))) {
        this.pendingVersion = previousVersion;
        this.pendingIntegrity = previousIntegrity;
        this.downloadMode = previousMode;
        this.installConfirmationRequired = previousConfirmation;
        this.phase = previousPhase === 'ready' ? 'ready' : 'error';
      } else {
        this.phase = 'error';
      }
    } finally {
      this.downloadRunning = false;
    }
  }

  /** 执行安装（环境受限）+ 重启 dsh 网页服务；返回 {ok, requiresManualRestart} */
  private async performInstall(): Promise<{ ok: boolean; requiresManualRestart: boolean }> {
    if (this.installRunning || this.restartPendingVersion !== null) return { ok: false, requiresManualRestart: false };
    this.installRunning = true;
    try {
      return await this.performInstallInternal();
    } finally {
      this.installRunning = false;
    }
  }

  private async performInstallInternal(): Promise<{ ok: boolean; requiresManualRestart: boolean }> {
    // 双重保险：等待重启期间绝不重复安装或写入 update_applied 审计。
    if (this.restartPendingVersion !== null) return { ok: false, requiresManualRestart: false };
    const version = this.pendingVersion ?? this.latestVersion ?? this.version;
    if (this.runtime === 'docker') return this.performDockerInstall(version);
    if (this.pendingVersion === null || !existsSync(this.artifactPath(this.pendingVersion))) {
      this.setError('安装取消：待装产物缺失');
      return { ok: false, requiresManualRestart: false };
    }
    if (this.pendingIntegrity === null) {
      this.setError('安装取消：待装产物缺少完整性记录，请重新下载');
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const artifactHash = createHash('sha512').update(readFileSync(this.artifactPath(this.pendingVersion))).digest('base64');
    if (artifactHash !== this.pendingIntegrity) {
      this.setError('安装取消：待装产物已被修改，请重新下载');
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const target = await this.resolveNpmInstallTarget();
    if (target === null) {
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    if (!this.persistDatabasePath()) {
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }

    this.phase = 'installing';
    const fixedDeployment = target.deploymentRoot !== null
      ? await this.installIntoFixedDeployment(target, this.pendingVersion)
      : await this.installIntoNpmTarget(target, this.pendingVersion);
    if (!fixedDeployment) {
      this.phase = 'ready';
      return { ok: false, requiresManualRestart: false };
    }

    this.db.audit('update_applied', {
      username: 'system',
      ip: 'update',
      detail: `dsh-passwords ${this.version} → ${version}${target.deploymentRoot !== null ? '（固定部署目录）' : '（npm）'}`,
    });
    this.clearDownloadedArtifacts();
    this.pendingVersion = null;
    this.downloadMode = null;
    this.installConfirmationRequired = false;
    this.lastNotificationAt = null;
    this.phase = 'restarting';
    this.lastApplyAt = this.ops.now();
    this.latestVersion = version;
    this.lastError = null;
    this.pendingIntegrity = null;
    this.db.setSetting('update_downloaded_ready', '');
    this.db.setSetting('update_download_mode', '');
    this.db.setSetting('update_downloaded_integrity', '');
    this.db.setSetting('update_install_confirmation_required', '');
    this.db.setSetting('update_last_notification_at', '');
    this.db.setSetting('update_latest_version', version);
    this.db.setSetting('update_last_error', '');
    this.restartPendingVersion = version;
    this.db.setSetting('update_restart_pending_version', version);
    if (this.config.patch.restartService === '') {
      this.setError(this.manualRestartMessage());
      this.phase = 'error';
      return { ok: true, requiresManualRestart: true };
    }
    if (this.config.patch.restartService !== '') {
      const restart = await this.ops.restartWebService(this.config.patch.restartService);
      if (restart.manual) {
        this.setError(restart.message);
        this.phase = 'error';
        return { ok: true, requiresManualRestart: true };
      }
      if (!restart.ok) {
        this.setError(`新版本已安装但 dsh-web 重启失败：${restart.message}`);
        this.phase = 'error';
        return { ok: false, requiresManualRestart: false };
      }
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      return { ok: true, requiresManualRestart: false };
    }
    return { ok: true, requiresManualRestart: false };
  }

  private manualRestartMessage(): string {
    return process.platform === 'win32'
      ? '新版本已安装，请退出并重新启动 DeepSeek Harness'
      : '新版本已安装，请手动重启 dsh-web 服务';
  }

  private persistDatabasePath(): boolean {
    const envFile = this.env.DSH_PASSWORDS_ENV_FILE?.trim() || path.join(this.installRoot, '.env');
    if (!existsSync(envFile)) {
      // 测试/纯环境变量运行没有可持久化的配置文件；显式 MCP_DB_PATH 已经足够。
      return (this.env.MCP_DB_PATH?.trim() ?? '') !== '';
    }
    const configuredDbPath = this.env.MCP_DB_PATH?.trim() ?? '';
    if (configuredDbPath !== '' && path.isAbsolute(configuredDbPath)) return true;
    const dbPath = path.resolve(this.config.dbPath);
    if (dbPath.includes('\n') || dbPath.includes('\r')) {
      this.setError('数据库路径包含非法换行，已停止安装');
      return false;
    }
    try {
      const raw = readFileSync(envFile, 'utf8');
      const line = `MCP_DB_PATH=${dbPath}`;
      const updated = /^MCP_DB_PATH=/m.test(raw)
        ? raw.replace(/^MCP_DB_PATH=.*$/m, line)
        : `${raw.trimEnd()}\n${line}\n`;
      if (updated !== raw) {
        const temporary = `${envFile}.tmp-${randomBytes(8).toString('hex')}`;
        const mode = statSync(envFile).mode & 0o777;
        try {
          writeFileSync(temporary, updated);
          chmodSync(temporary, mode);
          renameSync(temporary, envFile);
        } finally {
          rmSync(temporary, { force: true });
        }
      }
      return true;
    } catch (error) {
      this.setError(`无法持久化数据库路径，已停止安装：${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  private async resolveNpmInstallTarget(): Promise<NpmInstallTarget | null> {
    let installEnv: NodeJS.ProcessEnv = { ...this.env };
    if (this.runtime === 'unknown' || this.runtime === 'docker') {
      this.setError('当前环境不支持 npm 自动安装（详见手动命令）');
      return null;
    }
    // 原生 systemd 安装通过 DSH_PASSWORDS_ENV_FILE 明确声明了稳定配置目录。
    // 该目录才是用户要求的“旧 dsh-passwords 目录”：更新时替换程序文件，保留
    // .env/data/TLS 等部署状态，而不是把另一个全局 npm 目录越积越多。
    const explicitEnvFile = installEnv.DSH_PASSWORDS_ENV_FILE?.trim() ?? '';
    if (explicitEnvFile !== '') {
      const deploymentRoot = path.dirname(path.resolve(explicitEnvFile));
      if (deploymentRoot === path.parse(deploymentRoot).root || !existsSync(deploymentRoot)) {
        this.setError('无法确定固定部署目录，已停止安装');
        return null;
      }
      return { env: installEnv, packageRoot: this.installRoot, deploymentRoot };
    }
    if (this.runtime === 'npm-prefix') {
      const prefix = resolveNpmPrefix(this.installRoot);
      if (prefix === null) {
        this.setError('无法确定 npm --prefix 安装前缀，已停止安装');
        return null;
      }
      installEnv = { ...installEnv, npm_config_prefix: prefix };
    }
    const npm = resolveNpmCommand(['root', '-g'], installEnv);
    if (npm === null) {
      this.setError('无法解析 npm 可执行入口（缺少 npm-cli.js），已停止安装');
      return null;
    }
    const root = await this.ops.runCommand(npm.command, npm.args, this.installRoot, installEnv);
    if (!root.ok || root.message.trim() === '') {
      this.setError(`无法确定 npm 全局安装目录：${root.message}`);
      return null;
    }
    return { env: installEnv, packageRoot: path.join(path.resolve(root.message.trim()), 'dsh-passwords'), deploymentRoot: null };
  }

  private async installIntoNpmTarget(target: NpmInstallTarget, version: string): Promise<boolean> {
    const result = await this.ops.runInstall(npmGlobalInstallArgs(this.artifactPath(version)), target.env);
    if (!result.ok) {
      this.setError(`安装失败：${result.message}`);
      return false;
    }
    const registration = await this.ops.runCommand(
      process.execPath,
      [path.join(target.packageRoot, 'scripts', 'register-plugin.mjs')],
      target.packageRoot,
      target.env,
    );
    if (!registration.ok || !this.profileUses(target.packageRoot, target.env, version)) {
      this.setError(`安装完成但 dsh profile 切换失败：${registration.message || '未指向新安装包'}`);
      return false;
    }
    return true;
  }

  /**
   * 在固定部署目录同级完成临时安装，然后用目录交换替换运行文件。
   * 交换期间只移动程序目录；.env、data、setup-key 和环境中引用的 TLS 文件
   * 从旧目录移回新目录，更新产物和旧程序备份在成功后立即删除。
   *
   * Windows 上不能 rename 部署目录本身：进程 cwd、以及进程内已打开的 SQLite
   * 句柄（部署目录内 data/platform.db）都会让 rename 抛 EBUSY/EPERM。因此 Windows
   * 改为就地替换——旧程序目录项移入 backup、新程序目录项移入部署目录，保留项原地
   * 不动，数据库文件全程不移动；其余平台保持原有整目录交换语义。
   */
  private async installIntoFixedDeployment(target: NpmInstallTarget, version: string): Promise<boolean> {
    const deploymentRoot = target.deploymentRoot;
    if (deploymentRoot === null) return false;
    const releaseLock = this.acquireFixedDeploymentLock(deploymentRoot);
    if (releaseLock === null) {
      this.setError(`无法获得固定部署目录更新锁：可能有另一个更新正在进行，或锁文件不可用。请检查 ${path.join(path.dirname(deploymentRoot), `.${path.basename(deploymentRoot)}.update.lock`)} 及其 .gate 文件`);
      return false;
    }
    const inPlace = this.inPlaceDeploymentSwap;
    const dbRelative = path.relative(deploymentRoot, path.resolve(this.config.dbPath));
    const dbWithinDeployment = dbRelative !== '' && dbRelative !== '..' && !dbRelative.startsWith(`..${path.sep}`) && !path.isAbsolute(dbRelative);
    if (dbWithinDeployment && (process.platform === 'win32' ? dbRelative.split(path.sep)[0].toLowerCase() : dbRelative.split(path.sep)[0]) !== 'data') {
      this.setError('数据库位于部署目录的非保留位置，拒绝更新以避免删除数据；请将 MCP_DB_PATH 移到 data 目录或部署目录外');
      releaseLock();
      return false;
    }

    const parent = path.dirname(deploymentRoot);
    const base = path.basename(deploymentRoot);
    const suffix = randomBytes(8).toString('hex');
    const stagingRoot = path.join(parent, `.${base}.update-${suffix}`);
    const candidateRoot = path.join(stagingRoot, 'app');
    const backupRoot = path.join(parent, `.${base}.backup-${suffix}`);
    const failedRoot = path.join(parent, `.${base}.failed-${suffix}`);
    const artifact = this.artifactPath(version);
    let oldMoved = false;
    let swappedInPlace = false;
    let preservedEntries: string[] = [];
    let movedOut: string[] = [];
    let movedIn: string[] = [];
    let originalCwd: string | null = null;

    try {
      const gitCheckout = existsSync(path.join(deploymentRoot, '.git'));
      if (gitCheckout) {
        const status = await this.ops.runCommand('git', ['status', '--porcelain', '--untracked-files=all'], deploymentRoot, target.env);
        if (!status.ok || status.message.trim() !== '') {
          this.setError('Git 工作区包含未提交文件或无法确认状态，拒绝自动更新以保护本地修改');
          return false;
        }
      }
      mkdirSync(stagingRoot, { recursive: true });
      const stagingEnv: NodeJS.ProcessEnv = {
        ...target.env,
        npm_config_cache: path.join(stagingRoot, 'npm-cache'),
      };
      // 明确建立临时项目清单，避免不同 npm 版本对 --prefix 无 package.json
      // 的行为不一致；该清单和 npm cache 都只存在于一次更新 staging 中。
      writeFileSync(
        path.join(stagingRoot, 'package.json'),
        JSON.stringify({ private: true, dependencies: { 'dsh-passwords': artifact } }) + '\n',
      );
      const installed = await this.ops.runInstall(
        ['install', '--prefix', stagingRoot, '--omit=dev', '--ignore-scripts', '--no-save', '--no-audit', '--no-fund', artifact],
        stagingEnv,
        stagingRoot,
      );
      if (!installed.ok) {
        this.setError(`新版本临时安装失败：${installed.message}`);
        return false;
      }
      const stagedPackageRoot = path.join(stagingRoot, 'node_modules', 'dsh-passwords');
      if (!existsSync(path.join(stagedPackageRoot, 'dist', 'cli.js')) || !existsSync(path.join(stagedPackageRoot, 'scripts', 'register-plugin.mjs'))) {
        this.setError('新版本临时安装不完整，已停止替换');
        return false;
      }
      const packageJson = JSON.parse(readFileSync(path.join(stagedPackageRoot, 'package.json'), 'utf8')) as { version?: unknown };
      if (packageJson.version !== version) {
        this.setError('新版本包版本校验失败，已停止替换');
        return false;
      }
      mkdirSync(candidateRoot, { recursive: true });
      cpSync(stagedPackageRoot, candidateRoot, { recursive: true });
      // npm --prefix 会把运行时依赖提升到 stagingRoot/node_modules；复制到新目录，
      // 但跳过其中重复的 dsh-passwords 包，避免更新后留下第二份程序副本。
      cpSync(path.join(stagingRoot, 'node_modules'), path.join(candidateRoot, 'node_modules'), {
        recursive: true,
        filter: (source) => path.resolve(source) !== path.resolve(stagedPackageRoot),
      });
      preservedEntries = this.preservedDeploymentEntries(deploymentRoot);
      if (gitCheckout) {
        preservedEntries.push('.git');
        const incoming = new Set(readdirSync(candidateRoot).map((name) => process.platform === 'win32' ? name.toLowerCase() : name));
        for (const name of readdirSync(deploymentRoot)) {
          if (!incoming.has(process.platform === 'win32' ? name.toLowerCase() : name)) preservedEntries.push(name);
        }
      }
      const keptTop = new Set(preservedEntries.map((entry) => {
        const top = entry.split(/[\\/]/)[0];
        return process.platform === 'win32' ? top.toLowerCase() : top;
      }));
      const conflict = readdirSync(candidateRoot).find((name) => keptTop.has(process.platform === 'win32' ? name.toLowerCase() : name));
      if (conflict !== undefined) throw new Error(`新版本程序条目与保留数据目录冲突：${conflict}`);

      // 离开部署目录子树后再做任何目录交换。Windows 需要它来规避 cwd 句柄，
      // POSIX 也需要它，避免删除备份目录时把当前进程留在已删除的 cwd 中。
      originalCwd = this.chdirOutOfDeployment(deploymentRoot, parent);
      if (inPlace) {
        const moved = this.swapDeploymentEntriesInPlace(deploymentRoot, candidateRoot, backupRoot, preservedEntries);
        movedOut = moved.movedOut;
        movedIn = moved.movedIn;
        swappedInPlace = true;
      } else {
        renameSync(deploymentRoot, backupRoot);
        oldMoved = true;
        renameSync(candidateRoot, deploymentRoot);
        this.movePreservedEntries(backupRoot, deploymentRoot, preservedEntries);
      }

      const registration = await this.ops.runCommand(
        process.execPath,
        [path.join(deploymentRoot, 'scripts', 'register-plugin.mjs')],
        deploymentRoot,
        target.env,
      );
      if (!registration.ok || !this.profileUses(deploymentRoot, target.env, version)) {
        this.setError(`新版本已放入部署目录但 dsh profile 切换失败：${registration.message || '未指向新目录'}`);
        if (inPlace) {
          if (swappedInPlace) {
            this.restoreDeploymentEntries(deploymentRoot, backupRoot, movedOut, movedIn);
            swappedInPlace = false;
            movedOut = [];
            movedIn = [];
            const restored = await this.ops.runCommand(
              process.execPath,
              [path.join(deploymentRoot, 'scripts', 'register-plugin.mjs')],
              deploymentRoot,
              target.env,
            );
            if (!restored.ok) this.setError(`${this.lastError ?? '更新回滚'}；恢复旧 profile 失败：${restored.message}`);
          }
        } else {
          await this.rollbackFixedDeployment(deploymentRoot, backupRoot, failedRoot, preservedEntries, target.env);
          oldMoved = false;
        }
        return false;
      }
      // profile 已指向新目录且新包完整：先提交替换，之后备份/旧运行时清理失败
      // 都不再回滚（否则会把已注册的新程序又换回去）。
      oldMoved = false;
      swappedInPlace = false;
      try {
        rmSync(backupRoot, { recursive: true, force: true });
      } catch (error) {
        this.ops.log(`update: 清理旧程序备份失败：${error instanceof Error ? error.message : String(error)}`);
      }
      this.removeReplacedNpmRuntime(deploymentRoot);
      this.ops.log(`update: dsh-passwords@${version} 已替换固定部署目录 ${deploymentRoot}，用户数据已保留`);
      return true;
    } catch (error) {
      this.setError(`固定部署目录替换失败：${error instanceof Error ? error.message : String(error)}`);
      if (inPlace) {
        if (swappedInPlace) this.restoreDeploymentEntries(deploymentRoot, backupRoot, movedOut, movedIn);
      } else if (oldMoved) {
        await this.rollbackFixedDeployment(deploymentRoot, backupRoot, failedRoot, preservedEntries, target.env);
      }
      return false;
    } finally {
      if (originalCwd !== null) {
        try {
          process.chdir(originalCwd);
        } catch {
          /* 原 cwd 已不可用时保持安全目录，不掩盖真正的失败原因 */
        }
      }
      // 临时目录清理失败不得把更新锁留在运行中的进程里。
      try {
        rmSync(stagingRoot, { recursive: true, force: true });
      } catch (error) {
        this.ops.log(`update: 清理临时目录失败 ${stagingRoot}：${error instanceof Error ? error.message : String(error)}`);
      } finally {
        releaseLock();
      }
    }
  }

  /**
   * 同一固定部署目录只允许一个更新。锁文件位于部署目录同级，进程被强杀后
   * 超过 TTL 的锁视为陈旧并可接管，避免永久阻塞后续更新。
   */
  private acquireFixedDeploymentLock(deploymentRoot: string): (() => void) | null {
    const lockPath = path.join(path.dirname(deploymentRoot), `.${path.basename(deploymentRoot)}.update.lock`);
    const gatePath = `${lockPath}.gate`;
    const mine = JSON.stringify({ pid: process.pid, startedAt: this.ops.now(), token: randomBytes(8).toString('hex') });
    const gateMine = JSON.stringify({ pid: process.pid, startedAt: this.ops.now(), token: randomBytes(8).toString('hex') });
    // 所有更新者先抢占同一短临界区；陈旧锁判定、移除、新锁创建不可交错。
    // 进程若在临界区内崩溃会残留 gate：PID 已不存活或超过 TTL 后允许安全接管，
    // 绝不永久阻塞后续更新（Windows 上尤其重要）。
    if (!this.acquireFixedDeploymentGate(gatePath, gateMine)) return null;
    try {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        try {
          const fd = openSync(lockPath, 'wx');
          try {
            writeFileSync(fd, mine);
          } finally {
            closeSync(fd);
          }
          return () => {
            try {
              if (readFileSync(lockPath, 'utf8') === mine) rmSync(lockPath, { force: true });
            } catch {
              /* 锁已被其他更新接管或删除 */
            }
          };
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
            this.ops.log(`update: 无法创建更新锁 ${lockPath}：${error instanceof Error ? error.message : String(error)}`);
            return null;
          }
          let stale = true;
          try {
            const info = JSON.parse(readFileSync(lockPath, 'utf8')) as { startedAt?: unknown };
            stale = typeof info.startedAt !== 'number' || this.ops.now() - info.startedAt > UPDATE_INSTALL_LOCK_TTL_MS;
          } catch {
            stale = true;
          }
          if (!stale || attempt > 0) return null;
          const stalePath = `${lockPath}.stale-${randomBytes(8).toString('hex')}`;
          try {
            renameSync(lockPath, stalePath);
            rmSync(stalePath, { force: true });
          } catch {
            return null;
          }
        }
      }
      return null;
    } finally {
      try {
        if (readFileSync(gatePath, 'utf8') === gateMine) rmSync(gatePath, { force: true });
      } catch {
        /* gate 已被其他更新接管或删除 */
      }
    }
  }

  /**
   * 创建交换锁临界区 gate；已存在时仅在可判定为崩溃残留时接管。
   * 写者进程已不存活可立即接管；PID 被复用或 gate 内容缺失（创建后未写入即崩溃）
   * 时超过 TTL 后接管，保证任何残留都不会永久阻塞更新。
   */
  private acquireFixedDeploymentGate(gatePath: string, gateMine: string): boolean {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const fd = openSync(gatePath, 'wx');
        try {
          writeFileSync(fd, gateMine);
        } finally {
          closeSync(fd);
        }
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
          this.ops.log(`update: 更新锁临界区不可用 ${gatePath}：${error instanceof Error ? error.message : String(error)}`);
          return false;
        }
        if (attempt > 0 || !this.staleDeploymentGate(gatePath)) {
          this.ops.log(`update: 更新锁临界区被占用 ${gatePath}（其他更新正在进行或残留 gate 未超过接管 TTL）`);
          return false;
        }
        // 陈旧残留：先原子改名再删除，避免与并发接管者交错。
        const stalePath = `${gatePath}.stale-${randomBytes(8).toString('hex')}`;
        try {
          renameSync(gatePath, stalePath);
          rmSync(stalePath, { force: true });
        } catch {
          return false; // 另一个更新者已抢先接管
        }
      }
    }
    return false;
  }

  /** gate 可安全接管（写者已死或超过 TTL）时返回 true；不确定一律 fail-closed。 */
  private staleDeploymentGate(gatePath: string): boolean {
    let raw: string;
    try {
      raw = readFileSync(gatePath, 'utf8');
    } catch {
      return false; // 读不到内容：无法判定，按仍在持有处理
    }
    let pid: number | null = null;
    let startedAt: number | null = null;
    try {
      const info = JSON.parse(raw) as { pid?: unknown; startedAt?: unknown };
      if (typeof info.pid === 'number' && Number.isInteger(info.pid) && info.pid > 0) pid = info.pid;
      if (typeof info.startedAt === 'number' && Number.isFinite(info.startedAt)) startedAt = info.startedAt;
    } catch {
      /* 创建后未写入内容即崩溃：只能靠文件时间兜底 */
    }
    if (pid !== null && !processAlive(pid)) return true;
    let age: number;
    if (startedAt !== null) {
      age = Math.max(0, this.ops.now() - startedAt);
    } else {
      try {
        age = Math.max(0, Date.now() - statSync(gatePath).mtimeMs);
      } catch {
        return false;
      }
    }
    return age > UPDATE_GATE_TTL_MS;
  }

  /** cwd 在部署目录内时切到同级父目录，返回原 cwd 供 finally 恢复；不在其中返回 null。 */
  private chdirOutOfDeployment(deploymentRoot: string, safeDir: string): string | null {
    let current: string;
    try {
      current = process.cwd();
    } catch {
      return null;
    }
    const relative = path.relative(deploymentRoot, current);
    const insideDeployment = relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
    if (!insideDeployment) return null;
    process.chdir(safeDir);
    return current;
  }

  /**
   * Windows 就地替换：跳过保留项（含其父目录），把其余旧目录项移入 backup，
   * 再把候选程序项移入部署目录。旧的 data/.env 从不移动，因此已打开的数据库
   * 句柄不影响替换；任一 rename 失败即还原已移动项。
   */
  private swapDeploymentEntriesInPlace(
    deploymentRoot: string,
    candidateRoot: string,
    backupRoot: string,
    preservedEntries: string[],
  ): { movedOut: string[]; movedIn: string[] } {
    const keep = new Set<string>();
    for (const entry of preservedEntries) {
      const top = entry.split(/[\\/]/)[0];
      if (top !== '' && top !== '.' && top !== '..') keep.add(process.platform === 'win32' ? top.toLowerCase() : top);
    }
    const candidateConflicts = readdirSync(candidateRoot).filter((name) => keep.has(process.platform === 'win32' ? name.toLowerCase() : name));
    if (candidateConflicts.length > 0) {
      throw new Error(`新版本程序条目与保留数据目录冲突：${candidateConflicts.join(', ')}`);
    }
    mkdirSync(backupRoot, { recursive: true });
    const movedOut: string[] = [];
    const movedIn: string[] = [];
    try {
      for (const name of readdirSync(deploymentRoot)) {
        if (keep.has(process.platform === 'win32' ? name.toLowerCase() : name)) continue;
        renameSync(path.join(deploymentRoot, name), path.join(backupRoot, name));
        movedOut.push(name);
      }
      for (const name of readdirSync(candidateRoot)) {
        if (keep.has(process.platform === 'win32' ? name.toLowerCase() : name)) continue;
        renameSync(path.join(candidateRoot, name), path.join(deploymentRoot, name));
        movedIn.push(name);
      }
    } catch (error) {
      this.restoreDeploymentEntries(deploymentRoot, backupRoot, movedOut, movedIn);
      throw error;
    }
    return { movedOut, movedIn };
  }

  /** 就地替换失败时移除已移入的新程序，并把 backup 中的旧程序移回原位。 */
  private restoreDeploymentEntries(deploymentRoot: string, backupRoot: string, movedOut: string[], movedIn: string[]): void {
    for (const name of movedIn) {
      try {
        rmSync(path.join(deploymentRoot, name), { recursive: true, force: true });
      } catch (error) {
        this.ops.log(`update: 回滚新程序项失败 ${name}：${error instanceof Error ? error.message : String(error)}`);
      }
    }
    for (const name of movedOut) {
      const source = path.join(backupRoot, name);
      if (!existsSync(source)) continue;
      try {
        renameSync(source, path.join(deploymentRoot, name));
      } catch (error) {
        this.ops.log(`update: 回滚旧程序项失败 ${name}：${error instanceof Error ? error.message : String(error)}`);
      }
    }
    try {
      // 全部旧程序项已还原才删除 backup；否则保留供人工恢复。
      if (readdirSync(backupRoot).length === 0) rmSync(backupRoot, { recursive: true, force: true });
    } catch {
      /* backup 已不存在的正常路径 */
    }
  }

  private preservedDeploymentEntries(deploymentRoot: string): string[] {
    const entries = [...PRESERVED_DEPLOYMENT_ENTRIES];
    const envEntry = deploymentEnvFileRelativeEntry(deploymentRoot, this.env.DSH_PASSWORDS_ENV_FILE ?? '');
    if (envEntry !== null) entries.push(envEntry);
    for (const key of ['MCP_GATEWAY_TLS_CERT', 'MCP_GATEWAY_TLS_KEY']) {
      const value = this.env[key]?.trim() ?? '';
      if (value === '') continue;
      const absolute = path.isAbsolute(value) ? value : path.resolve(deploymentRoot, value);
      const relative = path.relative(deploymentRoot, absolute);
      if (relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) entries.push(relative);
    }
    if (process.platform !== 'win32') return [...new Set(entries)];
    const existing = readdirSync(deploymentRoot);
    return [...new Set(entries.map((entry) => {
      const top = entry.split(/[\\/]/)[0];
      const actual = existing.find((name) => name.toLowerCase() === top.toLowerCase());
      return actual === undefined ? entry : actual + entry.slice(top.length);
    }))];
  }

  private movePreservedEntries(fromRoot: string, toRoot: string, entries: string[]): void {
    for (const entry of entries) {
      const source = path.join(fromRoot, entry);
      if (!existsSync(source)) continue;
      const destination = path.join(toRoot, entry);
      mkdirSync(path.dirname(destination), { recursive: true });
      rmSync(destination, { recursive: true, force: true });
      renameSync(source, destination);
    }
  }

  /**
   * 整目录交换失败后回滚到旧程序。回滚会把部署目录先改名为 failedRoot，再把其中
   * 的保留项（.env、data、TLS 等）移回旧程序备份，最后把备份改回部署目录。
   *
   * failedRoot 里可能仍含有尚未移回的保留项；只有确认所有保留项都已离开 failedRoot
   * （即已安全回到部署目录）才允许删除它。任何一步失败都保留 failedRoot 并记录可操作
   * 错误，绝不能因为回滚失败就把用户数据一起删掉。
   */
  private async rollbackFixedDeployment(
    deploymentRoot: string,
    backupRoot: string,
    failedRoot: string,
    entries: string[],
    env: NodeJS.ProcessEnv,
  ): Promise<void> {
    let failure: string | null = null;
    try {
      if (existsSync(deploymentRoot)) renameSync(deploymentRoot, failedRoot);
      if (existsSync(backupRoot)) {
        this.movePreservedEntries(failedRoot, backupRoot, entries);
        renameSync(backupRoot, deploymentRoot);
        await this.ops.runCommand(
          process.execPath,
          [path.join(deploymentRoot, 'scripts', 'register-plugin.mjs')],
          deploymentRoot,
          env,
        );
      }
    } catch (error) {
      failure = error instanceof Error ? error.message : String(error);
    }
    // 仍留在 failedRoot 中的保留项即仍可能被删除的用户数据；只有全部移出、且部署目录
    // 已恢复，删除 failedRoot 才是安全的。
    const stranded = existsSync(failedRoot)
      ? entries.filter((entry) => existsSync(path.join(failedRoot, entry)))
      : [];
    if (failure === null && stranded.length === 0) {
      try {
        rmSync(failedRoot, { recursive: true, force: true });
      } catch (error) {
        this.ops.log(`update: 清理回滚残留目录失败 ${failedRoot}：${error instanceof Error ? error.message : String(error)}`);
      }
      return;
    }
    const reason = failure ?? `保留项仍残留在备份目录中：${stranded.join('、')}`;
    const kept = [failedRoot, backupRoot].filter((candidate) => existsSync(candidate));
    const message = `固定部署目录回滚未完成：${reason}；已保留 ${kept.join('、')}，请人工核对 .env、data 等保留数据后再清理`;
    this.setError(message);
    this.ops.log(`update: ${message}`);
  }

  private removeReplacedNpmRuntime(deploymentRoot: string): void {
    // 当前网关可能正从旧 npm 包运行。Linux/Windows 均允许在进程退出前删除其
    // 已加载文件；马上由 systemd 重启到新固定目录。只清理 npm 运行时，绝不删除
    // 其他位置的源码 checkout。
    if ((this.runtime !== 'npm-global' && this.runtime !== 'npm-prefix') || path.resolve(this.installRoot) === path.resolve(deploymentRoot)) return;
    try {
      const pkg = JSON.parse(readFileSync(path.join(this.installRoot, 'package.json'), 'utf8')) as { name?: unknown };
      if (pkg.name === 'dsh-passwords') rmSync(this.installRoot, { recursive: true, force: true });
    } catch (error) {
      this.ops.log(`update: 清理旧 npm 运行目录失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private clearDownloadedArtifacts(): void {
    try {
      // stateDir 由数据库目录派生；只删除明确命名的 update 目录，避免误删用户数据。
      if (path.basename(this.stateDir) === 'update') rmSync(this.stateDir, { recursive: true, force: true });
    } catch (error) {
      this.ops.log(`update: 清理更新临时目录失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private profileUses(packageRoot: string, env: NodeJS.ProcessEnv, expectedVersion?: string): boolean {
    try {
      const dshHome = env.DSH_HOME?.trim() || path.join(homedir(), '.dsh');
      const profileDir = path.join(dshHome, 'profiles', 'web');
      const manifest = JSON.parse(readFileSync(path.join(profileDir, 'package.json'), 'utf8')) as { dependencies?: Record<string, unknown> };
      const linkPath = path.join(profileDir, 'node_modules', 'dsh-passwords');
      if (manifest.dependencies?.['dsh-passwords'] !== `link:${packageRoot}` || !existsSync(linkPath)) return false;
      if (realpathSync(linkPath) !== realpathSync(packageRoot)) return false;
      if (expectedVersion !== undefined) {
        const packageJson = JSON.parse(readFileSync(path.join(linkPath, 'package.json'), 'utf8')) as { version?: unknown };
        if (packageJson.version !== expectedVersion) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /** 手动操作：关闭自动更新时第一次只下载，第二次才安装；Docker 直接走 Compose。 */
  async applyNow(): Promise<{ ok: boolean; code?: string; message: string; requiresManualRestart?: boolean; phase?: UpdatePhase; pendingVersion?: string | null }> {
    if (this.downloadRunning) return { ok: false, code: 'DOWNLOAD_IN_PROGRESS', message: '更新包正在下载', phase: this.phase };
    if (this.installRunning) return { ok: false, code: 'INSTALL_IN_PROGRESS', message: '更新正在安装', phase: this.phase };
    // 重启失败后程序已经替换完成，必须允许主用户立即重试；安装冷却只约束
    // 新的安装请求，不能把已完成安装的恢复动作锁住。
    if (this.restartPendingVersion !== null) {
      if (this.runtime === 'docker') return { ok: false, code: 'INSTALL_IN_PROGRESS', message: 'Docker 更新正在恢复，请等待容器健康检查完成', phase: this.phase };
      if (this.config.patch.restartService === '') return { ok: true, requiresManualRestart: true, message: this.manualRestartMessage(), phase: 'error', pendingVersion: this.restartPendingVersion };
      this.phase = 'restarting';
      const restart = await this.ops.restartWebService(this.config.patch.restartService);
      if (restart.manual) {
        this.setError(restart.message);
        this.phase = 'error';
        return { ok: true, requiresManualRestart: true, message: restart.message, phase: this.phase, pendingVersion: this.restartPendingVersion };
      }
      if (!restart.ok) {
        this.setError(`新版本已安装但 dsh-web 重启失败：${restart.message}`);
        this.phase = 'error';
        return { ok: false, code: 'RESTART_FAILED', message: this.lastError ?? 'dsh-web 重启失败', phase: this.phase };
      }
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.lastError = null;
      this.db.setSetting('update_last_error', '');
      return { ok: true, message: '新版本已安装，dsh 网页服务即将重启（约 3-5 秒）', phase: 'restarting' };
    }
    const now = this.ops.now();
    if (now - this.lastApplyAt < UPDATE_APPLY_COOLDOWN_MS) {
      const remain = Math.ceil((UPDATE_APPLY_COOLDOWN_MS - (now - this.lastApplyAt)) / 60000);
      return { ok: false, code: 'RATE_LIMITED', message: `安装过于频繁，请 ${remain} 分钟后再试` };
    }
    if (this.pendingVersion !== null && this.phase === 'ready') {
      // npm 安装、profile 注册和服务重启可超过插件内部回环请求的 8 秒上限。
      // 先同步占用安装互斥，再异步执行；调用方通过 status 轮询真实结果。
      const pendingVersion = this.pendingVersion;
      this.phase = 'installing';
      this.installRunning = true;
      void this.performInstallInternal()
        .catch((error) => {
          this.setError(`安装失败：${error instanceof Error ? error.message : String(error)}`);
          this.phase = 'error';
        })
        .finally(() => { this.installRunning = false; });
      return { ok: true, code: 'INSTALL_STARTED', message: '更新安装已开始，完成后将自动重启 dsh 网页服务', phase: 'installing', pendingVersion };
    }
    if (this.latestVersion === null) await this.checkNow();
    const cmp = this.latestVersion === null ? null : compareVersions(this.latestVersion, this.version);
    if (cmp === null || cmp <= 0) return { ok: false, code: 'NO_UPDATE', message: '当前已经是最新版本' };
    if (this.runtime === 'docker') {
      if (!this.dockerUpdateSupported()) {
        return {
          ok: false,
          code: 'MANUAL_ONLY',
          message: this.dockerManualMessage(),
        };
      }
      // Compose up 可能重建当前容器并终止本进程，不能等待任务完成后才
      // 回复 HTTP；状态页通过 INSTALL_IN_PROGRESS/状态轮询展示进度。
      void this.performInstall().catch((error) => this.setError(error instanceof Error ? error.message : String(error)));
      return { ok: true, code: 'INSTALL_STARTED', message: 'Docker 更新已开始，容器将自动重启', phase: 'installing' };
    }
    if (this.autoUpdateEnabled()) return { ok: false, code: 'NOT_READY', message: '更新包尚未下载完成，请等待自动下载' };
    if (!this.autoInstallSupported()) return { ok: false, code: 'MANUAL_ONLY', message: '当前环境不支持下载后自动安装' };
    const latestVersion = this.latestVersion;
    if (latestVersion === null) return { ok: false, code: 'NO_UPDATE', message: '当前已经是最新版本' };
    const metadata = parseNpmPackageInfo(await this.ops.fetchNpmMetadata(latestVersion), latestVersion);
    if (metadata === null) return { ok: false, code: 'DOWNLOAD_FAILED', message: '无法读取 npm 包元数据' };
    void this.startDownload(metadata, 'manual');
    return { ok: true, code: 'DOWNLOAD_STARTED', message: '正在下载更新包，下载完成后请再次点击立即安装', phase: 'downloading', pendingVersion: null };
  }

  private async recoverDockerInstall(): Promise<void> {
    const version = this.restartPendingVersion;
    const dir = this.dockerComposeDir();
    if (version === null) return;
    if (dir === null || !this.dockerUpdateSupported()) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.setError('Docker 更新恢复失败：Compose 目录或 Docker 访问能力不可用，请修复配置后重试');
      this.phase = 'error';
      return;
    }
    const running = await this.ops.runCommand('docker', this.dockerUpdateArgs('ps', '--status', 'running', '--services', 'dsh-passwords'), dir);
    if (!running.ok || !running.message.split(/\r?\n/).some((service) => service.trim() === 'dsh-passwords')) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.setError(`Docker 更新恢复健康检查失败：dsh-passwords 服务没有运行${running.message ? `（${running.message}）` : ''}`);
      this.phase = 'error';
      return;
    }
    const actual = await this.readDockerRunningVersion(dir);
    if (actual !== version || !(await this.waitDockerReady(dir))) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.setError(`Docker 更新恢复校验失败：运行版本 ${actual ?? '未知'}，目标版本 ${version} 或 readyz 未通过`);
      this.phase = 'error';
      return;
    }
    // 若旧进程已完成健康检查但在清 pending 前退出，不重复写审计记录。
    if (this.db.getSetting('update_docker_applied_version') !== version) {
      this.db.audit('update_applied', { username: 'system', ip: 'update', detail: `dsh-passwords ${this.version} → ${version}（docker 恢复）` });
      this.db.setSetting('update_docker_applied_version', version);
    }
    this.version = version;
    this.latestVersion = version;
    this.db.setSetting('update_latest_version', version);
    this.restartPendingVersion = null;
    this.db.setSetting('update_restart_pending_version', '');
    this.lastApplyAt = this.ops.now();
    this.removeDockerOverride(dir);
    this.lastError = null;
    this.db.setSetting('update_last_error', '');
    this.phase = 'idle';
  }

  private async performDockerInstall(version: string): Promise<{ ok: boolean; requiresManualRestart: boolean }> {
    const dir = this.dockerComposeDir();
    if (dir === null) {
      this.setError('未配置 MCP_DSH_DOCKER_COMPOSE_DIR，请手动执行 docker compose pull && docker compose up -d');
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    this.phase = 'installing';
    this.lastError = null;
    this.db.setSetting('update_last_error', '');
    if (!this.dockerUpdateSupported() || !this.writeDockerOverride(version)) {
      this.setError(this.dockerManualMessage());
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const pull = await this.ops.runCommand('docker', this.dockerUpdateArgs('pull', 'dsh-passwords'), dir);
    if (!pull.ok) {
      this.removeDockerOverride(dir);
      this.setError(`Docker 镜像拉取失败：${pull.message}`);
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    // Compose up 可能重建当前 dsh-passwords 容器并终止本进程；新容器启动后
    // 构造器会用当前 package.json 版本清除这个持久化待恢复标记。
    this.restartPendingVersion = version;
    this.db.setSetting('update_restart_pending_version', version);
    this.db.setSetting('update_latest_version', version);
    this.phase = 'restarting';
    const up = await this.ops.runCommand('docker', this.dockerUpdateArgs('up', '-d', 'dsh-passwords'), dir);
    if (!up.ok) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.removeDockerOverride(dir);
      this.setError(`Docker 容器重启失败：${up.message}`);
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const running = await this.ops.runCommand('docker', this.dockerUpdateArgs('ps', '--status', 'running', '--services', 'dsh-passwords'), dir);
    if (!running.ok || !running.message.split(/\r?\n/).some((service) => service.trim() === 'dsh-passwords')) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.removeDockerOverride(dir);
      this.setError(`Docker 健康检查失败：dsh-passwords 服务没有运行${running.message ? `（${running.message}）` : ''}`);
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const actual = await this.readDockerRunningVersion(dir);
    if (actual !== version || !(await this.waitDockerReady(dir))) {
      this.restartPendingVersion = null;
      this.db.setSetting('update_restart_pending_version', '');
      this.removeDockerOverride(dir);
      this.setError(`Docker 更新版本或 readyz 校验失败：运行版本 ${actual ?? '未知'}，目标版本 ${version}`);
      this.phase = 'error';
      return { ok: false, requiresManualRestart: false };
    }
    const previousVersion = this.version;
    this.version = version;
    this.latestVersion = version;
    this.db.setSetting('update_latest_version', version);
    // 先写已应用版本，再写审计和清 pending；进程若在中间被 compose 重建，
    // 新实例可据此幂等恢复而不会重复记账。
    this.db.setSetting('update_docker_applied_version', version);
    this.db.audit('update_applied', { username: 'system', ip: 'update', detail: `dsh-passwords ${previousVersion} → ${version}（docker）` });
    this.restartPendingVersion = null;
    this.lastApplyAt = this.ops.now();
    this.removeDockerOverride(dir);
    this.phase = 'idle';
    return { ok: true, requiresManualRestart: false };
  }

  private removeDockerOverride(dir: string): void {
    try {
      rmSync(path.join(dir, this.dockerOverrideFile()), { force: true });
    } catch (error) {
      this.ops.log(`update: 清理 Docker 更新覆盖文件失败：${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async readDockerRunningVersion(dir: string): Promise<string | null> {
    const result = await this.ops.runCommand('docker', this.dockerUpdateArgs('exec', 'dsh-passwords', 'node', '-p', "require('/opt/dsh-passwords/package.json').version"), dir);
    const version = result.message.trim().split(/\r?\n/).at(-1)?.trim() ?? '';
    return result.ok && compareVersions(version, '0.0.0') !== null ? version : null;
  }

  private async waitDockerReady(dir: string): Promise<boolean> {
    const attempts = 10;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const ready = await this.ops.runCommand('docker', this.dockerUpdateArgs('exec', 'dsh-passwords', 'node', '-e', "fetch('http://127.0.0.1:3088/gateway/readyz').then(async r => { if (!r.ok) process.exit(1); const j = await r.json(); if (!j.ok || !j.database) process.exit(1); })"), dir);
      if (ready.ok) return true;
      if (attempt + 1 < attempts) await (this.ops.wait?.(Math.min(1000 * 2 ** attempt, 8000)) ?? Promise.resolve());
    }
    return false;
  }

  status(): UpdateStatus {
    const now = this.ops.now();
    const checked = this.lastCheckedAt ?? 0;
    const cmp = this.latestVersion !== null ? compareVersions(this.latestVersion, this.version) : null;
    // 已安装、等待重启的版本不再属于「可更新」：避免状态页继续提示有新版本可装，
    // 而实际只能重启。updateAvailable 必须与 restartPendingVersion 保持一致。
    const restartPending = this.restartPendingVersion !== null;
    return {
      env: this.runtime,
      currentVersion: this.version,
      latestVersion: this.latestVersion,
      updateAvailable: !restartPending && cmp !== null && cmp > 0,
      checking: this.checkRunning,
      phase: this.phase,
      downloadPercent: this.phase === 'downloading' || this.phase === 'ready' ? this.downloadPercent : null,
      downloadMode: this.downloadMode,
      downloadedBytes: this.downloadedBytes,
      totalBytes: this.totalBytes,
      pendingVersion: this.pendingVersion,
      installConfirmationRequired: this.installConfirmationRequired,
      lastNotificationAt: this.lastNotificationAt,
      idleRemainingMs:
        this.pendingVersion !== null && this.phase === 'ready'
          ? Math.max(0, UPDATE_IDLE_MS - this.activityAgeMs())
          : null,
      autoUpdateEnabled: this.autoUpdateEnabled(),
      autoInstallSupported: this.autoInstallSupported(),
      manualCommand: this.autoInstallSupported() ? '' : this.manualCommand(this.latestVersion),
      lastCheckedAt: checked > 0 ? new Date(checked).toISOString() : null,
      lastError: this.lastError,
      applyCooldownRemainingMs: Math.max(0, UPDATE_APPLY_COOLDOWN_MS - (now - this.lastApplyAt)),
      restartPendingVersion: this.restartPendingVersion,
    };
  }
}

/** 真实实现：受信任 HTTPS JSON 请求（固定调用方传入 URL，不跟随重定向）。 */
function fetchJson(url: string, userAgent: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'user-agent': userAgent, accept: 'application/json' }, timeout: 12000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`更新元数据 HTTP ${String(res.statusCode ?? 'error')}`));
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('更新元数据请求超时')));
    req.on('error', reject);
  });
}

function fetchReleaseJson(url: string): Promise<unknown> {
  return fetchJson(url, 'dsh-passwords-update-check');
}

/**
 * 限速流式下载 + Range 断点续传：
 * - 已下载部分（.part 存在）→ Range: bytes=<size>-，append 续写
 * - 服务端忽略 Range（返回 200 而非 206）时截断重写（从头完整下载）
 * - 每块按「块大小应有耗时 − 实际经过时间」节流：超出 maxBps 则 pause 源，
 *   setTimeout 后 resume——暂停的是源头而非积压缓冲，不阻塞事件循环
 * - 完成后整体重读文件累计 sha512：append 续传时旧字节不在本次接收流里，
 *   必须整文件重算，否则校验对象不一致
 */
function downloadThrottled(
  url: string,
  dest: string,
  maxBps: number,
  resumedBytes: number,
  onProgress?: (receivedBytes: number, totalBytes: number | null) => void,
  redirectCount = 0,
): Promise<string> {
  return new Promise((resolve, reject) => {
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      reject(new Error('下载地址无效'));
      return;
    }
    if (target.protocol !== 'https:' || !ALLOWED_DOWNLOAD_HOSTS.has(target.hostname)) {
      reject(new Error('下载地址不在受信任的 npm registry 域名白名单中'));
      return;
    }
    if (redirectCount > 3) {
      reject(new Error('下载重定向次数过多'));
      return;
    }
    const headers: Record<string, string> = {};
    let mode: 'append' | 'truncate' = resumedBytes > 0 ? 'append' : 'truncate';
    if (mode === 'append') headers.range = `bytes=${String(resumedBytes)}-`;
    const req = https.get(target, { headers, timeout: 15000 }, (res) => {
      if (res.statusCode !== undefined && res.statusCode >= 300 && res.statusCode < 400) {
        const location = res.headers.location;
        res.resume();
        if (typeof location !== 'string' || location === '') {
          reject(new Error('下载重定向缺少目标地址'));
          return;
        }
        downloadThrottled(new URL(location, target).toString(), dest, maxBps, resumedBytes, onProgress, redirectCount + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode === 404) {
        res.resume();
        reject(new Error('下载地址 404（资产可能已下架）'));
        return;
      }
      // 忽略 Range 请求（不支持续传）→ 必须从头下载，避免拼接错位
      if (mode === 'append' && res.statusCode !== 206) {
        mode = 'truncate';
        try {
          unlinkSync(dest);
        } catch {
          /* best effort */
        }
      }
      if (res.statusCode !== 200 && res.statusCode !== 206) {
        res.resume();
        reject(new Error(`下载 HTTP ${String(res.statusCode ?? 'error')}`));
        return;
      }
      const out = createWriteStream(dest, { flags: mode === 'append' ? 'a' : 'w' });
      const contentLength = Number(res.headers['content-length'] ?? 0);
      const totalBytes = Number.isFinite(contentLength) && contentLength > 0 ? contentLength + (mode === 'append' ? resumedBytes : 0) : null;
      let receivedBytes = mode === 'append' ? resumedBytes : 0;
      onProgress?.(receivedBytes, totalBytes);
      let completed = false;
      let lastChunkAt = 0;
      let paused = false;
      res.on('data', (chunk: Buffer) => {
        if (out.destroyed) return;
        out.write(chunk);
        receivedBytes += chunk.length;
        onProgress?.(receivedBytes, totalBytes);
        // 逐块节流：块大小应有的耗时与实际经过时间差，超出则暂停源等待
        const now = Date.now();
        const elapsed = lastChunkAt === 0 ? 0 : now - lastChunkAt;
        lastChunkAt = now;
        const wait = (chunk.length / maxBps) * 1000 - elapsed;
        if (wait > 0 && !paused) {
          paused = true;
          res.pause();
          setTimeout(() => {
            paused = false;
            res.resume();
          }, wait);
        }
      });
      res.on('end', () => {
        completed = true;
        out.end();
      });
      res.on('error', (error) => {
        out.destroy();
        reject(error);
      });
      out.on('error', (error) => {
        res.destroy();
        reject(error);
      });
      out.on('close', () => {
        if (!completed) return; // 中途失败由 error 路径 reject
        // 整文件重算 sha512（续传场景旧字节不经过本进程接收流）
        const hash = createHash('sha512');
        const stream = createReadStream(dest);
        stream.on('data', (c: string | Buffer) => hash.update(c));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
      });
    });
    req.on('timeout', () => req.destroy(new Error('下载超时')));
    req.on('error', reject);
  });
}