// 主用户管理 API 内聚功能簇：机械拆分自 src/gateway.ts（原 L3250-L4932），
// 逐字保留原有行为、路由注册顺序、错误体与授权检查，不做任何优化/重构。
//
// 路由注册顺序（与拆分前完全一致）：
//   1. POST /gateway/api/dsh-passwords/purge     （主用户紧急清理）
//   2. GET  /gateway/api/overview                （主用户概览）
//   3. GET  /gateway/api/download                （文件下载，GET/HEAD）
//   4. POST /gateway/api/fs/delete-directory     （主用户目录删除联动）
//   5. POST /gateway/api/permissions             （主用户改子用户权限）
//   6. POST /gateway/api/usage/report            （token 增量上报）
//
// 本模块不 import './gateway.js'（无运行时循环依赖），依赖面全部经 AdminRouteDeps 注入：
//   · 共享 helper（apiAuth / jsonBody / nullableInt / stringArray）注入，绝不带走；
//   · 运行期可被热更新替换的 let（endpointRules / compat / hostModelCatalog /
//     upstreamAuthCookie）经 getter 注入，保证概览与目录删除联动读到最新值；
//   · 跨模块共享的 Map 与回调按【同一引用】注入，绝不复制（workspacePathById /
//     userWorkspacePaths / userSessionAccess / sessionCwdById /
//     pendingCreatedDirectories / usageThrottle 等）；
//   · usageReportThrottle 由本模块创建，经 AdminRoutesHandle 交回网关，供其在原
//     sweep 位置 prune/cap（保持 10 分钟清理与容量裁剪的原有相对时序）。
// 纯函数（folderAllowed / normalizePath / todayLocal / SANDBOX_RANK、findDshRoot、
// isContainerRuntime、pathWithinDeletedTree、samePathForMatch 等）从各自模块直接引入。
import { createRequire } from 'node:module';
import {
  closeSync,
  constants as fsConstants,
  copyFileSync,
  createReadStream,
  existsSync,
  fstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { opendir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { URL } from 'node:url';
import type { Agent, ClientRequest, IncomingMessage, RequestOptions } from 'node:http';
import type { Application, Request, RequestHandler, Response } from 'express';
import type { PlatformConfig } from './config.js';
import { AuthError, type AuthedUser, type RequestMeta } from './auth.js';
import {
  PermissionStateConflictError,
  SessionGrantsConflictError,
  pathWithinDeletedTree,
  samePathForMatch,
  type Database,
  type UserPermissionsRow,
  type WorkspaceCleanupIntent,
} from './db.js';
import { folderAllowed, isFilesystemRootPath, isFullyQualifiedPath, normalizePath, todayLocal, SANDBOX_RANK } from './permissions.js';
import { findDshRoot } from './patch.js';
import { isContainerRuntime } from './update.js';
import { createSensitivePathChecker } from './sensitive-paths.js';

/** 规范化后的 `provider/model` 允许项；与 gateway 内部 AllowedModelSpec 结构一致。 */
export interface AllowedModelSpec {
  readonly provider: string;
  readonly model: string;
}

/** 上游 Remote mux 服务端帧（与 gateway 内 RemoteMuxServerFrame 结构一致）。 */
export type UpstreamMuxServerFrame =
  | { type: 'item'; streamId: string; value?: unknown }
  | { type: 'end'; streamId: string }
  | { type: 'error'; streamId: string; error: Record<string, unknown> };

/** 上游 HTTP/HTTPS 传输模块的最小面（http 与 https 模块均满足）。 */
export interface UpstreamTransport {
  request(options: RequestOptions, callback?: (res: IncomingMessage) => void): ClientRequest;
}

/** 上游 workspace/follow 轮询所用的 WebSocket 最小面。 */
interface UpstreamMuxSocket {
  on(event: 'open' | 'error' | 'close', listener: () => void): void;
  on(event: 'message', listener: (data: Buffer) => void): void;
  send(data: string): void;
  close(): void;
}

const require = createRequire(import.meta.url);
const WebSocket = require('ws') as {
  WebSocket: new (url: string, options?: {
    headers?: Record<string, string>;
    rejectUnauthorized?: boolean;
    agent?: Agent;
    maxPayload?: number;
  }) => UpstreamMuxSocket;
};

/** 上游 assignable-resources 探针结果（与 gateway 内 AssignableResources 结构一致）。 */
export interface AssignableResources {
  folders: Set<string>;
  assignableSessions: Set<string>;
  retainedSessions: Set<string>;
}

/**
 * 管理路由依赖面（由 createGatewayServer 提供）。
 *
 * 命名约定：
 *   · get* 前缀 = 读取 gateway 内可被热更新替换的 let（必须每次调用取当前值）；
 *   · 其余为稳定的同一引用（Map / 回调 / 常量），网关侧绝不复制。
 */
export interface AdminRouteDeps {
  db: Database;
  config: PlatformConfig;
  /** 部署根（gatewayRoot）：purge helper 来源与敏感路径基之一。 */
  gatewayRoot: string;
  /** 配置根（configuredRoot）：部署目录、.env 定位与敏感路径基之一。 */
  configuredRoot: string;

  /** 统一 API 鉴权：跨站拒绝 + 会话校验 + 可选主用户门控。 */
  apiAuth: (req: Request, res: Response, requireAdmin?: boolean) => AuthedUser | null;
  /** gateway 的 express.json({ limit: '256kb' }) 中间件。 */
  jsonBody: RequestHandler;
  /** 共享输入清洗 helper：字符串数组（截断到 max）。 */
  stringArray: (v: unknown, max?: number) => string[];
  /**
   * 共享输入清洗 helper：严格非负整数（兼容性 null 语义）。
   * 当前管理路由未直接使用（配额解析用更严格的 parseNullableIntStrict），
   * 保留注入以维持与其它模块一致的共享 helper 契约，绝不复制进本模块。
   */
  nullableInt: (v: unknown) => number | null;
  /** 子用户权限（缺行时默认关闭全部工作区）。 */
  effectivePermissions: (userId: number) => UserPermissionsRow;
  /**
   * 目标路径是否伸进「另一存活子用户创建的工作区子树」（含相等）。
   * 与 /api/file 的对象级授权同口径（gateway 内 workspaceSubtreeOverlap），
   * 供 /gateway/api/download 在白名单之外再做归属校验：只被分配了共享父目录的
   * 子用户不能借白名单读到物主在父目录下自建子树里的文件。
   */
  workspaceSubtreeOverlap: (userId: number, workspacePath: string) => boolean;
  /** 规范化 model allowlist（失效项剔除、去重、截断）。 */
  normalizeAllowedModels: (value: readonly string[]) => string[];
  /** 解析单条 `provider/model` allowlist 项。 */
  parseAllowedModelSpec: (value: unknown) => AllowedModelSpec | null;

  /** 校验主用户当前密码（不创建新会话，不改变 credential_version）。 */
  verifyAdminPassword: (caller: AuthedUser, password: string, meta?: RequestMeta) => Promise<void>;
  /** systemd 独立清理器启动参数（gateway 顶层导出的纯函数）。 */
  systemdPurgeLaunchArgs: (
    unitName: string,
    executable: string,
    helperPath: string,
    planPath: string,
    temporaryDirectory?: string,
  ) => string[];

  /** 端点登记表（热更新 let）：概览按当前快照回显。 */
  getEndpointRules: () => readonly string[];
  /** 最近一次官方 modelCatalog 原样快照（热更新 let）；未观测到时为 null。 */
  getHostModelCatalog: () => Record<string, unknown> | null;
  /** 受保护通道登记的 dsh-auth Cookie（热更新 let；目录删除联动唯一凭据来源）。 */
  getUpstreamAuthCookie: () => string;

  /** 上游地址与传输（loopback 反向代理目标）。 */
  upstreamHost: string;
  upstreamPort: number;
  upstreamAuthority: string;
  upstreamScheme: string;
  upstreamTransport: UpstreamTransport;
  upstreamAgent: Agent;
  /** Remote mux 单帧上限（gateway 常量）。 */
  remoteMuxMaxPayloadBytes: number;
  /** 解析上游 Remote mux 服务端帧。 */
  parseRemoteMuxServerFrame: (data: Buffer) => UpstreamMuxServerFrame | null;
  /** 纯 JSON 记录判定（原型为 Object.prototype 或 null）。 */
  isPlainJsonRecord: (value: unknown) => value is Record<string, unknown>;
  /** 拉取可分配资源（folders/sessions 权威集合）；失败返回 null（fail-closed）。 */
  fetchAssignableResources: () => Promise<AssignableResources | null>;
  /** 向指定会话注入沙盒模式；返回被拒绝（失败）的会话 ID。 */
  applySandboxToSessions: (sessionIds: readonly string[], mode: string) => Promise<string[]>;

  /**
   * 共享可变状态（同一引用，绝不复制）：
   *   usageThrottle             —— 用量节流（权限改配额时清理）
   *   workspacePathById         —— workspaceId → 规范路径
   *   userWorkspacePaths        —— 子用户 workspaceId → 规范路径
   *   userSessionAccess         —— 子用户 sessionId → cwd 授权快照
   *   sessionCwdById            —— sessionId → cwd
   *   pendingCreatedDirectories —— 子用户待登记目录（30 分钟信任窗口）
   */
  usageThrottle: Map<number, number>;
  workspacePathById: Map<string, string>;
  userWorkspacePaths: Map<number, Map<string, string>>;
  userSessionAccess: Map<number, Map<string, string>>;
  sessionCwdById: Map<string, string>;
  pendingCreatedDirectories: Map<number, Map<string, { expiresAt: number }>>;

  /** 用一份可信可见性快照替换子用户 workspace 路径（含 epoch/order 栅栏）。 */
  replaceUserWorkspacePaths: (userId: number, paths: Map<string, string>, epoch: number, order?: number) => void;
  /** 该用户当前授权 epoch（授权/权限变更时单调递增）。 */
  userAccessEpochFor: (userId: number) => number;
  /** 权限行已提交但仍有 await 时立即推进 epoch（让在途响应失去回写资格）。 */
  fenceUserAccessEpoch: (userId: number) => void;
  /** 授权变更后失效内存会话快照。 */
  invalidateUserSessionAccess: (userId: number) => void;
  /** 关闭该用户的 Remote mux 连接（令其重建 workspace baseline）。 */
  closeUserRemoteMuxClients: (userId: number, code?: number, reason?: string) => void;
  /** 关闭该用户的 legacy/登记 WebSocket 连接。 */
  closeUserWebSocketClients: (userId: number, code?: number, reason?: string) => void;
}

/** 注册结果：交回网关原 sweep 位置继续持有/清理的状态。 */
export interface AdminRoutesHandle {
  /**
   * token 用量上报节流表（客户端 15 秒 flush + 服务端 5 秒最小间隔）。
   * 网关在原 setInterval sweep 的两处位置（按 TTL 清理、容量 cap）直接操作该 Map，
   * 保持拆分的零行为变化；权限改配额时本模块也会在此表上 delete。
   */
  usageReportThrottle: Map<number, number>;
}

// ── 管理员目录选择器：browse roots 纯函数 ────────────────────────────
// 与文件系统无关的判定抽成模块级纯函数便于直接测试；真实存在性/敏感基/符号链接越界
// 由路由在使用前按当前文件系统状态校验（fail-closed）。

/** 归一化比较键：normalizePath + win32 折叠大小写（与敏感路径判定同口径）。 */
export function directoryPickerPathKey(value: string): string {
  const normalized = normalizePath(value);
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

/** candidate 是否位于 base 子树内（含相等），按路径段边界比较；base='/' 或 'X:/' 均可。 */
export function directoryPickerPathWithin(base: string, candidate: string): boolean {
  const baseSegments = directoryPickerPathKey(base).split('/').filter((segment) => segment !== '');
  const candidateSegments = directoryPickerPathKey(candidate).split('/').filter((segment) => segment !== '');
  if (baseSegments.length > candidateSegments.length) return false;
  return baseSegments.every((segment, index) => segment === candidateSegments[index]);
}

/**
 * 若 ancestor 是 descendant 的严格祖先（按段边界与大小写口径一致），返回从 ancestor
 * 通往 descendant 的直接子路径（归一化形态，保留 descendant 的实际段大小写）；否则 null。
 * 用于「祖先路径只返回通往安全 root 的条目」：不枚举祖先目录的其它兄弟。
 */
export function directoryPickerChildToward(ancestor: string, descendant: string): string | null {
  const ancestorNorm = normalizePath(ancestor);
  const descendantNorm = normalizePath(descendant);
  if (directoryPickerPathKey(ancestorNorm) === directoryPickerPathKey(descendantNorm)) return null;
  if (!directoryPickerPathWithin(ancestorNorm, descendantNorm)) return null;
  const depth = directoryPickerPathKey(ancestorNorm).split('/').filter((segment) => segment !== '').length;
  const descendantSegments = descendantNorm.split('/').filter((segment) => segment !== '');
  const segment = descendantSegments[depth];
  if (segment === undefined || segment === '') return null;
  return normalizePath(ancestorNorm.endsWith('/') ? `${ancestorNorm}${segment}` : `${ancestorNorm}/${segment}`);
}

/** 已校验的 browse root：词法路径与 canonical（realpath）路径（均为归一化形态）。 */
export interface DirectoryPickerRootRef {
  lexical: string;
  real: string;
}

/** 请求路径相对 browse roots 的位置。 */
export interface DirectoryPickerScope {
  kind: 'root' | 'inside' | 'ancestor' | 'outside';
  /** kind 为 root/inside 时命中的 browse root 下标；否则 -1。 */
  rootIndex: number;
  /** kind 为 ancestor 时通往各安全 root 的直接子路径（归一化、已排序）；否则空数组。 */
  ancestorEntries: string[];
}

/**
 * 分类请求路径相对 browse roots 的位置。选择最具体的 root：先看是否等于某个 root
 * （parentPath 将为 null），再看是否位于某个 root 子树内（词法与 canonical 必须同时命中
 * 同一 root，否则视为符号链接逃逸）；都不命中且是某 root 的祖先时归为 ancestor（只回
 * 通往 root 的直接子条目）；否则 outside（拒绝，不把用户 path 当作新的 browse root）。
 */
export function classifyDirectoryPickerTarget(
  target: DirectoryPickerRootRef,
  roots: readonly DirectoryPickerRootRef[],
): DirectoryPickerScope {
  let bestIndex = -1;
  let bestDepth = -1;
  let exact = false;
  for (let index = 0; index < roots.length; index += 1) {
    const root = roots[index];
    if (!directoryPickerPathWithin(root.lexical, target.lexical)) continue;
    if (!directoryPickerPathWithin(root.real, target.real)) continue;
    const depth = directoryPickerPathKey(root.lexical).split('/').filter((segment) => segment !== '').length;
    if (directoryPickerPathKey(root.lexical) === directoryPickerPathKey(target.lexical)) {
      exact = true;
      bestIndex = index;
      break;
    }
    if (depth > bestDepth) {
      bestDepth = depth;
      bestIndex = index;
    }
  }
  if (bestIndex >= 0) {
    return { kind: exact ? 'root' : 'inside', rootIndex: bestIndex, ancestorEntries: [] };
  }
  const ancestorEntries: string[] = [];
  for (const root of roots) {
    const child = directoryPickerChildToward(target.lexical, root.lexical);
    if (child !== null && !ancestorEntries.includes(child)) ancestorEntries.push(child);
  }
  if (ancestorEntries.length > 0) {
    ancestorEntries.sort();
    return { kind: 'ancestor', rootIndex: -1, ancestorEntries };
  }
  return { kind: 'outside', rootIndex: -1, ancestorEntries: [] };
}

/** 选择器条目标签：取归一化路径最后一段；根路径（无段）回退整串。 */
export function directoryPickerEntryName(candidate: string): string {
  const trimmed = normalizePath(candidate).replace(/\/+$/, '');
  const segments = trimmed.split('/').filter((segment) => segment !== '');
  return segments.length > 0 ? segments[segments.length - 1] : trimmed;
}

/**
 * 校验并归一化 browse roots：丢弃非平台合规绝对路径、全盘根、不存在/非目录、词法或
 * canonical 命中敏感基的候选；按归一化词法路径去重。绝不因某个候选非法而放宽到全盘根。
 */
export function resolveDirectoryPickerBrowseRoots(
  configured: readonly string[],
  isSensitive: (candidate: string) => boolean,
): DirectoryPickerRootRef[] {
  const roots: DirectoryPickerRootRef[] = [];
  const seen = new Set<string>();
  for (const candidate of configured) {
    if (candidate.includes('\u0000') || !isFullyQualifiedPath(candidate)) continue;
    const lexical = path.resolve(candidate);
    if (isFilesystemRootPath(lexical)) continue;
    let real: string;
    try {
      if (!statSync(lexical).isDirectory()) continue;
      real = realpathSync(lexical);
    } catch {
      continue;
    }
    if (isFilesystemRootPath(real)) continue;
    if (isSensitive(lexical) || isSensitive(real)) continue;
    const key = directoryPickerPathKey(lexical);
    if (seen.has(key)) continue;
    seen.add(key);
    roots.push({ lexical: normalizePath(lexical), real: normalizePath(real) });
  }
  return roots;
}

/**
 * 注册全部主用户管理路由，返回共享状态句柄。
 * 注册顺序：purge → overview → download → fs/delete-directory → permissions → usage/report。
 */
export function registerAdminRoutes(app: Application, deps: AdminRouteDeps): AdminRoutesHandle {
  const {
    db,
    config,
    gatewayRoot,
    configuredRoot,
    apiAuth,
    jsonBody,
    stringArray,
    effectivePermissions,
    workspaceSubtreeOverlap,
    normalizeAllowedModels,
    parseAllowedModelSpec,
    verifyAdminPassword,
    systemdPurgeLaunchArgs,
    getEndpointRules,
    getHostModelCatalog,
    getUpstreamAuthCookie,
    upstreamHost,
    upstreamPort,
    upstreamAuthority,
    upstreamScheme,
    upstreamTransport,
    upstreamAgent,
    remoteMuxMaxPayloadBytes,
    parseRemoteMuxServerFrame,
    isPlainJsonRecord,
    fetchAssignableResources,
    applySandboxToSessions,
    usageThrottle,
    workspacePathById,
    userWorkspacePaths,
    userSessionAccess,
    sessionCwdById,
    pendingCreatedDirectories,
    replaceUserWorkspacePaths,
    userAccessEpochFor,
    fenceUserAccessEpoch,
    invalidateUserSessionAccess,
    closeUserRemoteMuxClients,
    closeUserWebSocketClients,
  } = deps;

  // ── 内部辅助：API 路由的输入清洗 ───────────────────────────
  // 严格非负整数：拒绝 1e3/0x10/小数/负数/超大值（之前 Number() 静默接受科学
  // 计数与十六进制，1e21 等超大值在 SQLite 64 位整数绑定里精度失真）。
  // Number.isSafeInteger 封顶 2^53-1，天然低于 int64 上限。
  type NullableIntResult = { ok: true; value: number | null } | { ok: false };
  const parseNullableIntStrict = (v: unknown): NullableIntResult => {
    if (v === undefined || v === null) return { ok: true, value: null };
    if (typeof v === 'number') {
      return Number.isSafeInteger(v) && v >= 0 ? { ok: true, value: v } : { ok: false };
    }
    if (typeof v === 'string') {
      const trimmed = v.trim();
      if (trimmed === '') return { ok: true, value: null };
      if (!/^\d+$/.test(trimmed)) return { ok: false };
      const value = Number(trimmed);
      return Number.isSafeInteger(value) && value >= 0 ? { ok: true, value } : { ok: false };
    }
    return { ok: false };
  };

  // ── 主用户紧急清理（十次头像点击后显示；密码验证后异步执行） ──
  // 清理器从临时目录启动，先停止宿主与网关，再删除 DSH/dsh-passwords 的全部
  // 配置、profile、数据和程序路径。网关不会在请求线程里删除自身文件。
  const purgeRate = new Map<number, number[]>();
  let purgeInProgress = false;
  const monitorPurgeReceipt = (receiptPath: string, transactionId: string): void => {
    const deadline = Date.now() + 10 * 60_000;
    const timer = setInterval(() => {
      try {
        const parsed: unknown = JSON.parse(readFileSync(receiptPath, 'utf8'));
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return;
        const receipt = parsed as Record<string, unknown>;
        if (receipt.transactionId !== transactionId || receipt.finished !== true) return;
        clearInterval(timer);
        purgeInProgress = false;
        if (receipt.ok !== true) {
          const errors = Array.isArray(receipt.errors) ? receipt.errors.filter((entry): entry is string => typeof entry === 'string') : [];
          console.error(`[dsh-passwords] 紧急清理未完成（transaction=${transactionId}）: ${errors.join('; ') || 'unknown error'}`);
        }
      } catch {
        // helper 尚未写回执或正在原子替换；继续等待。超时也保持锁定，避免重复删除竞态。
      }
      if (Date.now() >= deadline) {
        clearInterval(timer);
        console.error(`[dsh-passwords] 紧急清理回执等待超时（transaction=${transactionId}）；保持并发锁，请检查 ${receiptPath}`);
      }
    }, 250);
    timer.unref();
  };
  const purgeServiceName = config.patch.restartService.trim();
  const purgeServiceNameValid = purgeServiceName === '' || /^[A-Za-z0-9_.@-]+$/.test(purgeServiceName);
  app.post('/gateway/api/dsh-passwords/purge', jsonBody, async (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    if (purgeInProgress) {
      res.status(409).json({ ok: false, code: 'PURGE_IN_PROGRESS', error: '清理已在进行中' });
      return;
    }
    const now = Date.now();
    const recent = (purgeRate.get(me.userId) ?? []).filter((timestamp) => now - timestamp < 10 * 60_000);
    if (recent.length >= 3) {
      purgeRate.set(me.userId, recent);
      res.status(429).json({ ok: false, code: 'PURGE_RATE_LIMITED', error: '尝试过于频繁，请稍后再试' });
      return;
    }
    purgeInProgress = true;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const password = typeof body.password === 'string' ? body.password : '';
    if (password === '') {
      purgeInProgress = false;
      res.status(400).json({ ok: false, code: 'INVALID', error: '请输入主用户密码' });
      return;
    }
    if (body.confirm !== true) {
      purgeInProgress = false;
      res.status(400).json({ ok: false, code: 'INVALID', error: '请确认删除全部本地数据' });
      return;
    }
    try {
      await verifyAdminPassword(me, password, { ip: req.ip, userAgent: req.headers['user-agent'] ?? null });
    } catch (error) {
      const status = error instanceof AuthError ? error.status : 401;
      purgeInProgress = false;
      res.status(status).json({ ok: false, code: error instanceof AuthError ? error.code : 'INVALID_CURRENT_PASSWORD', error: '主用户密码错误' });
      return;
    }
    const parentPidRaw = process.env.DSH_GATEWAY_PARENT_PID ?? '';
    const parentPid = Number(parentPidRaw);
    const dshRoot = findDshRoot(config.patch.dshRoot);
    const helperSource = path.join(gatewayRoot, 'scripts', 'purge.mjs');
    let upstreamPortValue: number | null = null;
    try {
      const upstreamUrl = new URL(config.gateway.upstream);
      const candidate = Number(upstreamUrl.port || (upstreamUrl.protocol === 'https:' ? 443 : 80));
      upstreamPortValue = Number.isInteger(candidate) && candidate > 0 && candidate <= 65535 ? candidate : null;
    } catch {
      upstreamPortValue = null;
    }
    const canStopHost = process.platform === 'win32'
      ? (Number.isInteger(parentPid) && parentPid > 0) || upstreamPortValue !== null
      : purgeServiceNameValid && purgeServiceName !== '';
    const isDockerRuntime = isContainerRuntime();
    if (isDockerRuntime || !canStopHost || dshRoot === null || !existsSync(helperSource)) {
      purgeInProgress = false;
      res.status(422).json({ ok: false, code: 'PURGE_UNAVAILABLE', error: '当前部署没有可靠的 DSH 停止策略，未执行删除' });
      return;
    }
    recent.push(now);
    purgeRate.set(me.userId, recent);
    const transactionId = `${process.pid}-${Date.now()}-${randomUUID()}`;
    const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dsh-passwords-purge-'));
    const planPath = path.join(tempDir, 'plan.json');
    const startSignalPath = path.join(tempDir, 'start.signal');
    const helperPath = path.join(tempDir, 'purge.mjs');
    const receiptPath = path.join(os.tmpdir(), `dsh-passwords-purge-${transactionId}.receipt.json`);
    const dshHome = path.resolve(process.env.DSH_HOME?.trim() || path.join(os.homedir(), '.dsh'));
    const configuredEnvFile = process.env.DSH_PASSWORDS_ENV_FILE?.trim()
      ? path.resolve(process.env.DSH_PASSWORDS_ENV_FILE.trim())
      : path.join(configuredRoot, '.env');
    const plan = {
      transactionId,
      gatewayPid: process.pid,
      parentPid: Number.isInteger(parentPid) && parentPid > 0 ? parentPid : null,
      upstreamPort: upstreamPortValue,
      serviceName: purgeServiceNameValid ? purgeServiceName : '',
      creatorUid: typeof process.getuid === 'function' ? process.getuid() : null,
      creatorGid: typeof process.getgid === 'function' ? process.getgid() : null,
      packageRoot: gatewayRoot,
      configuredRoot,
      dshHome,
      dshRoot,
      envFile: configuredEnvFile,
      dbPath: config.dbPath,
      receiptPath,
      startSignalPath,
      deleteConfiguredRoot: path.resolve(configuredRoot) === path.resolve(gatewayRoot),
      dryRun: process.env.NODE_ENV !== 'production' && process.env.DSH_PASSWORDS_PURGE_DRY_RUN === '1',
    };
    let helperLaunched = false;
    let launchOutcomeUnknown = false;
    try {
      copyFileSync(helperSource, helperPath);
      writeFileSync(planPath, `${JSON.stringify(plan)}\n`, { mode: 0o600 });
      if (process.platform !== 'win32' && purgeServiceName !== '') {
        const unit = spawnSync('systemctl', ['cat', purgeServiceName], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        const unitText = String(unit.stdout ?? '').toLowerCase();
        const runner = spawnSync('systemd-run', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        const runnerText = `${String(runner.stdout ?? '')}\n${String(runner.stderr ?? '')}`;
        const runnerVersion = /systemd\s+(\d+)/i.exec(runnerText);
        const fragment = spawnSync('systemctl', ['show', purgeServiceName, '--property=FragmentPath', '--value'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        const fragmentPath = String(fragment.stdout ?? '').trim();
        const privateTmp = spawnSync('systemctl', ['show', purgeServiceName, '--property=PrivateTmp', '--value'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
        const privateTmpEnabled = String(privateTmp.stdout ?? '').trim().toLowerCase() === 'yes';
        const expectedUnitFile = purgeServiceName.endsWith('.service') ? purgeServiceName : `${purgeServiceName}.service`;
        const supportedUnitDirectories = ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'];
        if (unit.error !== undefined || unit.status !== 0 || !unitText.includes('dsh') ||
          fragment.error !== undefined || fragment.status !== 0 || !path.isAbsolute(fragmentPath) || path.basename(fragmentPath) !== expectedUnitFile ||
          !supportedUnitDirectories.includes(path.dirname(fragmentPath)) || privateTmp.error !== undefined || privateTmp.status !== 0 || privateTmpEnabled ||
          runner.error !== undefined || runner.status !== 0 || runnerVersion === null || Number(runnerVersion[1]) < 240) {
          purgeInProgress = false;
          try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* best effort */ }
          res.status(422).json({ ok: false, code: 'PURGE_UNAVAILABLE', error: '当前部署无法启动独立清理器，未执行删除' });
          return;
        }
      }
      const unitName = `dsh-passwords-purge-${transactionId.replace(/[^A-Za-z0-9_-]/g, '-')}`;
      const usesSystemdRunner = process.platform !== 'win32' && purgeServiceName !== '';
      const launch = usesSystemdRunner
        ? { command: 'systemd-run', args: systemdPurgeLaunchArgs(unitName, process.execPath, helperPath, planPath, os.tmpdir()) }
        : { command: process.execPath, args: [helperPath, planPath] };
      const child = spawn(launch.command, launch.args, {
        cwd: tempDir,
        detached: true,
        windowsHide: true,
        stdio: 'ignore',
      });
      const launchConfirmed = new Promise<void>((resolve, reject) => {
        let settled = false;
        let spawned = false;
        const timer = setTimeout(() => {
          if (usesSystemdRunner && spawned) launchOutcomeUnknown = true;
          child.kill();
          rejectLaunch(new Error('清理执行器启动确认超时'));
        }, 30_000);
        timer.unref();
        const confirmLaunch = () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve();
        };
        const rejectLaunch = (error: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (!helperLaunched && !launchOutcomeUnknown) purgeInProgress = false;
          reject(error);
        };
        child.once('spawn', () => {
          spawned = true;
          if (!usesSystemdRunner) {
            helperLaunched = true;
            confirmLaunch();
          }
        });
        child.once('error', (error) => {
          if (!helperLaunched) rejectLaunch(error);
          else console.error('[dsh-passwords] 紧急清理执行器运行失败:', String(error));
        });
        child.once('exit', (code, signal) => {
          if (!spawned) {
            rejectLaunch(new Error(`清理执行器在启动前退出（code=${String(code)}, signal=${String(signal)}）`));
          } else if (usesSystemdRunner) {
            if (code === 0) confirmLaunch();
            else rejectLaunch(new Error(`systemd-run 未能启动清理器（code=${String(code)}, signal=${String(signal)}）`));
          } else if (code !== null) {
            console.error(`[dsh-passwords] 紧急清理执行器退出，code=${String(code)}`);
          }
        });
      });
      child.unref();
      await launchConfirmed;
      launchOutcomeUnknown = true;
      const readyDeadline = Date.now() + 10_000;
      let helperReady = false;
      while (Date.now() < readyDeadline) {
        try {
          const parsed: unknown = JSON.parse(readFileSync(receiptPath, 'utf8'));
          if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
            const readyReceipt = parsed as Record<string, unknown>;
            if (readyReceipt.transactionId === transactionId && readyReceipt.ready === true) {
              helperReady = true;
              break;
            }
            if (readyReceipt.transactionId === transactionId && readyReceipt.finished === true) {
              throw new Error('清理器未能完成启动校验');
            }
          }
        } catch (error) {
          if (error instanceof Error && error.message === '清理器未能完成启动校验') throw error;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      if (!helperReady) throw new Error('清理器未能确认计划已校验');
      helperLaunched = true;
      launchOutcomeUnknown = false;
      monitorPurgeReceipt(receiptPath, transactionId);
      db.audit('purge_started', {
        username: me.username,
        ip: req.ip,
        userAgent: req.headers['user-agent'] ?? null,
        detail: JSON.stringify({ transactionId, dryRun: plan.dryRun }),
      });
      res.once('finish', () => {
        try {
          writeFileSync(startSignalPath, `${transactionId}\n`, { mode: 0o600, flag: 'wx' });
        } catch (error) {
          console.error('[dsh-passwords] 无法确认清理请求已送达，清理器将超时退出:', String(error));
        }
      });
      res.status(202).json({ ok: true, code: 'PURGE_STARTED', notice: '清理已开始，服务将停止且所有本地数据不可恢复' });
    } catch (error) {
      if (!helperLaunched && !launchOutcomeUnknown) {
        purgeInProgress = false;
        try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* best effort */ }
      } else if (launchOutcomeUnknown) {
        monitorPurgeReceipt(receiptPath, transactionId);
      }
      console.error('[dsh-passwords] 启动紧急清理失败:', String(error));
      if (!res.headersSent) res.status(500).json({ ok: false, code: 'INTERNAL', error: '清理启动失败' });
    }
  });

  // token 用量上报节流（客户端 15 秒 flush 一次；这里再加 5 秒最小间隔，防高频自刷）。
  // 声明在权限路由之前：permissions 路由改配额时会清理该缓存。
  const usageReportThrottle = new Map<number, number>();

  // ── 概览（仅主用户）：所有用户 + 权限 + 当日用量 ─────────────
  app.get('/gateway/api/overview', (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const day = todayLocal();
    const users = db.listUsers().map((u) => {
      const perms = effectivePermissions(u.id);
      const usage = db.getUsage(u.id, day);
      return {
        id: u.id,
        username: u.username,
        role: u.role,
        permissions: {
          allowedFolders: perms.allowed_folders,
          hourlyTokenLimit: perms.hourly_token_limit,
          dailyMinutesLimit: perms.daily_minutes_limit,
          allowUpload: perms.allow_upload,
          allowGitDownload: perms.allow_git_download,
          allowWorkspaceCreate: perms.allow_workspace_create,
          allowSsh: perms.allow_ssh,
          allowedAgentPresets: perms.allowed_agent_presets,
          // NULL = 不限模型；[] = 禁止全部；非空 = 严格 provider/model allowlist。
          // 归一化后回显，让权限卡与数据库语义一致（失效/非法项不会留到前端）。
          allowedModels: perms.allowed_models === null ? null : normalizeAllowedModels(perms.allowed_models),
          allowChatMedia: perms.allow_chat_media,
          banned: perms.banned,
          sandboxMode: perms.sandbox_mode,
          disabledSessions: perms.disabled_sessions,
          allowedSessionIds: db.listUserSessionGrants(u.id),
        },
        usage: usage
          ? {
              day: usage.day,
              activeSeconds: usage.active_seconds,
              hourlyTokens: usage.hourly_tokens,
              firstSeenAt: usage.first_seen_at,
              lastActiveAt: usage.last_active_at,
            }
          : null,
      };
    });
    res.json({
      ok: true,
      me: { id: me.userId, username: me.username, role: me.role },
      // 端点登记表（运维可见性）：规则带 [owner:][ws:|http:] 前缀。
      endpoints: [...getEndpointRules()],
      // 最近一次官方 session/modelCatalog 原样快照；仅主用户 overview 可见。
      // 尚未观测到上游目录时返回 null，前端必须保持 fail-closed。
      modelCatalog: getHostModelCatalog(),
      users,
    });
  });

  // ── 敏感目录基列表（下载与目录删除共用；实现与 gateway 同源）──────
  const { isSensitivePath, sensitivePathBases } = createSensitivePathChecker({
    dbPath: config.dbPath,
    dshRoot: config.patch.dshRoot,
    gatewayRoot,
    configuredRoot,
  });

  // ── 创建根/创建位置的共用路径判定 ─────────────────────────────
  /**
   * 平台合规的完全限定路径：Windows 必须 drive-qualified；/foo 与 \\foo 会按当前盘解析，
   * 属于含糊输入，必须拒绝。共享 helper 同时供保存校验与目录选择器使用。
   */
  const isPlatformAbsolutePath = isFullyQualifiedPath;
  /**
   * 真实存在、为目录、非根，且词法与 canonical 均非敏感的本地目录。
   * 供 allowedFolders 回退分配使用：DSH registry 是正向分配的权威来源，但目录选择器
   * 允许主用户显式分配一个尚未登记进 registry 的本地真实目录（不新增 DB 字段）。
   */
  const isAssignableRealDirectory = (candidate: string): boolean => {
    let real: string;
    try {
      if (!statSync(candidate).isDirectory()) return false;
      real = realpathSync(candidate);
    } catch {
      return false;
    }
    if (isFilesystemRootPath(candidate) || isFilesystemRootPath(real)) return false;
    return !isSensitivePath(candidate) && !isSensitivePath(real);
  };

  // ── 远程文件下载（Issue #4）──────────────────────────────────
  // 经网关远程访问时，点击对话里的“生成文件”标签不再在服务器容器里执行
  // xdg-open（无桌面环境 → spawn xdg-open ENOENT），而是下载到当前浏览器。
  // 安全约束（按执行顺序）：
  //  1. 仅已登录用户（apiAuth）
  //  2. 规范化 + realpath 后再校验，防 ../ 与符号链接逃逸
  //  3. 子用户需开启下载开关，且只能下载 allowedFolders 白名单内的文件（folderAllowed）
  //  4. 屏蔽敏感路径：DSH 根目录、数据库、部署目录（盖 .env/data/dist）、SSH 凭据、OS 系统目录
  //  5. 仅普通文件（拒绝目录/设备/socket），并锁定 fd 防路径替换后再读取
  //  6. 支持 GET（流式）+ HEAD
  app.get('/gateway/api/download', (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const rawPath = typeof req.query.path === 'string' ? req.query.path : '';
    if (rawPath === '') {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'path 无效' });
      return;
    }

    // 1) 规范化 + 绝对路径（防 ../ 与编码变体）
    const abs = path.resolve(rawPath);
    // 2) realpath 后再校验（防符号链接逃逸；文件不存在也在此失败）
    let real: string;
    try {
      real = realpathSync(abs);
    } catch {
      res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '文件不存在' });
      return;
    }

    // 3) 下载开关与目录白名单：管理员是平台运维者，跳过 tenant folder allowlist，
    // 但不跳过认证、realpath、敏感路径和普通文件检查。
    if (me.role !== 'admin') {
      const perms = effectivePermissions(me.userId);
      if (!perms.allow_git_download) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '未开启文件下载' });
        return;
      }
      if (!folderAllowed(real, perms.allowed_folders)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '目录越权' });
        return;
      }
      // 对象级授权（与 /api/file 同口径）：白名单只表达「能进哪些目录」，不表达
      // 「目录里哪些子树属于别人」。被分配共享父目录的子用户不得凭白名单读到物主
      // 在父目录下自建 workspace 子树内的文件（workspaceSubtreeOverlap 单向含相等）。
      if (workspaceSubtreeOverlap(me.userId, real)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '目录越权' });
        return;
      }
    }

    // 4) 敏感路径屏蔽：DSH_HOME（会话/设置/凭据）、数据库、部署目录（盖 .env/data/dist）、
    //    本机 SSH 凭据、OS 系统目录（/etc /proc /sys /dev —— 永不会是工作区文件）
    if (isSensitivePath(abs) || isSensitivePath(real)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感文件不可下载' });
      return;
    }

    // 5) 打开并锁定文件描述符：后续 HEAD/GET 都从同一个 fd 读取，避免
    // realpath/stat 之后再次按路径打开时被替换成另一文件。Linux 额外使用
    // O_NOFOLLOW 拒绝最终组件符号链接；Windows 没有等价的通用 flag。
    let fd: number;
    let st;
    try {
      const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
      fd = openSync(real, fsConstants.O_RDONLY | noFollow);
      st = fstatSync(fd);
    } catch {
      res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '文件不存在' });
      return;
    }
    if (!st.isFile()) {
      closeSync(fd);
      res.status(400).json({ ok: false, code: 'INVALID', error: '不是普通文件' });
      return;
    }

    // 6) 响应：GET 流式下载；HEAD 仅返回头（供客户端探测路径/权限）
    const name = path.basename(real);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(name)}`);
    res.setHeader('Content-Length', String(st.size));
    if (req.method === 'HEAD') {
      closeSync(fd);
      res.end();
      return;
    }
    const stream = createReadStream(real, { fd, autoClose: true });
    stream.on('error', () => {
      if (!res.headersSent) res.status(500).json({ ok: false, code: 'INTERNAL', error: '读取失败' });
      else res.destroy();
    });
    // 客户端中途断开时 pipe 只 unpipe、不销毁源流，被挂住的 ReadStream 会永久占着
    // fd；订阅响应 close，在【未写完】时显式 destroy（正常写完走 autoClose 关 fd）。
    res.once('close', () => {
      if (!res.writableFinished) stream.destroy();
    });
    stream.pipe(res);
  });

  // ── 管理员目录选择器：为 allowedFolders 浏览可选目录 ──────────
  // 仅主用户可用。响应统一为：
  //   { ok:true, currentPath:string|null, parentPath:string|null, selectable:boolean,
  //     entries:{ name, path, selectable }[], truncated:boolean,
  //     rootPath?:string, rootPaths:string[] }
  // browse roots（唯一授权浏览范围）：
  //   · 由 MCP_GATEWAY_DIRECTORY_PICKER_ROOTS（逗号/换行分隔的绝对路径）给出；未配置时唯一
  //     安全起点为 os.homedir()。全盘根（/ 或盘符根）永不作为起点——绝不从整机根枚举。
  //   · 每个 root 使用前按当前文件系统状态校验：存在、为目录、词法与 canonical 均非敏感且
  //     非全盘根；校验失败的候选直接丢弃（fail-closed），绝不因配置错误放宽到更宽的路径。
  // 契约：
  //   · 无 path：返回安全 roots 的入口条目（不下钻到 root 的子目录），currentPath/parentPath=null。
  //   · 有 path：必须平台合规绝对路径，且词法与 canonical 同时位于某个 browse root，或位于
  //     某个 root 的祖先链上（祖先只返回通往安全 root 的直接子条目，不枚举兄弟）。
  //   · root 自身 parentPath=null；子树内其它目录按真实父目录回溯，parentPath 绝不越过 root。
  //   · 绝不返回文件名/符号链接/非目录；敏感路径与 canonical 落到敏感基的一并过滤。
  //   · 用户传入的 path 永远不会被当作新的 browse root；不在范围内一律拒绝。
  //   · 目录读取错误回 HTTP 错误（不是 Express 未捕获）；响应 no-store。
  //   · 用 opendir 有界读取并回传 truncated，避免超大目录阻塞；结果排序。
  const DIRECTORY_PICKER_MAX_ENTRIES = 2000;
  const DIRECTORY_PICKER_SCAN_LIMIT = 4000;
  type DirectoryPickerEntry = { name: string; path: string; selectable: boolean };

  /** 每请求求值一次的安全 roots；config 已按平台默认/环境变量解析，未配置时为家目录。 */
  const directoryPickerRoots = (): DirectoryPickerRootRef[] =>
    resolveDirectoryPickerBrowseRoots(config.directoryPickerRoots ?? [os.homedir()], isSensitivePath);

  /**
   * 敏感基快照：与 createSensitivePathChecker 的 isSensitivePath 完全一致（normalizePath +
   * win32 折叠大小写）。每请求按当前文件系统状态求值一次，供目录项逐条复用，避免重复 realpath。
   */
  const directoryPickerSensitiveKeys = (): ((candidate: string) => boolean) => {
    const caseFold = process.platform === 'win32'
      ? (value: string): string => value.toLowerCase()
      : (value: string): string => value;
    const normalizedBases = sensitivePathBases().map((base) => caseFold(normalizePath(base)));
    return (candidate: string): boolean => {
      const normalized = caseFold(normalizePath(candidate));
      return normalizedBases.some((base) => normalized === base || normalized.startsWith(`${base}/`));
    };
  };

  /** 收集 dir 的直接子目录（限同一 root 内），过滤敏感项、符号链接与 canonical 逃逸。 */
  const collectSubdirectories = async (
    dir: string,
    root: DirectoryPickerRootRef,
  ): Promise<{ entries: DirectoryPickerEntry[]; truncated: boolean }> => {
    const isSensitive = directoryPickerSensitiveKeys();
    const entries: DirectoryPickerEntry[] = [];
    let truncated = false;
    let scanned = 0;
    const handle = await opendir(dir);
    try {
      for await (const dirent of handle) {
        if (scanned >= DIRECTORY_PICKER_SCAN_LIMIT) { truncated = true; break; }
        scanned += 1;
        // 符号链接条目一律不返回：链接目标可能跳出 browse root（fail-closed）。
        if (dirent.isSymbolicLink() || !dirent.isDirectory()) continue;
        const lexicalPath = path.join(dir, dirent.name);
        let real: string;
        try {
          if (!statSync(lexicalPath).isDirectory()) continue;
          real = realpathSync(lexicalPath);
        } catch {
          continue;
        }
        if (isSensitive(lexicalPath) || isSensitive(real)) continue;
        // canonical 必须仍在同一 root 内：junction/挂载/链接逃逸一律丢弃。
        if (!directoryPickerPathWithin(root.lexical, lexicalPath) || !directoryPickerPathWithin(root.real, real)) continue;
        entries.push({ name: dirent.name, path: normalizePath(lexicalPath), selectable: true });
      }
    } finally {
      await handle.close().catch(() => { /* 关闭失败不影响已读取结果 */ });
    }
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
    if (entries.length > DIRECTORY_PICKER_MAX_ENTRIES) {
      truncated = true;
      entries.length = DIRECTORY_PICKER_MAX_ENTRIES;
    }
    return { entries, truncated };
  };
  app.get('/gateway/api/directory-picker/list', async (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    res.setHeader('Cache-Control', 'no-store');
    try {
      const rawQuery = req.query.path;
      if (rawQuery !== undefined && typeof rawQuery !== 'string') {
        res.status(400).json({ ok: false, code: 'INVALID', error: 'path 无效' });
        return;
      }
      const rawPath = rawQuery === undefined ? '' : rawQuery;
      const roots = directoryPickerRoots();
      const rootPaths = roots.map((root) => root.lexical);
      // 无 path：返回安全 roots 的入口，不下钻到 root 的子目录。
      if (rawPath === '') {
        const entries: DirectoryPickerEntry[] = roots.map((root) => ({
          name: directoryPickerEntryName(root.lexical),
          path: root.lexical,
          selectable: true,
        }));
        res.json({ ok: true, currentPath: null, parentPath: null, selectable: false, entries, truncated: false, rootPaths });
        return;
      }
      // 有 path：必须是平台合规的绝对路径；相对路径与 Windows 默认盘形态一律拒绝。
      if (rawPath.includes('\u0000') || !isPlatformAbsolutePath(rawPath)) {
        res.status(400).json({ ok: false, code: 'INVALID', error: 'path 必须是绝对路径' });
        return;
      }
      const abs = path.resolve(rawPath);
      let real: string;
      let st;
      try {
        real = realpathSync(abs);
        st = statSync(abs);
      } catch {
        res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
        return;
      }
      if (!st.isDirectory()) {
        res.status(400).json({ ok: false, code: 'INVALID', error: '不是目录' });
        return;
      }
      // 词法与 canonical 都不敏感：管理员也不能浏览 DSH 会话/凭据/部署目录。
      if (isSensitivePath(abs) || isSensitivePath(real)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感路径不可浏览' });
        return;
      }
      const scope = classifyDirectoryPickerTarget(
        { lexical: normalizePath(abs), real: normalizePath(real) },
        roots,
      );
      if (scope.kind === 'outside') {
        // 用户传入的 path 永远不会被当作新的 browse root。
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '不在允许浏览的范围内' });
        return;
      }
      if (scope.kind === 'ancestor') {
        // 祖先路径只返回通往安全 root 的直接子条目：既不枚举兄弟目录，也不可作为落点。
        const isSensitive = directoryPickerSensitiveKeys();
        const entries: DirectoryPickerEntry[] = [];
        for (const childPath of scope.ancestorEntries) {
          let childReal: string;
          try {
            if (!statSync(childPath).isDirectory()) continue;
            childReal = realpathSync(childPath);
          } catch {
            continue;
          }
          if (isSensitive(childPath) || isSensitive(childReal)) continue;
          entries.push({ name: directoryPickerEntryName(childPath), path: childPath, selectable: false });
        }
        const parentPath = isFilesystemRootPath(abs) ? null : normalizePath(path.dirname(abs));
        res.json({ ok: true, currentPath: normalizePath(abs), parentPath, selectable: false, entries, truncated: false, rootPaths });
        return;
      }
      const root = roots[scope.rootIndex];
      let listing: { entries: DirectoryPickerEntry[]; truncated: boolean };
      try {
        listing = await collectSubdirectories(abs, root);
      } catch {
        res.status(500).json({ ok: false, code: 'INTERNAL', error: '目录读取失败' });
        return;
      }
      // root 自身 parentPath=null；子树内目录按真实父目录回溯，绝不越过 root。
      const parentPath = scope.kind === 'root' ? null : normalizePath(path.dirname(abs));
      res.json({
        ok: true,
        currentPath: normalizePath(abs),
        parentPath,
        selectable: true,
        entries: listing.entries,
        truncated: listing.truncated,
        rootPath: root.lexical,
        rootPaths,
      });
    } catch {
      // 兜底：任何未预期异常都回 HTTP 错误，而不是 Express 未捕获的 rejected promise。
      if (!res.headersSent) res.status(500).json({ ok: false, code: 'INTERNAL', error: '目录读取失败' });
      else res.end();
    }
  });

  // ── 目录删除联动：上游 workspace registry 快照与删除 ─────────────
  // 信封与当前上游 dsh 0.1.5-rc.2 的实际 Remote 协议逐字对齐（读包内源码确认，非猜测）：
  //   · 快照：WS /api/remote.mux 上 open `workspace/follow`（payload { args: {} }），
  //     首个 item 即 { type:'baseline', value:{ items:[{workspaceId,path,sessionIds}], archivedSessionIds } }。
  //   · 删除：POST /api/workspace/delete，请求体为 Connection 的 client-request 信封
  //     { type:'client-request', rpcId, method:'workspace/delete', payload:{ args:{ request:{ workspaceId } } } }；
  //     响应 { type:'server-response', rpcId, result:{ ok:true, value:{ deleted:true } } }；
  //     result.ok=false 且 error.code='workspace/not-found' 视为目标已不存在（删除目的已达成）。
  // 旧点号 workspace.list/remove 在当前上游已不存在，这里不做猜测性兼容；失败一律可观测。
  type UpstreamWorkspaceEntry = { workspaceId: string; path: string; sessionIds: string[] };

  // ── 删除联动专用路径判定 ──────────────────────────────────────
  // 上游注册表路径、内存 cwd 与插件 DB 记录可能以不同大小写/符号链接形态出现，
  // 且被删根在比较时已不存在（realpath 失败）。匹配实现放在 db.ts（网关已依赖
  // db.ts，反向 import 会形成循环），重试准入与 DB 清理共用同一函数，保证
  // 「准入认为可重试」与「清理实际命中」不会各说各话。
  /** 路径本身位于敏感基内（含相等）。 */
  const pathInsideSensitiveBase = (candidate: string): boolean =>
    sensitivePathBases().some((base) => pathWithinDeletedTree(candidate, base));
  /** 路径位于某个敏感基的上级（递归删除会连带删掉敏感目录）。 */
  const pathContainsSensitiveBase = (candidate: string): boolean =>
    sensitivePathBases().some((base) => pathWithinDeletedTree(base, candidate));
  /** 该路径是否仍被工作区状态或插件 DB 引用（重试已删除目录时的准入依据）。 */
  const pathReferencedByWorkspaceState = (requested: string): boolean => {
    const within = (candidate: string): boolean => pathWithinDeletedTree(candidate, requested);
    for (const workspacePath of workspacePathById.values()) if (within(workspacePath)) return true;
    for (const paths of userWorkspacePaths.values()) {
      for (const workspacePath of paths.values()) if (within(workspacePath)) return true;
    }
    for (const cwd of sessionCwdById.values()) if (within(cwd)) return true;
    for (const pending of pendingCreatedDirectories.values()) {
      for (const dir of pending.keys()) if (within(dir)) return true;
    }
    try {
      for (const owner of db.listWorkspaceOwners()) if (within(owner.path)) return true;
      for (const user of db.listUsers()) {
        if (user.role !== 'user') continue;
        const perms = db.getPermissions(user.id);
        if (perms !== null && perms.allowed_folders.some((folder) => within(folder))) return true;
      }
    } catch {
      // 读库失败 = 无法确认引用 = 维持 404（不凭猜测做注册表/DB 写入）。
      return false;
    }
    return false;
  };
  /** DB 清理失败时的失效兜底：从 DB 与内存中收集路径树相关的子用户（宁多勿漏）。 */
  const collectPathRelatedUserIds = (root: string): number[] => {
    const users = new Set<number>();
    const within = (candidate: string): boolean => pathWithinDeletedTree(candidate, root);
    try {
      for (const owner of db.listWorkspaceOwners()) if (within(owner.path)) users.add(owner.userId);
      for (const user of db.listUsers()) {
        if (user.role !== 'user') continue;
        const perms = db.getPermissions(user.id);
        if (perms !== null && perms.allowed_folders.some((folder) => within(folder))) users.add(user.id);
      }
    } catch {
      // DB 不可读时退回内存来源；失效范围宁大勿小。
    }
    for (const [userId, paths] of userWorkspacePaths) {
      for (const workspacePath of paths.values()) {
        if (within(workspacePath)) { users.add(userId); break; }
      }
    }
    for (const [userId, access] of userSessionAccess) {
      for (const cwd of access.values()) {
        if (within(cwd)) { users.add(userId); break; }
      }
    }
    return [...users];
  };

  /** 通过 Remote mux 读取 workspace/follow 的 baseline；任何失败/超时返回 null（不阻断物理删除）。 */
  const fetchUpstreamWorkspaceEntries = (cookie: string, timeoutMs = 2_000): Promise<UpstreamWorkspaceEntry[] | null> =>
    new Promise((resolve) => {
      let settled = false;
      let socket: UpstreamMuxSocket | null = null;
      const finish = (value: UpstreamWorkspaceEntry[] | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { if (socket !== null) socket.close(); } catch { /* 已关闭 */ }
        resolve(value);
      };
      const timer = setTimeout(() => finish(null), timeoutMs);
      const streamId = `gwfs-${randomUUID().replace(/-/g, '')}`;
      try {
        socket = new WebSocket.WebSocket(`${upstreamScheme === 'https' ? 'wss' : 'ws'}://${upstreamAuthority}/api/remote.mux`, {
          headers: {
            host: upstreamAuthority,
            origin: `${upstreamScheme}://${upstreamAuthority}`,
            ...(cookie === '' ? {} : { cookie }),
          },
          rejectUnauthorized: process.env.MCP_GATEWAY_UPSTREAM_TLS_VERIFY !== '0',
          agent: upstreamAgent,
          maxPayload: remoteMuxMaxPayloadBytes,
        });
      } catch {
        finish(null);
        return;
      }
      socket.on('open', () => {
        try {
          socket.send(JSON.stringify({ type: 'open', streamId, endpoint: 'workspace/follow', payload: { args: {} } }));
        } catch {
          finish(null);
        }
      });
      socket.on('message', (data: Buffer) => {
        const frame = parseRemoteMuxServerFrame(Buffer.from(data));
        if (frame === null || frame.streamId !== streamId || frame.type !== 'item') return;
        const value = frame.value;
        if (!isPlainJsonRecord(value) || value.type !== 'baseline' || !isPlainJsonRecord(value.value) || !Array.isArray(value.value.items)) return;
        const entries: UpstreamWorkspaceEntry[] = [];
        for (const item of value.value.items) {
          if (!isPlainJsonRecord(item) || typeof item.workspaceId !== 'string' || typeof item.path !== 'string') continue;
          entries.push({
            workspaceId: item.workspaceId,
            path: item.path,
            sessionIds: Array.isArray(item.sessionIds)
              ? item.sessionIds.filter((id): id is string => typeof id === 'string' && id.length > 0 && id.length <= 200)
              : [],
          });
        }
        finish(entries);
      });
      socket.on('error', () => finish(null));
      socket.on('close', () => finish(null));
    });

  /** 按上游真实信封删除一个 workspace 注册条目；workspace/not-found 视为已达成。 */
  const deleteUpstreamWorkspaceEntry = (
    workspaceId: string,
    cookie: string,
    timeoutMs = 3_000,
  ): Promise<{ ok: true } | { ok: false; error: string }> =>
    new Promise((resolve) => {
      const rpcId = randomUUID();
      const payload = JSON.stringify({
        type: 'client-request',
        rpcId,
        method: 'workspace/delete',
        payload: { args: { request: { workspaceId } } },
      });
      const request = upstreamTransport.request({
        hostname: upstreamHost,
        port: upstreamPort,
        path: '/api/workspace/delete',
        method: 'POST',
        headers: {
          host: upstreamAuthority,
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(payload)),
          ...(cookie === '' ? {} : { cookie }),
        },
        agent: upstreamAgent,
        timeout: timeoutMs,
      }, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size <= 256 * 1024) chunks.push(chunk);
        });
        response.on('end', () => {
          if (response.statusCode !== 200 || size > 256 * 1024) {
            resolve({ ok: false, error: `HTTP ${response.statusCode}` });
            return;
          }
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
            // 响应必须关联到本次请求，否则不能把它当成本次删除的结果。
            if (parsed.rpcId !== rpcId) {
              resolve({ ok: false, error: 'rpcId mismatch' });
              return;
            }
            const result = parsed.result;
            if (isPlainJsonRecord(result) && result.ok === true) {
              resolve({ ok: true });
              return;
            }
            if (isPlainJsonRecord(result) && result.ok === false && isPlainJsonRecord(result.error)) {
              const code = typeof result.error.code === 'string' ? result.error.code : '';
              const message = typeof result.error.message === 'string' ? result.error.message : '';
              // 目标已不存在 = 删除目的已达成（幂等）
              if (code === 'workspace/not-found') {
                resolve({ ok: true });
                return;
              }
              resolve({ ok: false, error: code !== '' ? `${code}: ${message}` : message || 'upstream error' });
              return;
            }
            resolve({ ok: false, error: 'invalid upstream response' });
          } catch {
            resolve({ ok: false, error: 'invalid upstream response' });
          }
        });
      });
      request.on('error', (error) => resolve({ ok: false, error: String((error as Error).message ?? error) }));
      request.on('timeout', () => {
        request.destroy();
        resolve({ ok: false, error: 'timeout' });
      });
      request.end(payload);
    });

  /** 本地兜底清单：网关进程内已见的 workspaceId→path（不完整）。仅用于向调用方报告
   *  「可能有工作区未被同步」，绝不作为上游删除的依据（删除只信权威快照）。 */
  const localUpstreamWorkspaceEntries = (): UpstreamWorkspaceEntry[] => {
    const entries = new Map<string, UpstreamWorkspaceEntry>();
    const remember = (workspaceId: string, workspacePath: string): void => {
      if (!entries.has(workspaceId)) entries.set(workspaceId, { workspaceId, path: workspacePath, sessionIds: [] });
    };
    for (const [workspaceId, workspacePath] of workspacePathById) remember(workspaceId, workspacePath);
    for (const paths of userWorkspacePaths.values()) {
      for (const [workspaceId, workspacePath] of paths) remember(workspaceId, workspacePath);
    }
    return [...entries.values()];
  };

  // ── 删除文件系统目录（仅主用户；目录选择器删除按钮的后端）────
  // 用途：主用户在「选择工作区目录」弹窗里清理服务器上的文件夹（含隐藏目录）。
  // 安全约束（按顺序）：
  //  1. 仅主用户（apiAuth requireAdmin）——后端强制，前端隐藏不是授权边界
  //  2. 规范化 + realpath 后再校验（防 ../ 与符号链接逃逸）
  //  3. 必须是真实目录（非 Windows 用 O_DIRECTORY|O_NOFOLLOW 锁 fd 后 fstat，
  //     Windows 上 openSync 目录会报错，退化为 statSync）
  //  4. 敏感目录屏蔽（与 /gateway/api/download 同一套基列表）及其一切子路径与祖先
  //  5. 文件系统根与用户主目录本身不可删
  //  6. 只有「注册 dsh-auth 凭据 + 权威上游 workspace/follow 快照」才允许调用
  //     workspace/delete；删除后重读注册表复核，残留一律计失败；本地缓存只用于报告
  //  7. 插件 DB 的 ownership / allowed_folders / grants 单事务清理（白名单清空回落
  //     __deny__，绝不 fail-open）；清理失败返回 5xx 且仍失效 mux 快照，并把受信
  //     根+会话写入 workspace_cleanup_intents，供重启/缓存清空后重试同一路径收敛
  //  8. 递归删除 + 审计日志；任一步骤部分失败都必须可观测（不假装全成功）
  const fsDeleteRate = new Map<number, number[]>();
  app.post('/gateway/api/fs/delete-directory', jsonBody, (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const now = Date.now();
    const recent = (fsDeleteRate.get(me.userId) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= 30) {
      fsDeleteRate.set(me.userId, recent);
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '删除过于频繁，请稍后再试' });
      return;
    }
    recent.push(now);
    fsDeleteRate.set(me.userId, recent);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const rawPath = typeof body.path === 'string' ? body.path : '';
    // 目录已物理删除、但联动/授权清理未收口时，选择器会带 cleanupOnly=true 重试。
    // 该模式绝不删除文件系统：它只接受与服务端持久化失败意图相同、且当前仍不存在的路径。
    const cleanupOnly = body.cleanupOnly === true;
    if (rawPath === '' || rawPath.length > 4096) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'path 无效' });
      return;
    }
    const abs = path.resolve(rawPath);
    let real: string | null = null;
    let missingCode: string | undefined;
    try {
      real = realpathSync(abs);
    } catch (error) {
      missingCode = (error as { code?: string }).code;
    }
    // 目录已不存在（重试场景）：仅当该路径仍被工作区状态/插件 DB 引用，或
    // 存在（上次删除写入的）持久化清理意图时才继续；其余维持 404——避免对任意
    // 不存在路径做注册表/DB 写入（重试先过敏感目录检查）。
    const alreadyDeleted = real === null && (missingCode === 'ENOENT' || missingCode === 'ENOTDIR');
    let retryIntent: WorkspaceCleanupIntent | null = null;
    // cleanupOnly 是墓碑行的恢复动作，而不是第二次删除确认：它必须先命中服务端
    // 持久化的失败意图。若同一路径已被重建，废弃旧意图并拒绝，而不是把旧清理应用到
    // 新目录或递归删除新内容。敏感路径仍优先维持 403，避免误报为普通冲突。
    if (cleanupOnly && !alreadyDeleted) {
      if (real === null) {
        res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
        return;
      }
      if (samePathForMatch(real, path.parse(real).root) || samePathForMatch(real, os.homedir()) ||
        pathInsideSensitiveBase(real) || pathContainsSensitiveBase(real)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感目录不可删除' });
        return;
      }
      try {
        // 用请求的规范化路径查意图而不是当前 realpath：重建路径可能已经指向与旧目录
        // 不同的对象，但同一路径文本仍是唯一可安全废弃的旧恢复任务。
        retryIntent = db.findWorkspaceCleanupIntent(normalizePath(abs));
      } catch {
        retryIntent = null;
      }
      if (retryIntent === null) {
        res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '未找到可重试的授权清理任务' });
        return;
      }
      // 不清除旧意图：它记载的是原删除的未收敛授权/注册表状态；若在这里丢弃，
      // 新目录恰好复用同一路径时旧授权残留会失去唯一的安全收敛线索。选择器退出
      // 墓碑并恢复常规删除；之后若主用户确认删除这个新目录，完整普通流程会把旧
      // 意图与当前目录状态一起收敛。cleanupOnly 本身绝不触碰新目录。
      db.audit('fs_directory_cleanup_retry_conflicted', {
        username: me.username,
        ip: req.ip,
        userAgent: req.headers['user-agent'] ?? null,
        detail: JSON.stringify({ path: normalizePath(abs), intentRoot: retryIntent.root, retained: true }),
      });
      res.status(409).json({
        ok: false,
        code: 'CLEANUP_RETRY_CONFLICT',
        error: '目录已被重新创建；为避免删除新内容，授权清理重试未执行。请刷新后按常规删除流程操作',
      });
      return;
    }
    if (alreadyDeleted) {
      const requested = normalizePath(abs);
      if (samePathForMatch(requested, path.parse(abs).root) || samePathForMatch(requested, os.homedir()) ||
        pathInsideSensitiveBase(requested) || pathContainsSensitiveBase(requested)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感目录不可删除' });
        return;
      }
      // 持久化意图是「目录已物理删除、DB 清理失败」的可信凭证：它允许在重启/内存
      // 缓存清空、上游条目已消失（仅剩会话 grants）时仍凭同一路径重试清理。
      // 读库失败 = 无法确认 = 维持 404（不凭猜测做注册表/DB 写入）。
      try {
        retryIntent = db.findWorkspaceCleanupIntent(requested);
      } catch {
        retryIntent = null;
      }
      if (cleanupOnly && retryIntent === null) {
        // 墓碑恢复只信持久化的失败意图；不允许调用方把任意缺失路径伪装成清理任务。
        res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '未找到可重试的授权清理任务' });
        return;
      }
      if (!cleanupOnly && retryIntent === null && !pathReferencedByWorkspaceState(requested)) {
        res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
        return;
      }
      // 仅清理重试使用首次失败时服务端记录的规范根，确保 DB 的别名匹配和审计口径
      // 与原删除一致；普通兼容重试保留请求路径。
      real = cleanupOnly && retryIntent !== null ? retryIntent.root : abs;
    } else if (real === null) {
      res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
      return;
    }
    if (!alreadyDeleted) {
      let isDir: boolean;
      if (process.platform === 'win32') {
        try {
          isDir = statSync(real).isDirectory();
        } catch {
          res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
          return;
        }
      } else {
        // 锁 fd 后再判定目录类型，缩短 realpath 与删除之间的替换窗口。
        // ENOTDIR = 路径存在但不是目录（400）；其它打开失败（不存在/权限）统一 404。
        let fd: number | undefined;
        let st;
        try {
          fd = openSync(real, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | (fsConstants.O_NOFOLLOW ?? 0));
          st = fstatSync(fd);
        } catch (error) {
          const code = (error as { code?: string }).code;
          if (fd !== undefined) closeSync(fd);
          if (code === 'ENOTDIR') {
            res.status(400).json({ ok: false, code: 'INVALID', error: '只能删除目录' });
          } else {
            res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
          }
          return;
        }
        closeSync(fd);
        isDir = st.isDirectory();
      }
      if (!isDir) {
        res.status(400).json({ ok: false, code: 'INVALID', error: '只能删除目录' });
        return;
      }
      if (samePathForMatch(real, path.parse(real).root) || samePathForMatch(real, os.homedir()) ||
        pathInsideSensitiveBase(real) || pathContainsSensitiveBase(real)) {
        res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感目录不可删除' });
        return;
      }
    }
    const targetPath: string = real;
    const recoveryOnly = cleanupOnly && retryIntent !== null;
    void (async () => {
      let physicallyDeleted = alreadyDeleted;
      // alreadyDeleted 语义可能在请求进行中由并发删除触发（快照后、复核前路径消失）：
      // 响应与联动都必须按幂等已删除路径处理，而不是 404 跳过清理。
      let idempotentDelete = alreadyDeleted;
      try {
        const deletedRoot = normalizePath(targetPath);
        // 1) 必须在上游删除之前取得权威快照；只使用受保护通道登记的 dsh-auth，
        //    浏览器 Cookie（含 dsh-auth-*）绝不转发给 loopback 上游。凭据缺失 =
        //    同步 fail-closed（只删目录，注册表保持原样并显式上报）。
        const registryCookie = getUpstreamAuthCookie();
        const registryAuthAvailable = registryCookie !== '';
        const upstreamEntries = registryAuthAvailable ? await fetchUpstreamWorkspaceEntries(registryCookie) : null;
        const registrySnapshot: 'upstream' | 'unavailable' = upstreamEntries !== null ? 'upstream' : 'unavailable';
        const affected = [...new Map(
          (upstreamEntries ?? []).filter((entry) => pathWithinDeletedTree(entry.path, deletedRoot))
            .map((entry) => [entry.workspaceId, entry] as const),
        ).values()];
        // 快照不可用时本地缓存只作为「可能受影响」报告，绝不驱动 workspace/delete。
        const localCandidates = upstreamEntries !== null
          ? []
          : [...new Map(
              localUpstreamWorkspaceEntries().filter((entry) => pathWithinDeletedTree(entry.path, deletedRoot))
                .map((entry) => [entry.workspaceId, entry] as const),
            ).values()];
        // 2) 快照等待期间路径可能被替换：删前重新 realpath 并复核目录身份与敏感基（fail-closed）。
        //    并发删除赢得竞争（路径在复核时已消失）→ 按 alreadyDeleted 的幂等联动继续，
        //    绝不 404 跳过注册表/DB/pending 清理；真正被替换成别的对象仍返回 409。
        if (!alreadyDeleted && !recoveryOnly) {
          let realAgain: string | null = null;
          let vanished = false;
          try {
            realAgain = realpathSync(targetPath);
          } catch (error) {
            const code = (error as { code?: string }).code;
            if (code === 'ENOENT' || code === 'ENOTDIR') {
              vanished = true;
            } else {
              res.status(404).json({ ok: false, code: 'NOT_FOUND', error: '目录不存在' });
              return;
            }
          }
          if (!vanished) {
            const rechecked: string = realAgain as string;
            if (!samePathForMatch(rechecked, targetPath)) {
              res.status(409).json({ ok: false, code: 'CONFLICT', error: '目录在删除前发生变化，请刷新后重试' });
              return;
            }
            let stillDirectory = false;
            let statMissing = false;
            try {
              stillDirectory = statSync(rechecked).isDirectory();
            } catch (error) {
              statMissing = (error as { code?: string }).code === 'ENOENT';
            }
            if (!stillDirectory) {
              if (statMissing) {
                // stat 与 realpath 之间又被并发删除：同样按幂等已删除处理。
                vanished = true;
              } else {
                res.status(400).json({ ok: false, code: 'INVALID', error: '只能删除目录' });
                return;
              }
            } else if (samePathForMatch(rechecked, path.parse(rechecked).root) || samePathForMatch(rechecked, os.homedir()) ||
              pathInsideSensitiveBase(rechecked) || pathContainsSensitiveBase(rechecked)) {
              res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '敏感目录不可删除' });
              return;
            } else {
              // 3) 物理删除（不可回滚；workspace 注册表同步失败在下面显式上报）
              try {
                rmSync(targetPath, { recursive: true, maxRetries: 3, retryDelay: 100 });
                physicallyDeleted = true;
              } catch (error) {
                if ((error as { code?: string }).code === 'ENOENT') {
                  // rmSync 前最后一个窗口也被并发删除赢下：删除目的已达成，继续联动清理。
                  vanished = true;
                } else {
                  console.warn('[dsh-passwords] 目录删除失败:', String(error));
                  res.status(500).json({ ok: false, code: 'INTERNAL', error: '删除失败' });
                  return;
                }
              }
            }
          }
          if (vanished) {
            physicallyDeleted = true;
            idempotentDelete = true;
          }
        }
        // 4) 上游注册表同步（仅权威快照）：并发上限 8，单个失败不影响其余条目；
        //    删除后必须重读注册表验证——仍存在的 workspaceId 一律计为失败，绝不假装成功。
        const deletedWorkspaceIds: string[] = [];
        const failedWorkspaces: Array<{ workspaceId: string; path: string; error: string }> = [];
        if (upstreamEntries !== null && affected.length > 0) {
          const failedById = new Map<string, { workspaceId: string; path: string; error: string }>();
          for (let index = 0; index < affected.length; index += 8) {
            const batch = affected.slice(index, index + 8);
            const results = await Promise.all(batch.map(async (entry) => ({
              entry,
              outcome: await deleteUpstreamWorkspaceEntry(entry.workspaceId, registryCookie),
            })));
            for (const { entry, outcome } of results) {
              if (!outcome.ok) {
                failedById.set(entry.workspaceId, { workspaceId: entry.workspaceId, path: entry.path, error: outcome.error });
              }
            }
          }
          // 复核快照：任何失败/超时都意味着「未经证实」，按失败上报（no false success）。
          const verified = await fetchUpstreamWorkspaceEntries(registryCookie);
          const stillPresent = verified === null ? null : new Set(verified.map((entry) => entry.workspaceId));
          for (const entry of affected) {
            const failed = failedById.get(entry.workspaceId);
            if (failed !== undefined) {
              failedWorkspaces.push(failed);
              continue;
            }
            if (stillPresent === null) {
              failedWorkspaces.push({ workspaceId: entry.workspaceId, path: entry.path, error: 'post-delete verification unavailable' });
              continue;
            }
            if (stillPresent.has(entry.workspaceId)) {
              failedWorkspaces.push({ workspaceId: entry.workspaceId, path: entry.path, error: 'still present after delete' });
              continue;
            }
            deletedWorkspaceIds.push(entry.workspaceId);
          }
        }
        // 5) 受影响会话：权威快照的 sessionIds ∪ 内存 cwd 映射命中的会话
        const affectedSessionIds = new Set<string>();
        for (const entry of affected) {
          for (const sessionId of entry.sessionIds) affectedSessionIds.add(sessionId);
        }
        for (const map of [sessionCwdById, ...userSessionAccess.values()]) {
          for (const [sessionId, cwd] of map) {
            if (pathWithinDeletedTree(cwd, deletedRoot)) affectedSessionIds.add(sessionId);
          }
        }
        // 重启/上游条目已消失时，权威快照与内存映射都不再有该目录树的会话；
        // 用持久化意图里保存的会话 ID 补齐，否则 grants-only 残留永远无法命中。
        if (retryIntent !== null) {
          for (const sessionId of retryIntent.sessionIds) affectedSessionIds.add(sessionId);
        }
        // 6) 清理内存快照与插件 DB（单事务）；白名单删空回落 __deny__，绝不 fail-open。
        //    已从上游删除的 id 不再保留任何 workspaceId→path 映射（含各子用户快照）。
        if (deletedWorkspaceIds.length > 0) {
          const removedIds = new Set(deletedWorkspaceIds);
          for (const [userId, paths] of [...userWorkspacePaths]) {
            let changed = false;
            for (const workspaceId of removedIds) {
              if (paths.delete(workspaceId)) changed = true;
            }
            if (changed) replaceUserWorkspacePaths(userId, new Map(paths), userAccessEpochFor(userId));
          }
        }
        for (const [workspaceId, workspacePath] of [...workspacePathById]) {
          if (pathWithinDeletedTree(workspacePath, deletedRoot)) workspacePathById.delete(workspaceId);
        }
        for (const [sessionId, cwd] of [...sessionCwdById]) {
          if (pathWithinDeletedTree(cwd, deletedRoot)) sessionCwdById.delete(sessionId);
        }
        let cleanup = { invalidateUserIds: [] as number[], removedWorkspaces: 0, removedFolders: 0, removedGrants: 0 };
        let cleanupFailed = false;
        try {
          cleanup = db.cleanupDeletedWorkspaceTree(deletedRoot, [...affectedSessionIds]);
        } catch (error) {
          // 单事务回滚：不会留下空 allowed_folders（无 fail-open），但必须让调用方可观测。
          console.warn('[dsh-passwords] 目录删除后的 workspace 授权清理失败:', String(error));
          cleanupFailed = true;
        }
        // 一个目录删除只有在两条独立收敛条件都成立时才算完整：插件 DB 授权已清理，
        // 且权威 DSH workspace/follow 快照已可用并确认所有命中条目都从 sidebar
        // 注册表消失。此前仅按 DB 成功清意图会在上游同步失败时丢掉唯一恢复凭据。
        const workspaceSyncIncomplete = upstreamEntries === null || failedWorkspaces.length > 0;
        const cleanupIncomplete = cleanupFailed || workspaceSyncIncomplete;
        // 任何未收敛路径（DB 或上游同步）都记录同一受信意图。重试只重读权威快照，
        // 对仍在树内的 workspace 发送真实 workspace/delete；绝不以本地缓存猜测删除。
        // 意图写不进去就绝不宣称可重试（见下方显式 *_NO_RETRY 分支）。
        let cleanupIntentSaved = false;
        if (cleanupIncomplete) {
          try {
            db.recordWorkspaceCleanupIntent(deletedRoot, [...affectedSessionIds], me.userId);
            cleanupIntentSaved = true;
          } catch (error) {
            console.warn('[dsh-passwords] 记录目录清理意图失败（自动重试不可保证）:', String(error));
          }
        } else {
          // 仅在 DB 与权威 sidebar 同步均收敛后清除意图。清除失败不推翻已完成的
          // 实际状态；残留只会使同路径后续调用做一次安全的幂等空清理。
          try {
            if (db.clearWorkspaceCleanupIntent(deletedRoot) > 0) {
              db.audit('fs_directory_cleanup_intent_cleared', {
                username: me.username,
                ip: req.ip,
                userAgent: req.headers['user-agent'] ?? null,
                detail: JSON.stringify({ path: targetPath }),
              });
            }
          } catch (error) {
            console.warn('[dsh-passwords] 清除目录清理意图失败:', String(error));
          }
        }
        // DB 清理失败也必须失效内存/mux 快照，否则旧 baseline 会继续把已删目录当作可见工作区。
        const invalidateUserIds = new Set<number>(cleanup.invalidateUserIds);
        if (cleanupFailed) {
          for (const userId of collectPathRelatedUserIds(deletedRoot)) invalidateUserIds.add(userId);
          // grants-only 残留不在路径引用里：按受影响会话补齐授权持有者，确保 mux/WS 失效。
          try {
            for (const userId of db.listSessionGrantUserIds([...affectedSessionIds])) invalidateUserIds.add(userId);
          } catch {
            // DB 不可读：无法补齐（响应仍为显式失败，不会伪装成功）。
          }
        }
        // pending 目录授权（workspace/create 的 30 分钟信任窗口）只存在内存中，DB 清理
        // 不会覆盖：必须为「每个 owner」清掉树内条目，并把 owner 一并纳入失效——
        // 否则旧 mux baseline 与陈旧 pending 会在路径被重建后继续放行登记/浏览。
        for (const [userId, pendingDirs] of [...pendingCreatedDirectories]) {
          let removedPending = false;
          for (const dir of [...pendingDirs.keys()]) {
            if (!pathWithinDeletedTree(dir, deletedRoot)) continue;
            pendingDirs.delete(dir);
            removedPending = true;
          }
          if (pendingDirs.size === 0) pendingCreatedDirectories.delete(userId);
          if (removedPending) invalidateUserIds.add(userId);
        }
        for (const userId of invalidateUserIds) {
          const row = db.getUserById(userId);
          if (row === null || row.role === 'admin') continue;
          // Remote mux 不会因 DB 变更自动刷新；关掉旧订阅令其重建 workspace baseline。
          invalidateUserSessionAccess(userId);
          closeUserRemoteMuxClients(userId);
          closeUserWebSocketClients(userId);
        }
        const warnings: string[] = [];
        if (recoveryOnly) {
          warnings.push('已执行仅授权/工作区同步恢复：未再次删除文件系统目录');
        }
        if (upstreamEntries === null) {
          warnings.push(registryAuthAvailable
            ? '未能读取 DSH 工作区注册表（上游不可达或超时），已跳过侧边栏工作区同步（未执行任何注册表删除）'
            : '未登记可用的上游 dsh-auth 凭据，无法同步 DSH 工作区注册表（未发送任何上游请求）');
          if (localCandidates.length > 0) {
            warnings.push(`网关缓存显示该目录树内可能有 ${localCandidates.length} 个工作区（${localCandidates.map((entry) => entry.workspaceId).join(', ')}），需人工核对`);
          }
        }
        if (cleanupFailed) {
          warnings.push(cleanupIntentSaved
            ? '插件数据库中的工作区授权清理失败，本响应不代表清理完成；请重试清理以完成授权与侧边栏同步'
            : '插件数据库中的工作区授权清理失败，且清理重试信息无法持久化；自动重试不可保证，请人工处理残留授权');
        } else if (workspaceSyncIncomplete) {
          warnings.push(cleanupIntentSaved
            ? 'DSH 侧边栏工作区同步未完成；请重试清理以重新读取权威注册表并收敛'
            : 'DSH 侧边栏工作区同步未完成，且清理重试信息无法持久化；请人工核对残留工作区');
        }
        const workspaces = {
          deleted: deletedWorkspaceIds,
          failed: failedWorkspaces,
          unverified: localCandidates.map((entry) => ({ workspaceId: entry.workspaceId, path: entry.path })),
        };
        db.audit(recoveryOnly ? 'fs_directory_cleanup_retried' : 'fs_directory_deleted', {
          username: me.username,
          ip: req.ip,
          userAgent: req.headers['user-agent'] ?? null,
          detail: targetPath,
        });
        if (failedWorkspaces.length > 0 || upstreamEntries === null) {
          db.audit('fs_directory_workspace_sync_failed', {
            username: me.username,
            ip: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
            detail: JSON.stringify({ path: targetPath, registrySnapshot, registryAuthAvailable, deleted: deletedWorkspaceIds, failed: failedWorkspaces, unverified: workspaces.unverified }),
          });
        }
        if (cleanupFailed) {
          db.audit('fs_directory_db_cleanup_failed', {
            username: me.username,
            ip: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
            detail: JSON.stringify({ path: targetPath, invalidateUserIds: [...invalidateUserIds], retryIntentSaved: cleanupIntentSaved }),
          });
        }
        if (workspaceSyncIncomplete && cleanupIntentSaved) {
          db.audit('fs_directory_workspace_sync_retry_scheduled', {
            username: me.username,
            ip: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
            detail: JSON.stringify({ path: targetPath, registrySnapshot, failed: failedWorkspaces.length }),
          });
        }
        const responseBase = {
          deleted: targetPath,
          ...(idempotentDelete ? { alreadyDeleted: true } : {}),
          ...(recoveryOnly ? { cleanupOnly: true } : {}),
          workspaces,
          registrySnapshot,
          warnings,
        };
        if (cleanupFailed && !cleanupIntentSaved) {
          // 清理意图写不进去：不得返回 DB_CLEANUP_FAILED（客户端与既有契约把它当作
          // 「保留墓碑行 + 可重试」）。用显式不可重试 code，提示人工处理残留授权。
          res.status(500).json({
            ok: false,
            code: 'DB_CLEANUP_FAILED_NO_RETRY',
            retryable: false,
            error: '目录已删除，但插件数据库清理失败，且清理重试信息无法保存；请人工处理残留授权',
            ...responseBase,
          });
          return;
        }
        if (cleanupFailed) {
          // 目录已删，稳定 code + retryable 契约：目录选择器保留该行的「重试授权清理」
          // 动作（不会移除行而丢掉唯一入口），重试同一路径即可完成 DB 清理（准入由
          // 持久化清理意图或残留状态引用决定，且必须先过敏感目录检查）。
          res.status(500).json({
            ok: false,
            code: 'DB_CLEANUP_FAILED',
            retryable: true,
            error: '目录已删除，但插件数据库清理失败；请重试删除以完成授权清理',
            ...responseBase,
          });
          return;
        }
        if (failedWorkspaces.length > 0) {
          // 目录已删除且不可回滚：绝不假装全部成功。只有意图已持久化时才允许客户端
          // 保留墓碑并走 cleanupOnly 重试；否则明确要求人工处理，不给虚假的重试入口。
          res.status(500).json({
            ok: false,
            code: cleanupIntentSaved ? 'WORKSPACE_SYNC_FAILED' : 'WORKSPACE_SYNC_FAILED_NO_RETRY',
            retryable: cleanupIntentSaved,
            error: cleanupIntentSaved
              ? `目录已删除，但 ${failedWorkspaces.length} 个侧边栏工作区未能确认从 DSH 注册表移除；请重试清理`
              : `目录已删除，但 ${failedWorkspaces.length} 个侧边栏工作区未能确认从 DSH 注册表移除，且重试信息无法保存；请人工处理`,
            ...responseBase,
          });
          return;
        }
        if (upstreamEntries === null) {
          // 同步 fail-closed：未用本地缓存猜测执行任何删除；仅在恢复任务已持久化时
          // 才暴露 cleanupOnly 重试，避免用户误以为一次普通重试会安全收敛。
          res.status(503).json({
            ok: false,
            code: cleanupIntentSaved ? 'WORKSPACE_SYNC_UNAVAILABLE' : 'WORKSPACE_SYNC_UNAVAILABLE_NO_RETRY',
            retryable: cleanupIntentSaved,
            error: cleanupIntentSaved
              ? '目录已删除，但未能获取权威 DSH 工作区注册表快照，侧边栏工作区未同步；请重试清理'
              : '目录已删除，但未能获取权威 DSH 工作区注册表快照，且重试信息无法保存；请人工处理',
            ...responseBase,
          });
          return;
        }
        res.json({ ok: true, ...responseBase });
      } catch (error) {
        console.error('[dsh-passwords] 目录删除联动处理异常:', String(error));
        if (!res.headersSent) {
          res.status(500).json({
            ok: false,
            code: 'INTERNAL',
            error: physicallyDeleted ? '目录已删除，但工作区联动清理异常' : '删除失败',
            ...(physicallyDeleted ? { deleted: targetPath } : {}),
          });
        }
      }
    })();
  });

  // ── 更新某子用户权限（仅主用户） ─────────────────────────────
  app.post('/gateway/api/permissions', jsonBody, async (req, res) => {
    const me = apiAuth(req, res, true);
    if (!me) return;
    const body = (req.body ?? {}) as Record<string, unknown>;
    const userId = Number(body.userId);
    if (!Number.isInteger(userId) || userId <= 0) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'userId 无效' });
      return;
    }
    const target = db.getUserById(userId);
    if (!target) {
      res.status(404).json({ ok: false, code: 'NO_SUCH_USER', error: '用户不存在' });
      return;
    }
    if (target.role === 'admin') {
      res.status(400).json({ ok: false, code: 'FORBIDDEN', error: '不能修改主用户权限' });
      return;
    }
    try {
    const currentPermissions = effectivePermissions(userId);
    const expectedPermissionState = db.getPermissions(userId);
    // `__deny__` 是本插件用于表达“不给任何工作区”的唯一内部哨兵值。前端在
    // allowedFolders 表示部分更新，必须保留当前值，避免旧草稿覆盖并发修改。
    if (body.allowedFolders !== undefined &&
      (!Array.isArray(body.allowedFolders) || body.allowedFolders.some((folder) => typeof folder !== 'string'))) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的工作区必须是路径数组' });
      return;
    }
    const allowedFolders = body.allowedFolders === undefined
      ? [...currentPermissions.allowed_folders]
      : stringArray(body.allowedFolders);
    const denyAll = allowedFolders.length === 1 && allowedFolders[0] === '__deny__';
    // 空字符串、当前目录和根目录会被 folderAllowed 归一为“全盘允许”，与 UI 的
    // “允许的工作区”语义相反；显式拒绝，管理员应使用空数组表示不限制。
    if (!denyAll && allowedFolders.some((folder) => {
      const trimmed = folder.trim().replace(/\\/g, '/');
      return (
        trimmed === '' ||
        trimmed === '.' ||
        trimmed === '/' ||
        (!(trimmed.startsWith('/') || /^[A-Za-z]:\//.test(trimmed))) ||
        /(^|\/)\.\.?($|\/)/.test(trimmed) ||
        normalizePath(trimmed) === '/' ||
        normalizePath(trimmed) === '.' ||
        /^[a-z]:\/$/i.test(normalizePath(trimmed))
      );
    })) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的工作区不能包含空路径、当前目录或根目录' });
      return;
    }
    // 0 归一为 null（=不限）：避免"每日 0 分钟"被误当作"首次使用即封禁"。
    // 但非法输入必须 400，不能沿用 nullableInt 的兼容性 null 语义而静默放宽限制。
    const parsedHourlyTokenLimit = parseNullableIntStrict(body.hourlyTokenLimit);
    const parsedDailyMinutesLimit = parseNullableIntStrict(body.dailyMinutesLimit);
    if (!parsedHourlyTokenLimit.ok || !parsedDailyMinutesLimit.ok) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '配额必须是非负整数' });
      return;
    }
    const hourlyTokenLimit = body.hourlyTokenLimit === undefined
      ? currentPermissions.hourly_token_limit
      : parsedHourlyTokenLimit.value === 0 ? null : parsedHourlyTokenLimit.value;
    const dailyMinutesLimit = body.dailyMinutesLimit === undefined
      ? currentPermissions.daily_minutes_limit
      : parsedDailyMinutesLimit.value === 0 ? null : parsedDailyMinutesLimit.value;
    const readBooleanPermission = (name: string, value: unknown, current: boolean): boolean | null => {
      if (value === undefined) return current;
      if (typeof value !== 'boolean') {
        res.status(400).json({ ok: false, code: 'INVALID', error: `${name} 必须是布尔值` });
        return null;
      }
      return value;
    };
    const allowUpload = readBooleanPermission('allowUpload', body.allowUpload, currentPermissions.allow_upload);
    if (allowUpload === null) return;
    const allowGitDownload = readBooleanPermission('allowGitDownload', body.allowGitDownload, currentPermissions.allow_git_download);
    if (allowGitDownload === null) return;
    const allowWorkspaceCreate = readBooleanPermission('allowWorkspaceCreate', body.allowWorkspaceCreate, currentPermissions.allow_workspace_create);
    if (allowWorkspaceCreate === null) return;
    // workspaceCreationRoots 已退役：allowedFolders 是唯一的工作区/创建范围。旧客户端仍可能
    // 提交该字段；显式 400（而非静默忽略）避免管理员误以为旧的创建根设置已生效。
    if (body.workspaceCreationRoots !== undefined) {
      res.status(400).json({
        ok: false,
        code: 'INVALID',
        error: 'workspaceCreationRoots 已停用；工作区范围（含可创建位置）统一由 allowedFolders 配置',
      });
      return;
    }
    const allowSsh = readBooleanPermission('allowSsh', body.allowSsh, currentPermissions.allow_ssh);
    if (allowSsh === null) return;
    const banned = readBooleanPermission('banned', body.banned, currentPermissions.banned);
    if (banned === null) return;
    // 聊天媒体（sticker/image/video）开关：独立于 allowUpload（后者只管 DSH 大请求体/
    // 官方上传档位），默认关闭。文本消息不受影响；省略字段时保留当前值。
    const allowChatMedia = readBooleanPermission('allowChatMedia', body.allowChatMedia, currentPermissions.allow_chat_media);
    if (allowChatMedia === null) return;
    // 模型白名单：null = 不限，[] = 禁止全部，非空 = 严格 provider/model。
    // 与 allowedAgentPresets 一致的部分更新语义；保存前正向校验每条记录，
    // 非法项直接 400（不能静默丢弃后让管理员以为已生效）。
    const submittedModels = body.allowedModels;
    if (submittedModels !== undefined && submittedModels !== null && !Array.isArray(submittedModels)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '模型权限必须是数组或 null' });
      return;
    }
    if (
      Array.isArray(submittedModels) &&
      (submittedModels.length > 512 || submittedModels.some((entry) => parseAllowedModelSpec(entry) === null))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '模型权限列表无效，必须是 provider/model' });
      return;
    }
    const allowedModels = submittedModels === undefined
      ? currentPermissions.allowed_models
      : submittedModels === null
        ? null
        : normalizeAllowedModels(submittedModels as string[]);
    let sandboxMode: 'read-only' | 'workspace-write' | 'danger-full-access' | null;
    if (body.sandboxMode === undefined) {
      // 权限卡片/旧客户端可能只提交部分字段；省略沙盒字段必须保留既有
      // 收紧策略，不能把已有 read-only 静默变成“不限制”。显式 null 才表示清除。
      // 损坏的历史值按最严格的 read-only 处理，不能借部分更新把它放宽。
      sandboxMode = currentPermissions.sandbox_mode === 'read-only' ||
        currentPermissions.sandbox_mode === 'workspace-write' ||
        currentPermissions.sandbox_mode === 'danger-full-access'
        ? currentPermissions.sandbox_mode
        : currentPermissions.sandbox_mode === null
          ? null
          : 'read-only';
    } else if (body.sandboxMode === null) {
      sandboxMode = null;
    } else if (
      typeof body.sandboxMode === 'string' &&
      (body.sandboxMode === 'read-only' || body.sandboxMode === 'workspace-write' || body.sandboxMode === 'danger-full-access')
    ) {
      sandboxMode = body.sandboxMode as 'read-only' | 'workspace-write' | 'danger-full-access';
    } else {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'sandboxMode 无效' });
      return;
    }
    const submittedAgentPresets = body.allowedAgentPresets;
    if (submittedAgentPresets !== undefined && submittedAgentPresets !== null && !Array.isArray(submittedAgentPresets)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'Agent preset 权限必须是数组或 null' });
      return;
    }
    if (
      Array.isArray(submittedAgentPresets) &&
      (submittedAgentPresets.length > 256 || submittedAgentPresets.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 200))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'Agent preset 权限列表无效' });
      return;
    }
    const allowedAgentPresets = submittedAgentPresets === undefined
      ? currentPermissions.allowed_agent_presets
      : submittedAgentPresets === null
        ? null
        : [...new Set(submittedAgentPresets as string[])];
    let disabledSessions: string[];
    if (body.disabledSessions === undefined) {
      // 同样遵循部分更新语义。省略 disabledSessions 不得恢复此前被主用户
      // 关闭的会话；显式数组才替换当前集合。
      disabledSessions = [...currentPermissions.disabled_sessions];
    } else if (
      !Array.isArray(body.disabledSessions) ||
      body.disabledSessions.length > 2000 ||
      body.disabledSessions.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 200)
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '禁用会话列表无效' });
      return;
    } else {
      disabledSessions = [...new Set(body.disabledSessions as string[])];
    }
    const expectedDisabledSessions = body.expectedDisabledSessions;
    if (
      expectedDisabledSessions !== undefined &&
      (!Array.isArray(expectedDisabledSessions) ||
        expectedDisabledSessions.length > 2000 ||
        expectedDisabledSessions.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 200))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '禁用会话基线无效' });
      return;
    }
    const disabledSessionsBaseline = expectedDisabledSessions === undefined
      ? [...currentPermissions.disabled_sessions]
      : [...new Set(expectedDisabledSessions as string[])];
    if (body.allowedSessionIds !== undefined && !Array.isArray(body.allowedSessionIds)) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的会话必须是数组' });
      return;
    }
    if (
      Array.isArray(body.allowedSessionIds) &&
      (body.allowedSessionIds.length > 2000 || body.allowedSessionIds.some(
        (id) => typeof id !== 'string' || id.length === 0 || id.length > 200,
      ))
    ) {
      res.status(400).json({ ok: false, code: 'INVALID', error: '允许的会话列表无效' });
      return;
    }
    const sessionAssignmentSubmitted = body.allowedSessionIds !== undefined;
    const previousAllowedSessionIds = db.listUserSessionGrants(userId);
    let allowedSessionIds = sessionAssignmentSubmitted
      ? [...new Set(body.allowedSessionIds as string[])]
      : previousAllowedSessionIds;
    // 旧草稿冲突侦察：UI 撤销会话时必然同时写入 disabledSessions，所以“丢弃了一个
    // 仍然可分配、又未被显式禁用的既有 grant”只可能是另一来源的并发写入（子用户
    // session/create 追加了会话），或者前端拿的是过期快照。两种都必须 fail-closed：
    // 保留服务端 grant 并回 409，让管理员重新同步，而不是静默撤销自己未见过的会话。
    let unackedDroppedGrants: string[] = [];
    // Explicit assignment is a security-sensitive write. The DSH plugin owns
    // the live registry and archive state, so a gateway cache or client draft
    // cannot authorize a deleted/archived session. A missing authority is a
    // 502, never an implicit allow.
    // 只有显式提交 allowedSessionIds 或 allowedFolders 时才需要这份权威核验。
    // 未提交 allowedFolders 时它只是被部分更新保留的既有值：不能因为当前存在目录
    // 就强制探测资源，否则探针不可用会把 banned/quota 等无关字段的保存变成 502。
    const foldersSubmitted = body.allowedFolders !== undefined;
    if (body.allowedSessionIds !== undefined || (foldersSubmitted && allowedFolders.length > 0 && !denyAll)) {
      const resources = await fetchAssignableResources();
      if (resources === null) {
        res.status(502).json({ ok: false, code: 'RESOURCES_UNAVAILABLE', error: '可分配资源暂不可用' });
        return;
      }
      const previousGrants = new Set(previousAllowedSessionIds);
      const assignableSessions = resources.assignableSessions;
      const retainedSessions = resources.retainedSessions;
      const staleSessionIds = allowedSessionIds.filter((id) =>
        !assignableSessions.has(id) && !retainedSessions.has(id) && previousGrants.has(id),
      );
      const invalidSession = allowedSessionIds.find((id) =>
        !assignableSessions.has(id) && !previousGrants.has(id),
      );
      if (invalidSession !== undefined) {
        res.status(400).json({ ok: false, code: 'SESSION_NOT_ASSIGNABLE', error: '会话不存在、已归档或当前不可分配' });
        return;
      }
      if (staleSessionIds.length > 0) {
        // 历史 grant 可能在 DSH 中被归档/删除后仍留在数据库，或被旧客户端
        // 保存回草稿。清理这类永不生效的授权，避免它阻塞同一请求中的有效会话；
        // 从未授权过的未知 ID 仍在上面 fail-closed，不能借此扩大授权。
        const stale = new Set(staleSessionIds);
        allowedSessionIds = allowedSessionIds.filter((id) => !stale.has(id));
      }
      if (sessionAssignmentSubmitted) {
        const submitted = new Set(allowedSessionIds);
        const disabled = new Set(disabledSessions);
        unackedDroppedGrants = previousAllowedSessionIds.filter((id) =>
          assignableSessions.has(id) && !submitted.has(id) && !disabled.has(id),
        );
      }
      if (foldersSubmitted && !denyAll && allowedFolders.some((folder) =>
        !resources.folders.has(normalizePath(folder)) && !isAssignableRealDirectory(folder),
      )) {
        // DSH registry 是正向分配的权威来源：命中即放行（含测试 fixture 的假路径）。
        // 未登记时仅回退到「真实存在 / 目录 / 非根 / 词法+canonical 非敏感」的本地目录；
        // 未知、不存在、敏感与根一律拒绝——绝不用任意目录绕过授权，也不自动 grant 会话。
        res.status(400).json({ ok: false, code: 'WORKSPACE_NOT_ASSIGNABLE', error: '工作区不存在或当前不可分配' });
        return;
      }
    }
    if (unackedDroppedGrants.length > 0) {
      res.status(409).json({
        ok: false,
        code: 'SESSION_GRANTS_CONFLICT',
        error: '会话授权已被并发修改，请刷新后重试',
        allowedSessionIds: db.listUserSessionGrants(userId),
      });
      return;
    }
    // 配额语义："改配额 = 重新给额度"——当 token/时长上限发生变化时
    // 重置该子用户已累计的用量（不同子用户每时段用量不同，改上限应重新计）。
    // 只改文件夹/上传/封禁等非配额字段时不重置（避免误清用量）。
    const prevPerms = effectivePermissions(userId);
    const previousDisabledSessions = disabledSessionsBaseline;
    const quotaChanged =
      prevPerms.hourly_token_limit !== hourlyTokenLimit || prevPerms.daily_minutes_limit !== dailyMinutesLimit;
    const sameStringSet = (left: readonly string[], right: readonly string[]): boolean => {
      const a = new Set(left);
      const b = new Set(right);
      return a.size === b.size && [...a].every((value) => b.has(value));
    };
    const sameFolderSet = (left: readonly string[], right: readonly string[]): boolean => {
      const normalize = (value: string): string => value === '__deny__' ? value : normalizePath(value);
      return sameStringSet(left.map(normalize), right.map(normalize));
    };
    const sameNullableStringSet = (left: readonly string[] | null, right: readonly string[] | null): boolean => {
      if (left === null || right === null) return left === right;
      return sameStringSet(left, right);
    };
    const foldersChanged = !sameFolderSet(prevPerms.allowed_folders, allowedFolders);
    const disabledSessionsChanged = !sameStringSet(prevPerms.disabled_sessions, disabledSessions);
    const sessionGrantsChanged = sessionAssignmentSubmitted && !sameStringSet(previousAllowedSessionIds, allowedSessionIds);
    const sshChanged = prevPerms.allow_ssh !== allowSsh;
    const sandboxChanged = prevPerms.sandbox_mode !== sandboxMode;
    const modelsChanged = !sameNullableStringSet(prevPerms.allowed_models, allowedModels);
    const mediaChanged = prevPerms.allow_chat_media !== allowChatMedia;
    const accessChanged = foldersChanged || disabledSessionsChanged || sessionGrantsChanged || prevPerms.banned !== banned || sandboxChanged;
    const otherPermissionChanged =
      quotaChanged ||
      prevPerms.allow_upload !== allowUpload ||
      prevPerms.allow_git_download !== allowGitDownload ||
      prevPerms.allow_workspace_create !== allowWorkspaceCreate ||
      sshChanged ||
      mediaChanged ||
      modelsChanged ||
      !sameNullableStringSet(prevPerms.allowed_agent_presets, allowedAgentPresets);
    // pending 目录信任窗口（gateway.ts，30 分钟 TTL）是「按创建时权限授予的临时登记
    // 授权」：撤权（foldersChanged）或关闭新建（allowWorkspaceCreate true→false）后必须
    // 立即作废，不能靠 TTL 慢慢过期，否则旧 pending 仍会替 workspace/create 放行登记
    // （登记门禁本身不看 allowWorkspaceCreate）。目录删除的逐树清理语义不受影响，仍由
    // fs/delete-directory 分支按被删树逐条清理。
    const workspaceCreateClosed = prevPerms.allow_workspace_create && !allowWorkspaceCreate;
    const workspaceCreateAuthorityChanged = foldersChanged || workspaceCreateClosed;
    try {
      db.setPermissions(userId, {
        allowedFolders,
        hourlyTokenLimit,
        dailyMinutesLimit,
        allowUpload,
        allowGitDownload,
        allowWorkspaceCreate,
        allowSsh,
        allowedAgentPresets,
        allowedModels,
        allowChatMedia,
        banned,
        sandboxMode,
        disabledSessions,
        ...(sessionAssignmentSubmitted
          ? { allowedSessionIds, sessionGrantsSeeded: true }
          // 仅调整工作区（未提交会话授权）也是显式授权变更：旧数据迁移标记必须在
          // 同一事务置位，否则新分配工作区里的既有会话会在子用户首次基线时被
          // “旧用户迁移”一次性种入授权（Issue #19 迁移只适用于从未被重新保存过
          // 的历史行）。已有 grant 全部保留，绝不被本分支清除。
          : foldersChanged
            ? { sessionGrantsSeeded: true }
            : {}),
        // 基线 = 本请求开始时的集合。上面的 await（资源核验/沙盒注入）期间子用户
        // 可能已追加 grant，或另一管理员已切换 disabled session；数据层在事务内复读
        // 并拒绝用旧集合覆盖任何一类安全集合。
        expectedDisabledSessions: previousDisabledSessions,
        expectedPermissionState,
        ...(sessionAssignmentSubmitted ? { expectedAllowedSessionIds: previousAllowedSessionIds } : {}),
      });
    } catch (error) {
      if (error instanceof PermissionStateConflictError) {
        res.status(409).json({ ok: false, code: 'PERMISSIONS_CONFLICT', error: '权限已被并发修改，请同步后重试' });
        return;
      }
      if (error instanceof SessionGrantsConflictError) {
        if (error.scope === 'disabled_sessions') {
          res.status(409).json({
            ok: false,
            code: 'DISABLED_SESSIONS_CONFLICT',
            error: '禁用会话列表已被并发修改，请刷新后重试',
            disabledSessions: error.currentSessionIds,
          });
        } else {
          res.status(409).json({
            ok: false,
            code: 'SESSION_GRANTS_CONFLICT',
            error: '会话授权已被并发修改，请刷新后重试',
            allowedSessionIds: error.currentSessionIds,
          });
        }
        return;
      }
      throw error;
    }
    // DB 已提交后立即作废该用户的 pending 目录信任窗口：放在沙盒 await 之前，
    // 确保在途创建/登记请求不能借旧窗口继续放行。目录删除的逐树清理仍由
    // fs/delete-directory 分支负责；这里按用户整表清理只处理权限收紧/关闭新建。
    if (workspaceCreateAuthorityChanged) {
      pendingCreatedDirectories.delete(userId);
      // 关闭 allowWorkspaceCreate 时推进 epoch：proxy 的迟到回包防线用「请求开始时 epoch」
      // 复核，只有 epoch 变化才能阻止在途 createDirectory 回包把已清除的 pending 目录重新记账。
      if (workspaceCreateClosed) fenceUserAccessEpoch(userId);
    }
    // DB 已提交后立即切断旧订阅：后续沙盒收紧存在 await，不能让旧的
    // legacy events.mux / Remote carrier 在等待窗口继续发送已撤回业务帧。
    // epoch 栅栏仍用于阻止旧请求快照在 await 后回写授权集合。
    if (accessChanged || sshChanged || otherPermissionChanged) {
      if (accessChanged) {
        fenceUserAccessEpoch(userId);
        invalidateUserSessionAccess(userId);
      }
      if (accessChanged || sshChanged) closeUserRemoteMuxClients(userId);
      closeUserWebSocketClients(userId);
    }
    // alpha.3 在每次工具执行时从 session log 的 sandbox/mode 折叠真实策略。
    // 因此受限子用户的每个会话授权都必须先把 log 里的 sandbox 档位注入到授权级
    // 别，绝不由权限保存隐式提升旧 session。
    // A null historical setting predates this control and may have inherited DSH's
    // broadest mode, so an explicit restrictive setting must be applied to old grants.
    const previousSandboxRank = prevPerms.sandbox_mode === 'read-only'
      ? SANDBOX_RANK['read-only']
      : prevPerms.sandbox_mode === 'workspace-write'
        ? SANDBOX_RANK['workspace-write']
        : SANDBOX_RANK['danger-full-access'];
    const sandboxTightened = sandboxMode !== null && SANDBOX_RANK[sandboxMode] < previousSandboxRank;
    let sandboxRevokedSessionIds: string[] = [];
    if (sandboxMode !== null) {
      const previouslyGranted = new Set(previousAllowedSessionIds);
      // 收紧策略要重写子用户**已经能访问**的会话（历史 grant 的 log 可能带着主用户
      // 的更高档位）。此外，本次**新授权**的会话同样必须注入：主用户把自己创建的
      // 会话共享给受限子用户时，该会话 log 里的 sandbox/mode 是主用户的
      // （danger-full-access 很常见），不注入等于子用户零操作借共享会话提权。
      // 两次注入取并集，任一失败都从授权集合回收（fail-closed）：绝不把未确认
      // 档位的会话留在受限子用户的授权里。
      const tightenedExisting = sandboxTightened
        ? allowedSessionIds.filter((id) => previouslyGranted.has(id))
        : [];
      const newlyGranted = allowedSessionIds.filter((id) => !previouslyGranted.has(id));
      const sessionsToEnforce = [...new Set([...tightenedExisting, ...newlyGranted])];
      sandboxRevokedSessionIds = await applySandboxToSessions(sessionsToEnforce, sandboxMode);
      if (sandboxRevokedSessionIds.length > 0) {
        // 只回收被沙盒策略拒绝的会话；整表替换会抹掉本次 await 期间子用户
        // session/create 并发追加（且并未被拒绝）的会话授权。
        db.deleteUserSessionGrants(userId, sandboxRevokedSessionIds);
        // 上面的 await 窗口里 carrier 已被切断并重连，DSH 可能已凭“grant 仍在 DB”
        // 重建过 workspace baseline；HTTP prompt 只信该内存快照（不复查 DB grant），
        // 会据此继续转发刚被回收的会话。所以删除权威 grant 后必须再次失效快照并
        // 关闭 carrier，让 control baseline、prompt 与列表投影统统从删除后的权威
        // 权限集合重建，绝不允许旧快照在沙盒回收后继续转发。
        invalidateUserSessionAccess(userId);
        closeUserRemoteMuxClients(userId);
        closeUserWebSocketClients(userId);
      }
    }
    // 只有显式提交会话集合时才完成一次性旧数据迁移/初始化；该标记已与权限行和
    // grant 集合在同一事务提交，避免沙盒 await 窗口被首次 baseline 全表种子覆盖。
    // 仅在实际影响会话可见性的权限变化后失效旧快照；同值保存必须是 no-op，
    // 否则设置页的重复提交会反复撕裂 Remote mux 并触发 DSH 无限重连。
    // 连接已在 DB 提交后、沙盒 await 前切断；本处不再重复关闭（同值保存无需撕裂
    // carrier）。只有沙盒失败真正回收 grant 时，才在上方沙盒分支里定向重新失效
    // 快照并关闭 carrier，让删除后的权威 grant 重建 baseline/prompt/投影。
    if (quotaChanged) {
      db.resetUsage(userId);
      // 清掉内存节流缓存：否则 15 秒节流可能跳过新记录的创建，配额暂时不生效
      usageThrottle.delete(userId);
      usageReportThrottle.delete(userId);
    }
    db.audit('permissions_changed', {
      username: target.username,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      detail: JSON.stringify({
        // actor：本次变更的操作者（主用户），username 保留为被改权限的子用户以兼容既有事件格式
        actor: me.username,
        allowedFolders,
        hourlyTokenLimit,
        dailyMinutesLimit,
        allowUpload,
        allowGitDownload,
        allowWorkspaceCreate,
        allowSsh,
        allowedAgentPresets,
        // 审计白名单本身（不是密钥/请求内容），便于事后核查授权变更
        allowedModels,
        allowChatMedia,
        banned,
        sandboxMode,
        disabledSessions,
        allowedSessionIds,
      }),
    });
    res.json({
      ok: true,
      allowedFolders,
      allowedSessionIds: db.listUserSessionGrants(userId),
      disabledSessions,
      sandboxRevokedSessionIds,
      // 回显规范化后的值：管理员看到的就是实际生效的白名单
      allowedModels,
      allowChatMedia,
    });
    } catch (error) {
      console.error('[dsh-passwords] 权限保存异常:', String(error));
      if (!res.headersSent) res.status(500).json({ ok: false, code: 'INTERNAL', error: '权限保存失败' });
    }
  });


  // ── token 用量上报（客户端 liveTokenUsage 投影增量，所有登录用户） ──
  // 替代旧的 HTTP 响应正则计量：客户端复用 dsh 的 tokenUsage 投影（与
  // dsh-web-ui 同源），只上报「增量」，服务端按小时窗口累计并用于配额判定。
  app.post('/gateway/api/usage/report', jsonBody, (req, res) => {
    const me = apiAuth(req, res);
    if (!me) return;
    const now = Date.now();
    const last = usageReportThrottle.get(me.userId) ?? 0;
    if (now - last < 5000) {
      res.status(429).json({ ok: false, code: 'RATE_LIMITED', error: '上报过于频繁' });
      return;
    }
    usageReportThrottle.set(me.userId, now);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const tokens = Number(body.tokens);
    if (!Number.isFinite(tokens) || tokens < 0 || tokens > 100_000_000) {
      res.status(400).json({ ok: false, code: 'INVALID', error: 'tokens 无效' });
      return;
    }
    const rounded = Math.round(tokens);
    if (rounded <= 0) {
      res.json({ ok: true });
      return;
    }
    db.addTokens(me.userId, todayLocal(), rounded, new Date().toISOString());
    res.json({ ok: true });
  });

  return { usageReportThrottle };
}
