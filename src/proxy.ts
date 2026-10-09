// 反向代理（HTTP + WebSocket）模块：由 src/gateway.ts 机械拆分而来。
//
// 反向代理 HTTP/WS 逻辑已由 gateway.ts 接入。认证门卫、共享授权状态、周期清理外壳
// 与端点热更新仍由 gateway.ts 持有；本模块通过 ProxyDeps 显式接收同一引用。
//
// 拆分边界：HTTP 代理响应/请求处理、沙盒注入、WebSocket upgrade 与 Remote mux
// 连接逻辑位于本模块；Map/Set 不复制，可变 let 通过 getter/setter 或 bump 访问器读取。
//
// 本模块与原实现之间的受控改写如下（其余路由与授权逻辑保持机械迁移）：
//   - [ready-write] "archivedSessionSnapshotReady = true;" -> "setArchivedSessionSnapshotReady(true);" x1
//   - [ready-read] "!archivedSessionSnapshotReady" -> "!getArchivedSessionSnapshotReady()" x1
//   - [rev-write] "archivedSessionSnapshotRevision = requestRevision;" -> "setArchivedSessionSnapshotRevision(requestRevision);" x1
//   - [rev-read] "requestRevision >= archivedSessionSnapshotRevision" -> "requestRevision >= getArchivedSessionSnapshotRevision()" x1
//   - [wlr-bump] "? ++workspaceListRequestRevision" -> "? bumpWorkspaceListRequestRevision()" x1

//   - [endpointRules-http] "endpointRules" -> "getEndpointRules()" x1
//   - [hdm-known] "hostDefaultModelKnown" -> "getHostDefaultModelKnown()" x1
//   - [hdm] "hostDefaultModel" -> "getHostDefaultModel()" x1
//   - [uac-http] "upstreamAuthCookie" -> "getUpstreamAuthCookie()" x1
//   - [endpointRules-ws] "endpointRules," -> "endpointRules: getEndpointRules()," x1
//   - [uac-ws] "upstreamAuthCookie" -> "getUpstreamAuthCookie()" x2
import http, { type IncomingMessage, type IncomingHttpHeaders } from 'node:http';
import https from 'node:https';
import { type Duplex, type Transform } from 'node:stream';
import net from 'node:net';
import { URL } from 'node:url';
import zlib from 'node:zlib';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { connect as tlsConnect } from 'node:tls';
import { type Application, type Request, type Response } from 'express';
import { createRequire } from 'node:module';
import type { AuthService } from './auth.js';
import { MuxHeartbeat, type MuxHeartbeatCloseSource, type MuxHeartbeatOptions, type MuxHeartbeatSocket } from './remote-mux-heartbeat.js';
import { createRemoteMuxDiagnosticsSession, type RemoteMuxCloseSource, type RemoteMuxStallKind } from './remote-mux-diagnostics.js';
import { MuxSender, MuxSenderBudget, type MuxAcceptOutcome, type MuxFragmentSocket, type MuxRejectKind } from './remote-mux-sender.js';
import { loadingTimeline, eventLoopDelaySampler } from './loading-timeline.js';
import { samePathForMatch, type Database, type UserPermissionsRow } from './db.js';
import type { Lang } from './i18n.js';
import { t } from './i18n.js';
import {
  clampSessionHistorySandbox,
  classifySubuserPath,
  dynamicPluginApiPath,
  dynamicPluginRootPath,
  OFFICIAL_API_NAMESPACES,
  isSubuserBlockedRemoteEndpoint,
  isSubuserBlockedApiPath,
  clientConnectionArgs,
  collectAuthorizedSessionIds,
  collectIdPathPairs,
  collectSessionCwd,
  collectSessionCwdFromWorkspaces,
  collectSessionIds,
  directoryEntryVisible,
  endpointAllowed,
  extractPathFromBody,
  extractDirectoryCreatePath,
  extractWorkspaceCreatePath,
  extractSessionId,
  extractWorkspaceId,
  extractWorkspaceRenamePaths,
  filterArchivedSessionIds,
  filterByPathFieldWithPredicate,
  filterOwnedSessionIds,
  filterSessionItems,
  filterSessionSearchItems,
  findStringField,
  folderAllowed,
  forceRejectApproval,
  isDirectoryListRequest,
  isWorkspaceCreate,
  isWorkspaceDeleteOrRename,
  isWorkspaceDirectoryCreate,
  isWorkspaceOrderWrite,
  isWorkspaceRestricted,
  isAbsoluteLikePath,
  isFilesystemRootPath,
  isFullyQualifiedPath,
  normalizePath,
  parseSessionAddress,
  pathWithin,
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  replaceArchivedSessionSnapshot,
  SANDBOX_RANK,
  sandboxPresetRank,
  SESSION_SCOPED_RE,
  WORKSPACE_ENDPOINT_RE,
  workspaceRegistrationAllowed,
} from './permissions.js';

// 与 gateway.ts L24 + L32-L43 逐字一致：ws 是 CJS 包，无 ESM 具名导出，
// 必须经 createRequire 取回并手写形状（含 noServer WebSocketServer）。
const require = createRequire(import.meta.url);

const WebSocket = require('ws') as {
  OPEN: number;
  WebSocket: new (url: string, options?: {
    headers?: Record<string, string>;
    rejectUnauthorized?: boolean;
    agent?: any;
    maxPayload?: number;
  }) => any;
  WebSocketServer: new (options: { noServer: true; maxPayload?: number }) => {
    handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, callback: (client: any) => void): void;
  };
};

/** ws readyState 的 CLOSING（RFC 6455 / WHATWG = 2）。手写形状沿用 gateway.ts 只声明 OPEN，
 *  而关闭握手判定另需区分「已进入 CLOSING」与「无法再握手」，故在此显式命名。 */
const WS_CLOSING = 2;

/** 与 gateway.ts L111-L137 逐字一致（结构类型，跨模块兼容）。 */
/** 网关内部扩展请求：权限执行时把用户/权限附在 req 上，供后续中间件与代理读取 */
type Req = Request & {
  dshpwUser?: number;
  /** 已认证用户名（审计 actor）；权限行仍只挂子用户。 */
  dshpwUsername?: string;
  dshpwPerms?: UserPermissionsRow;
  /** 会话目录白名单校验用：本次请求判定出的目标工作区路径（session.create/fork 时）；
   *  由 needsFolderCheck 写入，供 session.create 响应回调记录 sessionId→cwd 缓存 */
  dshpwSessionCwd?: string;
  /** fork 的源会话已通过逐会话授权校验，响应中的新会话可登记到当前用户快照。 */
  dshpwForkAuthorized?: boolean;
  /** 工作区管理请求通过白名单校验后的目标路径。 */
  dshpwWorkspacePath?: string;
  dshpwWorkspaceCreate?: boolean;
  dshpwWorkspaceOrderId?: string;
  dshpwWorkspaceOrderPath?: string;
  dshpwWorkspaceOldPath?: string;
  dshpwWorkspaceNewPath?: string;
  dshpwIsAdmin?: boolean;
  /** 当前 create/fork 请求已验证的 agent preset，供成功响应登记。 */
  dshpwAgentPreset?: string;
  dshpwSelectedSessionId?: string;
  /** Preallocated session identity used to bridge the create/follow race. */
  dshpwCreatedSessionId?: string;
  /** session/selectModel 已通过白名单校验的会话 ID；响应回调用它登记会话有效模型。 */
  dshpwModelSessionId?: string;
  /** directoryPicker/list 响应过滤：authorized 只逐条过滤敏感/他人子树；ancestors 再按授权根裁剪条目与 crumbs。 */
  dshpwDirListFilter?: {
    mode: 'authorized' | 'ancestors';
    /** 授权可读根（canonical 形态）：条目可见性与导航判定。 */
    readRoots: string[];
    /** 入口注入用的词法根（readable roots）。 */
    injectRoots: string[];
    showRoots?: boolean;
  };

};

/** 与 gateway.ts L435 逐字一致。 */
type AllowedModelSpec = { readonly provider: string; readonly model: string };

/** 与 gateway.ts L690-L697 逐字一致。 */
type OriginRequest = {
  headers: {
    origin?: string | string[];
    host?: string | string[];
    'x-forwarded-host'?: string | string[];
  };
  socket: { remoteAddress?: string | null };
};

/** 与 gateway.ts L2199-L2223 + L2224-L2228 逐字一致。 */
type RemoteMuxUserStreamState = {
  streamId: string;
  endpoint: string;
  jobSessionId?: string;
  jobId?: string;
  jobOwnerConfirmed?: boolean;
  /** Workspace path is retained only to re-check the current permission on each delta. */
  workspaceFileScopeId?: string;
  workspaceFileRoot?: string;
  workspaceFileTarget?: string;
  workspaceFileRootCanonical?: string;
  workspaceFileTargetCanonical?: string;
  workspaceFileReady?: boolean;
  visibleWorkspaces: Map<string, string>;
  /** Authorized ordinary session or child session identity for session/follow. */
  followAddress?: ReturnType<typeof parseSessionAddress>;
  /** Exactly one alpha.1 snapshot must precede history/live frames. */
  followSnapshotSeen?: boolean;
  /** Last filtered workspace rows, used for a compensating attach after session/create. */
  visibleWorkspaceRows: Map<string, Record<string, unknown>>;
  /** The protocol has one bootstrap item; later ready frames are never data-plane events. */
  remoteEventsReady?: boolean;
  /** The DSH Remote generation that may submit a result for its waterfall events. */
  remoteEventsClientId?: string;
};
type RemoteMuxUserConnection = {
  socket: any;
  publishSessionAttachment: (sessionId: string, cwd: string) => void;
  publishWorkspaceUpsert: (workspace: Record<string, unknown>) => void;
  /**
   * 权限/身份撤销的受限入口：gateway 在下发 socket.close 之前调用它，立即 dispose 两条腿的
   * 发送器与心跳、把诊断首因锁定为 permission-revoked 并 arm 5s grace，避免关闭握手完成前
   * 旧 carrier 继续携带已撤销的授权快照。只接受受限的关闭码，不向调用方暴露
   * active/发送器/诊断等内部状态；重复调用幂等。
   */
  teardownCarrier: (code?: number) => void;
};

/** WebSocket.OPEN；有界发送 helper 不依赖 ws，故本地保留常量。 */
const MUX_SOCKET_OPEN = 1;

/**
 * MuxSender 用户态写入前导水位（传输规格 §3.1）：分片模式下把已提交给 ws/Node 的
 * `bufferedAmount` 压在 256 KiB 内，降到 128 KiB 再续片。它们是**用户态**前导指标，与
 * 共享预队列 `REMOTE_MUX_MAX_PENDING_BYTES`（2 MiB）及单条/接受容量预算相互独立，不得混用。
 */
const REMOTE_MUX_HIGH_WATER_BYTES = 256 * 1024;
const REMOTE_MUX_LOW_WATER_BYTES = 128 * 1024;

/** Remote mux 有界发送所需的最小 socket 面（生产为 ws 连接，测试为 stub）。 */
export type MuxBufferedSocket = {
  readonly readyState: number;
  readonly bufferedAmount: number;
  /**
   * 写出一个文本帧。`onFlush` 在该帧的**本地写入完成**后回调：成功即一次可解释的
   * 本地写入进度；带 error 表示本地写入失败，不是进度，调用方按各自 send failure 路径处理。
   */
  send(data: string, onFlush?: (error?: Error) => void): void;
};

export type MuxSendOutcome = 'sent' | 'skipped' | 'oversized' | 'backpressure' | 'failed';

/**
 * Remote mux 两侧共用的有界发送。`bufferedAmount` 是 socket 内尚未冲出的字节：
 * 总积压上限为 `limit + maxFrameBytes`，即正常待发送余量再加一个最大合法帧，
 * 允许单个历史快照及其后的帧正常排队，但不能让多个慢消费帧无界累积。检查写入后的
 * 预计总量，超过上限时调用方以 1013 关闭。单帧自身超限与聚合背压分开返回，便于
 * 下行把单个逻辑流隔离，而不误杀共享 carrier。`onFlush` 是写出帧的本地写入完成回调
 * （ws 的 send 回调）：成功表示一次可解释的本地写入进度，带 error 不是进度。返回：
 *  - 'sent'         写出（顺序不变）；
 *  - 'skipped'      socket 非 OPEN，未写出也无需收尾；
 *  - 'oversized'    单帧超过最大合法帧大小；
 *  - 'backpressure' 写入后会超过聚合缓冲上限，调用方以 1013 关闭；
 *  - 'failed'       `send` 抛异常，调用方以 1011 关闭。
 */
export function sendMuxFrameBounded(
  socket: MuxBufferedSocket,
  text: string,
  limit: number,
  maxFrameBytes: number,
  onFlush?: (error?: Error) => void,
): MuxSendOutcome {
  if (socket.readyState !== MUX_SOCKET_OPEN) return 'skipped';
  const frameBytes = Buffer.byteLength(text);
  if (frameBytes > maxFrameBytes) return 'oversized';
  if (socket.bufferedAmount + frameBytes > limit + maxFrameBytes) return 'backpressure';
  try {
    socket.send(text, onFlush);
  } catch {
    return 'failed';
  }
  return 'sent';
}
/**
 * 跨块依赖注入面。共注入 117 个符号：107 项值/函数容器
 * + 10 项 get/set/bump 访问器（被迁代码会读写的可变 let）。全部来自 gateway.ts 的
 * createGatewayServer 闭包或其导入项——本模块自身不复制任何授权状态。
 */
export function upstreamResponseHeaderTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS ?? '');
  return Number.isFinite(raw) && raw >= 1 && raw <= 600_000 ? raw : 60_000;
}

export interface ProxyDeps {
  db: Database;
  auth: AuthService;
  AGENT_PRESET_LIST_RE: RegExp;
  AGENT_PRESET_MUTATION_RE: RegExp;
  AGENT_PRESET_SELECT_RE: RegExp;
  agentPresetFromRequest: (value: unknown) => string | null;
  allowedModelSet: (allowed: readonly string[] | null) => Set<string> | null;
  archivedSessionSnapshot: Set<string>;
  authorizedSubuserSessionRoot: (userId: number, sessionId: unknown, perms: UserPermissionsRow) => string | null;
  authorizedWorkspaceFileChangeTarget: (userId: number, perms: UserPermissionsRow, request: { scopeId: string; path: string; }) => { scopeId: string; root: string; target: string; rootCanonical: string; targetCanonical: string; } | null;
  canonicalizePathBestEffort: (candidate: string) => string;
  clearPendingCreatedSession: (userId: number, sessionId: string) => void;
  closeUserRemoteMuxClients: (userId: number, code?: number, reason?: string) => void;
  collectSessionAgentPresets: (value: unknown, target: Map<string, string>, depth?: number) => void;
  COOKIE_NAME: "dsh_gateway_token";
  effectivePermissions: (userId: number) => UserPermissionsRow;
  effectiveSessionModel: (sessionId: string) => AllowedModelSpec | null;
  ensureSessionCreateId: (value: unknown, generatedId: string) => string | null;
  escapeHtml: (value: string) => string;
  filterEventWebSocketFrame: (userId: number, perms: UserPermissionsRow, channel: "host" | "mux", data: Buffer) => Buffer | null;
  filterModelCatalogValue: (value: unknown, allowed: readonly string[] | null) => unknown;
  filterRemoteMuxUserItem: (userId: number, fallbackPerms: UserPermissionsRow, state: RemoteMuxUserStreamState, value: unknown) => unknown | null;
  forbiddenPage: (lang: Lang, message: string) => string;
  forceRejectRemoteEventOutcome: (value: unknown) => boolean;
  gatePathOf: (reqUrl: string) => string;
  hasImageAttachment: (value: unknown) => boolean;
  hostEventFilter: (userId: number, perms: UserPermissionsRow) => Transform;
  INJECT_SCRIPT: string;
  isPlainJsonRecord: (value: unknown) => value is Record<string, unknown>;
  isSensitivePath: (candidate: string) => boolean;
  isTokenRevoked: (token: string) => boolean;
  langOf: (req: Request) => Lang;
  mergeAuthorizedAccess: (userId: number, perms: UserPermissionsRow, grants: ReadonlySet<string>, visible: ReadonlyMap<string, string>) => Map<string, string>;
  mergeWorkspacePaths: (userId: number, perms: UserPermissionsRow, visible: ReadonlyMap<string, string>) => Map<string, string>;
  MODEL_CATALOG_RE: RegExp;
  modelChoiceVerdict: (allowed: readonly string[] | null, selection: AllowedModelSpec | null) => { ok: boolean; reason: "unrestricted" | "allowed" | "denied" | "unknown" | "empty"; };
  modelSelectionFrom: (value: unknown) => AllowedModelSpec | null;
  muxEventFilter: (userId: number, perms: UserPermissionsRow) => Transform;
  normalizeDecodedPath: (rawPath: string) => string;
  OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS: Set<string>;
  OFFICIAL_JOB_REMOTE_ENDPOINTS: Set<string>;
  OFFICIAL_TERMINAL_HTTP_RE: RegExp;
  OFFICIAL_TERMINAL_REMOTE_ENDPOINTS: Set<string>;

  originHostMatches: (req: OriginRequest) => boolean;
  parseRemoteMuxClientFrame: (data: Buffer, allowAnyEndpoint: boolean) => { type: "open"; streamId: string; endpoint: string; payload: unknown; } | { type: "cancel"; streamId: string; } | { type: "item"; streamId: string; value?: unknown; } | { type: "end"; streamId: string; } | null;
  parseRemoteMuxServerFrame: (data: Buffer) => ({ type: "item"; streamId: string; value?: unknown; } | { type: "end"; streamId: string; } | { type: "error"; streamId: string; error: Record<string, unknown>; }) | null;
  pendingCreatedDirectoryPaths: (userId: number) => string[];
  pendingCreatedSessionFor: (userId: number) => Map<string, { cwd: string; expiresAt: number; }>;
  pendingCreatedSessions: Map<number, Map<string, { cwd: string; expiresAt: number; }>>;
  readCookie: (cookieHeader: string | undefined, name: string) => string | null;
  recordHostDefaultModel: (catalog: unknown) => void;
  recordPendingCreatedDirectory: (userId: number, canonicalPath: string) => void;
  recordSessionModelSelection: (sessionId: string, selection: AllowedModelSpec | null) => void;
  registerUserWebSocketClient: (userId: number, client: { close: (code?: number, reason?: string) => void; }) => (() => void);
  registryAuthorizedSockets: Set<Duplex>;
  REMOTE_MUX_FRAGMENT_BYTES: number;
  REMOTE_MUX_PING_INTERVAL_MS: number;
  REMOTE_MUX_PONG_TIMEOUT_MS: number;
  REMOTE_MUX_WRITE_STALL_MS: number;
  REMOTE_MUX_MAX_PAYLOAD_BYTES: number;
  REMOTE_MUX_MAX_PENDING_BYTES: number;
  REMOTE_MUX_MAX_STREAMS: 64;
  remoteAccountRequestIsEmpty: (payload: unknown) => boolean;
  remoteEventOwnership: Map<string, { userId: number; clientId: string; sessionId: string; expiresAt: number; }>;
  remoteEventOwnershipKey: (eventId: string, clientId: string) => string;
  remoteJobRequest: (payload: unknown, endpoint: "job/list" | "job/follow") => { sessionId?: string; jobId?: string; from?: number; } | null;
  remoteMuxClientsByUser: Map<number, Set<RemoteMuxUserConnection>>;
  remoteMuxEmptyArgs: (payload: unknown) => boolean;
  remoteMuxFollowAddress: (payload: unknown) => ReturnType<typeof parseSessionAddress>;
  remoteMuxStreamEndpoints: Set<string>;
  remoteMuxSubuserRejectedEndpoints: Map<string, { code: string; message: string; }>;
  remoteWorkspaceFileChangeRequest: (payload: unknown) => { scopeId: string; path: string; } | null;
  /** 返回是否被 epoch/order 栅栏接受；同源派生快照必须复用该结果。 */
  replaceUserSessionAccess: (userId: number, access: Map<string, string>, epoch: number, order?: number) => boolean;
  replaceUserWorkspacePaths: (userId: number, paths: Map<string, string>, epoch: number, order?: number) => void;
  requestBodyLimitFor: (role: "admin" | "user", allowLargeBody: boolean) => number;
  resolveUpstreamHostSafe: (host: string) => Promise<"private" | string | null>;
  resolveWorkspaceFileTarget: (root: string, requestedPath: string, relativePath: string | null) => string | null;
  rpcRequestPayload: (value: unknown) => Record<string, unknown> | null;
  sanitizeHiddenUnicodeJson: (value: unknown, depth?: number) => unknown;
  sessionAgentPresetMapFor: (userId: number) => Map<string, string>;
  sessionAuthorizationId: (address: NonNullable<ReturnType<typeof parseSessionAddress>>) => string;
  sessionCwdById: Map<string, string>;
  sessionFollowIdentityAllowed: (userId: number, address: NonNullable<ReturnType<typeof parseSessionAddress>>) => boolean;
  stripGatewayAuthQuery: (rawUrl: string, pathname: string) => string;
  upstream: URL;
  upstreamAgent: http.Agent;
  upstreamAuthority: string;
  upstreamCookieHeader: (browserCookie: string | undefined, authoritativeCookie: string) => string | undefined;
  upstreamHost: string;
  upstreamIsHttps: boolean;
  upstreamPort: number;
  upstreamScheme: "https" | "http";
  upstreamTransport: typeof https | typeof http;
  upstreamWsOptions: () => { headers: Record<string, string>; rejectUnauthorized?: boolean; agent?: any; maxPayload: number; perMessageDeflate?: false; };
  userAccessEpochFor: (userId: number) => number;
  userArchivedSessionIds: Map<number, Set<string>>;
  userSessionAccess: Map<number, Map<string, string>>;
  userSessionAccessFor: (userId: number) => Map<string, string>;
  userWorkspaceIds: Map<number, Set<string>>;
  userWorkspacePaths: Map<number, Map<string, string>>;
  waitForUserSessionAccess: (userId: number, timeoutMs?: number, requireWorkspacePaths?: boolean) => Promise<boolean>;
  WORKSPACE_FILES_RPC_RE: RegExp;
  workspaceFileScopeRequest: (value: unknown, readBytes: boolean) => { scopeId: string; path: string; relativePath: string | null; baseFile: string | null; } | null;
  workspaceOwnedByAnotherSubuser: (userId: number, workspacePath: string) => boolean;
  workspaceOwnedByUser: (userId: number, workspacePath: string) => boolean;
  workspacePathById: Map<string, string>;
  workspaceSubtreeOverlap: (userId: number, workspacePath: string) => boolean;
  /** 沙盒注入用内部凭据（原 config.internalSecret）。 */
  internalSecret: string;
  getEndpointRules(): readonly string[];
  getDynamicPluginManifest(): import('./permissions.js').DynamicPluginManifest | undefined;
  getUpstreamAuthCookie(): string;
  getHostDefaultModel(): AllowedModelSpec | null;
  getHostDefaultModelKnown(): boolean;
  getArchivedSessionSnapshotReady(): boolean;
  setArchivedSessionSnapshotReady(v: boolean): void;
  getArchivedSessionSnapshotRevision(): number;
  setArchivedSessionSnapshotRevision(v: number): void;
  bumpWorkspaceListRequestRevision(): number;
}

/** 沙盒注入所需的窄接口（供 admin 复用，见文件末尾说明）。 */
export interface SandboxApplierDeps {
  upstreamTransport: typeof https | typeof http;
  upstreamHost: string;
  upstreamPort: number;
  internalSecret: string;
}

export interface ProxyRoutesHandle {
  /** 挂载 WebSocket upgrade 代理（在 http/https server 创建后调用）。 */
  attachUpgrade(server: UpgradeCapableServer): void;
  /** 周期清理钩子。本轮拆分后本模块不持有服务级可清理状态（见实现注释）。 */
  sweep(now: number): void;
}

/** 结构化 server 面：http.Server 与 https.Server 均满足。 */
export interface UpgradeCapableServer {
  on(event: 'upgrade', listener: (req: IncomingMessage, socket: Duplex, head: Buffer) => void): unknown;
}

/**
 * 沙盒注入器工厂。gateway.ts 用它构造 applySandboxToSessions 注入
 * admin（原 L3329 的 admin deps 项），registerProxyRoutes 内部同源构造。
 */
export function createSandboxApplier(deps: SandboxApplierDeps): {
  applySandboxToSession(sessionId: string, mode: string): Promise<boolean>;
  applySandboxToSessions(sessionIds: readonly string[], mode: string): Promise<string[]>;
} {
  const { upstreamTransport, upstreamHost, upstreamPort, internalSecret } = deps;
  /**
   * F-26：向 dsh 注入会话沙盒，并等待插件确认。
   * 受限子用户的新会话在确认前仍是 DSH 默认 sandbox；若此处 fire-and-forget，
   * 内部调用失败后会把比授权更宽松的会话成功交给用户。因此失败必须让创建请求
   * 失败，不能把未确认的会话当作可用会话返回。
   */
  function applySandboxToSession(sessionId: string, mode: string): Promise<boolean> {
    return new Promise((resolve) => {
      const body = JSON.stringify({ sessionId, mode });
      let settled = false;
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        resolve(ok);
      };
      const r = upstreamTransport.request(
        {
          hostname: upstreamHost,
          port: upstreamPort,
          path: '/api/dsh-passwords/internal/sandbox',
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': String(Buffer.byteLength(body)),
            'x-internal-secret': internalSecret,
          },
          timeout: 3000,
        },
        (response) => {
          response.resume();
          finish((response.statusCode ?? 500) >= 200 && (response.statusCode ?? 500) < 300);
        },
      );
      r.on('error', (error) => {
        console.error(`[dsh-passwords] 沙盒注入失败 session=${sessionId} mode=${mode}: ${error?.message ?? error}`);
        finish(false);
      });
      r.on('timeout', () => {
        r.destroy();
        finish(false);
      });
      r.end(body);
    });
  }

  /**
   * Do not serialize up to 2,000 internal requests behind a permission-save HTTP
   * request. A small fixed pool bounds upstream pressure while preserving the
   * fail-closed contract: every failed confirmation is returned for grant revocation.
   */
  async function applySandboxToSessions(sessionIds: readonly string[], mode: string): Promise<string[]> {
    const failed: string[] = [];
    let cursor = 0;
    const workerCount = Math.min(16, sessionIds.length);
    const worker = async (): Promise<void> => {
      while (true) {
        const index = cursor;
        cursor += 1;
        if (index >= sessionIds.length) return;
        const sessionId = sessionIds[index];
        if (!(await applySandboxToSession(sessionId, mode))) failed.push(sessionId);
      }
    };
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return failed;
  }
  return { applySandboxToSession, applySandboxToSessions };
}

/**
 * `/api/schedule/catalog`（点号/斜杠两种官方写法同口径）。
 *
 * `catalog` 无参（`() => …`），返回宿主**全局**的活跃/非活跃提醒，value 是裸数组，
 * 每个条目带原始 `sessionId`（ScheduleCatalogEntry）。它不在 SESSION_SCOPED_RE 里
 * （wire 里没有会话身份可校验），所以必须在网关解析响应、逐条按 sessionId 过滤：
 * 官方命名空间分类对子用户放行，授权边界完全落在本响应过滤器上（fail-closed）。
 */
const SCHEDULE_CATALOG_RE = /^\/api\/schedule[.\/]catalog$/;

/**
 * 子用户目录浏览/创建的路径必须“完全限定”：POSIX 下为绝对路径；Windows 下只有盘符限定
 * （`C:\…`）或完整 UNC（`\\server\share…`）才算——`\foo`、`/foo` 这类 rooted 形式会落到
 * 进程当前盘符，属于含糊输入，拒绝以免与授权根判定错位（与 DSH `fullyQualified` 同口径）。
 */

export function registerProxyRoutes(app: Application, deps: ProxyDeps): ProxyRoutesHandle {
  const processMuxBudget = new MuxSenderBudget(512 * 1024 * 1024);
  const {
    db,
    auth,
    AGENT_PRESET_LIST_RE,
    AGENT_PRESET_MUTATION_RE,
    AGENT_PRESET_SELECT_RE,
    agentPresetFromRequest,
    allowedModelSet,
    archivedSessionSnapshot,
    authorizedSubuserSessionRoot,
    authorizedWorkspaceFileChangeTarget,
    canonicalizePathBestEffort,
    clearPendingCreatedSession,
    closeUserRemoteMuxClients,
    collectSessionAgentPresets,
    COOKIE_NAME,
    effectivePermissions,
    effectiveSessionModel,
    ensureSessionCreateId,
    escapeHtml,
    filterEventWebSocketFrame,
    filterModelCatalogValue,
    filterRemoteMuxUserItem,
    forbiddenPage,
    forceRejectRemoteEventOutcome,
    gatePathOf,
    hasImageAttachment,
    hostEventFilter,
    INJECT_SCRIPT,
    isPlainJsonRecord,
    isSensitivePath,
    isTokenRevoked,
    langOf,
    mergeAuthorizedAccess,
    mergeWorkspacePaths,
    MODEL_CATALOG_RE,
    modelChoiceVerdict,
    modelSelectionFrom,
    muxEventFilter,
    normalizeDecodedPath,
    OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS,
    OFFICIAL_JOB_REMOTE_ENDPOINTS,
    OFFICIAL_TERMINAL_HTTP_RE,
    OFFICIAL_TERMINAL_REMOTE_ENDPOINTS,

    originHostMatches,
    parseRemoteMuxClientFrame,
    parseRemoteMuxServerFrame,
    pendingCreatedDirectoryPaths,
    pendingCreatedSessionFor,
    pendingCreatedSessions,
    readCookie,
    recordHostDefaultModel,
    recordPendingCreatedDirectory,
    recordSessionModelSelection,
    registerUserWebSocketClient,
    registryAuthorizedSockets,
    REMOTE_MUX_FRAGMENT_BYTES,
    REMOTE_MUX_MAX_PAYLOAD_BYTES,
    REMOTE_MUX_MAX_PENDING_BYTES,
    REMOTE_MUX_MAX_STREAMS,
    REMOTE_MUX_PING_INTERVAL_MS,
    REMOTE_MUX_PONG_TIMEOUT_MS,
    REMOTE_MUX_WRITE_STALL_MS,
    remoteAccountRequestIsEmpty,
    remoteEventOwnership,
    remoteEventOwnershipKey,
    remoteJobRequest,
    remoteMuxClientsByUser,
    remoteMuxEmptyArgs,
    remoteMuxFollowAddress,
    remoteMuxStreamEndpoints,
    remoteMuxSubuserRejectedEndpoints,
    remoteWorkspaceFileChangeRequest,
    replaceUserSessionAccess,
    replaceUserWorkspacePaths,
    requestBodyLimitFor,
    resolveUpstreamHostSafe,
    resolveWorkspaceFileTarget,
    rpcRequestPayload,
    sanitizeHiddenUnicodeJson,
    sessionAgentPresetMapFor,
    sessionAuthorizationId,
    sessionCwdById,
    sessionFollowIdentityAllowed,
    stripGatewayAuthQuery,
    upstream,
    upstreamAgent,
    upstreamAuthority,
    upstreamCookieHeader,
    upstreamIsHttps,
    upstreamScheme,
    upstreamWsOptions,
    userAccessEpochFor,
    userArchivedSessionIds,
    userSessionAccess,
    userSessionAccessFor,
    userWorkspaceIds,
    userWorkspacePaths,
    waitForUserSessionAccess,
    WORKSPACE_FILES_RPC_RE,
    workspaceFileScopeRequest,
    workspaceOwnedByAnotherSubuser,
    workspaceOwnedByUser,
    workspacePathById,
    workspaceSubtreeOverlap,
    getEndpointRules,
    getDynamicPluginManifest,
    getUpstreamAuthCookie,
    getHostDefaultModel,
    getHostDefaultModelKnown,
    getArchivedSessionSnapshotReady,
    setArchivedSessionSnapshotReady,
    getArchivedSessionSnapshotRevision,
    setArchivedSessionSnapshotRevision,
    bumpWorkspaceListRequestRevision,
  } = deps;
  const { upstreamTransport, upstreamHost, upstreamPort } = deps;
  const { applySandboxToSession } = createSandboxApplier(deps);

  /**
   * 受限子用户实际生效的沙盒档位：请求进入时的权限快照与转发前的当前权限行取
   * 更严一档。管理员可能在请求在途（或会话已授权之后）收紧沙盒，绝不让任一时刻
   * 策略之外的宽档位落到会话上；未知值不参与判定（由调用方 fail-closed 处理）。
   */
  function strictestSandboxMode(
    snapshotMode: string | null | undefined,
    currentMode: string | null | undefined,
  ): keyof typeof SANDBOX_RANK | null {
    const modes = [snapshotMode, currentMode].filter(
      (mode): mode is keyof typeof SANDBOX_RANK =>
        typeof mode === 'string' && Object.hasOwn(SANDBOX_RANK, mode),
    );
    return modes.reduce<keyof typeof SANDBOX_RANK | null>(
      (strictest, mode) => strictest === null || SANDBOX_RANK[mode] < SANDBOX_RANK[strictest] ? mode : strictest,
      null,
    );
  }

  // ── 子用户删除自建工作区后的内存收口 ──────────────────────────────
  // 30 分钟 pending 目录窗口只存在内存中（gateway.ts），proxy 侧拿不到可写引用；
  // 删除成功后把该路径记入本地墓碑，使它不再能借残留 pending 重新登记。只有重新
  // 通过目录选择器创建同名目录（recordPendingCreatedDirectory 成功）才解除。
  // 键用 canonicalizePathBestEffort 同一口径，避免别名/大小写导致墓碑命中不一致。
  const deletedOwnedWorkspacePaths = new Map<number, Set<string>>();
  const deletedOwnedWorkspaceKey = (candidate: string): string =>
    normalizePath(canonicalizePathBestEffort(candidate));
  const markDeletedOwnedWorkspace = (userId: number, workspacePath: string): void => {
    let set = deletedOwnedWorkspacePaths.get(userId);
    if (set === undefined) {
      set = new Set();
      deletedOwnedWorkspacePaths.set(userId, set);
    }
    if (set.size >= 256 && !set.has(deletedOwnedWorkspaceKey(workspacePath))) {
      const oldest = set.values().next().value;
      if (typeof oldest === 'string') set.delete(oldest);
    }
    set.add(deletedOwnedWorkspaceKey(workspacePath));
  };
  const clearDeletedOwnedWorkspace = (userId: number, workspacePath: string): void => {
    const set = deletedOwnedWorkspacePaths.get(userId);
    if (set === undefined) return;
    set.delete(deletedOwnedWorkspaceKey(workspacePath));
    if (set.size === 0) deletedOwnedWorkspacePaths.delete(userId);
  };
  /** pending 目录授权（workspace/create 的 30 分钟信任窗口）减去已删除的自建工作区。 */
  const visiblePendingCreatedDirectories = (userId: number): string[] => {
    const deleted = deletedOwnedWorkspacePaths.get(userId);
    const pending = pendingCreatedDirectoryPaths(userId);
    if (deleted === undefined || deleted.size === 0) return pending;
    return pending.filter((entry) => !deleted.has(deletedOwnedWorkspaceKey(entry)));
  };

  // ── Issue #38 审计：子用户新建目录 / 工作区登记 ─────────────────────
  // 只记 actor（用户名）、ip、user-agent 与结果摘要；目标路径仅在非敏感时明文记录，
  // 敏感路径只留叶子名，绝不落完整敏感主机路径、请求体、token 或密码。db.audit
  // 自身吞异常且不返回值，因此审计写入失败既不阻断也不改变任何授权结果。
  const auditPathSummary = (value: string): string | { sensitive: true; leaf: string } => {
    const normalized = normalizePath(value);
    if (isSensitivePath(value) || isSensitivePath(normalized)) {
      return { sensitive: true, leaf: path.basename(normalized) };
    }
    return normalized;
  };
  const auditDirectoryEvent = (eventType: string, req: Request, reqAs: Req, detail: Record<string, unknown>): void => {
    db.audit(eventType, {
      username: reqAs.dshpwUsername ?? null,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
      detail: JSON.stringify(detail),
    });
  };

  // ── 反向代理私有 helper（原 gateway.ts L3808-L3924）──────────────────────
  // ── 反向代理（HTTP）→ 上游 dsh ──────────────────────────────
  // 改写路径：body 已重算，分帧以新 content-length 为准，必须清掉上游的
  // transfer-encoding（RFC 9110 §8.6：CL 与 TE 同帧属于畸形消息，Nginx 直接 502）
  function headersForRewrittenBody(upstreamHeaders: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
    const h: Record<string, string | string[] | undefined> = { ...upstreamHeaders };
    delete h['content-length'];
    delete h['content-encoding'];
    delete h['transfer-encoding'];
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    h['x-dsh-gateway'] = '1';
    return h;
  }
  // 流式透传：上游若异常同时带 CL+TE，按 RFC 9110 §8.6 保留 TE、丢弃 CL
  function headersForStreaming(upstreamHeaders: IncomingHttpHeaders): Record<string, string | string[] | undefined> {
    const h: Record<string, string | string[] | undefined> = { ...upstreamHeaders };
    if (h['content-length'] !== undefined && h['transfer-encoding'] !== undefined) delete h['content-length'];
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    h['x-dsh-gateway'] = '1';
    return h;
  }

  /** 缓冲上游响应体的上限：超过则放弃改写（注入/过滤），转流式透传，保证内存有界 */
  const MAX_BUFFER_BYTES = 16 * 1024 * 1024;
  /** gunzip 解压后的上限：缓冲体本身有界，但 16MB 高压缩比炸弹可解压出数百 MB——过滤前拒绝 */
  const MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
  /** 安全过滤分支专属：解压超限时 fail-closed（502），不得透传未过滤内容 */
  class OversizeResponseError extends Error {}



  /**
   * 有界解压：用 zlib 的 maxOutputLength 在分配内存前限制输出——事后 body.length 检查
   * 只能发现炸弹，内存峰值已经发生（高压缩比 payload 可把 16MB 输入解压到数百 MB）。
   * 超限抛 OversizeResponseError（安全分支 → 502）；其他解压错误（gzip 损坏）原样抛出，
   * 由调用方按既有“解析失败透传”契约处理。
   */
  function gunzipBounded(input: Buffer): Buffer {
    try {
      return zlib.gunzipSync(input, { maxOutputLength: MAX_DECOMPRESSED_BYTES });
    } catch (error) {
      // 超限错误形态：ERR_BUFFER_TOO_LARGE（code）或 "Cannot create a Buffer larger than ..."（message）
      const code = (error as { code?: unknown }).code;
      if (
        error instanceof Error &&
        (code === 'ERR_BUFFER_TOO_LARGE' || /too large|larger than/i.test(error.message))
      ) {
        throw new OversizeResponseError();
      }
      throw error;
    }
  }

  function decodeUpstreamBody(input: Buffer, contentEncoding: string): Buffer {
    const encoding = contentEncoding.trim().toLowerCase();
    if (encoding === '' || encoding === 'identity') return input;
    if (encoding === 'gzip') return gunzipBounded(input);
    throw new Error(`unsupported content-encoding: ${encoding}`);
  }

  /**
   * 递归过滤响应里的 pinnedSessionIds 数组，只保留当前子用户已授权的会话。
   *
   * workspace.list 与 Remote baseline 的 pin 集合都和 archivedSessionIds 同级，
   * 是宿主机 registry 全局状态（任一租户 pin 一次即可枚举其他租户会话 ID）。字段
   * 存在但不是数组时返回 'malformed'，调用方必须 fail-closed（502），绝不回放未
   * 过滤的全局集合；字段不存在（旧 dsh）返回 'absent'，无需改写。
   */
  function filterPinnedSessionIds(
    value: unknown,
    keep: (id: string) => boolean,
    depth = 0,
  ): 'absent' | 'filtered' | 'malformed' {
    if (depth > 8 || value === null || typeof value !== 'object') return 'absent';
    if (Array.isArray(value)) {
      let outcome: 'absent' | 'filtered' = 'absent';
      for (const item of value) {
        const nested = filterPinnedSessionIds(item, keep, depth + 1);
        if (nested === 'malformed') return 'malformed';
        if (nested === 'filtered') outcome = 'filtered';
      }
      return outcome;
    }
    const obj = value as Record<string, unknown>;
    let outcome: 'absent' | 'filtered' = 'absent';
    if (Object.hasOwn(obj, 'pinnedSessionIds')) {
      const pinned = obj.pinnedSessionIds;
      if (!Array.isArray(pinned)) return 'malformed';
      obj.pinnedSessionIds = pinned.filter((id): id is string => typeof id === 'string' && keep(id));
      outcome = 'filtered';
    }
    for (const key of Object.keys(obj)) {
      const nested = filterPinnedSessionIds(obj[key], keep, depth + 1);
      if (nested === 'malformed') return 'malformed';
      if (nested === 'filtered') outcome = 'filtered';
    }
    return outcome;
  }

  /**
   * 缓冲上游响应：正常路径在 'end' 时调用 onEnd(body) 做改写/过滤；
   * 若超过 MAX_BUFFER_BYTES（异常大的 HTML/JSON），自动放弃缓冲，
   * 无缝切换为流式透传（不再注入/过滤，但连接不中断、内存有界）。
   * 上游中途出错时销毁客户端连接（头未发出，无法再写错误页）。
   */
  function bufferUpstream(
    upstreamRes: http.IncomingMessage,
    res: Response,
    onEnd: (body: Buffer) => void | Promise<void>,
    onOversize: 'stream' | 'fail' = 'fail',
  ): void {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const onData = (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_BUFFER_BYTES) {
        settled = true;
        upstreamRes.off('data', onData);
        upstreamRes.off('end', onEndHandler);
        upstreamRes.off('error', onError);
        if (onOversize === 'fail') {
          upstreamRes.destroy();
          if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
          return;
        }
        // HTML 注入可安全退化为流式透传。必须写入先前缓冲的内容和当前越界 chunk；
        // 旧实现丢弃当前 chunk，导致响应中间断裂。
        // ⚠ 重挂 error 监听：pipe 不会为源挂 error，缺监听时上游中断 emit 'error'
        // 会触发 uncaughtException 击穿网关进程。
        upstreamRes.on('error', () => res.destroy());
        const respHeaders = headersForStreaming(upstreamRes.headers);
        if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
        if (!res.writableEnded) {
          res.write(Buffer.concat([...chunks, chunk]));
          upstreamRes.pipe(res);
        }
        return;
      }
      chunks.push(chunk);
    };
    const onEndHandler = () => {
      if (settled) return;
      settled = true;
      Promise.resolve(onEnd(Buffer.concat(chunks))).catch(() => {
        if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
        else res.destroy();
      });
    };
    const onError = () => {
      if (settled) return;
      settled = true;
      res.destroy();
    };
    upstreamRes.on('data', onData);
    upstreamRes.on('end', onEndHandler);
    upstreamRes.on('error', onError);
  }

  // ── 反向代理 HTTP 处理器（原 gateway.ts L3993-L5873）─────────────────────
  app.use((req, res) => {
    // F-1 纵深防御：能到达这里（代理兑底）的 /gateway* 请求必然是未被具体网关路由
    // 处理的畸形/伪装路径（合法网关路由都在各自处理器里 return 了）——一律 404，
    // 绝不转发上游（防未登录 SPA 壳泄露 window.__DSH_BOOT__ 插件清单）。
    const fallbackGatePath = gatePathOf(req.url ?? '/');
    if (fallbackGatePath === '/gateway' || fallbackGatePath.startsWith('/gateway/')) {
      res.status(404).type('text/plain').send('404 Not Found');
      return;
    }
    const headers: Record<string, string | string[] | undefined> = { ...req.headers };
    // 改写 Host 为上游地址（过 dsh 的 browser-trust fence 第 1 道：Host 检查）
    headers.host = upstreamAuthority;
    // 改写 Origin 为上游地址（过第 3 道：Origin 必须与 Host 同 host——
    // 浏览器发来的是网关地址 origin，与改写后的 Host 不一致会被 403）
    if (typeof headers.origin === 'string') {
      headers.origin = `${upstreamScheme}://${upstreamAuthority}`;
    }
    delete headers['content-length'];
    // 缓冲/改写路径用 end(body) 重写 content-length，chunked 的 transfer-encoding
    // 若保留会造成 Node 的 ERR_HTTP_CONTENT_LENGTH_MISMATCH
    delete headers['transfer-encoding'];
    // F-15：剥离网关会话 Cookie（dsh_gateway_token JWT）——上游 dsh 是无认证
    // 应用，本不需要令牌；不剥离则上游或其第三方插件被入侵/投毒时可收割全部
    // 活动会话 JWT 并回放。白盒确认 dsh-host-webserver / dsh-anonymous-user-id
    // 均无 cookie 逻辑。
    // 例外：/api/dsh-passwords/* 是本网关自身插件路由，其 guard 靠 Cookie 中
    // 的 JWT 鉴权（同一信任域、自己签发的服务），必须保留；其他上游面移除
    // 网关 JWT 和浏览器伪造的 dsh-auth Cookie，但保留第三方插件自己的 Cookie。
    const ownPluginRoute = normalizeDecodedPath(
      new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`).pathname,
    ).startsWith('/api/dsh-passwords/');
    if (!ownPluginRoute) {
      const forwardedCookie = upstreamCookieHeader(
        typeof req.headers.cookie === 'string' ? req.headers.cookie : undefined,
        getUpstreamAuthCookie(),
      );
      if (forwardedCookie === undefined) delete headers.cookie;
      else headers.cookie = forwardedCookie;
    }
    // 只允许 gzip/identity：HTML 注入与 workspace/session 过滤只处理 gzip，
    // 上游若返回 br 会损坏页面/导致过滤静默失效（brotli 不走代理缓冲）
    headers['accept-encoding'] = 'gzip';

    const parsedUrl = new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`);
    // 外部网关 JWT 与 alpha 根路径 launch token 都是本层凭据，不能通过 query
    // 泄露到 dsh 或第三方插件；其余业务 query 参数原样保留。
    const proxyPath = normalizeDecodedPath(parsedUrl.pathname);
    const stateChanging = req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE';
    if (stateChanging && req.headers.origin !== undefined && !originHostMatches(req)) {
      res.status(403).type('text/plain').send('403 Forbidden');
      return;
    }
    const upstreamSearch = stripGatewayAuthQuery(req.originalUrl, proxyPath);
    // 请求上挂的用户/权限（子用户才有）
    const reqAs = req as Req;
    // alpha.1 的 uploadFileBinary 是 Connection 注册的独立原始字节流，
    // 不会进入后面的 JSON ownership 检查。它必须在 pipe 到上游之前完成
    // sessionId 授权，否则已认证用户会变成“可向任意已知会话上传”。
    if (
      reqAs.dshpwUser !== undefined &&
      reqAs.dshpwIsAdmin !== true &&
      req.method === 'POST' &&
      proxyPath === '/api/session/uploadFileBinary'
    ) {
      const sessionId = parsedUrl.searchParams.get('sessionId');
      const address = sessionId === null ? null : parseSessionAddress({ kind: 'session', sessionId });
      if (address === null || !sessionFollowIdentityAllowed(reqAs.dshpwUser, address)) {
        res.status(403).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.folderDenied')));
        return;
      }
    }
    // rc.2 client-connection 的统一 carrier 上限：主用户恒为 300 MiB；子用户按
    // allow_upload 分档——关闭时维持默认 64 MiB，开启后才与上游 carrier cap 对齐
    // 到 300 MiB。先检查声明长度，避免接收必然超限的请求体；无 Content-Length
    // 的请求仍由下方权限检查分支在实际收包时执行同一上限。
    const declaredRequestLength = Number(req.headers['content-length'] ?? '');
    const requestBodyLimit = requestBodyLimitFor(
      reqAs.dshpwIsAdmin === true ? 'admin' : 'user',
      reqAs.dshpwPerms?.allow_upload === true,
    );
    if (Number.isFinite(declaredRequestLength) && declaredRequestLength > requestBodyLimit) {
      res.status(413).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.bodyTooLarge')));
      return;
    }
    // 序号在请求发出前分配：并发 workspace.list 返回乱序时，较早请求的旧快照
    // 不能覆盖较晚请求对应的新状态。
    const archiveRequestRevision = req.method === 'POST' && /^\/api\/workspace[.\/]list$/.test(proxyPath)
      ? bumpWorkspaceListRequestRevision()
      : 0;
    // fork/create 的响应可能在权限修改后才返回；记录请求开始时的授权 epoch，
    // 这样慢响应不能在管理员撤销权限后把新会话重新写回旧快照。
    const sessionAccessRequestEpoch = reqAs.dshpwUser === undefined
      ? 0
      : userAccessEpochFor(reqAs.dshpwUser);
    // 无 Content-Length 的 chunked 请求不能绕过与声明长度相同的硬上限。
    // 该标志同时阻止 upstreamReq 的 error 处理器把主动的 413 误报成 502。
    let requestBodyRejected = false;
    // 上游响应头等待：只覆盖「尚未收到响应头」的窗口，收到头或上游出错即清除。
    let upstreamResponseHeaderTimer: NodeJS.Timeout | undefined;
    let upstreamResponseHeaderTimedOut = false;
    const clearUpstreamResponseHeaderTimer = (): void => {
      if (upstreamResponseHeaderTimer === undefined) return;
      clearTimeout(upstreamResponseHeaderTimer);
      upstreamResponseHeaderTimer = undefined;
    };
    const upstreamReq = upstreamTransport.request(
      {
        hostname: upstreamHost,
        port: upstreamPort,
        // 规范化路径转发（与 dsh 的 new URL 解析行为一致，杜绝 ../ 混入上游）
        // F-03：与门卫同口径——pathname 解码后再归一化，编码变体（%2f/%2e）
        // 转发为等价规范路径，避免上游按自身规则解码导致路径语义漂移
        path: proxyPath + upstreamSearch,
        method: req.method,
        headers,
        agent: upstreamAgent,
      },
      (upstreamRes) => {
        // 响应头已到达：等待窗口立即结束——其后无论是 SSE 还是长响应都不再受该计时器约束
        clearUpstreamResponseHeaderTimer();
        const contentType = String(upstreamRes.headers['content-type'] ?? '');
        const encoding = String(upstreamRes.headers['content-encoding'] ?? '');

        // ── HTML 响应：缓冲 + 注入兼容脚本（crypto.randomUUID polyfill 等） ──
        if (contentType.includes('text/html')) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              if (encoding.includes('gzip')) body = gunzipBounded(body);
              const html = body.toString('utf8');
              const injected = html.replace(/<head[^>]*>/i, (match) => match + INJECT_SCRIPT);
              let out = Buffer.from(injected, 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              // 代理层补齐防嵌框头（dsh 应用自身未设置）：
              // 允许同源内嵌（dsh 内部如有同源 iframe 不受影响），禁止跨站嵌框。
              // 仅在上游未提供 CSP 时补充 frame-ancestors，避免冲掉上游更严的策略。
              respHeaders['x-frame-options'] = 'SAMEORIGIN';
              const upstreamCsp = String(upstreamRes.headers['content-security-policy'] ?? '');
              if (!upstreamCsp.includes('frame-ancestors')) {
                respHeaders['content-security-policy'] = upstreamCsp
                  ? `${upstreamCsp}; frame-ancestors 'self'`
                  : "frame-ancestors 'self'";
              }
              if (encoding.includes('gzip')) {
                out = zlib.gzipSync(out);
                respHeaders['content-encoding'] = 'gzip';
              }
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              // 注入仅改善兼容性，解析失败可安全保留原始 HTML；其余安全过滤分支
              // 则使用 bufferUpstream 默认 fail-closed，不能把未检查内容透传。
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          }, 'stream');
          return;
        }

        // 注：session/history 与 session/page 的响应处理在下方专用分支完成
        // （history：隐藏 Unicode 清洗 + 受限子用户沙盒降级；page：隐藏 Unicode 清洗）。
        // 不要在此处再加宽泛的 history/page 分支——先到先返回会让沙盒降级变成死代码。

        // ── workspace 管理响应：成功后同步工作区登记 ──
        // DSH Remote business failures also use HTTP 200. In particular,
        // workspace/create reports { created: false } when resolving an existing
        // administrator workspace; that must never turn a shared workspace into a
        // subuser-owned one.
        if (reqAs.dshpwWorkspacePath !== undefined && reqAs.dshpwUser !== undefined) {
          bufferUpstream(upstreamRes, res, (raw) => {
            let businessOk = false;
            let created = false;
            let createdPath: string | null = null;
            let createdWorkspaceId: string | null = null;
            let createdWorkspaceRow: Record<string, unknown> | null = null;
            // workspace/create|rename 的成功响应回带整份 workspace 投影（sessionIds
            // 是该工作区全部会话 ID）。子用户解析既有共享工作区（created:false）或
            // 重命名时若不按授权会话收租，即可枚举同工作区里其他租户的会话 ID。
            // 解析失败或形状不符一律 fail-closed（502），不解析透传全局集合；
            // 改写后才用 headersForRewrittenBody 重算 content-length。
            let rewrittenBody: Buffer | null = null;
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = parsed.result;
              if (isPlainJsonRecord(result) && result.ok === true) {
                businessOk = true;
                const value = result.value;
                if (isPlainJsonRecord(value) && isPlainJsonRecord(value.workspace) && typeof value.workspace.path === 'string') {
                  created = value.created === true;
                  createdPath = value.workspace.path;
                  createdWorkspaceRow = value.workspace;
                  if (typeof value.workspace.workspaceId === 'string') createdWorkspaceId = value.workspace.workspaceId;
                  // 官方 workspaceView 必带 sessionIds：缺失/非数组无法证明已收租 → 502。
                  const sessions = value.workspace.sessionIds;
                  if (!Array.isArray(sessions)) throw new Error('workspace response shape invalid');
                  const userId = reqAs.dshpwUser!;
                  // 用请求侧已校验的目标工作区（不是上游路径）做归属判定，避免被
                  // 伪造的响应 path 把其他租户会话洗成“自己工作区的会话”。
                  const workspacePath = reqAs.dshpwWorkspacePath!;
                  const disabled = new Set(reqAs.dshpwPerms!.disabled_sessions);
                  const visible = sessions.filter((id): id is string =>
                    typeof id === 'string' && !disabled.has(id) &&
                    (db.hasUserSessionGrant(userId, id) || workspaceOwnedByUser(userId, workspacePath)),
                  );
                  if (visible.length !== sessions.length) {
                    value.workspace.sessionIds = visible;
                    rewrittenBody = Buffer.from(JSON.stringify(parsed), 'utf8');
                  }
                }
              }
            } catch {
              // 无法确认 workspace.sessionIds 已收租时绝不回放原始响应（fail-closed）。
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
              return;
            }
            if (businessOk) {
              if (reqAs.dshpwWorkspaceCreate === true) {
                const grantUserId = reqAs.dshpwUser!;
                const grantPath = reqAs.dshpwWorkspacePath!;
                if (createdPath !== null && normalizePath(createdPath) === grantPath) {
                  // 上游 created:true 只表示 DSH registry 新增了条目，不代表目录由
                  // 当前子用户创建。主用户分配的共享目录不能因此变成私有工作区。
                  // 迟到回包防线：管理员可能在 await 上游期间撤权/关开关/推进 epoch；
                  // 回包到达时以当前 live 权限行与请求 epoch 复核，绝不重赋读取 grant。
                  const owned = db.listUserWorkspacePaths(grantUserId);
                  const pending = visiblePendingCreatedDirectories(grantUserId);
                  const livePerms = effectivePermissions(grantUserId);
                  const epochUnchanged = userAccessEpochFor(grantUserId) === sessionAccessRequestEpoch;
                  if (created && epochUnchanged && livePerms.allow_workspace_create &&
                    folderAllowed(grantPath, livePerms.allowed_folders) &&
                    // 迟到的登记回包同样复核敏感基：请求通过到回包之间 realpath/链接可能
                    // 改指敏感目录，登记与请求门禁必须同口径。
                    !isSensitivePath(grantPath) && !isSensitivePath(canonicalizePathBestEffort(grantPath)) &&
                    // 请求通过到回包之间另一子用户可能已登记同名/祖先子树：必须以当前
                    // live 所有权快照复核单向子树重叠，否则后到的回包会把该目录登记成本
                    // 用户私有工作区（跨租户 TOCTOU）。
                    !workspaceSubtreeOverlap(grantUserId, grantPath) &&
                    workspaceRegistrationAllowed(grantPath, [], owned, pending)) {
                    db.addUserWorkspace(grantUserId, grantPath);
                    db.addAllowedFolder(grantUserId, grantPath);
                    // 该路径重新成为活跃工作区：解除删除墓碑，避免后续 pending 被误屏蔽。
                    clearDeletedOwnedWorkspace(grantUserId, grantPath);
                    auditDirectoryEvent('workspace_registered', req, reqAs, {
                      result: 'ok', path: auditPathSummary(grantPath),
                    });
                  }
                  // 立即更新该用户的 workspaceId→path 映射并向已建立的 Remote mux
                  // 连接补发过滤后的 upsert：否则紧随其后的 session.create（带
                  // workspaceId）会因映射缺失被 403，早到的上游 upsert 也已被丢弃。
                  if (createdWorkspaceId !== null && createdWorkspaceRow !== null && createdPath !== null) {
                    const epoch = userAccessEpochFor(reqAs.dshpwUser!);
                    const paths = new Map(userWorkspacePaths.get(reqAs.dshpwUser!) ?? new Map<string, string>());
                    paths.set(createdWorkspaceId, createdPath);
                    replaceUserWorkspacePaths(reqAs.dshpwUser!, paths, epoch);
                    for (const muxConnection of remoteMuxClientsByUser.get(reqAs.dshpwUser!) ?? []) {
                      muxConnection.publishWorkspaceUpsert(createdWorkspaceRow);
                    }
                  }
                }
              } else if (reqAs.dshpwWorkspaceOldPath !== undefined && reqAs.dshpwWorkspaceNewPath !== undefined) {
                db.renameUserWorkspace(reqAs.dshpwUser!, reqAs.dshpwWorkspaceOldPath, reqAs.dshpwWorkspaceNewPath);
              } else if (/(?:remove|delete)(?:[./]|$)/.test(proxyPath) && reqAs.dshpwWorkspacePath !== undefined) {
                const deleteUserId = reqAs.dshpwUser!;
                const deletedPath = normalizePath(reqAs.dshpwWorkspacePath);
                // 归属该工作区的会话：内存 cwd 快照 + 全局 cwd 缓存 + pending 会话。
                // 只取精确 cwd，避免误伤同用户其它（嵌套）工作区的会话。
                const affectedSessionIds = new Set<string>();
                for (const [sessionId, cwd] of userSessionAccess.get(deleteUserId) ?? new Map<string, string>()) {
                  if (normalizePath(cwd) === deletedPath) affectedSessionIds.add(sessionId);
                }
                for (const [sessionId, cwd] of sessionCwdById) {
                  if (normalizePath(cwd) === deletedPath) affectedSessionIds.add(sessionId);
                }
                for (const [sessionId, marker] of pendingCreatedSessions.get(deleteUserId) ?? new Map<string, { cwd: string }>()) {
                  if (normalizePath(marker.cwd) === deletedPath) affectedSessionIds.add(sessionId);
                }
                // DB 收口：归属行 + 自建白名单条目（精确，保留管理员父目录/其它分配）
                // + 该工作区会话授权，单事务。
                db.removeUserOwnedWorkspace(deleteUserId, deletedPath, [...affectedSessionIds]);
                const epoch = userAccessEpochFor(deleteUserId);
                // workspaceId→path 映射：本用户快照与全局缓存都清掉，旧 id 不再解析到已删工作区。
                if (userWorkspacePaths.has(deleteUserId)) {
                  const paths = new Map(userWorkspacePaths.get(deleteUserId)!);
                  for (const [workspaceId, workspacePath] of [...paths]) {
                    if (normalizePath(workspacePath) === deletedPath) paths.delete(workspaceId);
                  }
                  replaceUserWorkspacePaths(deleteUserId, paths, epoch);
                }
                for (const [workspaceId, workspacePath] of [...workspacePathById]) {
                  if (normalizePath(workspacePath) === deletedPath) workspacePathById.delete(workspaceId);
                }
                // 会话 cwd 缓存与 pending 会话：一并清掉已删除工作区的条目。
                for (const sessionId of affectedSessionIds) {
                  sessionCwdById.delete(sessionId);
                  clearPendingCreatedSession(deleteUserId, sessionId);
                }
                // 授权快照：去掉已删除工作区的会话，旧 baseline 不再放行；并令 Remote mux
                // 重建 baseline（proxy 侧无可直接推进的 epoch 写入入口，重建是最强可用口径）。
                const existingAccess = userSessionAccess.get(deleteUserId);
                if (existingAccess !== undefined) {
                  const access = new Map(existingAccess);
                  for (const [sessionId, cwd] of [...access]) {
                    if (normalizePath(cwd) === deletedPath) access.delete(sessionId);
                  }
                  replaceUserSessionAccess(deleteUserId, access, epoch);
                }
                // 残留 pending 目录不再能重新登记同一路径（否则删除形同虚设）；重建目录时解除。
                markDeletedOwnedWorkspace(deleteUserId, deletedPath);
                closeUserRemoteMuxClients(deleteUserId, 1012, 'Workspace deleted');
              }
            }
            if (rewrittenBody !== null) {
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(rewrittenBody.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(rewrittenBody);
              return;
            }
            const respHeaders = headersForStreaming(upstreamRes.headers);
            if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
            if (!res.writableEnded) res.end(raw);
          });
          return;
        }

        // ── directoryPicker/createDirectory 成功记账（子用户）：把 DSH 返回的新目录
        // 写入 pending 表，供后续 workspace/create 的「刚创建目录」登记通道使用。
        // 解析失败只影响记账（登记变得更严格），响应本身原样透传。
        if (reqAs.dshpwUser !== undefined && reqAs.dshpwIsAdmin !== true &&
          req.method === 'POST' && isWorkspaceDirectoryCreate(proxyPath)) {
          const recordUserId = reqAs.dshpwUser;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = parsed.result;
              if (isPlainJsonRecord(result) && result.ok === true && typeof result.value === 'string' && result.value.length > 0) {
                // pending 只是「刚创建目录」的登记凭据，不再授予浏览或创建例外。
                // 只登记「本次请求的父目录之内」的新目录：DSH 的 createDirectory 只接受
                // 单个路径段（拒绝 . / .. / 含分隔符），若上游被替换或回归，返回路径可能逃逸
                // 出请求的父目录，而 pending 命中即可把该越界目录登记为私有工作区并写入
                // 白名单。父目录解析不出（请求未带 path）时同样记账不成立（fail-closed）。
                // 词法与 canonical 必须**同时**命中请求父目录（与创建门禁同口径）：
                // 只要求其一即可时，根内目录链接能把回包 canonical 带出根，逃逸路径会被记入 pending。
                const requestedParent = reqAs.dshpwSessionCwd;
                const createdPath = canonicalizePathBestEffort(result.value);
                const insideRequestedParent = requestedParent !== undefined &&
                  pathWithin(result.value, requestedParent) &&
                  pathWithin(createdPath, canonicalizePathBestEffort(requestedParent));
                // 迟到回包防线：管理员可能在 await 上游期间撤权/关开关/推进 epoch；
                // 回包到达时以当前 live 权限行与请求 epoch 复核，且新目录仍须落在当前
                // 可读范围内，避免撤权后旧回复重新登记 pending。
                const livePerms = effectivePermissions(recordUserId);
                const epochUnchanged = userAccessEpochFor(recordUserId) === sessionAccessRequestEpoch;
                const stillReadable = folderAllowed(result.value, livePerms.allowed_folders) &&
                  folderAllowed(createdPath, livePerms.allowed_folders);
                if (insideRequestedParent && epochUnchanged && livePerms.allow_workspace_create && stillReadable) {
                  // 用户重新创建了同名目录：解除删除墓碑，使其进入正常 pending 信任窗口。
                  clearDeletedOwnedWorkspace(recordUserId, createdPath);
                  recordPendingCreatedDirectory(recordUserId, createdPath);
                  auditDirectoryEvent('directory_created', req, reqAs, {
                    result: 'ok', path: auditPathSummary(createdPath),
                  });
                }
              }
            } catch {
              // 记账失败 fail-safe：后续登记会因不在 pending 表而被拒绝。
            }
            const respHeaders = headersForStreaming(upstreamRes.headers);
            if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
            if (!res.writableEnded) res.end(raw);
          });
          return;
        }

        // ── directoryPicker/list 响应过滤（子用户）：逐条剔除敏感（lexical+canonical）与他人
        // 工作区子树；ancestors 模式再按授权根/创建根裁剪条目与 crumbs；home/path 未授权时
        // 替换为授权根。结构畸形 fail-closed（502），绝不回放未过滤清单。
        if (reqAs.dshpwDirListFilter !== undefined && reqAs.dshpwUser !== undefined) {
          const filter = reqAs.dshpwDirListFilter;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = parsed.result;
              if (isPlainJsonRecord(result) && result.ok === true) {
                if (!isPlainJsonRecord(result.value)) {
                  // ok:true 但缺列表结构 → 畸形，fail-closed。
                  throw new Error('directory listing shape invalid');
                }
                const value = result.value;
                // 结构畸形一律 fail-closed：不做“只过滤 entries 就透传”的半处理，
                // 否则 crumbs/home/path 会把未过滤的宿主目录信息原样放回。
                if (typeof value.path !== 'string' || typeof value.home !== 'string' ||
                    !Array.isArray(value.crumbs) || !Array.isArray(value.entries)) {
                  throw new Error('directory listing shape invalid');
                }
                const userId = reqAs.dshpwUser!;
                // 条目可见性只看当前可读根（allowed_folders）；创建范围与之同源，无独立导航集。
                const navRoots = [...filter.readRoots, ...filter.injectRoots];
                // 敏感（lexical + canonical）与他人工作区子树（lexical + canonical）逐条剔除。
                const blockedEntry = (candidate: string): boolean => {
                  const canonicalCandidate = canonicalizePathBestEffort(candidate);
                  return isSensitivePath(candidate) || isSensitivePath(canonicalCandidate) ||
                    workspaceSubtreeOverlap(userId, candidate) || workspaceSubtreeOverlap(userId, canonicalCandidate);
                };
                const navigableEntry = (candidate: string): boolean =>
                  directoryEntryVisible(candidate, navRoots) ||
                  directoryEntryVisible(canonicalizePathBestEffort(candidate), navRoots);
                value.entries = (value.entries as unknown[]).filter((entry) => {
                  if (!isPlainJsonRecord(entry) || typeof entry.path !== 'string') return false;
                  const entryPath = entry.path;
                  if (blockedEntry(entryPath)) return false;
                  if (filter.mode === 'authorized') return true;
                  return navigableEntry(entryPath);
                });
                // crumbs：只回放导航可达的祖先（授权根的祖先或自身），
                // 不向不相关目录泄漏宿主路径段。
                value.crumbs = (value.crumbs as unknown[]).filter((crumb) =>
                  isPlainJsonRecord(crumb) && typeof crumb.path === 'string' && navigableEntry(crumb.path));
                // home：真实宿主 home 不在授权可读位置时替换为授权根，避免泄漏宿主 home 元数据；
                // path：仅在不相关（非导航祖先）时替换，保留合法导航位置。
                const authorizedLocation = (candidate: string): boolean =>
                  filter.readRoots.some((root) => pathWithin(candidate, root)) ||
                  filter.injectRoots.some((root) => pathWithin(candidate, root));
                const fallbackRoot = filter.injectRoots[0] ?? filter.readRoots[0];
                if (!authorizedLocation(value.home) && fallbackRoot !== undefined) value.home = fallbackRoot;
                if (!authorizedLocation(value.path) && fallbackRoot !== undefined &&
                    !navigableEntry(value.path)) value.path = fallbackRoot;
                if (filter.showRoots) {
                  const existing = new Set((value.entries as unknown[]).filter(isPlainJsonRecord)
                    .map((entry) => typeof entry.path === 'string' ? normalizePath(entry.path) : ''));
                  for (const root of filter.injectRoots) {
                    if (existing.has(normalizePath(root))) continue;
                    existing.add(normalizePath(root));
                    const normalized = root.replace(/\\/g, '/').replace(/\/$/, '');
                    const slash = normalized.lastIndexOf('/');
                    const name = slash >= 0 && slash < normalized.length - 1 ? normalized.slice(slash + 1) : normalized;
                    (value.entries as unknown[]).push({ name, path: root, hidden: false });
                  }
                }
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── workspace.list 响应：收集 id→path 缓存 + 受限子用户过滤白名单外的工作区 ──
        if (req.method === 'POST' && /^\/api\/workspace[.\/]list$/.test(proxyPath)) {
          const requestRevision = archiveRequestRevision;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              // 只有完整、明确的 archivedSessionIds 数组才能更新快照；解析/解压/容量
              // 异常不得用空集合覆盖旧状态。按请求序号防止较早的慢响应回滚新快照。
              const nextArchived = new Set<string>();
              const hasValidArchiveState = replaceArchivedSessionSnapshot(nextArchived, parsed);
              if (hasValidArchiveState && requestRevision >= getArchivedSessionSnapshotRevision()) {
                archivedSessionSnapshot.clear();
                for (const id of nextArchived) archivedSessionSnapshot.add(id);
                setArchivedSessionSnapshotReady(true);
                setArchivedSessionSnapshotRevision(requestRevision);
              }
              // 先缓存全量 id→path（供 session.create 用 workspaceId 时解析路径）
              collectIdPathPairs(parsed, workspacePathById);
              // 管理员仍使用全局 cwd 缓存；普通用户只建立自己的可见会话授权快照。
              if (reqAs.dshpwIsAdmin === true) collectSessionCwdFromWorkspaces(parsed, sessionCwdById);
              const workspaceVisible = (candidate: string): boolean => {
                if (!folderAllowed(candidate, reqAs.dshpwPerms?.allowed_folders ?? [])) return false;
                if (reqAs.dshpwUser === undefined || reqAs.dshpwIsAdmin === true) return true;
                return !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser, candidate);
              };
              // Only a restricted child needs the recursive path projection. The
              // administrator must receive the exact DSH response: recursive copying
              // can turn deeply nested official workspace metadata into null values.
              const outBody = reqAs.dshpwPerms !== undefined
                ? filterByPathFieldWithPredicate(parsed, 'path', workspaceVisible)
                : parsed;
              // F-25/#16：子用户只能看到被授权的会话。dsh rc.8 保留归档会话在
              // workspace.sessionIds 槽位，并用 archivedSessionIds 另行标记状态；如果
              // 把归档 ID 从 sessionIds 删除，dsh 会把完整会话错误归入「未分组」。
              if (reqAs.dshpwPerms !== undefined) {
                if (!hasValidArchiveState && !getArchivedSessionSnapshotReady()) {
                  if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
                  return;
                }
                const disabled = new Set(reqAs.dshpwPerms.disabled_sessions);
                const archived = new Set(archivedSessionSnapshot);
                const visibleSessionIds = new Set(collectSessionCwdFromWorkspaces(outBody).keys());
                // Issue #19 旧数据迁移：显式会话授权上线前就已获授权工作区的子用户，
                // 第一次成功拿到 workspace.list 时，把可见工作区内“未禁用”的既有会话一次性
                // 写入显式授权，保持旧行为；之后新出现的会话不会自动加入授权。归档会话也
                // 一并授权——归档是展示状态，不是放弃授权的依据（仍保留在工作区槽位）。
                if (reqAs.dshpwPerms !== undefined && !db.isSessionGrantsSeeded(reqAs.dshpwUser!)) {
                  // 只追加、绝不整表替换：同一窗口里子用户 session/create 追加的
                  // grant 不得被这次迁移 seed 抹掉（标记同事务提交）。
                  const seedIds = [...visibleSessionIds].filter((id) => !disabled.has(id));
                  db.seedUserSessionGrants(reqAs.dshpwUser!, seedIds);
                }
                const grants = new Set(db.listUserSessionGrants(reqAs.dshpwUser!));
                // 只暴露当前可见工作区中的归档标记，避免借 archivedSessionIds 枚举
                // 其他用户的会话；归档槽位本身仍保留在 sessionIds。
                const visibleCwds = collectSessionCwdFromWorkspaces(outBody);
                const sessionAllowed = (id: string): boolean => {
                  const sessionPath = visibleCwds.get(id);
                  return !disabled.has(id) && (grants.has(id) ||
                    (sessionPath !== undefined && workspaceOwnedByUser(reqAs.dshpwUser!, sessionPath)));
                };
                filterArchivedSessionIds(
                  outBody,
                  (id) => archived.has(id) && visibleSessionIds.has(id) && sessionAllowed(id),
                );
                // 分配工作区的既有会话仍须 grant；自建工作区的会话按归属自动可见。
                filterOwnedSessionIds(outBody, sessionAllowed);
                // pinnedSessionIds 与 archivedSessionIds 同级且同为宿主机全局状态：
                // 出现就必须按授权会话收租；形状不符 fail-closed（502），不回放全局集合。
                if (filterPinnedSessionIds(outBody, sessionAllowed) === 'malformed') {
                  throw new Error('workspace.list pinnedSessionIds shape invalid');
                }
                const visibleAccess = new Map<string, string>();
                collectSessionCwdFromWorkspaces(outBody, visibleAccess);
                for (const [id] of visibleAccess) {
                  if (disabled.has(id)) visibleAccess.delete(id);
                }
                // 合并旧快照里仍然合法的条目：一次不完整/乱序的列表响应不得把仍在
                // 授权内的会话抹掉（grant/禁用/白名单/所有权不满足的仍丢弃）。
                const authorizedAccess = mergeAuthorizedAccess(
                  reqAs.dshpwUser!,
                  reqAs.dshpwPerms,
                  grants,
                  visibleAccess,
                );
                // 授权回写栅栏用请求开始时的 epoch（授权在途中变更则不回写）；
                // requestRevision 只做同一用户 workspace.list 响应之间的排序。
                const accessReplaced = replaceUserSessionAccess(
                  reqAs.dshpwUser!,
                  authorizedAccess,
                  sessionAccessRequestEpoch,
                  requestRevision,
                );
                replaceUserWorkspacePaths(
                  reqAs.dshpwUser!,
                  mergeWorkspacePaths(reqAs.dshpwUser!, reqAs.dshpwPerms, collectIdPathPairs(outBody)),
                  sessionAccessRequestEpoch,
                  requestRevision,
                );
                // 归档集合与授权快照共用同一栅栏：被 epoch/order 拒绝的旧响应不得
                // 单独写入，否则旧权限视图算出的归档标记会覆盖新快照，让已归档会话
                // 重新出现在 session.list。
                if (accessReplaced) {
                  userArchivedSessionIds.set(reqAs.dshpwUser!, new Set(
                    [...archivedSessionSnapshot].filter((id) => authorizedAccess.has(id)),
                  ));
                }
              }
              const out = Buffer.from(JSON.stringify(outBody), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 子用户列表需要会话/白名单过滤：解析或过滤异常时无法产出已过滤响应，
              // 绝不能把未过滤的全量列表透传（fail-open 泄露其他租户会话）；
              // 主用户列表不涉及过滤，保持原样透传。
              if (reqAs.dshpwPerms !== undefined) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
                return;
              }
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }

        // ── workspace ordering responses: never return global workspace/session order to a subuser ──
        if (reqAs.dshpwUser !== undefined && reqAs.dshpwIsAdmin !== true && req.method === 'POST' &&
          /^\/api\/workspace[.\/](?:insertBefore|insertSessionBefore)$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              if (result?.ok === true && !isPlainJsonRecord(result.value)) throw new Error('workspace order response shape invalid');
              if (result?.ok === true && isPlainJsonRecord(result.value)) {
                if (/insertBefore$/.test(proxyPath)) {
                  if (!Array.isArray(result.value.workspaceIds)) throw new Error('workspace order response shape invalid');
                  const visible = userWorkspaceIds.get(reqAs.dshpwUser!);
                  if (visible === undefined) throw new Error('workspace order authority unavailable');
                  result.value.workspaceIds = result.value.workspaceIds.filter((id): id is string => typeof id === 'string' && visible.has(id));
                } else if (/insertSessionBefore$/.test(proxyPath)) {
                  if (!isPlainJsonRecord(result.value.workspace)) throw new Error('workspace session order response shape invalid');
                  const workspace = result.value.workspace;
                  const workspaceId = workspace.workspaceId;
                  const sessionIds = workspace.sessionIds;
                  const access = userSessionAccess.get(reqAs.dshpwUser!);
                  const visibleWorkspacePath = typeof workspaceId === 'string'
                    ? userWorkspacePaths.get(reqAs.dshpwUser!)?.get(workspaceId) ?? null
                    : null;
                  if (typeof workspaceId !== 'string' || workspaceId !== reqAs.dshpwWorkspaceOrderId ||
                    !Array.isArray(sessionIds) || access === undefined || visibleWorkspacePath === null ||
                    reqAs.dshpwWorkspaceOrderPath === undefined ||
                    normalizePath(visibleWorkspacePath) !== normalizePath(reqAs.dshpwWorkspaceOrderPath)) {
                    throw new Error('workspace session order authority unavailable');
                  }
                  workspace.sessionIds = sessionIds.filter((id): id is string => {
                    if (typeof id !== 'string') return false;
                    const sessionPath = access.get(id);
                    return sessionPath !== undefined && normalizePath(sessionPath) === normalizePath(visibleWorkspacePath) &&
                      authorizedSubuserSessionRoot(reqAs.dshpwUser!, id, db.getPermissions(reqAs.dshpwUser!) ?? reqAs.dshpwPerms!) !== null;
                  });
                }
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const headers = headersForRewrittenBody(upstreamRes.headers);
              headers['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, headers);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── workspace/pinSession|unpinSession 响应（子用户）：pinnedSessionIds 收租 ──
        // 0.1.7-alpha.1 的 pin 集合是宿主机 registry 全局状态，上游把完整
        // pinnedSessionIds 放在成功响应里。请求侧已由 SESSION_SCOPED_RE 报归属，
        // 但响应若不过滤，任一子用户 pin 一次就能枚举其他租户的会话 ID（与
        // workspace.list 的 archivedSessionIds 同一类枚举面）。形状不符时
        // fail-closed（502），绝不回放未过滤集合。
        if (reqAs.dshpwUser !== undefined && reqAs.dshpwIsAdmin !== true &&
          req.method === 'POST' && /^\/api\/workspace[.\/](?:pinSession|unpinSession)$/.test(proxyPath)) {
          const pinnedUserId = reqAs.dshpwUser;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              // 业务失败不带会话集合，原样透传；成功结果必须是完整 pin 集合。
              if (result !== null && result.ok === true) {
                const value = isPlainJsonRecord(result.value) ? result.value : null;
                const pinned = value === null ? undefined : value.pinnedSessionIds;
                if (value === null || !Array.isArray(pinned)) throw new Error('invalid pin value');
                const pinnedPerms = effectivePermissions(pinnedUserId);
                value.pinnedSessionIds = pinned.filter((id): id is string =>
                  typeof id === 'string' && authorizedSubuserSessionRoot(pinnedUserId, id, pinnedPerms) !== null,
                );
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── workspace/archiveSession|unarchiveSession 响应（子用户）：archivedSessionIds 收租 ──
        // 0.1.7 的归档集合与 pin 集合同为宿主机 registry 全局状态：archiveSession /
        // unarchiveSession 的**成功响应直接回带完整 archivedSessionIds**。请求侧已由
        // SESSION_SCOPED_RE 完成会话归属校验，但响应若不过滤，任一子用户归档一次就能
        // 枚举其他租户的会话 ID（与 workspace.list / pinSession 同一枚举面）。形状不符
        // 时 fail-closed（502），绝不回放未过滤集合。
        if (reqAs.dshpwUser !== undefined && reqAs.dshpwIsAdmin !== true &&
          req.method === 'POST' && /^\/api\/workspace[.\/](?:archiveSession|unarchiveSession)$/.test(proxyPath)) {
          const archiveUserId = reqAs.dshpwUser;
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              // 业务失败（如 workspace/session-active）不带归档集合，原样透传；成功结果
              // 必须是完整归档集合。
              if (result !== null && result.ok === true) {
                const value = isPlainJsonRecord(result.value) ? result.value : null;
                const archived = value === null ? undefined : value.archivedSessionIds;
                if (value === null || !Array.isArray(archived)) throw new Error('invalid archive value');
                const archivePerms = effectivePermissions(archiveUserId);
                const projected = archived.filter((id): id is string =>
                  typeof id === 'string' && authorizedSubuserSessionRoot(archiveUserId, id, archivePerms) !== null,
                );
                value.archivedSessionIds = projected;
                // 归档动作是权威投影：立即刷新该用户的内存归档集合（只含已授权会话），并
                // 推进同一用户 workspace.list 的顺序水位，令在途更旧的列表响应无法回滚它。
                // 畸形/业务失败不会进入本分支，旧状态保持不动。
                const access = userSessionAccess.get(archiveUserId);
                if (access !== undefined) {
                  userArchivedSessionIds.set(archiveUserId, new Set(projected));
                  replaceUserSessionAccess(archiveUserId, access, userAccessEpochFor(archiveUserId), bumpWorkspaceListRequestRevision());
                }
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── session.create / fork 响应：登记当前用户会话 + 注入真实沙盒（F-26） ──
        // 响应体不变；已通过目录/源会话校验的新会话写入显式授权（未禁用时），
        // 其可见性由显式 grant + 工作区白名单 + 逐会话禁用共同决定。
        if (req.method === 'POST' && /^\/api\/session[.\/](create|fork)$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, async (raw) => {
            try {
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              const decoded = enc.includes('gzip') ? gunzipBounded(raw) : raw;
              const parsed = JSON.parse(decoded.toString('utf8'));
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              const businessFailure = result?.ok === false;
              const sessionId = businessFailure ? null : result === null ? null : extractSessionId(result.value);
              if (reqAs.dshpwCreatedSessionId !== undefined && businessFailure) {
                clearPendingCreatedSession(reqAs.dshpwUser!, reqAs.dshpwCreatedSessionId);
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              if (reqAs.dshpwCreatedSessionId !== undefined && sessionId !== reqAs.dshpwCreatedSessionId) {
                clearPendingCreatedSession(reqAs.dshpwUser!, reqAs.dshpwCreatedSessionId);
                if (!res.headersSent) res.status(502).type('text/plain').send('502 DSH session identity mismatch');
                return;
              }
              if (reqAs.dshpwCreatedSessionId !== undefined && sessionId === null) {
                clearPendingCreatedSession(reqAs.dshpwUser!, reqAs.dshpwCreatedSessionId);
                if (!res.headersSent) res.status(502).type('text/plain').send('502 DSH session response missing identity');
                return;
              }
              if (sessionId !== null && reqAs.dshpwUser !== undefined) {
                // dsh create/fork 都用 agentDefaultModel.currentSelection() 给新会话
                // 配模型（fork 不继承源会话模型），所以新会话的初始有效模型就是 Host
                // 共享默认。这里记为 'default'（而不是把它当成未知）：后续 prompt 时
                // 与白名单比对，默认不在允许列表就会 fail-closed，用户选一个允许模型后即可。
                recordSessionModelSelection(sessionId, null);
                // 沙盒必须先确认，再建立子用户的 session grant/access 快照。
                // 若注入失败，不能留下一个可由该子用户继续访问的默认 workspace-write 会话。
                if (reqAs.dshpwPerms !== undefined) {
                  // 请求进入后管理员可能收紧沙盒。响应期重读当前行并取两者更严
                  // 档位，绝不让一个在途 create/fork 留在任一时刻策略之外的宽权限。
                  const snapshotMode = reqAs.dshpwPerms.sandbox_mode;
                  const currentMode = db.getPermissions(reqAs.dshpwUser)?.sandbox_mode ?? null;
                  const sandboxMode = strictestSandboxMode(snapshotMode, currentMode);
                  const applied = sandboxMode === null || await applySandboxToSession(sessionId, sandboxMode);
                  if (!applied) {
                    if (reqAs.dshpwCreatedSessionId !== undefined) clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
                    if (!res.headersSent) res.status(502).type('text/plain').send('502 Sandbox enforcement failed');
                    return;
                  }
                }
                if (reqAs.dshpwAgentPreset !== undefined) sessionAgentPresetMapFor(reqAs.dshpwUser).set(sessionId, reqAs.dshpwAgentPreset);
                else collectSessionAgentPresets(parsed, sessionAgentPresetMapFor(reqAs.dshpwUser));
                const reqCwd = reqAs.dshpwSessionCwd;
                const cwd = typeof reqCwd === 'string' && reqCwd.length > 0
                  ? reqCwd
                  : collectSessionCwd(parsed).get(sessionId);
                if (cwd) {
                  if (reqAs.dshpwCreatedSessionId !== undefined) clearPendingCreatedSession(reqAs.dshpwUser!, reqAs.dshpwCreatedSessionId);
                  sessionCwdById.set(sessionId, cwd);
                  if (
                    reqAs.dshpwIsAdmin !== true &&
                    reqAs.dshpwPerms !== undefined &&
                    (reqAs.dshpwSessionCwd !== undefined || reqAs.dshpwForkAuthorized === true) &&
                    sessionAccessRequestEpoch === userAccessEpochFor(reqAs.dshpwUser)
                  ) {
                    const access = new Map(userSessionAccessFor(reqAs.dshpwUser));
                    // epoch 相等只说明授权行在本请求期间未变；仍按最新权限行复核一次
                    // disabled/folder，双重保险（未来新增权限入口忘记推进 epoch 时也不放行）。
                    const currentPerms = db.getPermissions(reqAs.dshpwUser) ?? reqAs.dshpwPerms;
                    if (!currentPerms.disabled_sessions.includes(sessionId) &&
                        folderAllowed(cwd, currentPerms.allowed_folders)) {
                      // 增量追加单条 grant：不读取也不重写整张授权表，所以同一窗口内
                      // 其它调用（管理员保存、沙盒定向回收）并发写入的 grant 不会被
                      // 这次回写抹掉（epoch 已保证期间没有授权变更，故不回写异常数据）。
                      db.addUserSessionGrant(reqAs.dshpwUser, sessionId);
                      access.set(sessionId, cwd);
                    }
                    replaceUserSessionAccess(reqAs.dshpwUser!, access, sessionAccessRequestEpoch);
                    // The durable workspace upsert can be lost or arrive before the
                    // browser has installed its baseline. Publish a compensating
                    // filtered upsert after the grant is committed so the client
                    // cannot leave the new session under Ungrouped.
                    for (const connection of remoteMuxClientsByUser.get(reqAs.dshpwUser!) ?? []) {
                      connection.publishSessionAttachment(sessionId, cwd);
                    }
                  }
                }
              }
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) {
                // 诊断：上游状态/编码/首字节与解析错误一并落日志，便于定位真机差异。
                console.error(
                  `[dsh-passwords] session.create/fork 响应不可解析: status=${String(upstreamRes.statusCode)} encoding=${String(upstreamRes.headers['content-encoding'] ?? '')} type=${String(upstreamRes.headers['content-type'] ?? '')} bytes=${String(raw.length)} head=${JSON.stringify(raw.subarray(0, 120).toString('utf8'))} error=${error instanceof Error ? error.message : String(error)}`,
                );
                clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
                // 上游 4xx/5xx 的非 JSON 响应原样透传（如 404 not found）：伪装成 502
                // 会误导排障；只有上游 2xx 却解析失败才是网关侧不可处理。
                if ((upstreamRes.statusCode ?? 502) >= 400) {
                  const passthrough = headersForStreaming(upstreamRes.headers);
                  if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 502, passthrough);
                  if (!res.writableEnded) res.end(raw);
                  return;
                }
                if (!res.headersSent) res.status(502).type('text/plain').send('502 DSH session response unprocessable');
                return;
              }
              // 非 JSON 响应：原样透传，但 cwd 缓存/沙盒副作用缺失——记录 warn 便于排查。
              console.warn(`[dsh-passwords] session.create/fork 上游响应非 JSON，cwd/沙盒副作用缺失: ${proxyPath}`);
              const respHeaders = headersForStreaming(upstreamRes.headers);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(raw);
            }
          });
          return;
        }


        // ── session.list 响应过滤：显式授权快照 + 工作区白名单 + 逐会话禁用 + 归档排除 ──
        // 子用户只看到授权快照命中（由 workspace.list 建立）、未禁用且未归档的活动会话；
        // 管理员保持完整视图。
        if (
          reqAs.dshpwPerms !== undefined &&
          req.method === 'POST' &&
          /^\/api\/session[.\/]list$/.test(proxyPath)
        ) {
          bufferUpstream(upstreamRes, res, async (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              // Admin retains the legacy global cache. A subuser waits briefly
              // for alpha.3's independent workspace/follow baseline instead of
              // treating normal stream ordering as an authorization failure.
              if (reqAs.dshpwIsAdmin === true) collectSessionCwd(parsed, sessionCwdById);
              const userId = reqAs.dshpwUser!;
              if (!userSessionAccess.has(userId) && !(await waitForUserSessionAccess(userId))) {
                if (!res.headersSent && !res.destroyed && !res.writableEnded) {
                  res.status(503).json({ ok: false, code: 'BASELINE_PENDING', retryable: true });
                }
                return;
              }
              if (res.destroyed || res.writableEnded) return;

              const perms = reqAs.dshpwPerms!;
              const cwdAllowed = isWorkspaceRestricted(perms.allowed_folders)
                ? (cwd: string) => folderAllowed(cwd, perms.allowed_folders)
                : null;
              const disabled = new Set(perms.disabled_sessions);
              const access = userSessionAccessFor(userId);
              const archived = userArchivedSessionIds.get(userId) ?? new Set<string>();
              collectSessionAgentPresets(parsed, sessionAgentPresetMapFor(userId));
              const filtered = filterSessionItems(
                parsed,
                (id) => {
                  const sessionPath = access.get(id);
                  return sessionPath !== undefined && !disabled.has(id) && !archived.has(id) &&
                    (db.hasUserSessionGrant(userId, id) || workspaceOwnedByUser(userId, sessionPath));
                },
                cwdAllowed,
              );
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              // 该分支仅处理子用户列表：任何解析/过滤异常都 fail-closed 502，
              // 绝不把未过滤的全量列表回放给子用户（fail-open 泄露面）
              if (!res.headersSent) {
                const msg =
                  error instanceof OversizeResponseError
                    ? '502 Upstream response too large'
                    : '502 Upstream response unprocessable';
                res.status(502).type('text/plain').send(msg);
              }
              return;
            }
          });
          return;
        }

        // ── session.search 响应过滤：搜索结果携带 Session ID 与消息摘要 ──
        // rc.1 的搜索是跨会话查询；DSH 上游只知道单一 Host，不知道网关子用户。
        // 子用户必须等待自己的 workspace/follow 基线，再按显式 grant、禁用状态、
        // 目录白名单和跨用户工作区所有权过滤结果。管理员保留原始搜索结果。
        if (
          reqAs.dshpwPerms !== undefined &&
          reqAs.dshpwIsAdmin !== true &&
          req.method === 'POST' &&
          /^\/api\/session[.\/]search$/.test(proxyPath)
        ) {
          bufferUpstream(upstreamRes, res, async (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              if (!isPlainJsonRecord(parsed) || !isPlainJsonRecord(parsed.result)) throw new Error('invalid search envelope');
              const result = parsed.result;
              // 业务失败仍按上游原始结果返回；只有成功结果需要做租户过滤。
              if (result.ok !== true) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              if (!isPlainJsonRecord(result.value) || typeof result.value.hasMore !== 'boolean') {
                throw new Error('invalid search result');
              }
              const userId = reqAs.dshpwUser!;
              if (!(await waitForUserSessionAccess(userId))) {
                if (!res.headersSent && !res.destroyed && !res.writableEnded) {
                  res.status(503).json({ ok: false, code: 'BASELINE_PENDING', retryable: true });
                }
                return;
              }
              if (res.destroyed || res.writableEnded) return;
              const items = filterSessionSearchItems(
                result.value.items,
                (id) => {
                  const perms = reqAs.dshpwPerms!;
                  const access = userSessionAccessFor(userId);
                  const sessionPath = access.get(id);
                  return sessionPath !== undefined &&
                    (db.hasUserSessionGrant(userId, id) || workspaceOwnedByUser(userId, sessionPath)) &&
                    !perms.disabled_sessions.includes(id) &&
                    folderAllowed(sessionPath, perms.allowed_folders) &&
                    !workspaceOwnedByAnotherSubuser(userId, sessionPath);
                },
              );
              if (items === null) throw new Error('invalid search items');
              const filtered = {
                ...parsed,
                result: { ...result, value: { ...result.value, items } },
              };
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (!res.headersSent) {
                const msg = error instanceof OversizeResponseError
                  ? '502 Upstream response too large'
                  : '502 Upstream response unprocessable';
                res.status(502).type('text/plain').send(msg);
              }
            }
          });
          return;
        }

        // ── sessionReferenceResolver/candidates 响应过滤 ──
        // The request's agentId only identifies the caller's current Session; the
        // result is deliberately cross-session discovery. Filter every candidate
        // against the same persisted grant, cwd and ownership rules as session/search.
        if (
          reqAs.dshpwPerms !== undefined &&
          reqAs.dshpwIsAdmin !== true &&
          req.method === 'POST' &&
          proxyPath === '/api/sessionReferenceResolver/candidates'
        ) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              if (!isPlainJsonRecord(parsed) || !isPlainJsonRecord(parsed.result)) throw new Error('invalid session reference envelope');
              const result = parsed.result;
              if (result.ok !== true) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              if (!Array.isArray(result.value)) throw new Error('invalid session reference result');
              const userId = reqAs.dshpwUser!;
              const perms = reqAs.dshpwPerms!;
              const access = userSessionAccessFor(userId);
              const visible = result.value.filter((candidate): candidate is Record<string, unknown> => {
                if (!isPlainJsonRecord(candidate) || typeof candidate.sessionId !== 'string') return false;
                const sessionPath = access.get(candidate.sessionId);
                return sessionPath !== undefined &&
                  (db.hasUserSessionGrant(userId, candidate.sessionId) || workspaceOwnedByUser(userId, sessionPath)) &&
                  !perms.disabled_sessions.includes(candidate.sessionId) &&
                  folderAllowed(sessionPath, perms.allowed_folders) &&
                  !workspaceOwnedByAnotherSubuser(userId, sessionPath);
              }).map((candidate) => ({ ...candidate }));
              const filtered = {
                ...parsed,
                result: { ...result, value: visible },
              };
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (!res.headersSent) {
                const msg = error instanceof OversizeResponseError
                  ? '502 Upstream response too large'
                  : '502 Upstream response unprocessable';
                res.status(502).type('text/plain').send(msg);
              }
            }
          });
          return;
        }

        // ── session/selectModel 成功响应后登记会话有效模型（所有用户）──
        // 只认官方 SessionSelectModelValue.selected（上游规范化后的 provider/model）。
        // 对受限子用户，这个状态就是 prompt/fork 后续校验的授权依据；业务失败
        // （result.ok === false）绝不变更状态，防止借异常响应把状态写成允许值。
        if (req.method === 'POST' && /^\/api\/session[.\/]selectModel$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              if (result !== null && result.ok === true && isPlainJsonRecord(result.value)) {
                const selected = modelSelectionFrom(result.value.selected);
                // 会话 ID 来自同一次请求已校验过的 RPC 参数（selectModel 响应不带
                // sessionId），不允许从响应体里“随手”取字段当授权依据。
                const sessionId = reqAs.dshpwModelSessionId;
                if (selected !== null && sessionId !== undefined) {
                  recordSessionModelSelection(sessionId, selected);
                }
              }
            } catch {
              // 登记失败只影响后续严格校验（prompt 会 fail-closed），响应原样回放。
            }
            const respHeaders = headersForStreaming(upstreamRes.headers);
            if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
            if (!res.writableEnded) res.end(raw);
          });
          return;
        }

        // ── Agent preset 成功响应后登记会话当前 preset ──
        // DSH RPC 的业务失败可以使用 HTTP 200，因此必须解析 result.ok，不能只看状态码。
        if (req.method === 'POST' && AGENT_PRESET_SELECT_RE.test(proxyPath) && reqAs.dshpwAgentPreset !== undefined) {
          const sessionId = reqAs.dshpwSelectedSessionId;
          const selectedAgentPreset = reqAs.dshpwAgentPreset;
          bufferUpstream(upstreamRes, res, (raw) => {
            let businessOk = false;
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = parsed.result;
              businessOk = result !== null && typeof result === 'object' && (result as Record<string, unknown>).ok === true;
            } catch {
              businessOk = false;
            }
            if (businessOk && sessionId !== undefined && reqAs.dshpwUser !== undefined) {
              sessionAgentPresetMapFor(reqAs.dshpwUser).set(sessionId, selectedAgentPreset);
            }
            const respHeaders = headersForStreaming(upstreamRes.headers);
            if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
            if (!res.writableEnded) res.end(raw);
          });
          return;
        }

        // ── session.history 响应：F-A2 隐藏 Unicode 清洗（所有用户）+ 受限子用户沙盒降级 ──
        // F-A2：AI agent 读取文件后内容进入会话历史，重读历史时隐藏指令（零宽/bidi）会
        // 重新进入模型——历史响应经网关代理，在这里对所有用户清洗（主用户同样可能被
        // 诱导读恶意文件）；上游 dsh 不处理，网关补偿。
        // 沙盒降级：主用户把会话设为 danger-full-access 后共享给子用户，子用户打开会话时
        // 会话 log 里的 permission/preset 就是 full access——不拦截就直接继承提权，
        // 这里把超过子用户授权级别的 preset/mode 统一降级（仅受限子用户）。
        if (req.method === 'POST' && /^\/api\/session[.\/]history$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              let body = raw;
              const enc = String(upstreamRes.headers['content-encoding'] ?? '');
              // 观测：解压+JSON.parse（parse）；清洗（filter）；重新序列化（stringify）。
              // 只记录耗时与输入/输出字节，绝不记录正文。
              const parseStart = loadingTimeline.begin();
              if (enc.includes('gzip')) body = gunzipBounded(body);
              const parsed = JSON.parse(body.toString('utf8'));
              loadingTimeline.elapsed('gateway.history.parse', parseStart, { bytesIn: raw.length });
              if (reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.sandbox_mode !== null) {
                void clampSessionHistorySandbox(
                  parsed,
                  reqAs.dshpwPerms!.sandbox_mode as 'read-only' | 'workspace-write' | 'danger-full-access',
                );
              }
              // F-A2：递归清洗历史中所有字符串字段（消息内容/工具结果）的隐藏 Unicode
              const filterStart = loadingTimeline.begin();
              const cleaned = sanitizeHiddenUnicodeJson(parsed);
              loadingTimeline.elapsed('gateway.history.filter', filterStart);
              const stringifyStart = loadingTimeline.begin();
              const out = Buffer.from(JSON.stringify(cleaned), 'utf8');
              loadingTimeline.elapsed('gateway.history.stringify', stringifyStart, { bytesOut: out.length });
              eventLoopDelaySampler.sample('gateway.eventLoop.delay');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 隐藏 Unicode 清洗对所有用户强制生效（受限子用户还叠加沙盒降级）。
              // 解码/解析失败时无法产出已清洗历史，绝不能把上游原始体回放给客户端；
              // 未知 content-encoding（如 br）或畸形 JSON 一律 fail-closed 502。
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── session/page 响应：隐藏 Unicode 清洗 ──
        // page 是只读分页窗口，不能作为当前模型授权状态的权威来源。
        if (req.method === 'POST' && /^\/api\/session[.\/]page$/.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              // 观测：parse（解码+JSON.parse）/ filter（清洗）/ stringify（重新序列化）。
              const parseStart = loadingTimeline.begin();
              const parsed = JSON.parse(
                decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? '')).toString('utf8'),
              ) as unknown;
              loadingTimeline.elapsed('gateway.page.parse', parseStart, { bytesIn: raw.length });
              const filterStart = loadingTimeline.begin();
              const cleaned = sanitizeHiddenUnicodeJson(parsed);
              loadingTimeline.elapsed('gateway.page.filter', filterStart);
              const stringifyStart = loadingTimeline.begin();
              const out = Buffer.from(JSON.stringify(cleaned), 'utf8');
              loadingTimeline.elapsed('gateway.page.stringify', stringifyStart, { bytesOut: out.length });
              eventLoopDelaySampler.sample('gateway.eventLoop.delay');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (error instanceof OversizeResponseError) {
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response too large');
                return;
              }
              // 隐藏 Unicode 清洗同样对所有用户强制生效；解码/解析失败时无法产出
              // 已清洗内容，绝不回放上游原始体，fail-closed 502。
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }
        // ── session/modelCatalog 响应过滤（受限子用户）────────────────────
        // 官方协议：modelCatalog 无参数，value = { default, routableProviders,
        // groups: [{id,name,models}], failures }；provider 身份在 group.id，不在
        // model 对象。modelCatalog 不在 SESSION_SCOPED_RE 里（无 sessionId），
        // 必须用专用判定。
        // 这里同时把未过滤的 Host 默认模型记入网关内存：受限用户的 prompt 校验在
        // 会话没有显式选择时需要拿它与白名单比对（不能把共享默认暴露给子用户，
        // 也不能用它当“未限制”的借口）。
        if (req.method === 'POST' && MODEL_CATALOG_RE.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const result = isPlainJsonRecord(parsed) && isPlainJsonRecord(parsed.result) ? parsed.result : null;
              // 只有成功结果才携带目录；业务失败原样返回（不泄辟信息也不掩盖错误）。
              if (result === null || result.ok !== true || !isPlainJsonRecord(result.value)) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              // 主用户没有 dshpwPerms，但其官方 modelCatalog 请求同样必须填充
              // overview 使用的最近目录快照；否则设置页在用户尚未打开会话模型选择器
              // 时永远显示“模型目录暂不可用”。子用户仍在下方按 allowlist 过滤。
              recordHostDefaultModel(result.value);
              if (reqAs.dshpwPerms === undefined || reqAs.dshpwPerms.allowed_models === null) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              // 过滤结果只改 value 内的官方字段（groups/models/routableProviders/
              // failures/default），其它包层字段原样保留。
              result.value = filterModelCatalogValue(result.value, reqAs.dshpwPerms.allowed_models);
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch {
              // 受限用户的目录必须过滤：解析/解压失败不能回放未过滤的全量模型列表。
              // 主用户不需要改写，但也不应因网关无法解析而被伪造 502；原始响应继续透传。
              if (reqAs.dshpwPerms === undefined) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
              } else if (!res.headersSent) {
                res.status(502).type('text/plain').send('502 Upstream response unprocessable');
              }
            }
          });
          return;
        }

        // ── schedule/catalog 响应过滤（受限子用户）──────────────────────────
        // `catalog` 无参，返回宿主全局提醒的裸数组，每个条目带原始 sessionId
        // （ScheduleCatalogEntry）。官方分类对子用户放行，授权边界只能落在本分支：
        // 逐条按 authorizedSubuserSessionRoot(userId, entry.sessionId, perms) 判定，
        // sessionId 缺失/非法/非该用户授权会话一律丢弃。主用户（无 dshpwPerms）不解析、
        // 不改写，整段原样透传。
        // 信封/形状不合法或解压失败时 fail-closed（502），绝不回放未过滤的全局清单。
        if (req.method === 'POST' && SCHEDULE_CATALOG_RE.test(proxyPath) &&
          reqAs.dshpwPerms !== undefined && reqAs.dshpwIsAdmin !== true) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as unknown;
              if (!isPlainJsonRecord(parsed) || !isPlainJsonRecord(parsed.result)) {
                throw new Error('invalid schedule catalog envelope');
              }
              const result = parsed.result;
              // 业务失败不携带提醒数据：原样返回，不掩盖上游错误。
              if (result.ok !== true) {
                const respHeaders = headersForStreaming(upstreamRes.headers);
                if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
                if (!res.writableEnded) res.end(raw);
                return;
              }
              if (!Array.isArray(result.value)) throw new Error('invalid schedule catalog result');
              const userId = reqAs.dshpwUser!;
              const perms = reqAs.dshpwPerms!;
              // fail-closed：只有命中该用户已授权会话快照的条目保留；缺失/非法
              // sessionId 由 authorizedSubuserSessionRoot 统一判空丢弃。
              const visible = result.value.filter((entry): entry is Record<string, unknown> =>
                isPlainJsonRecord(entry) &&
                authorizedSubuserSessionRoot(userId, entry.sessionId, perms) !== null,
              ).map((entry) => ({ ...entry }));
              const filtered = { ...parsed, result: { ...result, value: visible } };
              const out = Buffer.from(JSON.stringify(filtered), 'utf8');
              const respHeaders = headersForRewrittenBody(upstreamRes.headers);
              respHeaders['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, respHeaders);
              if (!res.writableEnded) res.end(out);
            } catch (error) {
              if (!res.headersSent) {
                const msg = error instanceof OversizeResponseError
                  ? '502 Upstream response too large'
                  : '502 Upstream response unprocessable';
                res.status(502).type('text/plain').send(msg);
              }
            }
          });
          return;
        }

        // ── 受限用户 Agent preset 列表过滤 ──
        if (req.method === 'POST' && reqAs.dshpwPerms !== undefined && reqAs.dshpwPerms.allowed_agent_presets !== null && AGENT_PRESET_LIST_RE.test(proxyPath)) {
          bufferUpstream(upstreamRes, res, (raw) => {
            try {
              const body = decodeUpstreamBody(raw, String(upstreamRes.headers['content-encoding'] ?? ''));
              const parsed = JSON.parse(body.toString('utf8')) as Record<string, unknown>;
              const allowed = new Set(reqAs.dshpwPerms!.allowed_agent_presets);
              const filterItems = (value: unknown): unknown => {
                if (!Array.isArray(value)) return value;
                return value.filter((item) => {
                  if (item === null || typeof item !== 'object') return false;
                  const row = item as Record<string, unknown>;
                  const id = typeof row.id === 'string' ? row.id : typeof row.agentPreset === 'string' ? row.agentPreset : null;
                  return id !== null && allowed.has(id);
                });
              };
              const result = parsed.result;
              if (result !== null && typeof result === 'object') {
                const resultObj = result as Record<string, unknown>;
                const value = resultObj.value;
                if (value !== null && typeof value === 'object') {
                  const valueObj = value as Record<string, unknown>;
                  if ('items' in valueObj) valueObj.items = filterItems(valueObj.items);
                  if ('presets' in valueObj) valueObj.presets = filterItems(valueObj.presets);
                } else if (Array.isArray(value)) {
                  resultObj.value = filterItems(value);
                }
              }
              const out = Buffer.from(JSON.stringify(parsed), 'utf8');
              const headers = headersForRewrittenBody(upstreamRes.headers);
              headers['content-length'] = String(out.length);
              if (!res.headersSent) res.writeHead(upstreamRes.statusCode ?? 200, headers);
              if (!res.writableEnded) res.end(out);
            } catch {
              if (!res.headersSent) res.status(502).type('text/plain').send('502 Upstream response unprocessable');
            }
          });
          return;
        }

        // ── 非 HTML：原样流式转发 ───────────────────────────────────
        const respHeaders = headersForStreaming(upstreamRes.headers);
        // dsh 对插件/静态资源返回 no-cache（或不给缓存头），浏览器每次
        // 进页面都要重新下载全部 ~30 个插件文件，导致卡在 "Loading plugins…"。
        // rev 参数/文件名都是内容哈希（换内容即换新 URL），可安全长缓存：
        const isHashedStatic =
          proxyPath.startsWith('/assets/') ||
          (proxyPath.startsWith('/plugins/') && parsedUrl.searchParams.has('rev'));
        if (isHashedStatic) {
          respHeaders['cache-control'] = 'public, max-age=31536000, immutable';
        }
        if (res.headersSent) {
          // 响应已被 fail-closed 分支发送（上游仍返回了响应）：不再重复写头
          res.destroy();
          return;
        }
        res.writeHead(upstreamRes.statusCode ?? 502, respHeaders);
        // 已加载插件路由按宿主清单统一转发；不在网关按插件协议猜测文件/上传/清洗语义。
        // 官方 session/history/page 等需要响应处理的分支在上方独立完成。
        // 旧线 /api/events.host|events.mux 的 HTTP SSE 长连接与 WS 通道同口径登记
        // （含主用户）：权限变更/登出/删号必须立即终止仍在升级时身份下推送的旧订阅，
        // 否则撤销后连接会继续持有旧授权（主用户为原样透传，泄露面更大）。只在真正
        // 建立的事件流（GET + 2xx）上登记，响应关闭即注销，避免登记表滞留。
        if (
          req.method === 'GET' &&
          (upstreamRes.statusCode ?? 0) === 200 &&
          reqAs.dshpwUser !== undefined &&
          (proxyPath === '/api/events.host' || proxyPath === '/api/events.mux')
        ) {
          const unregisterEventSse = registerUserWebSocketClient(reqAs.dshpwUser, {
            close: () => {
              // HTTP SSE 没有 WS close 帧：直接销毁响应，立即中断下行并释放缓冲；
              // 客户端 EventSource 会按协议重连，重新经过认证门卫与权限过滤。
              if (!res.writableEnded) res.destroy();
            },
          });
          res.on('close', unregisterEventSse);
        }
        if (proxyPath === '/api/events.host' && reqAs.dshpwUser !== undefined && reqAs.dshpwPerms !== undefined) {
          upstreamRes.pipe(hostEventFilter(reqAs.dshpwUser, reqAs.dshpwPerms)).pipe(res);
          upstreamRes.on('error', () => res.destroy());
          return;
        }
        if (proxyPath === '/api/events.mux' && reqAs.dshpwUser !== undefined && reqAs.dshpwPerms !== undefined) {
          upstreamRes.pipe(muxEventFilter(reqAs.dshpwUser, reqAs.dshpwPerms)).pipe(res);
          upstreamRes.on('error', () => res.destroy());
          return;
        }
        upstreamRes.pipe(res);
        // 上游响应流中途断开：客户端侧直接中断（头已发，不能再写错误页）
        upstreamRes.on('error', () => {
          res.destroy();
        });
      },
    );
    // 请求体写尽后才开始等待响应头（Go Transport.ResponseHeaderTimeout 语义）：客户端
    // 上传大 body 的耗时不计入窗口，避免正常大文件上传被误判成上游卡死。
    upstreamReq.on('finish', () => {
      if (upstreamResponseHeaderTimer !== undefined || res.headersSent) return;
      upstreamResponseHeaderTimer = setTimeout(() => {
        upstreamResponseHeaderTimer = undefined;
        if (res.headersSent) return;
        // 先置标记再销毁：destroy() 可能异步 emit 'error'，不能让它把 504 覆盖成 502
        upstreamResponseHeaderTimedOut = true;
        upstreamReq.destroy();
        if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) {
          clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
        }
        res.status(504).type('text/plain').send('504 Upstream response timeout');
      }, upstreamResponseHeaderTimeoutMs());
      upstreamResponseHeaderTimer.unref();
    });
    upstreamReq.on('error', (error) => {
      clearUpstreamResponseHeaderTimer();
      if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) {
        clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
      }
      if (requestBodyRejected || upstreamResponseHeaderTimedOut) return;
      if (res.headersSent || res.writableEnded || res.destroyed) {
        // 响应已开始转发或客户端已断开：只能中断连接，避免
        // ERR_HTTP_HEADERS_SENT 崩溃。
        if (!res.destroyed) res.destroy();
        return;
      }
      res
        .status(502)
        .type('html')
        .send(`<h3>${escapeHtml(t(langOf(req), 'gw.upstreamDown'))}</h3><p>${escapeHtml(error.message)}</p>`);
    });
    // 客户端中途断开：中止上游请求，避免悬挂连接（同时回收响应头等待计时器）
    res.on('close', () => {
      clearUpstreamResponseHeaderTimer();
      if (!res.writableEnded) upstreamReq.destroy();
      if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) {
        clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
      }
    });
    // 受限子用户的请求体缓冲检查（尽力而为）：
    //   1) 文件夹白名单：session.create/fork 的 cwd/workspaceId 必须在授权目录内
    //   2) 沙盒权限（纵深防御）：settings 写方法（mutate/update/replace）已在上游分类前
    //      由 SUBUSER_BLOCKED_API_ENDPOINTS 对子用户硬拒绝，这里的 defaultPreset clamp
    //      只是该硬边界被放宽时的兜底，不再是可到达的主路径。
    const workspaceManagementRequest = isWorkspaceCreate(proxyPath) || isWorkspaceDeleteOrRename(proxyPath);
    const workspaceOrderRequest = isWorkspaceOrderWrite(proxyPath);
    const workspaceDirectoryCreateRequest = isWorkspaceDirectoryCreate(proxyPath);
    // 子用户目录浏览（alpha.1 in-app picker / 旧 host.listDirectory）：请求路径必须
    // 在授权子树内，或是通往某个授权根的祖先（此时响应条目按授权根过滤）。
    const needsDirectoryListCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwIsAdmin !== true &&
      req.method === 'POST' &&
      isDirectoryListRequest(proxyPath);
    const needsFolderCheck =
      reqAs.dshpwPerms !== undefined &&
      (req.method === 'POST' || req.method === 'PUT') &&
      (WORKSPACE_ENDPOINT_RE.test(proxyPath) || workspaceManagementRequest || workspaceOrderRequest || workspaceDirectoryCreateRequest);
    const needsSandboxCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/settings[.\/]/.test(proxyPath);
    // 沙盒切换的实际主路径是 /permission slash 命令：经 commands/execute RPC
    // （body { agentId, line }，line 形如 "/permission workspace-write"），
    // 而不是 settings.mutate。这里对受限子用户同样做越权预设检查。
    const needsCommandCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/commands[.\/]execute$/.test(proxyPath);
    // AI 提权审批：沙盒升级经 /api/respond（body { sessionId, approvalId, outcome }）。
    // 受限子用户（sandbox_mode 非空）即使点了“允许”，也强制改成 rejected，把 AI 的
    // 越权提权直接取消。ask_user_question 用的是 answer 字段，不会被这里误伤。
    const needsApprovalCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.sandbox_mode !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      /^\/api\/respond$/.test(proxyPath);
    // 会话作用域 RPC（history/prompt/respond/archive/delete/rename/fork 等）
    // 必须命中显式授权快照、位于已开启工作区，且未被管理员逐会话关闭。
    const needsOwnershipCheck =
      reqAs.dshpwPerms !== undefined &&
      (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') &&
      (SESSION_SCOPED_RE.test(proxyPath) || AGENT_PRESET_SELECT_RE.test(proxyPath));
    const needsWorkspaceOrderCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwIsAdmin !== true &&
      req.method === 'POST' &&
      workspaceOrderRequest;
    // ── 已登记 SSH 端点的 SSRF 纵深防御（与任何具体插件无关）──
    // 命中已登记 SSH 端点（HTTP 通道）的写请求若带 host 字段：私网/回环
    // 地址一律拒绝（插件源码不在我们控制内，网关拦一层；所有登录用户含主用户
    // 都拦，管理员同样可能被诱导连接内网）。F-27：PATCH/PUT 同样要拦——只拦
    // POST 时 PATCH 可直接把已有主机的 host 改成 127.0.0.1 等私网地址（实测可改）。
    const needsAgentPresetCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.allowed_agent_presets !== null &&
      (req.method === 'POST' || req.method === 'PUT') &&
      (/^\/api\/session[.\/](create|fork|prompt)$/.test(proxyPath) ||
        AGENT_PRESET_SELECT_RE.test(proxyPath));
    // alpha.3 图片附件随 ClientConnection RPC JSON 内嵌，不经过第三方上传路由。
    // 关闭上传时必须在解封装请求体后拒绝，普通文本 prompt/command 保持可用。
    const needsImageAttachmentCheck = false;
    // ── 模型白名单（allowed_models）请求侧强制 ──
    // 受限子用户（allowed_models 非 null）的每个模型入口都要在转发前判定：
    //   · session/selectModel：请求体带 {provider, model}，直接正向校验（绝不靠上游报错）
    //   · session/create/fork/prompt：协议里**没有**模型字段，只能拿网关记录的会话
    //     有效模型（官方 model/selection 投影 / selectModel 结果 / Host 默认）再校验，
    //     这样权限收紧后旧会话也拿不到已撤销的模型。
    const needsModelCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwPerms.allowed_models !== null &&
      req.method === 'POST' &&
      (/^\/api\/session[.\/](selectModel|create|fork|prompt)$/.test(proxyPath) ||
        /^\/api\/subagents[.\/]prompt$/.test(proxyPath));
    // ── 受限子用户执行期沙盒确认（共享既有会话的越权面）──
    // create/fork 在创建响应里注入沙盒，但「主用户把已有会话授权给子用户」不经过
    // create/fork：该会话 log 里的 sandbox/mode 是主用户的（可能 danger-full-access）。
    // DSH 在每次工具执行时从 session log 折叠策略，所以一旦一次 run 被接纳，
    // 子用户就会拿到会话自身的更宽档位。这里在最能启动/驱动一次 run 的入口
    // （session/prompt、subagents/prompt，DSH 要求 prompt 前显式 resume，故此时
    // 会话必为活会话）再确认一次授权档位并 fail-closed。
    const needsSandboxRunCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwUser !== undefined &&
      req.method === 'POST' &&
      /^\/api\/(?:session[.\/]prompt|subagents[.\/]prompt)$/.test(proxyPath);
    const agentPresetMutation = AGENT_PRESET_MUTATION_RE.test(proxyPath);
    if (reqAs.dshpwPerms !== undefined && reqAs.dshpwIsAdmin !== true && agentPresetMutation) {
      res.status(403).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.folderDenied')));
      return;
    }
    const needsUpstreamHostCheck =
      reqAs.dshpwUser !== undefined &&
      (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT') &&
      endpointAllowed(proxyPath, getEndpointRules(), { transport: 'http' }) &&
      !OFFICIAL_TERMINAL_HTTP_RE.test(proxyPath);
    // A Remote waterfall result is a separate browser HTTP RPC. Restrict it to
    // the subuser, client generation, and authorized session that received it.
    const needsRemoteEventResultCheck =
      reqAs.dshpwPerms !== undefined &&
      req.method === 'POST' &&
      proxyPath === '/api/$events/result';
    // The official open-in-app host route accepts an absolute directory path and
    // launches a server-side application. For a child account, bind that path
    // to a workspace already present in the child's filtered Remote baseline;
    // allowed_folders alone must not turn this into an arbitrary directory launcher.
    const needsOpenInAppCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwIsAdmin !== true &&
      req.method === 'POST' &&
      proxyPath === '/open-in-app/open';
    // ── workspaceFiles 会话作用域 + 目标路径守卫 ──
    // 上游 read/readAll/readBytes/readRelated/stat 接受绝对路径且明确不做工作区
    // 包含检查，list 只保证在会话根内；请求里的 workspaceFileScopeId 完全由客户端
    // 指定。子用户只有在「该 scope 会话已授权」且「目标路径（含 readBytes 的
    // baseFile）同时通过词法口径（pathWithin + folderAllowed）与 canonical 口径
    // （realpath 后与 canonical 化的会话根比较）」时才能转发，其余（含无法解析
    // scope/path）一律 403。`changes` 是带 path 的 Remote 流，其 HTTP unary 面
    // 已在前面显式 403；保留在这里是纵深防御。
    const needsWorkspaceFilesCheck =
      reqAs.dshpwPerms !== undefined &&
      reqAs.dshpwIsAdmin !== true &&
      req.method === 'POST' &&
      WORKSPACE_FILES_RPC_RE.test(proxyPath);

    if (needsFolderCheck || needsSandboxCheck || needsCommandCheck || needsApprovalCheck || needsOwnershipCheck || needsWorkspaceOrderCheck || needsAgentPresetCheck || needsImageAttachmentCheck || needsModelCheck || needsSandboxRunCheck || needsUpstreamHostCheck || needsRemoteEventResultCheck || needsOpenInAppCheck || needsWorkspaceFilesCheck || needsDirectoryListCheck) {
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      // 权限检查必须先完整读取 JSON，平台统一设置有界硬上限；不再按子用户
      // 或上传/Prompt 类型施加业务大小限制。超过平台硬上限时 fail-closed，
      // 防止超大请求绕过 ownership/preset/sandbox 检查或耗尽网关内存。
      const bodyLimit = requestBodyLimit;
      const declaredLength = Number(req.headers['content-length'] ?? '');
      if (Number.isFinite(declaredLength) && declaredLength > bodyLimit) {
        settled = true;
        upstreamReq.destroy();
        res.status(413).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.bodyTooLarge')));
        return;
      }
      req.on('data', (chunk: Buffer) => {
        if (settled) return;
        size += chunk.length;
        if (size > bodyLimit) {
          if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
          // F-17：超限一律 fail-closed（413）——之前插件写超大 body 会
          // 透传跳过白名单校验（fail-open），形成防御缺口
          settled = true;
          const lang = langOf(req);
          // 先中止上游请求，否则上游响应到达时会对已发送的响应再 writeHead
          upstreamReq.destroy();
          res.status(413).type('html').send(forbiddenPage(lang, t(lang, 'gw.bodyTooLarge')));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', async () => {
        if (settled || res.headersSent || res.writableEnded || res.destroyed) return;
        settled = true;
        const lang = langOf(req);
        let bodyObj: unknown = null;
        try {
          bodyObj = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        } catch {
          bodyObj = null;
        }
        // 需要检查的端点 body 必须是可解析的 JSON。解析失败（gzip/非 JSON 编码
        // 构造）一律 fail-closed：直接拒绝，防止绕过文件夹白名单、沙盒越权、
        // 命令越权与 AI 提权审批（之前会静默透传到上游）。
        if (bodyObj === null) {
          if (reqAs.dshpwUser !== undefined && reqAs.dshpwCreatedSessionId !== undefined) clearPendingCreatedSession(reqAs.dshpwUser, reqAs.dshpwCreatedSessionId);
          upstreamReq.destroy();
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
          return;
        }
        // 转发体默认原样；SSRF 校验或审批改写时会整体重建（重建必须同步更新 content-length）
        let forwardBody = Buffer.concat(chunks);

        // ── 模型白名单（allowed_models）判定 ──
        // 官方这些 RPC 都无法只靠请求体判定真实模型（create/fork/prompt 没有模型字段），
        // 所以：selectModel 对请求体里的 {provider, model} 正向校验；其余用网关记录的会话
        // 有效模型（官方 modelSelection 投影 / selectModel 结果 / Host 默认）再校验，拿不到
        // 就 fail-closed。受限用户创建的会话记录为 'default'（Host 共享默认），fork 新建会话
        // 同理（DSH fork 用 agentDefaultModel 而不是源会话模型，源模型与默认模型都要判）。
        // 判定只依赖 bodyObj/proxyPath 与传入的允许列表；reqAs 状态写入留在原始调用点。
        // 转发前门禁与沙盒 await 之后的复核共用本函数，避免两处逻辑漂移；null = 不限。
        const modelGateAllows = (allowed: readonly string[] | null): boolean => {
          if (allowed === null) return true;
          if (/^\/api\/session[.\/]selectModel$/.test(proxyPath)) {
            // 模型字段只从官方 wire 位置读取：有 ClientConnection envelope 时只看
            // args.request（DSH 同源解码）；否则兼容直接顶层字段的调用方。绝不允许顶层
            // 伪字段在 envelope 请求里“洗白”一个不同模型。缺字段/格式非法同样拒绝
            // （不能只靠上游 resolveCallConfig 报错）。
            const requestEnvelope = clientConnectionArgs(bodyObj);
            const requestPayload = rpcRequestPayload(bodyObj);
            const selection = modelSelectionFrom(requestPayload) ??
              (requestEnvelope === null ? modelSelectionFrom(bodyObj) : null);
            return selection !== null && modelChoiceVerdict(allowed, selection).ok;
          }
          if (/^\/api\/session[.\/]create$/.test(proxyPath)) {
            // create 不带模型：新会话用 Host 共享默认，默认不在白名单仍允许创建（客户端拿到
            // 过滤后的 modelCatalog 后可另选允许模型；prompt 会在模型未收敛时 fail-closed）。
            // 唯一提前拒绝：白名单为空（[] = 禁止全部），建了也永远用不了。
            return allowedModelSet(allowed)?.size !== 0;
          }
          // 用协议感知的会话地址解析（与所有权校验同源）：只认官方 RPC 的
          // request/args/address/sessionId 结构，不扫描请求体里的任意字段。
          const authorized = collectAuthorizedSessionIds(bodyObj);
          const sessionIds = authorized === null ? [] : [...authorized];
          if (sessionIds.length === 0) return false;
          // subagents/prompt 的模型同样来自 Host 默认（子代理没有自己的 model/selection
          // 状态），所以只能拿默认模型做判定。
          const isSubagentPrompt = /^\/api\/subagents[.\/]prompt$/.test(proxyPath);
          for (const sessionId of sessionIds) {
            const effective = isSubagentPrompt ? null : effectiveSessionModel(sessionId);
            // fork：DSH 新会话用 Host 默认模型，所以源会话模型与默认模型都要过白名单。
            const candidates: (AllowedModelSpec | null)[] = [effective];
            if (isSubagentPrompt || /^\/api\/session[.\/]fork$/.test(proxyPath)) {
              candidates.push(getHostDefaultModelKnown() ? getHostDefaultModel() : null);
            }
            if (candidates.some((candidate) => !modelChoiceVerdict(allowed, candidate).ok)) return false;
          }
          return true;
        };
        // Agent preset 白名单判定：同上，转发前与沙盒 await 后共用；null = 不限。
        const agentPresetGateAllows = (allowedPresets: readonly string[] | null): boolean => {
          if (allowedPresets === null) return true;
          const allowedSet = new Set(allowedPresets);
          const requestedPreset = agentPresetFromRequest(bodyObj);
          const sessionIds = collectSessionIds(bodyObj);
          const requiresExplicitPreset = AGENT_PRESET_SELECT_RE.test(proxyPath);
          const sessionAgentPresets = sessionAgentPresetMapFor(reqAs.dshpwUser!);
          const inheritedPreset = /^\/api\/session[.\/]fork$/.test(proxyPath)
            ? [...sessionIds].map((id) => sessionAgentPresets.get(id)).find((id): id is string => id !== undefined)
            : undefined;
          const promptPresets = /^\/api\/session[.\/]prompt$/.test(proxyPath)
            ? [...sessionIds].map((id) => sessionAgentPresets.get(id))
            : [];
          const selectedPreset = requestedPreset ?? inheritedPreset;
          const isSessionCreate = /^\/api\/session[.\/]create$/.test(proxyPath);
          return isSessionCreate
            ? requestedPreset === null || allowedSet.has(requestedPreset)
            : requiresExplicitPreset
            ? requestedPreset !== null && allowedSet.has(requestedPreset)
            : /^\/api\/session[.\/]fork$/.test(proxyPath)
              ? selectedPreset !== undefined && allowedSet.has(selectedPreset)
              : promptPresets.length > 0 && promptPresets.every((preset) => preset !== undefined && allowedSet.has(preset));
        };

        if (needsImageAttachmentCheck && hasImageAttachment(bodyObj)) {
          upstreamReq.destroy();
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noUpload')));
          return;
        }

        if (needsOpenInAppCheck) {
          const requestedPath = isPlainJsonRecord(bodyObj) && typeof bodyObj.path === 'string'
            ? bodyObj.path
            : null;
          const normalizedRequestedPath = requestedPath !== null && isAbsoluteLikePath(requestedPath)
            ? normalizePath(requestedPath)
            : null;
          // canonical 口径：realpath 解析符号链接/junction（失败回退字符串归一，不更宽松）。
          const canonicalRequestedPath = normalizedRequestedPath === null
            ? null
            : canonicalizePathBestEffort(normalizedRequestedPath);
          const access = userSessionAccess.get(reqAs.dshpwUser!);
          // 「同一工作区」判定走 samePathForMatch：canonical + win32 大小写折叠 + 段边界。
          // 单用 normalizePath 相等会在 Windows 大小写/别名形态下把合法工作区静默漏配。
          const authorizedWorkspace = normalizedRequestedPath !== null && canonicalRequestedPath !== null &&
            access !== undefined &&
            [...access.values()].some((workspacePath) =>
              samePathForMatch(workspacePath, normalizedRequestedPath) &&
              samePathForMatch(workspacePath, canonicalRequestedPath)) &&
            folderAllowed(normalizedRequestedPath, reqAs.dshpwPerms!.allowed_folders) &&
            folderAllowed(canonicalRequestedPath, reqAs.dshpwPerms!.allowed_folders) &&
            !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser!, normalizedRequestedPath) &&
            // 绑定/白名单/归属之后仍须拒绝敏感路径：管理员可能把敏感目录（或其祖先）误
            // 登记为工作区，或工作区本身是指向敏感目录的链接；只有敏感基能挡住。
            !isSensitivePath(normalizedRequestedPath) && !isSensitivePath(canonicalRequestedPath);
          if (!authorizedWorkspace) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }

        if (needsWorkspaceFilesCheck) {
          // 只从官方 wire 位置取授权输入（payload.args 的 workspaceFileScopeId/path；
          // 0.1.7-alpha.1 readBytes 另有 options.baseFile/options.range）；任一字段缺失或
          // 形状不符就 fail-closed，绝不回退到信封外层字段。
          const isRelated = /^\/api\/workspaceFiles[.\/]readRelated$/.test(proxyPath);
          const isReadBytes = /^\/api\/workspaceFiles[.\/]readBytes$/.test(proxyPath);
          const request = workspaceFileScopeRequest(bodyObj, isReadBytes);
          // relativePath 只属于 readRelated；其它 RPC 带第二个文件参数就是形状不符。
          const relativePath = request === null || !isRelated ? null : request.relativePath;
          const sessionRoot = request === null ||
            (isRelated && request.relativePath === null) ||
            (!isRelated && request.relativePath !== null)
            ? null
            : authorizedSubuserSessionRoot(reqAs.dshpwUser!, request.scopeId, reqAs.dshpwPerms!);
          // readBytes 带 baseFile 时，上游按 resolve(dirname(baseFile), path) 读取；网关必须
          // 用同一口径解析真实目标（baseFile 为选定路径、path 为相对路径），否则
          // `{ path: 'x', options: { baseFile: '/etc/file' } }` 会以“工作区内的 x”通过校验，
          // 而上游实际读的是 /etc/x。baseFile 自身也必须在同一会话根内，不能只验证最终
          // 目标恰好回到工作区。绝对/scheme 形状的 path 在这里直接解析成 null。
          // 归属判定同时走两套口径：
          //   · 词法：归一化 + pathWithin + folderAllowed（段边界与白名单原样判定；
          //     __deny__ 仍由 folderAllowed 直接拒掉，fail-closed 不变）；
          //   · canonical：realpath 解析符号链接/junction 后与 canonical 化的会话根
          //     比较，且同一份白名单仍要命中。
          // 只做词法判定会被工作区内的符号链接/junction 带出根外；只做 canonical 判定
          // 则在 realpath 失败时失去边界保护。canonicalizePathBestEffort 失败时回退为
          // 字符串归一，因此第二套判定不会比词法更宽松（不把失败 realpath 变成放宽）。
          const canonicalSessionRoot = sessionRoot === null ? null : canonicalizePathBestEffort(sessionRoot);
          const targetAllowed = (candidate: string | null): candidate is string => {
            if (candidate === null || sessionRoot === null || canonicalSessionRoot === null) return false;
            const canonicalCandidate = canonicalizePathBestEffort(candidate);
            // 归属用单向子树：会话根可能落在被分配的父目录下，只要目标伸进另一
            // 子用户创建的工作区子树（含相等）就拒——等值判定会漏掉深一层的目标。
            return pathWithin(candidate, sessionRoot) &&
              pathWithin(canonicalCandidate, canonicalSessionRoot) &&
              folderAllowed(candidate, reqAs.dshpwPerms!.allowed_folders) &&
              folderAllowed(canonicalCandidate, reqAs.dshpwPerms!.allowed_folders) &&
              !workspaceSubtreeOverlap(reqAs.dshpwUser!, candidate);
          };
          const baseFileTarget = request === null || sessionRoot === null || request.baseFile === null
            ? null
            : resolveWorkspaceFileTarget(sessionRoot, request.baseFile, null);
          const baseFileAllowed = targetAllowed(baseFileTarget);
          const target = request === null || sessionRoot === null
            ? null
            : request.baseFile !== null
              ? (!baseFileAllowed ? null : resolveWorkspaceFileTarget(sessionRoot, request.baseFile, request.path))
              : resolveWorkspaceFileTarget(sessionRoot, request.path, relativePath);
          if (!targetAllowed(target)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // 通过会话根/白名单/归属之后，仍须拒绝敏感路径：管理员可能把敏感目录的祖先
          // 误登记为工作区，此时目标会同时命中白名单与归属，只有敏感基能挡住。
          if (isSensitivePath(target) || isSensitivePath(canonicalizePathBestEffort(target))) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }

        if (needsRemoteEventResultCheck) {
          const envelope = isPlainJsonRecord(bodyObj) ? bodyObj : null;
          const payload = envelope !== null && envelope.type === 'client-request' && typeof envelope.rpcId === 'string' &&
            envelope.method === '$events/result' && isPlainJsonRecord(envelope.payload) && Object.keys(envelope.payload).length === 1 &&
            isPlainJsonRecord(envelope.payload.args)
            ? envelope.payload.args
            : null;
          const clientId = payload?.clientId;
          const eventId = payload?.eventId;
          const ownership = typeof clientId === 'string' && typeof eventId === 'string'
            ? remoteEventOwnership.get(remoteEventOwnershipKey(eventId, clientId))
            : undefined;
          const access = reqAs.dshpwUser === undefined ? undefined : userSessionAccess.get(reqAs.dshpwUser);
          const sessionPath = ownership === undefined ? undefined : access?.get(ownership.sessionId);
          if (
            ownership === undefined ||
            ownership.expiresAt <= Date.now() ||
            ownership.userId !== reqAs.dshpwUser ||
            ownership.clientId !== clientId ||
            sessionPath === undefined ||
            !db.hasUserSessionGrant(reqAs.dshpwUser!, ownership.sessionId) ||
            reqAs.dshpwPerms!.disabled_sessions.includes(ownership.sessionId) ||
            !folderAllowed(sessionPath, reqAs.dshpwPerms!.allowed_folders) ||
            workspaceOwnedByAnotherSubuser(reqAs.dshpwUser!, sessionPath)
          ) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // The DSH Host settles each event only once. Consume the gateway-side
          // correlation before forwarding so a duplicated HTTP request cannot
          // race the same answer into another active waterfall.
          remoteEventOwnership.delete(remoteEventOwnershipKey(eventId as string, clientId as string));
          // alpha.2 的审批/提问结果走同一条 $events/result 通道（旧客户端走
          // /api/respond）。审批改写沿用旧通道完全相同的门槛（受限子用户 =
          // sandbox_mode 非空）：只能把授权的 'allowed-once' 改写为 rejected；
          // user-questions 的 { answers } 结果不受影响，两条通道语义保持一致。
          if (reqAs.dshpwPerms!.sandbox_mode !== null && forceRejectRemoteEventOutcome(bodyObj)) {
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
            upstreamReq.setHeader('content-length', String(forwardBody.length));
          }
        }

        if (needsAgentPresetCheck) {
          if (!agentPresetGateAllows(reqAs.dshpwPerms!.allowed_agent_presets)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // DSH RPC 业务成功后的 preset 登记（供后续 prompt 的继承校验）仍需在此计算。
          const requestedPreset = agentPresetFromRequest(bodyObj);
          const sessionIds = collectSessionIds(bodyObj);
          const sessionAgentPresets = sessionAgentPresetMapFor(reqAs.dshpwUser!);
          const inheritedPreset = /^\/api\/session[.\/]fork$/.test(proxyPath)
            ? [...sessionIds].map((id) => sessionAgentPresets.get(id)).find((id): id is string => id !== undefined)
            : undefined;
          const selectedPreset = requestedPreset ?? inheritedPreset;
          if ((/^\/api\/session[.\/](create|fork)$/.test(proxyPath) || AGENT_PRESET_SELECT_RE.test(proxyPath)) && selectedPreset !== undefined) {
            reqAs.dshpwAgentPreset = selectedPreset;
          }
          if (AGENT_PRESET_SELECT_RE.test(proxyPath)) {
            reqAs.dshpwSelectedSessionId = [...sessionIds][0];
          }
        }

        // 已登记 SSH 端点的 SSRF 封堵：写请求 body.host 命中私网/回环 → 403。
        // 只校验 host 字段存在的情况（无 host 字段的请求，如用别名引用已创建
        // 目标的操作，在创建时已拦截）。
        // F-28：host 为 hostname（如 nip.io 通配）时 DNS 解析逐地址判定；校验通过后
        // 把请求体 host 改写为已验证的 IP 字面量，钉死 DNS 重绑定 TOCTOU。
        if (needsUpstreamHostCheck && bodyObj !== null && typeof bodyObj === 'object') {
          const host = (bodyObj as Record<string, unknown>).host;
          if (typeof host === 'string') {
            const verdict = await resolveUpstreamHostSafe(host);
            if (res.headersSent || res.writableEnded || res.destroyed) return;
            if (verdict === 'private' || verdict === null) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            (bodyObj as Record<string, unknown>).host = verdict;
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
            // 重写 body 必须同步更新 content-length，否则上游按旧长度读流会挂起/错位
            upstreamReq.setHeader('content-length', String(forwardBody.length));
          }
        }

        // ── 目录浏览授权：请求路径在授权子树内（完整列表），或是通往某个授权根的
        // 祖先（只保留通往授权根的条目）；其余一律 403（fail-closed）。
        if (needsDirectoryListCheck) {
          if (!isPlainJsonRecord(bodyObj)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          const explicitPath = extractPathFromBody(bodyObj);
          // 子用户目录浏览不做相对解析：显式 path 必须完全限定（拒绝相对与 Windows 盘符含糊的 rooted 形式）。
          if (explicitPath !== null && !isFullyQualifiedPath(explicitPath)) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          const requestedPath = explicitPath ?? os.homedir();
          const canonical = canonicalizePathBestEffort(requestedPath);
          const folders = reqAs.dshpwPerms!.allowed_folders;
          const readableRoots = folders.filter((entry) => entry !== '__deny__' &&
            (entry.startsWith('/') || /^[A-Za-z]:\//.test(entry)));
          const readableRootsCanonical = readableRoots.map((entry) => canonicalizePathBestEffort(entry));
          // 读取与创建范围合二为一后没有独立创建根导航：可读根（allowed_folders）即
          // 唯一的条目可见性与导航来源，pending 只在登记侧生效，不再扩大浏览范围。
          if (folderAllowed(requestedPath, folders) && folderAllowed(canonical, folders)) {
            // 授权子树内：内容保留，但响应仍逐条剔除敏感（lexical + canonical）与他人
            // 工作区子树，并清洗 crumbs/home/path。
            reqAs.dshpwDirListFilter = {
              mode: 'authorized',
              readRoots: readableRootsCanonical,
              injectRoots: readableRoots,
            };
          } else {
            const roots = readableRootsCanonical.filter((entry) => pathWithin(entry, canonical));
            if (roots.length === 0) {
              // 初始 picker 可能从 home/根目录开始，而授权根位于另一棵树或另一盘符。
              // 不把它当成越权浏览：上游内容全部过滤，并在响应中给出已授权根作为
              // 可点击入口。真正进入根目录后仍按 folderAllowed + canonical path 双判定。
              // __deny__ / 空白名单同样走这条路径：有可读根时给出入口，没有时条目为空，
              // 既不回放上游内容，也不返回会让官方 picker 直接报错的 403。
              reqAs.dshpwDirListFilter = {
                mode: 'ancestors',
                readRoots: readableRootsCanonical,
                injectRoots: readableRoots,
                showRoots: true,
              };
            } else {
              reqAs.dshpwDirListFilter = {
                mode: 'ancestors',
                readRoots: roots,
                injectRoots: [],
              };
            }
          }
        }

        if (needsFolderCheck && reqAs.dshpwUser !== undefined && extractPathFromBody(bodyObj) === null) {
          const workspaceId = extractWorkspaceId(bodyObj);
          if (workspaceId !== null) {
            const currentPerms = effectivePermissions(reqAs.dshpwUser);
            // 优先用本用户的过滤基线；基线尚未建立（或未包含该 id）时回退到全局
            // workspaceId→path 缓存，但必须再经白名单 + 非他人工作区双判定——
            // 缓存命中本身不构成授权，只用于避免无谓等待。
            const mapped = userWorkspacePaths.get(reqAs.dshpwUser)?.get(workspaceId) ?? null;
            const globallyMapped = workspacePathById.get(workspaceId) ?? null;
            const knownPath = mapped !== null && folderAllowed(mapped, currentPerms.allowed_folders) &&
              !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser, mapped)
              ? mapped
              : globallyMapped !== null && folderAllowed(globallyMapped, currentPerms.allowed_folders) &&
                !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser, globallyMapped)
                ? globallyMapped
                : null;
            if (knownPath !== null) {
              // 已能在无 Remote 基线时解析目标目录：立即登记映射，后续解析不再等待。
              const paths = new Map(userWorkspacePaths.get(reqAs.dshpwUser) ?? new Map<string, string>());
              paths.set(workspaceId, knownPath);
              replaceUserWorkspacePaths(reqAs.dshpwUser, paths, userAccessEpochFor(reqAs.dshpwUser));
            } else if (!(await waitForUserSessionAccess(reqAs.dshpwUser, 5_000, true))) {
              if (res.headersSent || res.writableEnded || res.destroyed) return;
              // 全局缓存也没有该 workspaceId：等一次有界基线；仍拿不到才返回可重试
              // 的 503。能解析的已分配工作区绝不因基线未到而 503。
              upstreamReq.destroy();
              if (!res.headersSent && !res.writableEnded && !res.destroyed) {
                res.status(503).json({ ok: false, code: 'BASELINE_PENDING', retryable: true, error: '工作区会话基线尚未就绪，请重试' });
              }
              return;
            }
            if (res.headersSent || res.writableEnded || res.destroyed) return;
          }
        }

        if (needsFolderCheck) {
          const exactCreatePath = isWorkspaceDirectoryCreate(proxyPath)
            ? extractDirectoryCreatePath(bodyObj)
            : isWorkspaceCreate(proxyPath)
              ? extractWorkspaceCreatePath(bodyObj)
              : extractPathFromBody(bodyObj);
          let targetPath: string | null = exactCreatePath;
          if (targetPath === null && !isWorkspaceDirectoryCreate(proxyPath) && !isWorkspaceCreate(proxyPath)) {
              const wid = extractWorkspaceId(bodyObj);
              if (wid !== null) {
                // A subuser resolves IDs through that user's filtered workspace baseline;
                // the global cache is only a fallback that was already re-validated above
                // against the child's folder allowlist and other subusers' ownership.
                targetPath = reqAs.dshpwUser === undefined
                  ? workspacePathById.get(wid) ?? null
                  : userWorkspacePaths.get(reqAs.dshpwUser)?.get(wid) ?? null;
              }
              // 走到这里仍为 null = 既无路径字段、也无经过已过滤 workspace baseline
              // 建立的 workspaceId 映射 → 一律 fail-closed，不能放行默认目录。
              if (targetPath === null) {
                upstreamReq.destroy();
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
                return;
              }
            }
          if (targetPath === null && (isWorkspaceDirectoryCreate(proxyPath) || isWorkspaceCreate(proxyPath))) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // session.create 即使用户的目录白名单为空（不限目录），仍不可借共享父目录
          // 或 workspaceId 缓存向其他用户拥有的工作区创建会话。用单向子树判定：
          // A 被分配父目录、B 拥有其子工作区时，目标只要伸进 B 的子树（含相等）即拒；
          // 等值会漏掉 /A/B-child/sub 这类深一层的目标。
          if (targetPath !== null && WORKSPACE_ENDPOINT_RE.test(proxyPath) && !reqAs.dshpwIsAdmin) {
            if (workspaceSubtreeOverlap(reqAs.dshpwUser!, targetPath)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
              return;
            }
          }
          // 新建工作区本身由专门权限控制；目录选择器创建仍必须先限制父目录，
          // 不能因允许“登记工作区”而获得任意宿主路径写入能力。
          if (targetPath !== null && !isWorkspaceCreate(proxyPath) && !isWorkspaceDirectoryCreate(proxyPath)) {
            const folders = reqAs.dshpwPerms!.allowed_folders;
            // 子用户会话 cwd 只做词法白名单判定不够：授权目录树内的符号链接/junction 可
            // 把 cwd 指到白名单外或敏感基。session/create 必须再用 canonical path 复核
            // 白名单与敏感基，任一不通过即 fail-closed（null 旧规则分支同样适用）。
            const canonicalTarget = WORKSPACE_ENDPOINT_RE.test(proxyPath)
              ? canonicalizePathBestEffort(targetPath)
              : null;
            if (!folderAllowed(targetPath, folders) ||
              (canonicalTarget !== null && (!folderAllowed(canonicalTarget, folders) || isSensitivePath(canonicalTarget)))) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
          }
          if (targetPath !== null && isWorkspaceDirectoryCreate(proxyPath)) {
            // 目录创建的父路径必须是平台完全限定路径，避免 Windows 的 /foo 或 \\foo
            // 被网关按当前盘解析，而上游按另一种 rooted 语义解释。
            if (!isFullyQualifiedPath(targetPath)) {
              auditDirectoryEvent('directory_create_denied', req, reqAs, {
                result: 'denied', reason: 'not_fully_qualified', parent: auditPathSummary(targetPath),
              });
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            // 读取与创建范围合二为一：allowed_folders 是唯一范围，创建不引入任何独立
            // 创建根、主目录或 pending 例外。父目录与新目标都必须以**当前 live 权限行**
            // 同时通过词法与 canonical 两个口径的 folderAllowed，并落在非文件系统根、
            // 非敏感基、非他人工作区子树内（根/敏感/归属为顶层合取，不能被开关短路）。
            const canonicalParent = canonicalizePathBestEffort(targetPath);
            const currentPerms = effectivePermissions(reqAs.dshpwUser!);
            const folders = currentPerms.allowed_folders;
            const directoryArgs = clientConnectionArgs(bodyObj) ?? (isPlainJsonRecord(bodyObj) ? bodyObj : null);
            const name = directoryArgs?.name;
            const validName = typeof name === 'string' && name.length > 0 && name !== '.' && name !== '..' &&
              !/[\\/\u0000-\u001f\u007f]/.test(name);
            const targetLexical = validName ? path.join(targetPath, name) : '';
            const targetCanonical = validName ? canonicalizePathBestEffort(path.join(canonicalParent, name)) : '';
            const parentAllowed = folderAllowed(targetPath, folders) && folderAllowed(canonicalParent, folders) &&
              !isFilesystemRootPath(targetPath) && !isFilesystemRootPath(canonicalParent) &&
              !isSensitivePath(targetPath) && !isSensitivePath(canonicalParent);
            const targetAllowed = validName &&
              folderAllowed(targetLexical, folders) && folderAllowed(targetCanonical, folders) &&
              !isFilesystemRootPath(targetLexical) && !isFilesystemRootPath(targetCanonical) &&
              !isSensitivePath(targetLexical) && !isSensitivePath(targetCanonical);
            if (!currentPerms.allow_workspace_create || !parentAllowed || !targetAllowed ||
              workspaceSubtreeOverlap(reqAs.dshpwUser!, targetPath) ||
              workspaceSubtreeOverlap(reqAs.dshpwUser!, canonicalParent) ||
              (validName && workspaceSubtreeOverlap(reqAs.dshpwUser!, targetCanonical))) {
              auditDirectoryEvent('directory_create_denied', req, reqAs, {
                result: 'denied',
                reason: !currentPerms.allow_workspace_create ? 'create_disabled'
                  : (!parentAllowed || !targetAllowed) ? 'path_not_allowed'
                    : 'workspace_overlap',
                target: auditPathSummary(validName ? targetLexical : targetPath),
              });
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
          }
          if (targetPath !== null && (isWorkspaceCreate(proxyPath) || isWorkspaceDeleteOrRename(proxyPath))) {
            // ── 子用户登记新工作区（D1 收紧）：只接受主用户显式分配的精确目录、
            // 自己创建的工作区子树、或刚通过目录选择器成功创建且未过期的目录；
            // 其余一切预存在且未分配的目录一律 403，且不得与另一子用户的
            // 工作区子树重叠（相等或父子嵌套）。
            if (!reqAs.dshpwIsAdmin && isWorkspaceCreate(proxyPath)) {
              const canonicalTarget = canonicalizePathBestEffort(targetPath);
              // 登记与读取同源：目标必须落在**当前 live 白名单**内（词法+canonical 双命中），
              // 再命中 assigned/owned/pending 三者之一。__deny__ 表示不可读，因此必须拒；
              // 旧 pending 也不得绕过已撤销的读取权限。
              const registrationPerms = effectivePermissions(reqAs.dshpwUser!);
              const assigned = registrationPerms.allowed_folders
                .filter((entry) => entry !== '__deny__')
                .flatMap((entry) => [entry, canonicalizePathBestEffort(entry)]);
              const owned = db.listUserWorkspacePaths(reqAs.dshpwUser!).flatMap((entry) => [entry, canonicalizePathBestEffort(entry)]);
              if (!folderAllowed(targetPath, registrationPerms.allowed_folders) ||
                !folderAllowed(canonicalTarget, registrationPerms.allowed_folders) ||
                !workspaceRegistrationAllowed(canonicalTarget, assigned, owned, visiblePendingCreatedDirectories(reqAs.dshpwUser!)) ||
                workspaceSubtreeOverlap(reqAs.dshpwUser!, canonicalTarget) ||
                // 登记与读取同源：管理员误把敏感目录（或其祖先）分配为工作区时，目标会同时
                // 命中白名单与 assigned/owned/pending，只有敏感基能挡住登记。
                isSensitivePath(targetPath) || isSensitivePath(canonicalTarget)) {
                auditDirectoryEvent('workspace_registration_denied', req, reqAs, {
                  result: 'denied',
                  reason: (!folderAllowed(targetPath, registrationPerms.allowed_folders) ||
                    !folderAllowed(canonicalTarget, registrationPerms.allowed_folders))
                    ? 'not_in_allowlist'
                    : !workspaceRegistrationAllowed(canonicalTarget, assigned, owned, visiblePendingCreatedDirectories(reqAs.dshpwUser!))
                      ? 'not_assigned_or_created'
                      : (isSensitivePath(targetPath) || isSensitivePath(canonicalTarget))
                        ? 'sensitive_path'
                        : 'workspace_overlap',
                  target: auditPathSummary(canonicalTarget),
                });
                upstreamReq.destroy();
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
                return;
              }
            }
            const renamePaths = isWorkspaceDeleteOrRename(proxyPath) ? extractWorkspaceRenamePaths(bodyObj) : null;
            // alpha workspace/rename changes only the title and therefore carries
            // workspaceId + title rather than a path pair. Legacy workspace/update
            // remains a path mutation and must retain the explicit old/new check.
            if (renamePaths === null && /(?:update)(?:[./]|$)/.test(proxyPath)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            const oldPath = normalizePath(renamePaths?.oldPath ?? targetPath);
            const newPath = renamePaths === null ? null : normalizePath(renamePaths.newPath);
            const pathsToAuthorize = newPath === null ? [oldPath] : [oldPath, newPath];
            if (!reqAs.dshpwIsAdmin && pathsToAuthorize.some((path) => workspaceOwnedByAnotherSubuser(reqAs.dshpwUser!, path))) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
              return;
            }
            // A shared administrator workspace is selectable and can host an
            // explicitly granted session, but its global registry entry remains
            // administrator-owned. Subusers may only rename or remove entries
            // created under their own account.
            if (!reqAs.dshpwIsAdmin && isWorkspaceDeleteOrRename(proxyPath) && !workspaceOwnedByUser(reqAs.dshpwUser!, oldPath)) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
              return;
            }
            if (newPath !== null && (!folderAllowed(newPath, reqAs.dshpwPerms!.allowed_folders) ||
              (!reqAs.dshpwIsAdmin && workspaceSubtreeOverlap(reqAs.dshpwUser!, newPath)))) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            reqAs.dshpwWorkspacePath = isWorkspaceCreate(proxyPath) ? canonicalizePathBestEffort(oldPath) : oldPath;
            reqAs.dshpwWorkspaceCreate = isWorkspaceCreate(proxyPath);
            if (newPath !== null) {
              reqAs.dshpwWorkspaceOldPath = oldPath;
              reqAs.dshpwWorkspaceNewPath = newPath;
            }
          }
          // 记录本次判定出的目标目录，供 session.create/fork 响应回调登记 sessionId→cwd 缓存
          if (targetPath !== null) reqAs.dshpwSessionCwd = targetPath;
        }

        if (needsSandboxCheck && bodyObj !== null) {
          const preset = presetFromSettingsMutate(bodyObj);
          const assignedRank =
            SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
          const targetRank = preset === null ? assignedRank : sandboxPresetRank(preset);
          if (targetRank > assignedRank) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
            return;
          }
        }

        if (needsCommandCheck && bodyObj !== null) {
          const line = findStringField(bodyObj, 'line');
          const preset = line === null ? null : permissionPresetFromCommand(line);
          if (preset !== null) {
            const assignedRank =
              SANDBOX_RANK[reqAs.dshpwPerms!.sandbox_mode as keyof typeof SANDBOX_RANK] ?? 0;
            const targetRank = sandboxPresetRank(preset);
            if (targetRank > assignedRank) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.sandboxDenied')));
              return;
            }
          }
        }

        // 审批响应改写：受限子用户的 AI 提权审批一律强制 rejected（返回取消）
        if (needsApprovalCheck && bodyObj !== null && typeof bodyObj === 'object') {
          if (forceRejectApproval(bodyObj)) {
            forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
            upstreamReq.setHeader('content-length', String(forwardBody.length));
          }
        }

        if (needsWorkspaceOrderCheck && reqAs.dshpwUser !== undefined &&
          (!userSessionAccess.has(reqAs.dshpwUser) || !userWorkspacePaths.has(reqAs.dshpwUser))) {
          if (!(await waitForUserSessionAccess(reqAs.dshpwUser, 5_000, true))) {
            if (res.headersSent || res.writableEnded || res.destroyed) return;
            upstreamReq.destroy();
            res.status(503).json({ ok: false, code: 'BASELINE_PENDING', retryable: true, error: '工作区会话基线尚未就绪，请重试' });
            return;
          }
        }

        if (needsWorkspaceOrderCheck && bodyObj !== null) {
          const request = isPlainJsonRecord(bodyObj) && isPlainJsonRecord(bodyObj.payload) && isPlainJsonRecord(bodyObj.payload.args)
            ? bodyObj.payload.args.request : null;
          const validId = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 200;
          const workspaceId = isPlainJsonRecord(request) && validId(request.workspaceId) ? request.workspaceId : null;
          const beforeWorkspaceId = isPlainJsonRecord(request) && request.beforeWorkspaceId !== undefined
            ? (validId(request.beforeWorkspaceId) ? request.beforeWorkspaceId : null) : undefined;
          const sessionId = isPlainJsonRecord(request) && validId(request.sessionId) ? request.sessionId : null;
          const beforeSessionId = isPlainJsonRecord(request) && request.beforeSessionId !== undefined
            ? (validId(request.beforeSessionId) ? request.beforeSessionId : null) : undefined;
          const workspacePath = workspaceId === null ? null : userWorkspacePaths.get(reqAs.dshpwUser!)?.get(workspaceId) ?? null;
          const beforePath = beforeWorkspaceId === undefined || beforeWorkspaceId === null
            ? null
            : userWorkspacePaths.get(reqAs.dshpwUser!)?.get(beforeWorkspaceId) ?? null;
          const sessionPath = sessionId === null ? null : userSessionAccess.get(reqAs.dshpwUser!)?.get(sessionId) ?? null;
          const beforeSessionPath = beforeSessionId === undefined || beforeSessionId === null
            ? null
            : userSessionAccess.get(reqAs.dshpwUser!)?.get(beforeSessionId) ?? null;
          const validWorkspace = workspacePath !== null && folderAllowed(workspacePath, reqAs.dshpwPerms!.allowed_folders) && !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser!, workspacePath);
          const validBeforeWorkspace = beforeWorkspaceId === undefined || (beforePath !== null && folderAllowed(beforePath, reqAs.dshpwPerms!.allowed_folders) && !workspaceOwnedByAnotherSubuser(reqAs.dshpwUser!, beforePath));
          const isSessionOrder = /insertSessionBefore$/.test(proxyPath);
          const validSession = !isSessionOrder || (sessionId !== null && sessionPath !== null && authorizedSubuserSessionRoot(reqAs.dshpwUser!, sessionId, reqAs.dshpwPerms!) !== null);
          const validBeforeSession = !isSessionOrder || beforeSessionId === undefined || (beforeSessionId !== null && beforeSessionPath !== null && authorizedSubuserSessionRoot(reqAs.dshpwUser!, beforeSessionId, reqAs.dshpwPerms!) !== null);
          const sameWorkspace = !isSessionOrder || (workspacePath !== null && sessionPath !== null && normalizePath(workspacePath) === normalizePath(sessionPath) && (beforeSessionId === undefined || (beforeSessionPath !== null && normalizePath(workspacePath) === normalizePath(beforeSessionPath))));
          if (!validWorkspace || !validBeforeWorkspace || !validSession || !validBeforeSession || !sameWorkspace) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          if (/insertSessionBefore$/.test(proxyPath)) {
            reqAs.dshpwWorkspaceOrderId = workspaceId!;
            reqAs.dshpwWorkspaceOrderPath = workspacePath!;
          }
        }

        // 会话访问校验：子用户须命中显式授权快照且位于已开启工作区；逐会话关闭优先。
        if (needsOwnershipCheck && bodyObj !== null) {
          if (reqAs.dshpwUser !== undefined && !userSessionAccess.has(reqAs.dshpwUser)) {
            const ready = await waitForUserSessionAccess(reqAs.dshpwUser);
            if (res.headersSent || res.writableEnded || res.destroyed) return;
            if (!ready) {
              upstreamReq.destroy();
              res.status(503).json({ ok: false, code: 'BASELINE_PENDING', retryable: true });
              return;
            }
          }
          const bodySessionIds = collectAuthorizedSessionIds(bodyObj) ?? new Set<string>();
          const querySessionId = parsedUrl.searchParams.get('sessionId');
          if (querySessionId !== null) bodySessionIds.add(querySessionId);
          const perms = reqAs.dshpwPerms!;
          const access = reqAs.dshpwUser === undefined ? new Map<string, string>() : userSessionAccessFor(reqAs.dshpwUser);
          const allowed = (sessionId: string): boolean => {
            const cwd = reqAs.dshpwIsAdmin === true
              ? sessionCwdById.get(sessionId)
              : access.get(sessionId);
            if (perms.disabled_sessions.includes(sessionId) || cwd === undefined || !folderAllowed(cwd, perms.allowed_folders)) {
              return false;
            }
            if (reqAs.dshpwIsAdmin === true) return true;
            const userId = reqAs.dshpwUser;
            return userId !== undefined && (db.hasUserSessionGrant(userId, sessionId) || workspaceOwnedByUser(userId, cwd));
          };
          if (bodySessionIds.size === 0 || [...bodySessionIds].some((sessionId) => !allowed(sessionId))) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // history/page 只读窗口不能成为模型授权来源：窗口可能过时，且其嵌套
          // sessionId 不是写入网关模型状态的权威。这里仅保留对象级授权结果供后续
          // ownership 分支使用，不从响应反向产生模型权限。
          // 只有已经通过源会话授权的 fork 才能把新 sessionId 登记到当前用户快照。
          // fork 的 cwd 必须继承已校验的源会话目录，不能信任上游响应里的 cwd，
          // 否则异常/被投毒的响应可能把新会话写入白名单外目录。
          if (/^\/api\/session[.\/]fork$/.test(proxyPath)) {
            const sourceId = [...bodySessionIds][0];
            const sourceCwd = access.get(sourceId);
            if (sourceCwd === undefined) {
              upstreamReq.destroy();
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
              return;
            }
            reqAs.dshpwForkAuthorized = true;
            reqAs.dshpwSessionCwd = sourceCwd;
          }
        }

        // ── 模型白名单：转发前判定（所有模型入口的强制点，与沙盒 await 后复核共用）──
        if (needsModelCheck) {
          const allowed = reqAs.dshpwPerms!.allowed_models;
          const fail = (): void => {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
          };
          if (!modelGateAllows(allowed)) {
            fail();
            return;
          }
          if (/^\/api\/session[.\/]selectModel$/.test(proxyPath)) {
            // 登记本次判定出的目标会话，供成功响应回调登记有效模型。
            const requestedSessionIds = collectAuthorizedSessionIds(bodyObj);
            const requestedSessionId = requestedSessionIds === null ? null : [...requestedSessionIds][0];
            if (requestedSessionId !== null && requestedSessionId !== undefined) {
              reqAs.dshpwModelSessionId = requestedSessionId;
            }
          }
        }

        // ── 受限子用户执行期沙盒确认：一次 run 被接纳前再夹一次档位 ──────────
        // 所有权校验已保证这些会话在本用户授权快照内；此处只负责把会话 log 里的
        // sandbox/mode 钉到授权档位。失败（内部接口不可用/会话不再活）一律 fail-closed：
        // 绝不把未确认档位的会话交给子用户跑。
        if (needsSandboxRunCheck) {
          const authorizedSessionIds = collectAuthorizedSessionIds(bodyObj);
          const runSessionIds = authorizedSessionIds === null ? [] : [...authorizedSessionIds];
          if (runSessionIds.length === 0) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          const snapshotMode = reqAs.dshpwPerms!.sandbox_mode;
          const currentMode = db.getPermissions(reqAs.dshpwUser!)?.sandbox_mode ?? null;
          const runSandboxMode = strictestSandboxMode(snapshotMode, currentMode);
          if (runSandboxMode !== null) {
            for (const runSessionId of runSessionIds) {
              if (!(await applySandboxToSession(runSessionId, runSandboxMode))) {
                upstreamReq.destroy();
                if (!res.headersSent) res.status(502).type('text/plain').send('502 Sandbox enforcement failed');
                return;
              }
            }
          }
          if (res.headersSent || res.writableEnded || res.destroyed) return;
        }

        // Sandbox enforcement awaits an internal confirmation. Re-check the
        // authoritative permission epoch and DB grant before forwarding the old request.
        if (needsSandboxRunCheck && reqAs.dshpwUser !== undefined) {
          const userId = reqAs.dshpwUser;
          const postSandboxSessionIds = collectAuthorizedSessionIds(bodyObj);
          const postSandboxIds = postSandboxSessionIds === null ? [] : [...postSandboxSessionIds];
          const currentPerms = db.getPermissions(userId);
          const currentAccess = userSessionAccessFor(userId);
          const currentEpoch = userAccessEpochFor(userId);
          const currentMode = currentPerms?.sandbox_mode ?? null;
          const requestedMode = reqAs.dshpwPerms!.sandbox_mode;
          const currentModeIsStricter = currentMode !== null &&
            strictestSandboxMode(requestedMode, currentMode) === currentMode;
          const allowedAfterSandbox = (sessionId: string): boolean => {
            const cwd = currentAccess.get(sessionId);
            return currentPerms !== null && cwd !== undefined &&
              !currentPerms.disabled_sessions.includes(sessionId) &&
              folderAllowed(cwd, currentPerms.allowed_folders) &&
              (db.hasUserSessionGrant(userId, sessionId) || workspaceOwnedByUser(userId, cwd));
          };
          // 沙盒确认是一次 await：期间管理员可能收紧 allowed_models/allowed_agent_presets。
          // 这类变更不推进授权 epoch（只有子集/会话授权变更才 fence），所以必须用当前
          // live 权限行对这两个白名单重新判定，避免在途 prompt 用旧快照放行已撤销的
          // 模型/预设。原请求受该门禁约束时（needs*Check）才复核，保持行为一致。
          const modelsStillAllowed = !needsModelCheck || modelGateAllows(currentPerms?.allowed_models ?? null);
          const presetsStillAllowed = !needsAgentPresetCheck || agentPresetGateAllows(currentPerms?.allowed_agent_presets ?? null);
          if (currentEpoch !== sessionAccessRequestEpoch ||
            currentPerms === null ||
            (currentModeIsStricter && requestedMode !== currentMode) ||
            !modelsStillAllowed ||
            !presetsStillAllowed ||
            postSandboxIds.some((sessionId) => !allowedAfterSandbox(sessionId))) {
            upstreamReq.destroy();
            if (!res.headersSent) res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }

        // The alpha client may publish the workspace upsert before the unary
        // create response. Preallocate the identity only after every path and
        // ownership check above has passed, then retain the relation until DSH
        // confirms the same identity.
        if (
          reqAs.dshpwUser !== undefined &&
          /^\/api\/session[.\/]create$/.test(proxyPath) &&
          reqAs.dshpwSessionCwd !== undefined &&
          clientConnectionArgs(bodyObj) !== null
        ) {
          const requestPayload = rpcRequestPayload(bodyObj);
          const requestedSessionId = requestPayload?.sessionId;
          const pendingForUser = pendingCreatedSessions.get(reqAs.dshpwUser);
          const pendingRequested = typeof requestedSessionId === 'string' ? pendingForUser?.get(requestedSessionId) : undefined;
          // DSH 0.2 reuses an existing blank session in the selected workspace
          // when starting a new chat. Accept that identity only when it already
          // belongs to this subuser and its authorized cwd is this exact target.
          // A foreign, ungranted, expired, or cross-workspace id remains denied.
          const reusedAuthorizedSession = typeof requestedSessionId === 'string' &&
            reqAs.dshpwPerms !== undefined &&
            authorizedSubuserSessionRoot(reqAs.dshpwUser, requestedSessionId, reqAs.dshpwPerms) !== null &&
            normalizePath(authorizedSubuserSessionRoot(reqAs.dshpwUser, requestedSessionId, reqAs.dshpwPerms)!) === normalizePath(reqAs.dshpwSessionCwd);
          if (
            requestedSessionId !== undefined && !reusedAuthorizedSession &&
            (pendingRequested === undefined || pendingRequested.expiresAt <= Date.now() ||
              normalizePath(pendingRequested.cwd) !== normalizePath(reqAs.dshpwSessionCwd))
          ) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          const createdSessionId = ensureSessionCreateId(bodyObj, `session-${randomUUID()}`);
          if (createdSessionId === null) {
            upstreamReq.destroy();
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          reqAs.dshpwCreatedSessionId = createdSessionId;
          forwardBody = Buffer.from(JSON.stringify(bodyObj), 'utf8');
          upstreamReq.setHeader('content-length', String(forwardBody.length));
          pendingCreatedSessionFor(reqAs.dshpwUser).set(reqAs.dshpwCreatedSessionId, {
            cwd: reqAs.dshpwSessionCwd,
            expiresAt: Date.now() + 30_000,
          });
        }
        if (res.headersSent || res.writableEnded || res.destroyed) return;
        upstreamReq.end(forwardBody);
      });
      req.on('error', () => {
        if (!settled) {
          settled = true;
          upstreamReq.destroy();
        }
      });
    } else {
      // 对无 Content-Length 的 chunked 请求也执行同一平台硬上限；否则大文件上传
      // 可以通过改用 Transfer-Encoding 绕过 64/300 MiB 分档。
      let receivedBodyBytes = 0;
      let bodyLimitExceeded = false;
      const onRequestData = (chunk: Buffer): void => {
        if (bodyLimitExceeded) return;
        receivedBodyBytes += chunk.length;
        if (receivedBodyBytes <= requestBodyLimit) return;
        bodyLimitExceeded = true;
        requestBodyRejected = true;
        req.unpipe(upstreamReq);
        upstreamReq.destroy();
        req.pause();
        res.status(413).type('html').send(forbiddenPage(langOf(req), t(langOf(req), 'gw.bodyTooLarge')));
        // 排空客户端剩余请求体，避免连接复用时把尾部数据解析成下一请求。
        req.resume();
      };
      req.on('data', onRequestData);
      req.on('end', () => {
        req.off('data', onRequestData);
      });
      req.pipe(upstreamReq);
    }
  });

  // ── WebSocket upgrade 代理（原 gateway.ts L5976-L6670）───────────────────
  function attachUpgrade(server: UpgradeCapableServer): void {
  server.on('upgrade', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    // F-03 同口径：网关前缀判定与转发路径都用「原始路径迭代解码 + 压平
    // 斜杠 + WHATWG 归一化」，与 HTTP 代理保持一致，杜绝 %2f/%2e 变体
    // 在 WS 升级请求里漂移（HTTP 侧已修，这里补齐同口径）。
    const rawPath = (req.url ?? '/').split('?')[0];
    const gatePath = normalizeDecodedPath(rawPath);
    if (gatePath === '/gateway' || gatePath.startsWith('/gateway/')) {
      socket.destroy();
      return;
    }
    const queryIndex = (req.url ?? '').indexOf('?');
    const fwdPath = gatePath + (queryIndex >= 0 ? stripGatewayAuthQuery(req.url ?? '/', gatePath) : '');
    // WebSocket 同样是浏览器携带 Cookie 的状态变更通道，先拒绝跨源升级。
    if (!originHostMatches(req)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    // 认证检查（复用 Cookie；与 HTTP 侧一致：校验 cv + banned + 登出吊销）
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    let authed = false;
    let authUserId: number | null = null;
    let userRole: 'admin' | 'user' | null = null;
    if (token && !isTokenRevoked(token)) {
      try {
        const user = auth.verifyToken(token);
        const row = db.getUserById(user.userId);
        if (row !== null && row.username === user.username && user.cv === row.credential_version) {
          const perms = effectivePermissions(row.id);
          if (!perms.banned) {
            authed = true;
            authUserId = row.id;
            userRole = row.role === 'admin' ? 'admin' : 'user';
          }
        }
      } catch {
        authed = false;
      }
    }
    if (!authed) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // P1-1：internal 端点不接受外部 WS 升级（仅限网关→dsh 本机 HTTP 调用）
    if (gatePath.startsWith('/api/dsh-passwords/internal/')) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    // 与 HTTP 侧一致：owner: 登记一律拒绝；ssh 登记与官方 terminal 共用 allowSsh；
    // 已加载普通插件的 WS 仍须命中运行时清单。
    const wsPathClass = classifySubuserPath(gatePath, {
      endpointRules: getEndpointRules(),
      transport: 'ws',
      dynamicManifest: getDynamicPluginManifest(),
    });

    const dynamicPluginPathPassed = userRole === 'user' && !isSubuserBlockedApiPath(gatePath) && (
      dynamicPluginApiPath(gatePath, getDynamicPluginManifest()) ||
      dynamicPluginRootPath(gatePath, getDynamicPluginManifest())
    );
    let userSshEndpointPassed = false;
    if (userRole === 'user') {
      // owner: 规则与跨 transport 的 SSH 登记一律拒绝（两把钥匙之外的能力不放行）。
      if (wsPathClass === 'owner-only' ||
          (wsPathClass !== 'ssh' && endpointAllowed(gatePath, getEndpointRules(), { capability: 'ssh' }))) {
        socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
        return;
      }
      if (wsPathClass === 'ssh') {
        const perms = authUserId === null ? null : effectivePermissions(authUserId);
        if (perms === null || !perms.allow_ssh) {
          socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
          return;
        }
        userSshEndpointPassed = true;
      }
    }
    if (dynamicPluginPathPassed || userSshEndpointPassed) {
      // SSH 登记或宿主插件清单授权建立后纳入撤销集合：运行时收紧时立即断开旧连接。
      registryAuthorizedSockets.add(socket);
      socket.once('close', () => { registryAuthorizedSockets.delete(socket); });
    }
    // RC.1's Remote streams share one physical /api/remote.mux carrier.
    // Keep the administrator path compatible with registered plugin streams;
    // subusers still require the resource-aware filtering below.
    if (gatePath === '/api/remote.mux') {
      const isSubuser = userRole === 'user';
      const wsServer = new WebSocket.WebSocketServer({ noServer: true, maxPayload: REMOTE_MUX_MAX_PAYLOAD_BYTES });
      wsServer.handleUpgrade(req, socket, head, (client: any) => {
        const endpointUrl = `${upstream.protocol === 'https:' ? 'wss' : 'ws'}://${upstreamAuthority}${fwdPath}`;
        const upstreamWs = new WebSocket.WebSocket(endpointUrl, upstreamWsOptions());
        const active = new Map<string, RemoteMuxUserStreamState | null>();
        const diagnostics = createRemoteMuxDiagnosticsSession(`mux-${Date.now().toString(36)}`);
        // 记录已经排队/发送 open 的逻辑流。若网关随后因首帧授权校验拒绝它，
        // rejectLogicalStream 必须向上游补 cancel，避免宿主侧订阅脱离 active 后泄漏。
        const upstreamForwardedStreamIds = new Set<string>();
        // 观测：记录每个逻辑流 open 被转发到上游的时刻（关闭时为哨兵 0），用于测算
        // 上游快照准备耗时（open 转发 → 上游首个 item）。只存数值，绝不存帧内容。
        const upstreamForwardedAt = new Map<string, number>();
        let upstreamOpen = false;
        // 两条腿各持一个 MuxHeartbeat。在 closeCarrier、heartbeatClose 与 expirePendingSessionStreams
        // 全部定义之后再构造（见下方 startHeartbeats）；onClose/onTick 只引用其闭包，不会早于声明被调用。
        let clientHeartbeat: MuxHeartbeat | null = null;
        let upstreamHeartbeat: MuxHeartbeat | null = null;
        // 两条腿各持一个 MuxSender（下行网关→浏览器、上行网关→上游）：业务数据与 pending drain
        // 统一经它发送。实例在 closeCarrier/heartbeat 定义之后构造（见 createDirectionSender）。
        let clientSender: MuxSender | null = null;
        let upstreamSender: MuxSender | null = null;
        const pending: string[] = [];
        let pendingBytes = 0;
        // session/control/follow may arrive before workspace/follow. A grant
        // alone has no trustworthy cwd, so defer either session stream until
        // the workspace baseline has established the per-user ownership snapshot.
        // Deferred frames share the carrier's pending-byte budget with the frames
        // queued for a not-yet-open upstream socket (they are sent on the same
        // path later), so one deferred burst cannot bypass REMOTE_MUX_MAX_PENDING_BYTES.
        const pendingSessionStreams = new Map<string, {
          text: string;
          bytes: number;
          endpoint: string;
          authorizationSessionId: string | null;
          expiresAt: number;
        }>();
        // 延迟等待 workspace baseline 的会话流有界 TTL：baseline 迟迟不到（客户端只开了
        // session/control|follow，或 carrier 卡在未认证）时不能永久挂起，超时按该逻辑流
        // 拒绝（error 帧），不关整条 carrier。
        const PENDING_SESSION_STREAM_TTL_MS = 5_000;
        const dropPendingSessionStream = (streamId: string): void => {
          const entry = pendingSessionStreams.get(streamId);
          if (entry === undefined) return;
          pendingSessionStreams.delete(streamId);
          pendingBytes = Math.max(0, pendingBytes - entry.bytes);
        };
        const publishSessionAttachment = (sessionId: string, cwd: string): void => {
          if (!isSubuser) return;
          const perms = effectivePermissions(authUserId!);
          const access = userSessionAccess.get(authUserId!);
          if (access === undefined || normalizePath(access.get(sessionId) ?? '') !== normalizePath(cwd) ||
            (!db.hasUserSessionGrant(authUserId!, sessionId) && !workspaceOwnedByUser(authUserId!, cwd)) || perms.disabled_sessions.includes(sessionId) ||
            !folderAllowed(cwd, perms.allowed_folders) ||
            workspaceOwnedByAnotherSubuser(authUserId!, cwd)) return;
          for (const state of active.values()) {
            if (state?.endpoint !== 'workspace/follow') continue;
            for (const [workspaceId, workspacePath] of state.visibleWorkspaces) {
              if (normalizePath(workspacePath) !== normalizePath(cwd)) continue;
              const previous = state.visibleWorkspaceRows.get(workspaceId);
              if (previous === undefined) continue;
              const previousIds = Array.isArray(previous.sessionIds)
                ? previous.sessionIds.filter((id): id is string => typeof id === 'string')
                : [];
              const row = { ...previous, sessionIds: [...new Set([...previousIds, sessionId])] };
              state.visibleWorkspaceRows.set(workspaceId, row);
              if (!sendClientItemFrame(state.streamId, JSON.stringify({
                type: 'item',
                streamId: state.streamId,
                value: { type: 'upsert', workspace: row },
              }))) break;
            }
          }
        };
        const publishWorkspaceUpsert = (workspace: Record<string, unknown>): void => {
          if (!isSubuser) return;
          const workspaceId = typeof workspace.workspaceId === 'string' ? workspace.workspaceId : null;
          const workspacePath = typeof workspace.path === 'string' ? workspace.path : null;
          if (workspaceId === null || workspacePath === null) return;
          const perms = effectivePermissions(authUserId!);
          if (!folderAllowed(workspacePath, perms.allowed_folders) ||
            workspaceOwnedByAnotherSubuser(authUserId!, workspacePath)) return;
          const access = userSessionAccess.get(authUserId!);
          const grants = new Set(db.listUserSessionGrants(authUserId!));
          const pending = pendingCreatedSessions.get(authUserId!);
          const sessionAllowed = (sessionId: unknown): sessionId is string => {
            if (typeof sessionId !== 'string' || perms.disabled_sessions.includes(sessionId)) return false;
            if (access?.has(sessionId) && (grants.has(sessionId) || workspaceOwnedByUser(authUserId!, workspacePath))) return true;
            const candidate = pending?.get(sessionId);
            return candidate !== undefined && candidate.expiresAt > Date.now() &&
              normalizePath(candidate.cwd) === normalizePath(workspacePath) &&
              folderAllowed(candidate.cwd, perms.allowed_folders) &&
              !workspaceOwnedByAnotherSubuser(authUserId!, candidate.cwd);
          };
          for (const state of active.values()) {
            if (state?.endpoint !== 'workspace/follow') continue;
            const previous = state.visibleWorkspaceRows.get(workspaceId);
            const previousIds = previous !== undefined && Array.isArray(previous.sessionIds)
              ? previous.sessionIds.filter(sessionAllowed)
              : [];
            const rowIds = Array.isArray(workspace.sessionIds)
              ? workspace.sessionIds.filter(sessionAllowed)
              : [];
            const row = { ...workspace, sessionIds: [...new Set([...rowIds, ...previousIds])] };
            state.visibleWorkspaces.set(workspaceId, workspacePath);
            state.visibleWorkspaceRows.set(workspaceId, row);
            if (!sendClientItemFrame(state.streamId, JSON.stringify({
              type: 'item',
              streamId: state.streamId,
              value: { type: 'upsert', workspace: row },
            }))) break;
          }
        };
        const connection: RemoteMuxUserConnection = {
          socket: client,
          publishSessionAttachment,
          publishWorkspaceUpsert,
          // 前向引用：teardownCarrier 在下方定义；connection 仅在权限撤销时被 gateway 调用，
          // 那时同步初始化早已完成。
          teardownCarrier: (code?: number) => teardownCarrier(code),
        };
        const registeredClients = remoteMuxClientsByUser.get(authUserId!) ?? new Set<RemoteMuxUserConnection>();
        registeredClients.add(connection);
        remoteMuxClientsByUser.set(authUserId!, registeredClients);
        const unregisterClient = (): void => {
          registeredClients.delete(connection);
          if (registeredClients.size === 0 && remoteMuxClientsByUser.get(authUserId!) === registeredClients) {
            remoteMuxClientsByUser.delete(authUserId!);
          }
        };
        // 停止并回收两条腿的探测/写停滞状态机。幂等：MuxHeartbeat.dispose() 幂等，且它先
        // 收敛状态、推进 generation 再通知 onClose，故关闭回调反复调用也不会重入关闭。
        const disposeHeartbeats = (): void => {
          clientHeartbeat?.dispose();
          upstreamHeartbeat?.dispose();
        };
        // 关闭/撤销时立即收敛两条腿的发送器与心跳。MuxSender.dispose 与 MuxHeartbeat.dispose
        // 都幂等：重复调用不再触发任何发送失败或探测关闭。
        const disposeSenders = (): void => {
          clientSender?.dispose();
          upstreamSender?.dispose();
        };
        const disposeCarrier = (): void => {
          disposeSenders();
          disposeHeartbeats();
        };
        const remoteMuxCloseSource = (reason: string | undefined): RemoteMuxCloseSource => {
          if (reason === 'Permissions changed' || reason === 'Identity switched' || reason === 'Credentials changed' || reason === 'Session ended' || reason === 'Workspace deleted') return 'permission-revoked';
          if (reason === 'Remote stream backpressure limit exceeded') return 'backpressure';
          if (reason === 'Remote stream queue too large') return 'queue-overflow';
          if (reason === 'Remote stream send failed') return 'send-failed';
          if (reason === 'upstream error') return 'upstream-error';
          if (reason === 'upstream closed') return 'upstream-close';
          if (reason === 'client websocket error') return 'client-error';
          if (reason === 'text messages required' || reason === 'invalid Remote stream request' || reason === 'invalid Remote stream payload' || reason === 'invalid Remote stream response' || reason === 'duplicate stream id' || reason === 'too many Remote streams') return 'protocol';
          return 'unknown';
        };
        const senderSnapshot = (sender: MuxSender | null) => {
          const snapshot = sender?.snapshot();
          return {
            queuedMessages: snapshot?.queuedMessages ?? 0,
            queuedBytes: snapshot?.queuedBytes ?? 0,
            acceptedBytes: snapshot?.acceptedBytes ?? 0,
            inFlight: snapshot?.inFlight ?? false,
            bufferedAmount: snapshot?.bufferedAmount ?? 0,
          };
        };
        const observeCarrierClose = (reject?: { direction: 'client' | 'upstream'; kind: MuxRejectKind; messageBytes: number } | null): void => {
          const clientState = senderSnapshot(clientSender);
          const upstreamState = senderSnapshot(upstreamSender);
          diagnostics.observe({
            pendingBytes,
            clientSender: clientState,
            upstreamSender: upstreamState,
            ...(reject === undefined ? {} : { reject }),
          });
        };
        const logCloseRecord = (record: ReturnType<typeof diagnostics.close>): void => {
          if (record === null) return;
          console.error(`[dsh-passwords] remote.mux close source=${record.source} direction=${record.direction} code=${record.code} buffered=${record.bufferedBytes} pending=${record.pendingBytes} streams=${record.streams} stall=${record.stall} clientQueued=${record.clientSender.queuedMessages}/${record.clientSender.queuedBytes} clientAccepted=${record.clientSender.acceptedBytes} clientInFlight=${Number(record.clientSender.inFlight)} clientBuffered=${record.clientSender.bufferedAmount} upstreamQueued=${record.upstreamSender.queuedMessages}/${record.upstreamSender.queuedBytes} upstreamAccepted=${record.upstreamSender.acceptedBytes} upstreamInFlight=${Number(record.upstreamSender.inFlight)} upstreamBuffered=${record.upstreamSender.bufferedAmount}${record.reject === null ? '' : ` rejectDirection=${record.reject.direction} reject=${record.reject.kind} rejectBytes=${record.reject.messageBytes}`}`);
        };
        const REMOTE_MUX_CLOSE_GRACE_MS = 5_000;
        let closeIssued = false;
        let closeGraceCancel: (() => void) | null = null;
        // 两腿各自的关闭完成标记：仅用于 grace 收敛判定与到期回收，不参与任何授权/权限决策。
        let clientLegClosed = false;
        let upstreamLegClosed = false;
        // 优雅 close 之后最多 5 秒 grace：到期只强制回收**尚未完成关闭握手**的那条腿，避免半开连接
        // 长期占用，同时不再把已进入关闭握手（CLOSING）的腿提前 terminate。定时器 unref，不拖住进程退出。
        const armCloseGrace = (): void => {
          if (closeGraceCancel !== null) return;
          if (clientLegClosed && upstreamLegClosed) return;
          const timer = setTimeout(() => {
            closeGraceCancel = null;
            disposeCarrier();
            if (!clientLegClosed) { try { client.terminate(); } catch {} }
            if (!upstreamLegClosed) { try { upstreamWs.terminate(); } catch {} }
          }, REMOTE_MUX_CLOSE_GRACE_MS);
          timer.unref();
          closeGraceCancel = () => clearTimeout(timer);
        };
        // 两腿都完成关闭握手后立即取消 grace：已无需要强制回收的半开腿。
        const cancelCloseGraceIfSettled = (): void => {
          if (!clientLegClosed || !upstreamLegClosed) return;
          if (closeGraceCancel === null) return;
          closeGraceCancel();
          closeGraceCancel = null;
        };
        // 统一幂等关闭的共用收尾：立即 dispose 两条腿的发送器与心跳（避免关闭过程中再冒出一次
        // 发送失败/探测关闭），随后只记录一次结构化诊断（首个关闭来源加锁，即“首因”不被迟到
        // 来源改写）。不触碰物理 socket：由调用方决定是否下发 socket close/terminate。
        const settleCarrierClose = (
          source: RemoteMuxCloseSource,
          code: number | undefined,
          close?: { stall?: RemoteMuxStallKind; direction?: 'client' | 'upstream' | 'both'; reject?: { direction: 'client' | 'upstream'; kind: MuxRejectKind; messageBytes: number } },
        ): void => {
          observeCarrierClose(close?.reject ?? null);
          const observedPending = pendingBytes;
          const clientState = senderSnapshot(clientSender);
          const upstreamState = senderSnapshot(upstreamSender);
          disposeCarrier();
          const record = diagnostics.close({
            source,
            direction: close?.direction ?? 'both',
            code,
            bufferedBytes: client.bufferedAmount + upstreamWs.bufferedAmount,
            pendingBytes: observedPending,
            streams: active.size,
            stall: close?.stall,
            clientSender: clientState,
            upstreamSender: upstreamState,
            reject: close?.reject ?? null,
          });
          logCloseRecord(record);
        };
        // 单腿关闭请求：OPEN 时发起/继续优雅关闭握手；CLOSING 时握手已在进行，继续等待对端 Close
        // （绝不 terminate，否则会丢弃已入队的 Close，让对端只观察到 1006）；CONNECTING/CLOSED 无法
        // 再握手，直接 terminate 收敛以避免悬空连接。
        const requestLegClose = (ws: any, code?: number, reason?: string): void => {
          try {
            if (ws.readyState === WebSocket.OPEN) ws.close(code, reason);
            else if (ws.readyState !== WS_CLOSING) ws.terminate();
          } catch {}
        };
        const closeCarrier = (code?: number, reason?: string, close?: { source?: RemoteMuxCloseSource; stall?: RemoteMuxStallKind; direction?: 'client' | 'upstream' | 'both'; reject?: { direction: 'client' | 'upstream'; kind: MuxRejectKind; messageBytes: number } }): void => {
          settleCarrierClose(close?.source ?? remoteMuxCloseSource(reason), code, close);
          if (closeIssued) return;
          closeIssued = true;
          requestLegClose(client, code, reason);
          requestLegClose(upstreamWs, code, reason);
          armCloseGrace();
        };
        // 受限的权限/身份撤销入口：由 gateway 在下发 socket.close 之前调用。它立即收敛两条腿的
        // 发送器与心跳，把诊断首因锁定为 permission-revoked（不依赖调用方文案），并 arm 5s grace；
        // 物理 socket 的 close(code, reason) 仍由 gateway 保留，以维持既有 code/reason 与权限行为。
        // 不向调用方暴露 active/发送器/诊断等内部状态；重复调用幂等（dispose 幂等、诊断已锁存、
        // grace 只 arm 一次）。
        const teardownCarrier = (code = 1012): void => {
          settleCarrierClose('permission-revoked', code);
          armCloseGrace();
        };
        // 下行（网关→浏览器）与上行（网关→上游）各一个 MuxSender：所有业务数据与 pending
        // drain 统一经它发送。它保证一条业务文本 = 一条 WS 文本消息、同方向 FIFO、分片不交错，
        // 在单条 100 MiB / 方向接受 102 MiB 预算内接受消息，并按 256 KiB/128 KiB **用户态**水位做
        // 排水等待（与独立的共享 pending 2 MiB 预队列预算分开）；心跳的忙/闲与写入进度由它按
        // 边沿/成功分片回调，以及排水实测 bufferedAmount 下降驱动。
        const fragmentBytes = REMOTE_MUX_FRAGMENT_BYTES;
        // 方向接受预算：单条 100 MiB + 一条最大帧后的 2 MiB 余量。队列字节预算必须与它同值——
        // 一条合法消息（最大 100 MiB）可能排在在途消息之后等待，若队列字节上限更小，合法消息会在
        // 接受预算远未用尽时被判 queue-full 并误关整条 carrier。旧值误用共享 pending 2 MiB 预算，
        // 导致 3 MiB 兄弟流 item 在 A 在途时被 1013 误杀。总接受字节已由本预算封顶（queueBytes ≤
        // acceptedBytes），队列仍有界，等待深度由 maxQueueMessages 条数上限兜底。
        const directionAcceptBudgetBytes = REMOTE_MUX_MAX_PAYLOAD_BYTES + REMOTE_MUX_MAX_PENDING_BYTES;
        const fragmentSocketOf = (ws: any): MuxFragmentSocket => ({
          get readyState(): number { return ws.readyState; },
          get bufferedAmount(): number { return ws.bufferedAmount; },
          // ws 的 send(data, options, cb)：文本帧（binary:false）＋ fin 决定是否消息末片。
          // ws 成功时把回调参数传 null（不是 undefined）；发送器仅把带值回调视为失败，
          // 因此这里把 null/undefined 归一为 undefined，避免成功回调被误判为写失败。
          send: (data: Buffer, options: { binary: false; fin: boolean }, onFlush?: (error?: Error) => void) =>
            ws.send(data, options, (error?: Error | null) => onFlush?.(error ?? undefined)),
        });
        const createDirectionSender = (ws: any, direction: 'client' | 'upstream', heartbeat: () => MuxHeartbeat | null): MuxSender =>
          new MuxSender(fragmentSocketOf(ws), {
            fragmentBytes,
            // 用户态写入前导水位与共享 pending 预队列预算分离：分片模式下把已提交给 ws/Node 的
            // bufferedAmount 压在 256 KiB 内，降到 128 KiB 再续片（单帧模式不做排水等待）。
            highWaterBytes: REMOTE_MUX_HIGH_WATER_BYTES,
            lowWaterBytes: REMOTE_MUX_LOW_WATER_BYTES,
            // 单条消息 100 MiB；方向接受总量 102 MiB。
            maxMessageBytes: REMOTE_MUX_MAX_PAYLOAD_BYTES,
            acceptBudgetBytes: directionAcceptBudgetBytes,
            // 等待队列字节与接受预算同值：任何能被接受的合法消息都必须能排在在途消息之后，
            // 否则大 item 的兄弟流会被误判 queue-full。条数上限仍是队列深度的独立护栏。
            // 8192 条等待槽可容纳已复现的 5000 条小事件突发；字节/接受预算仍是硬上限，
            // 不把该缓解误当成无限背压。持续输入仍由 102 MiB 方向预算和 write-stall 收敛。
            maxQueueMessages: REMOTE_MUX_MAX_STREAMS * 128,
            maxQueueBytes: directionAcceptBudgetBytes,
            sharedBudget: processMuxBudget,
            drainPollIntervalMs: 10,
            onBusy: () => heartbeat()?.markBusy(),
            onIdle: () => heartbeat()?.markIdle(),
            onProgress: () => heartbeat()?.noteWriteProgress(),
            onReject: (kind, messageBytes) => diagnostics.observe({ reject: { direction, kind, messageBytes } }),
            onFailure: () => closeCarrier(1011, 'Remote stream send failed'),
          });
        clientSender = createDirectionSender(client, 'client', () => clientHeartbeat);
        upstreamSender = createDirectionSender(upstreamWs, 'upstream', () => upstreamHeartbeat);
        const sendClientFrame = (text: string, tag: string | null = null): MuxAcceptOutcome => {
          if (clientSender === null) return 'closed';
          return clientSender.enqueue(text, tag === null ? {} : { tag });
        };
        const rejectKindOf = (outcome: Exclude<MuxAcceptOutcome, 'accepted' | 'closed'>): MuxRejectKind => {
          if (outcome === 'oversized') return 'message-bytes';
          if (outcome === 'overflow') return 'accepted-bytes';
          return 'queue-count';
        };
        const sendClientControlFrame = (text: string): boolean => {
          const outcome = sendClientFrame(text);
          if (outcome === 'accepted') return true;
          if (outcome === 'closed') return false;
          closeCarrier(1013, 'Remote stream backpressure limit exceeded', { direction: 'client', reject: { direction: 'client', kind: rejectKindOf(outcome), messageBytes: Buffer.byteLength(text, 'utf8') } });
          return false;
        };
        function sendClientItemFrame(streamId: string, text: string): boolean {
          const outcome = sendClientFrame(text, streamId);
          if (outcome === 'accepted') return true;
          if (outcome === 'closed') return false;
          // item 帧的容量拒绝（oversized / overflow / queue-full）是该逻辑流的应用级失败，不是
          // carrier 失败：发送受限 error 让 DSH 停止重试该流，同 carrier 的兄弟流继续运行。
          // rejectLogicalStream 先取消该流尚未开始的下行待发项（释放队列），再排 error；只有连
          // error 控制帧也排不进时才由 sendClientControlFrame 按 carrier 级收敛。
          rejectLogicalStream(streamId, 'gateway/overflow', outcome === 'oversized'
            ? 'Remote item exceeds carrier frame limit'
            : 'Remote stream send queue full');
          return false;
        }
        // A denied logical stream is an application-level Remote failure, not a
        // carrier failure. Sending an error frame lets DSH stop retrying that
        // stream while workspace/control/events streams on the same mux survive.
        // ws emits protocol failures (for example an unmasked client frame) as
        // EventEmitter 'error'. Handle it locally so malformed client traffic
        // closes this carrier instead of terminating the gateway process.
        client.on('error', () => closeCarrier(1002, 'client websocket error'));

        const rejectLogicalStream = (streamId: string, code: string, message: string): void => {
          dropPendingSessionStream(streamId);
          active.delete(streamId);
          // 取消该逻辑流**尚未开始发送**的消息；正在分片的消息必须发到 FIN，error/cancel 排在其后
          // （FIFO），绝不会把半条消息与 error 交错。两个方向都要取消：上行被拒时若不清空该流尚未
          // 开始的上行待发项，紧随其后的上游 cancel 会因共享队列仍满而再次失败，退化成 carrier 关闭。
          clientSender?.cancel(streamId);
          upstreamSender?.cancel(streamId);
          if (upstreamForwardedStreamIds.delete(streamId)) {
            // 该 open 已经到达或排队等待到达上游；即使浏览器不再发送 cancel，
            // 也要由网关回收宿主侧流。cancel 自身走同一 pending budget。
            queueUpstreamFrame(JSON.stringify({ type: 'cancel', streamId }), streamId);
          }
          upstreamForwardedAt.delete(streamId);
          sendClientControlFrame(JSON.stringify({
            type: 'error',
            streamId,
            error: { code, message, details: {} },
          }));
        };
        /**
         * 延迟等待 baseline 的会话/控制流已在上面登记授权身份；超时即拒（该逻辑流的
         * error 帧），避免永久挂起。调用时机：心跳、收到任何客户端消息、flush 前。
         * 必须在 startHeartbeats() 之前声明：heartbeatOptions.onTick 直接引用本函数，
         * 否则同步调度的 start() 会在闭包引用时命中暂时性死区。
         */
        const expirePendingSessionStreams = (): void => {
          if (pendingSessionStreams.size === 0) return;
          const now = Date.now();
          for (const [streamId, entry] of [...pendingSessionStreams]) {
            if (entry.expiresAt <= now) {
              rejectLogicalStream(streamId, 'gateway/forbidden', 'Remote session not available for this user');
            }
          }
        };
        // 每条腿一个 MuxHeartbeat：nonce probe + 独立 Pong deadline + 写停滞 deadline，替换旧
        // 的“每 2 秒计数、漏 2 次即关”的窗口心跳。onClose 每腿至多一次，直接收敛到既有
        // closeCarrier 路径；tick 继续驱动 expirePendingSessionStreams 收敛过期的延迟会话流。
        const heartbeatClose = (direction: 'client' | 'upstream') => (source: MuxHeartbeatCloseSource): void => {
          // write-stall/探测失败/timed out 都保持受限诊断分类 'heartbeat'，并附带受限的停滞
          // 类型（write/probe）；分类直接传入，不依赖 reason 文案匹配，客户端 code/reason 兼容。
          const details = { source: 'heartbeat' as const, stall: source === 'write-stall' ? 'write' as const : 'probe' as const, direction };
          if (source === 'ping-send-failed') { closeCarrier(1011, 'Remote stream heartbeat failed', details); return; }
          if (source === 'write-stall') { closeCarrier(1011, 'Remote stream write stalled', details); return; }
          closeCarrier(1011, 'Remote stream heartbeat timed out', details);
        };
        // ws 适配：ping(payload, done) 交由 ws 按 _isServer 决定掩码（浏览器腿 unmasked、上游腿
        // masked）。硬编码 mask=true 会把服务端帧错误掩码，被对端判为协议错误而断连。
        const heartbeatSocketOf = (ws: any, mask: boolean): MuxHeartbeatSocket => ({
          get readyState(): number { return ws.readyState; },
          // 浏览器腿是 ws server 侧，控制帧不能掩码；上游腿是 ws client 侧，
          // RFC 6455 要求客户端发出的 Ping 必须掩码。两条腿必须显式区分。
          ping: (payload, done) => ws.ping(payload, mask, (error: Error | null) => done(error ?? undefined)),
        });
        const heartbeatOptions: Omit<MuxHeartbeatOptions, 'onClose'> = {
          pingIntervalMs: REMOTE_MUX_PING_INTERVAL_MS,
          pongTimeoutMs: REMOTE_MUX_PONG_TIMEOUT_MS,
          writeStallMs: REMOTE_MUX_WRITE_STALL_MS,
          onTick: () => expirePendingSessionStreams(),
        };
        const startHeartbeats = (): void => {
          if (clientHeartbeat === null) {
            clientHeartbeat = new MuxHeartbeat(heartbeatSocketOf(client, false), { ...heartbeatOptions, onClose: heartbeatClose('client') });
            clientHeartbeat.start();
          }
          if (upstreamHeartbeat === null) {
            upstreamHeartbeat = new MuxHeartbeat(heartbeatSocketOf(upstreamWs, true), { ...heartbeatOptions, onClose: heartbeatClose('upstream') });
            upstreamHeartbeat.start();
          }
        };
        client.on('pong', (payload: Buffer) => { clientHeartbeat?.notePong(payload); });
        upstreamWs.on('pong', (payload: Buffer) => { upstreamHeartbeat?.notePong(payload); });
        startHeartbeats();
        const queueUpstreamFrame = (text: string, tag: string | null = null, kind: 'item' | 'control' = 'control'): boolean => {
          const textBytes = Buffer.byteLength(text);
          if (!upstreamOpen || upstreamWs.readyState !== WebSocket.OPEN || upstreamSender === null) {
            // 上游尚未 open：先落在网关侧 pending 队列（共享 2 MiB 预算），open 后原子
            // 转入 Sender 发送（见 upstreamWs 'open' 排水）。pending 是 carrier 级预算，
            // 与控制帧一样不属于任何单个逻辑流，超限仍按 carrier 级收敛。
            if (pendingBytes + textBytes > REMOTE_MUX_MAX_PENDING_BYTES) {
              closeCarrier(1009, 'Remote stream queue too large', { direction: 'upstream', reject: { direction: 'upstream', kind: 'queue-bytes', messageBytes: textBytes } });
              return false;
            }
            pending.push(text);
            pendingBytes += textBytes;
            return true;
          }
          const outcome = upstreamSender.enqueue(text, tag === null ? {} : { tag });
          if (outcome === 'accepted') return true;
          if (outcome === 'closed') return false;
          if (kind === 'item' && tag !== null) {
            // item 帧的容量拒绝只隔离该逻辑流，不关整条 carrier；控制帧仍 carrier 级。
            rejectLogicalStream(tag, 'gateway/overflow', 'Remote stream send queue full');
            return false;
          }
          closeCarrier(1013, 'Remote stream backpressure limit exceeded', { direction: 'upstream', reject: { direction: 'upstream', kind: rejectKindOf(outcome), messageBytes: textBytes } });
          return false;
        };
        const flushPendingSessionStreams = (): void => {
          expirePendingSessionStreams();
          const access = isSubuser ? userSessionAccess.get(authUserId!) : undefined;
          for (const [streamId, pendingStream] of pendingSessionStreams) {
            if (isSubuser) {
              if (pendingStream.authorizationSessionId === null) {
                // 只有 session/control 可以在没有会话身份的情况下延迟后放行；任何其它
                // 端点（尤其 session/follow/job）缺失授权身份一律拒绝，绝不 fail-open。
                if (pendingStream.endpoint !== 'session/control') {
                  rejectLogicalStream(streamId, 'gateway/forbidden', 'Remote session not available for this user');
                  continue;
                }
              } else {
                // baseline 已建立：统一重读 grant/disabled/白名单/所有权后再放行。
                if (access === undefined) continue;
                const perms = effectivePermissions(authUserId!);
                const sessionPath = access.get(pendingStream.authorizationSessionId);
                if (
                  sessionPath === undefined ||
                  perms.disabled_sessions.includes(pendingStream.authorizationSessionId) ||
                  (!db.hasUserSessionGrant(authUserId!, pendingStream.authorizationSessionId) && !workspaceOwnedByUser(authUserId!, sessionPath)) ||
                  !folderAllowed(sessionPath, perms.allowed_folders) ||
                  workspaceOwnedByAnotherSubuser(authUserId!, sessionPath)
                ) {
                  rejectLogicalStream(streamId, 'gateway/forbidden', 'Remote session not available for this user');
                  continue;
                }
              }
            }
            dropPendingSessionStream(streamId);
            if (active.has(streamId)) {
              if (!queueUpstreamFrame(pendingStream.text, streamId)) return;
              upstreamForwardedStreamIds.add(streamId);
              upstreamForwardedAt.set(streamId, loadingTimeline.begin());
            }
          }
        };
        client.on('message', (data: Buffer, isBinary: boolean) => {
          if (isBinary) { closeCarrier(1003, 'text messages required'); return; }
          // 任何上行消息都是收敛延迟会话流的时机（等价于心跳的超时检查）。
          expirePendingSessionStreams();
          // 子用户侧只校验端点名形状，具体端点是否可用在下面逐条判定：端点属于
          // 允许集合才建立逻辑流，属于「拒绝但仍可回答」集合或完全未知时只回该
          // 逻辑流的 error（不转发上游），不再因为一条流不可用而重启整条 carrier。
          const frame = parseRemoteMuxClientFrame(Buffer.from(data), !isSubuser);
          if (frame === null) { closeCarrier(1008, 'invalid Remote stream request'); return; }
          // alpha.1 上行帧（item/end）只对「已真正转发到上游、且由网关透明放行」的逻辑
          // 流生效：active.get() 为 undefined 是未打开/已结束的流（伪造或竞态），返回
          // 状态对象则是子用户按资源逐帧过滤的流（session/control、workspace/follow、
          // session/follow、$events）。两类都必须丢弃：后者绝不能让子用户借上行帧把
          // 数据注入按租户过滤的流。丢弃只影响该帧，不关闭 carrier。
          if (frame.type === 'item' || frame.type === 'end') {
            if (active.get(frame.streamId) !== null || !upstreamForwardedStreamIds.has(frame.streamId)) return;
            // 客户端 end 只结束上行；下行仍由上游的 end/error（已有逻辑）驱动收尾，
            // 因此这里不删除本地状态，避免提前丢掉仍在上游产生的输出。
            queueUpstreamFrame(JSON.stringify(frame), frame.streamId, frame.type === 'item' ? 'item' : 'control');
            return;
          }
          let deferUntilWorkspaceBaseline = false;
          if (frame.type === 'open') {
            if (active.has(frame.streamId)) { closeCarrier(1008, 'duplicate stream id'); return; }
            if (active.size >= REMOTE_MUX_MAX_STREAMS) { closeCarrier(1008, 'too many Remote streams'); return; }
            if (isSubuser) {
              const perms = effectivePermissions(authUserId!);
              // 核心网关授权流（Remote mux 官方面）由下方官方逐流授权逻辑负责：
              // session/control、session/follow、workspace/follow、$events 走会话
              // grant/所有权与 workspace baseline，job/account/workspaceFiles 各有专属
              // 授权。它们绝不能落到通用 SSH 登记规则上——登记 /api/* 或
              // /api/session/* 会把核心流误拒并导致客户端反复重连。因此这里先判定核心
              // 集合，只有非核心流才走通用 SSH 登记检查。
              const isOfficialRemoteCoreEndpoint =
                frame.endpoint === 'session/control' ||
                frame.endpoint === 'session/follow' ||
                frame.endpoint === 'workspace/follow' ||
                frame.endpoint === '$events' ||
                OFFICIAL_JOB_REMOTE_ENDPOINTS.has(frame.endpoint) ||
                OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS.has(frame.endpoint) ||
                frame.endpoint === 'workspaceFiles/changes';
              const endpointPaths = [
                `/api/${frame.endpoint}`,
                `/api/${frame.endpoint.replace('/', '.')}`,
              ];
              // owner: 登记对子用户始终拒绝：官方 terminal 与 allowSsh 都不构成例外。
              // 必须先于下方的官方 terminal allowSsh 分支判定，否则
              // owner:/api/terminal/follow（或 owner:/api/terminal/*）会被 allowSsh 覆盖，
              // 让子用户绕过 owner-only 拿到宿主 shell。
              if (endpointPaths.some((path) =>
                endpointAllowed(path, getEndpointRules(), { capability: 'owner-only' }))) {
                rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote host capability is owner-only');
                return;
              }
              // 已登记的 ssh 能力 Remote 流不随 allowSsh 放开：mux 只由 allowSsh 放行
              // 官方 terminal（v2.7.5 既定语义），其余登记命中一律拒绝；未登记流仍走
              // 下方官方集合/敏感面的 fail-closed 判定，不在这里凭空放开。
              if (!isOfficialRemoteCoreEndpoint &&
                  !OFFICIAL_TERMINAL_REMOTE_ENDPOINTS.has(frame.endpoint) &&
                  endpointPaths.some((path) => endpointAllowed(path, getEndpointRules()))) {
                rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote endpoint is not available for this user');
                return;
              }
              // workspaceFiles/changes carries a lookup session id and a target path.
              // It is allowed only after both are bound to the current subuser's
              // authorized workspace; the downlink is filtered again below.
              if (frame.endpoint === 'workspaceFiles/changes') {
                const request = remoteWorkspaceFileChangeRequest(frame.payload);
                const target = request === null ? null : authorizedWorkspaceFileChangeTarget(authUserId!, perms, request);
                if (target === null) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Workspace file changes are not available for this user');
                  return;
                }
                active.set(frame.streamId, {
                  streamId: frame.streamId,
                  endpoint: 'workspaceFiles/changes',
                  workspaceFileScopeId: target.scopeId,
                  workspaceFileRoot: target.root,
                  workspaceFileTarget: target.target,
                  workspaceFileRootCanonical: target.rootCanonical,
                  workspaceFileTargetCanonical: target.targetCanonical,
                  visibleWorkspaces: new Map(),
                  visibleWorkspaceRows: new Map(),
                });
              } else if (OFFICIAL_JOB_REMOTE_ENDPOINTS.has(frame.endpoint)) {
                const endpoint = frame.endpoint as 'job/list' | 'job/follow';
                const request = remoteJobRequest(frame.payload, endpoint);
                const sessionId = request?.sessionId ?? null;
                const sessionRoot = sessionId === null ? null : authorizedSubuserSessionRoot(authUserId!, sessionId, perms);
                const access = userSessionAccess.get(authUserId!);
                if (request === null ||
                  (access !== undefined && sessionId !== null && sessionRoot === null)) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote job is not available for this user');
                  return;
                }
                if (endpoint === 'job/follow' && sessionId === null) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote job requires an authorized session');
                  return;
                }
                if (access === undefined) deferUntilWorkspaceBaseline = true;
                active.set(frame.streamId, {
                  streamId: frame.streamId,
                  endpoint,
                  ...(sessionId === null ? {} : { jobSessionId: sessionId }),
                  ...(request.jobId === undefined ? {} : { jobId: request.jobId }),
                  visibleWorkspaces: new Map(),
                  visibleWorkspaceRows: new Map(),
                });
              } else if (OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS.has(frame.endpoint)) {
                if (!remoteAccountRequestIsEmpty(frame.payload)) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote account stream request is invalid');
                  return;
                }
                active.set(frame.streamId, {
                  streamId: frame.streamId,
                  endpoint: 'account/watch',
                  visibleWorkspaces: new Map(),
                  visibleWorkspaceRows: new Map(),
                });
              } else {
                // 官方 terminal Remote 流由 allowSsh 控制：开启时才放行
                // terminal/follow / terminal/retain；关闭时只结束该逻辑流
                // （terminal/unavailable），不让一条被拒流关闭整条 carrier。
                // 已登记的第三方 SSH mux 流不在此放开（见上方登记检查），
                // terminal 也仍不进通用 SSH 登记分类。
                const officialTerminalAllowed =
                  OFFICIAL_TERMINAL_REMOTE_ENDPOINTS.has(frame.endpoint) && perms.allow_ssh;
                const rejectedEndpoint = remoteMuxSubuserRejectedEndpoints.get(frame.endpoint);
                if (rejectedEndpoint !== undefined && !officialTerminalAllowed) {
                  rejectLogicalStream(frame.streamId, rejectedEndpoint.code, rejectedEndpoint.message);
                  return;
                }
                // 宿主敏感面优先于运行时清单拒绝：即使流已登记也不能放行；
                // allowSsh 授予的官方 terminal 流是唯一例外。
                if (!officialTerminalAllowed && isSubuserBlockedRemoteEndpoint(frame.endpoint)) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote endpoint is not available for this user');
                  return;
                }
                // 普通扩展端点按通用姿态透明转发，未知官方端点 fail-closed。
                const namespace = frame.endpoint.split('/')[0] ?? '';
                if (!remoteMuxStreamEndpoints.has(frame.endpoint) && OFFICIAL_API_NAMESPACES.has(namespace)) {
                  rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote endpoint is not available for this user');
                  return;
                }

                if (officialTerminalAllowed || !remoteMuxStreamEndpoints.has(frame.endpoint)) {
                    // allowSsh 授予的官方 terminal 流与官方集合之外的普通扩展流
                    // 都按透明姿态转发。动态清单不能覆盖官方流的授权、baseline
                    // 建立和响应过滤逻辑。
                    active.set(frame.streamId, null);
                  } else if (frame.endpoint === 'session/follow') {
                    const address = remoteMuxFollowAddress(frame.payload);
                    const authorizationSessionId = address === null ? null : sessionAuthorizationId(address);
                    const access = userSessionAccess.get(authUserId!);
                    // 解析不出会话身份 = 没有任何可信授权依据，直接拒绝（fail-closed）。
                    if (
                      authorizationSessionId === null ||
                      perms.disabled_sessions.includes(authorizationSessionId)
                    ) {
                      rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote session not available for this user');
                      return;
                    }
                    if (access === undefined) {
                      // baseline 尚未建立：此时既没有可信 cwd，grant 也可能还没 seed
                      // （旧用户一次性迁移）。只有「已 seed 且明确未授权」才是无需 baseline
                      // 即可判定的拒绝；其余一律延迟到 baseline 之后统一重读
                      // grant/disabled/folder/ownership（flushPendingSessionStreams）。
                      // 绝不能把「快照缺失」本身当成拒绝依据（grant 尚未 seed 就 403）。
                      // 快照缺失只表示 workspace/follow 还没到，不能据此使用
                      // 持久化 grant 表提前拒绝。由 baseline 到达后统一重查授权、所有权和白名单。
                      deferUntilWorkspaceBaseline = true;
                    } else {
                      const sessionPath = access.get(authorizationSessionId);
                      if (
                        sessionPath === undefined ||
                        (!db.hasUserSessionGrant(authUserId!, authorizationSessionId) && !workspaceOwnedByUser(authUserId!, sessionPath)) ||
                        !folderAllowed(sessionPath, perms.allowed_folders) ||
                        workspaceOwnedByAnotherSubuser(authUserId!, sessionPath)
                      ) {
                        rejectLogicalStream(frame.streamId, 'gateway/forbidden', 'Remote session not available for this user');
                        return;
                      }
                    }
                  } else if (!remoteMuxEmptyArgs(frame.payload)) {
                    closeCarrier(1008, 'invalid Remote stream payload');
                    return;
                  }
                  // $events is the alpha.3 Remote connection bootstrap. Blocking it
                  // prevents every client stream from becoming ready and makes the
                  // sidebar reconnect forever. workspace/control remain filtered
                  // below; session/follow is constrained to an explicit grant.
                  if (frame.endpoint === 'session/control' && userSessionAccess.get(authUserId!) === undefined) {
                    deferUntilWorkspaceBaseline = true;
                  }
                  if (active.get(frame.streamId) !== null) active.set(frame.streamId, {
                    streamId: frame.streamId,
                    endpoint: frame.endpoint,
                    followAddress: frame.endpoint === 'session/follow' ? remoteMuxFollowAddress(frame.payload) : undefined,
                    visibleWorkspaces: new Map(),
                    visibleWorkspaceRows: new Map(),
                  });
              }
            } else {
              active.set(frame.streamId, null);
            }
          } else if (!active.has(frame.streamId)) {
            return;
          }
          const text = JSON.stringify(frame);
          if (frame.type === 'cancel' && pendingSessionStreams.has(frame.streamId)) {
            dropPendingSessionStream(frame.streamId);
            active.delete(frame.streamId);
            return;
          }
          if (deferUntilWorkspaceBaseline && frame.type === 'open') {
            const bytes = Buffer.byteLength(text);
            // 与 queueUpstreamFrame 同一预算：延迟流同样占用 2MB 待发送额度。
            if (pendingBytes + bytes > REMOTE_MUX_MAX_PENDING_BYTES) {
              rejectLogicalStream(frame.streamId, 'gateway/overflow', 'Remote stream queue too large');
              return;
            }
            dropPendingSessionStream(frame.streamId);
            pendingSessionStreams.set(frame.streamId, {
              text,
              bytes,
              endpoint: String(frame.endpoint),
              authorizationSessionId: frame.endpoint === 'session/follow'
                ? (() => {
                    const address = remoteMuxFollowAddress(frame.payload);
                    return address === null ? null : sessionAuthorizationId(address);
                  })()
                : (frame.endpoint === 'job/list' || frame.endpoint === 'job/follow')
                  ? (remoteJobRequest(frame.payload, frame.endpoint as 'job/list' | 'job/follow')?.sessionId ?? null)
                  : null,
              expiresAt: Date.now() + PENDING_SESSION_STREAM_TTL_MS,
            });
            pendingBytes += bytes;
            return;
          }
          if (!queueUpstreamFrame(text, frame.streamId)) return;
          if (frame.type === 'open') {
            upstreamForwardedStreamIds.add(frame.streamId);
            upstreamForwardedAt.set(frame.streamId, loadingTimeline.begin());
          }
          if (frame.type === 'cancel') {
            // 客户端取消该逻辑流：删除其尚未开始发送的下行消息；正在分片的消息发完 FIN。
            clientSender?.cancel(frame.streamId);
            upstreamForwardedStreamIds.delete(frame.streamId);
            upstreamForwardedAt.delete(frame.streamId);
            active.delete(frame.streamId);
          }
        });
        client.on('close', () => {
          clientLegClosed = true;
          const observedPending = pendingBytes + senderSnapshot(clientSender).queuedBytes + senderSnapshot(upstreamSender).queuedBytes;
          const clientState = senderSnapshot(clientSender);
          const upstreamState = senderSnapshot(upstreamSender);
          disposeCarrier();
          const record = diagnostics.close({ source: 'client-close', direction: 'client', code: 0, pendingBytes: observedPending, bufferedBytes: client.bufferedAmount + upstreamWs.bufferedAmount, streams: active.size, clientSender: clientState, upstreamSender: upstreamState });
          logCloseRecord(record);
          unregisterClient();
          if (isSubuser) {
            const clientIds = new Set<string>();
            for (const state of active.values()) {
              if (state?.endpoint === '$events' && state.remoteEventsClientId !== undefined) clientIds.add(state.remoteEventsClientId);
            }
            for (const [eventId, ownership] of remoteEventOwnership) {
              if (ownership.userId === authUserId! && clientIds.has(ownership.clientId)) remoteEventOwnership.delete(eventId);
            }
          }
          requestLegClose(upstreamWs);
          armCloseGrace();
          cancelCloseGraceIfSettled();
        });
        upstreamWs.on('open', () => {
          upstreamOpen = true;
          // 上游一开就把网关侧 pending 队列原子转入 Sender：按 FIFO 逐帧 enqueue，
          // 转出即从共享 2 MiB 预算扣减，避免网关队列与 Sender 队列双重占用。
          while (pending.length > 0 && upstreamWs.readyState === WebSocket.OPEN) {
            const text = pending[0]!;
            const outcome = upstreamSender === null ? 'closed' : upstreamSender.enqueue(text);
            if (outcome === 'accepted') {
              pending.shift();
              pendingBytes -= Buffer.byteLength(text);
              continue;
            }
            if (outcome === 'closed') return;
            // 预先已通过共享 2 MiB pending 预算；排水中仍超预算说明口径不一致，按背压关闭。
            closeCarrier(1013, 'Remote stream backpressure limit exceeded', { direction: 'upstream', reject: { direction: 'upstream', kind: rejectKindOf(outcome), messageBytes: Buffer.byteLength(text, 'utf8') } });
            return;
          }
        });
        upstreamWs.on('message', (data: Buffer, isBinary: boolean) => {
          if (isBinary) { closeCarrier(1003, 'text messages required'); return; }
          const frame = parseRemoteMuxServerFrame(Buffer.from(data));
          // An unparseable frame is a carrier-level protocol violation and stays
          // fail-closed. A well-formed frame for an unknown stream id is not:
          // the official Remote contract tolerates a late item/end/error that
          // raced a cancel this side already forwarded (or a stream the Host
          // already ended). Dropping it must never close the physical carrier —
          // doing so restarted every other stream, which is what turned one
          // cancelled stream into a main/subuser reconnect loop.
          if (frame === null) { closeCarrier(1011, 'invalid Remote stream response'); return; }
          const state = active.get(frame.streamId);
          if (state === undefined) return;
          if (client.readyState !== WebSocket.OPEN) return;
          if (frame.type === 'item') {
            // 观测：上游快照准备（open 转发 → 上游首个 item）。首个完整 item 到达后即
            // 清除记录点，后续 item 不再计时；只记录耗时与入站字节数。
            const forwardedAt = upstreamForwardedAt.get(frame.streamId);
            if (forwardedAt !== undefined) {
              loadingTimeline.elapsed('mux.upstream.snapshot.prepare', forwardedAt, { bytesIn: data.length });
              upstreamForwardedAt.delete(frame.streamId);
            }
          }
          if (frame.type === 'item' && state !== null) {
            const filtered = filterRemoteMuxUserItem(authUserId!, effectivePermissions(authUserId!), state, frame.value);
            // A session/follow or workspace file changes stream cannot make progress
            // without its opening frame. A rejected frame is that logical stream's
            // failure, not the carrier's, so the browser gets a bounded error while
            // sibling streams keep running.
            if (filtered === null &&
              ((state.endpoint === 'session/follow' && state.followSnapshotSeen !== true) ||
                (state.endpoint === 'workspaceFiles/changes' && state.workspaceFileReady !== true))) {
              const code = state.endpoint === 'workspaceFiles/changes' ? 'gateway/invalid-change-feed' : 'gateway/invalid-snapshot';
              const message = state.endpoint === 'workspaceFiles/changes'
                ? 'Remote workspace file changes frame rejected'
                : 'Remote session follow snapshot rejected';
              rejectLogicalStream(frame.streamId, code, message);
              return;
            }
            if (filtered === null) return;
            if (!sendClientItemFrame(frame.streamId, JSON.stringify({ type: 'item', streamId: frame.streamId, value: filtered }))) return;
            if (
              state.endpoint === 'workspace/follow' &&
              typeof filtered === 'object' &&
              (filtered as { type?: unknown }).type === 'baseline'
            ) {
              flushPendingSessionStreams();
            }
          } else if (frame.type === 'item') {
            // 未过滤流（管理员，或官方未过滤端点）的 item 仍是业务数据帧：走 item 通道，
            // 容量拒绝只隔离该逻辑流；只有 open/end/error/cancel 等控制帧才走 carrier 级通道。
            if (!sendClientItemFrame(frame.streamId, JSON.stringify(frame))) return;
          } else {
            if (!sendClientControlFrame(JSON.stringify(frame))) return;
          }
          if (frame.type === 'end' || frame.type === 'error') {
            active.delete(frame.streamId);
            upstreamForwardedStreamIds.delete(frame.streamId);
            upstreamForwardedAt.delete(frame.streamId);
          }
        });
        upstreamWs.on('error', () => closeCarrier(1011, 'upstream error'));
        upstreamWs.on('close', () => {
          upstreamLegClosed = true;
          const observedPending = pendingBytes + senderSnapshot(clientSender).queuedBytes + senderSnapshot(upstreamSender).queuedBytes;
          const clientState = senderSnapshot(clientSender);
          const upstreamState = senderSnapshot(upstreamSender);
          disposeCarrier();
          const record = diagnostics.close({ source: 'upstream-close', direction: 'upstream', code: 1011, pendingBytes: observedPending, bufferedBytes: client.bufferedAmount + upstreamWs.bufferedAmount, streams: active.size, clientSender: clientState, upstreamSender: upstreamState });
          logCloseRecord(record);
          requestLegClose(client, 1011, 'upstream closed');
          armCloseGrace();
          cancelCloseGraceIfSettled();
        });
      });
      return;
    }
    if (userRole === 'user' && (gatePath === '/api/events.host' || gatePath === '/api/events.mux')) {
      const channel = gatePath === '/api/events.host' ? 'host' : 'mux';
      const wsServer = new WebSocket.WebSocketServer({ noServer: true });
      wsServer.handleUpgrade(req, socket, head, (client: any) => {
        const upstreamWs = new WebSocket.WebSocket(`${upstream.protocol === 'https:' ? 'wss' : 'ws'}://${upstreamAuthority}${fwdPath}`, upstreamWsOptions());
        const unregisterClient = registerUserWebSocketClient(authUserId!, {
          close: (code = 1012, reason = 'Permissions changed') => {
            if (client.readyState === WebSocket.OPEN) client.close(code, reason);
          },
        });
        client.on('message', () => client.close(1008, 'downlink only'));
        client.on('error', () => { unregisterClient(); try { upstreamWs.close(); } catch {} });
        client.on('close', () => { unregisterClient(); try { upstreamWs.close(); } catch {} });
        upstreamWs.on('open', () => {});
        upstreamWs.on('message', (data: Buffer) => {
          const filtered = authUserId === null
            ? null
            : filterEventWebSocketFrame(authUserId, effectivePermissions(authUserId), channel, Buffer.from(data));
          if (filtered !== null && client.readyState === WebSocket.OPEN) client.send(filtered);
        });
        upstreamWs.on('error', () => { if (client.readyState === WebSocket.OPEN) client.close(1011, 'upstream error'); });
        upstreamWs.on('close', () => { if (client.readyState === WebSocket.OPEN) client.close(); });
      });
      return;
    }
    // 普通已加载插件的 WS 路径由运行时清单通用放行；已登记的 SSH 端点（allowSsh
    // 已勾选）与官方 terminal 在上述分支放行；未加载/未知 WS 路径仍 fail-closed。
    // 管理员不受限制。
    const builtinWsPath =
      gatePath === '/api/events.mux' ||
      gatePath === '/api/events.host' ||
      gatePath === '/plugins/events';
    if (userRole === 'user' && !builtinWsPath && !dynamicPluginPathPassed && !userSshEndpointPassed) {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }

    // 受限子用户的获授权第三方 WS 也必须在封禁/权限变更时主动撤销。
    const unregisterRawUserWebSocket = authUserId !== null
      ? registerUserWebSocketClient(authUserId, { close: () => socket.destroy() })
      : undefined;
    // 转发升级请求（Host/Origin 改写，同 HTTP 路径；路径已规范化）
    const upstreamSocket = upstreamIsHttps
      ? tlsConnect({ host: upstreamHost, port: upstreamPort, servername: upstreamHost, rejectUnauthorized: process.env.MCP_GATEWAY_UPSTREAM_TLS_VERIFY !== '0' }, () => {
          const lines: string[] = [`${req.method ?? 'GET'} ${fwdPath} HTTP/1.1`];
          for (const [key, value] of Object.entries(req.headers)) {
            const lower = key.toLowerCase();
            if (lower === 'cookie') continue;
            if (lower === 'host') lines.push(`Host: ${upstreamAuthority}`);
            else if (lower === 'origin' && typeof value === 'string') lines.push(`Origin: ${upstreamScheme}://${upstreamAuthority}`);
            else if (value !== undefined) lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
          }
          const forwardedCookie = upstreamCookieHeader(req.headers.cookie, getUpstreamAuthCookie());
          if (forwardedCookie !== undefined) lines.push(`Cookie: ${forwardedCookie}`);
          lines.push('', '');
          upstreamSocket.write(lines.join('\r\n'));
          if (head && head.length > 0) upstreamSocket.write(head);
          socket.pipe(upstreamSocket);
          upstreamSocket.pipe(socket);
        })
      : net.connect(upstreamPort, upstreamHost, () => {
      const lines: string[] = [
        `${req.method ?? 'GET'} ${fwdPath} HTTP/1.1`,
      ];
      for (const [key, value] of Object.entries(req.headers)) {
        const lower = key.toLowerCase();
        // F-15：与 HTTP 代理同口径——不把外部网关 JWT 转发给上游；
        // alpha 的官方 dsh-auth cookie 使用单独的受控值注入。
        if (lower === 'cookie') continue;
        if (lower === 'host') {
          lines.push(`Host: ${upstreamAuthority}`);
        } else if (lower === 'origin' && typeof value === 'string') {
          lines.push(`Origin: ${upstreamScheme}://${upstreamAuthority}`);
        } else if (value !== undefined) {
          lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
        }
      }
      const forwardedCookie = upstreamCookieHeader(req.headers.cookie, getUpstreamAuthCookie());
      if (forwardedCookie !== undefined) lines.push(`Cookie: ${forwardedCookie}`);
      lines.push('', '');
      upstreamSocket.write(lines.join('\r\n'));
      if (head && head.length > 0) upstreamSocket.write(head);
      socket.pipe(upstreamSocket);
      upstreamSocket.pipe(socket);
    });
    upstreamSocket.on('error', () => socket.destroy());
    socket.on('error', () => upstreamSocket.destroy());
    socket.on('close', () => { unregisterRawUserWebSocket?.(); upstreamSocket.destroy(); });
    upstreamSocket.on('close', () => socket.destroy());
  });
  }

  /**
   * 本模块当前不持有需要周期清理的服务级状态：原 sweep 外壳清理的容器
   * （remoteEventOwnership / pendingCreatedSessions / sessionCwdById /
   * workspacePathById 等）全部是与门卫、管理路由共享的授权状态，按拆分约束
   * 保留在 gateway.ts。此处保持接口形状，便于后续把代理独占状态迁入。
   */
  function sweep(_now: number): void {
    /* 无可清理状态 */
  }

  return { attachUpgrade, sweep };
}

/**
 * 生命周期说明：gateway.ts 在认证门卫之后注册 HTTP 代理，在 server 创建后调用
 * attachUpgrade，并在周期清理中调用 sweep。当前代理没有独占的周期状态；共享的
 * remoteEventOwnership 仍由 gateway.ts 按原位置清理，避免改变授权状态生命周期。
 */
