// 登录网关：劫持 dsh 访问入口
//   用户访问网关端口 → 未认证则渲染登录页（dsh 风格 + 动画）
//   → 登录成功 Set-Cookie(JWT, HttpOnly) → 302 回到原始 URL（重定向兼容层）
//   → 已认证请求反向代理到上游 dsh（HTTP + WebSocket，Host 改写为上游地址）
import http, { type IncomingMessage, type IncomingHttpHeaders } from 'node:http';
import https from 'node:https';
import { createSecureContext, connect as tlsConnect } from 'node:tls';
import {
  readFileSync, createReadStream, createWriteStream, realpathSync, openSync, fstatSync, closeSync,
  mkdirSync, renameSync, statSync, unlinkSync, readdirSync, rmSync, copyFileSync, writeFileSync, mkdtempSync, existsSync, constants as fsConstants,
} from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { createHmac, createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { type Duplex, Transform } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import zlib from 'node:zlib';
import { URL, fileURLToPath } from 'node:url';
import dns from 'node:dns';
import { createRequire } from 'node:module';
import express, { type Request, type Response } from 'express';

const require = createRequire(import.meta.url);
export const DEFAULT_USER_REQUEST_BODY_BYTES = 64 * 1024 * 1024;
export const ADMIN_REQUEST_BODY_BYTES = 300 * 1024 * 1024;

export function requestBodyLimitFor(role: 'admin' | 'user', allowLargeBody: boolean): number {
  return role === 'admin' || allowLargeBody ? ADMIN_REQUEST_BODY_BYTES : DEFAULT_USER_REQUEST_BODY_BYTES;
}

export function internalProbeTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(String(env.MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS ?? '').trim());
  return Number.isFinite(raw) && raw >= 1_000 && raw <= 600_000 ? raw : 10_000;
}

/**
 * internal/assignable-resources 探针的响应体上限。
 *
 * 该端点旧实现把响应缓冲硬编码在 256 KiB 之内，清单随工作区/会话规模增长后，一份
 * 完全合法的清单会被这个固定上限拒绝，直接让管理员保存权限失败（R4）。真正的容量
 * 约束是条目数上限（folders ≤ 10_000、assignable/retained sessions 各 ≤ 20_000）；
 * 这里的字节上限只负责让缓冲内存有界，不参与条目判定。取 160 MiB 是为了覆盖条目
 * 上限内的合法清单经 UTF-8/JSON 放大后的字节数，超出才 fail-closed。解析只拒绝
 * U+0000–U+001F 控制字符，合法 Unicode 路径/ID（含非 ASCII）原样保留。
 */
export const ASSIGNABLE_RESOURCES_MAX_BYTES = 160 * 1024 * 1024;

type AssignableResources = {
  folders: Set<string>;
  assignableSessions: Set<string>;
  retainedSessions: Set<string>;
};

/**
 * 解析 assignable-resources 清单：字段/条目任一不符契约（ok≠true、缺数组、含非法元素、
 * 超条目上限）一律返回 null，调用方 fail-closed，绝不把截断/伪造清单当成权威资源。
 */
export function parseAssignableResources(raw: Buffer): AssignableResources | null {
  try {
    const parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
    let rawAssignable: unknown;
    if (parsed.assignableSessions === undefined) {
      rawAssignable = parsed.sessions;
    } else if (!Array.isArray(parsed.assignableSessions)) {
      return null;
    } else if (parsed.sessions !== undefined) {
      if (!Array.isArray(parsed.sessions)) return null;
      const canonical = new Set(parsed.assignableSessions);
      const legacy = new Set(parsed.sessions);
      if (canonical.size !== legacy.size || [...canonical].some((id) => !legacy.has(id))) return null;
      rawAssignable = parsed.assignableSessions;
    } else {
      rawAssignable = parsed.assignableSessions;
    }
    if (parsed.ok !== true || !Array.isArray(parsed.folders) || !Array.isArray(rawAssignable)) return null;
    if (!Array.isArray(parsed.retainedSessions)) return null;
    const rawRetained = parsed.retainedSessions;
    const validResourceString = (value: unknown, maxLength: number): value is string =>
      typeof value === 'string' && value.length > 0 && value.length <= maxLength && !/[\u0000-\u001f]/.test(value);
    const folders = parsed.folders.filter((value): value is string => validResourceString(value, 4096));
    const assignableSessions = rawAssignable.filter((value): value is string => validResourceString(value, 200));
    const retainedSessions = rawRetained.filter((value): value is string => validResourceString(value, 200));
    if (folders.length !== parsed.folders.length || assignableSessions.length !== rawAssignable.length || retainedSessions.length !== rawRetained.length || folders.length > 10_000 || assignableSessions.length > 20_000 || retainedSessions.length > 20_000) {
      return null;
    }
    const assignableSet = new Set(assignableSessions);
    const retainedSet = new Set(retainedSessions);
    if ([...assignableSet].some((id) => retainedSet.has(id))) return null;
    return { folders: new Set(folders.map(normalizePath)), assignableSessions: assignableSet, retainedSessions: retainedSet };
  } catch {
    return null;
  }
}

/**
 * 有界读取上游响应体。resolve 覆盖所有终止形态：正常 'end'（返回缓冲体）、超出 maxBytes
 * 或连接中断（'aborted'/'error'/'close' 早于 'end'，返回 null 并销毁 socket）。
 *
 * R2：截断响应（连接结束但从未 emit 'end'）必须在这里有界结束，不能等独立的探测
 * 超时——否则探针 Promise 永不 settle，管理员保存请求会一直挂起。maxMs 是墙钟截止
 * 时间，独立于 socket 空闲超时，防止持续 trickle 永久延长请求。'close' 在正常响应里
 * 排在 'end' 之后（settled 哨兵使其 no-op），只在截断时先于 'end' 触发。
 */
export function readBoundedResponseBody(
  response: IncomingMessage,
  maxBytes: number,
  maxMs = 10_000,
): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    // settled 哨兵而非 in-flight 摘监听器：'error' 监听必须留到流真正结束，
    // 否则截断/超限后迟到的 socket error 会变成 uncaughtException。
    const settle = (value: Buffer | null): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(value);
    };
    timer = setTimeout(() => {
      response.destroy();
      settle(null);
    }, maxMs);
    timer.unref?.();
    response.on('data', (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        response.destroy();
        settle(null);
        return;
      }
      chunks.push(chunk);
    });
    response.on('end', () => settle(Buffer.concat(chunks)));
    response.on('aborted', () => settle(null));
    response.on('error', () => settle(null));
    response.on('close', () => settle(null));
  });
}

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
import type { PlatformConfig } from './config.js';
import { hardenSecretsAfterSetup, readEndpointRuntimeConfig, resolveRemoteMuxConfig } from './config.js';
import { AuthService, AuthError, type RequestMeta } from './auth.js';
import { Database, PermissionStateConflictError, SessionGrantsConflictError, canonicalForMatch, pathWithinDeletedTree, samePathForMatch, type UserPermissionsRow, type WorkspaceCleanupIntent } from './db.js';
import {
  folderAllowed,
  normalizePath,
  isSubuserBlockedApiPath,
  classifySubuserPath,
  type DynamicPluginManifest,
  OFFICIAL_API_NAMESPACES,
  SUBUSER_BLOCKED_API_NAMESPACES,
  isSubuserBlockedRemoteEndpoint,
  endpointAllowed,
  isWorkspaceWrite,
  isWorkspaceOrderWrite,
  isWorkspaceCreate,
  isWorkspaceDirectoryCreate,
  isWorkspaceDeleteOrRename,
  isAbsoluteLikePath,
  isDirectoryListRequest,
  isFullyQualifiedPath,
  isUploadRequest,
  isGitRequest,
  pathWithin,
  workspaceRegistrationAllowed,
  directoryEntryVisible,
  extractWorkspaceRenamePaths,
  isStaticAsset,
  isPollingRequest,
  isUsageAnchorRequest,
  WORKSPACE_ENDPOINT_RE,
  extractPathFromBody,
  filterByPathField,
  filterByPathFieldWithPredicate,
  collectIdPathPairs,
  collectSessionCwd,
  collectSessionCwdFromWorkspaces,
  extractWorkspaceId,
  findStringField,
  SESSION_SCOPED_RE,
  extractSessionId,
  collectSessionIds,
  collectAuthorizedSessionIds,
  parseSessionAddress,
  clientConnectionArgs,
  replaceArchivedSessionSnapshot,
  collectArchivedSessionIds,
  filterArchivedSessionIds,
  filterOwnedSessionIds,
  filterSessionItems,
  filterSessionSearchItems,
  sandboxPresetRank,
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  forceRejectApproval,
  clampSessionHistorySandbox,
  SANDBOX_RANK,
  isPrivateHost,
  sanitizeText,
  sanitizeHiddenUnicode,
  todayLocal,
} from './permissions.js';
import { findDshRoot, applyRemotePatch, restartDshWeb } from './patch.js';
import { t, resolveGatewayLang, type Lang } from './i18n.js';
import { isContainerRuntime, type UpdateEngine } from './update.js';
import { registerMediaRoutes } from './media.js';
import { registerMessageRoutes } from './messages.js';
import { registerAdminRoutes } from './admin.js';
import { createSandboxApplier, registerProxyRoutes } from './proxy.js';
import { SseFrameBuffer } from './sse-frames.js';
import { createSensitivePathChecker } from './sensitive-paths.js';
import { loadingTimeline } from './loading-timeline.js';

/** 网关内部扩展请求：权限执行时把用户/权限附在 req 上，供后续中间件与代理读取 */
type Req = Request & {
  dshpwUser?: number;
  /** 已认证用户名（审计用 actor 归属）；权限行仍只挂子用户。 */
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
  /** directoryPicker/list 响应过滤：ancestors 模式只保留通往授权根的条目。 */
  dshpwDirListFilter?: { mode: 'ancestors'; roots: string[]; showRoots?: boolean };

};

const AGENT_PRESET_SELECT_RE = /^\/api\/agentPresets?[.\/]select$/;
const AGENT_PRESET_LIST_RE = /^\/api\/agentPresets?[.\/]list$/;
const AGENT_PRESET_MUTATION_RE = /^\/api\/agentPresets?[.\/](?:copy|openDocument|remove|read|deletePreset)$/;

/** DSH 官方 terminal HTTP unary RPC：主用户直通，子用户由 allowSsh 控制。 */
const OFFICIAL_TERMINAL_HTTP_RE = /^\/api\/terminal[.\/](?:environment|shells|list|create|write|resize|rename|close)$/;
/** DSH 官方 terminal Remote 流：主用户直通，子用户由 allowSsh 控制。 */
const OFFICIAL_TERMINAL_REMOTE_ENDPOINTS = new Set(['terminal/follow', 'terminal/retain']);
/** 子用户 terminal UX 桩路径（点号/斜杠两种官方写法）：list / environment /
 *  shells / close。allowSsh 关闭时只回不放开能力的 server-response，见下方中间件；
 *  allowSsh 开启后这些请求也原样透传。 */
const TERMINAL_STUB_RE = /^\/api\/terminal[.\/](list|environment|shells|close)$/;

/** 与 Remote mux 侧共用：两条通道对同一个「terminal 不可用」失败给出同一文案。 */
const TERMINAL_UNAVAILABLE_MESSAGE = 'Remote terminal is not available for this user';
const OFFICIAL_JOB_REMOTE_ENDPOINTS = new Set(['job/list', 'job/follow']);
const OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS = new Set(['account/watch']);

export function systemdPurgeLaunchArgs(
  unitName: string,
  executable: string,
  helperPath: string,
  planPath: string,
  temporaryDirectory = os.tmpdir(),
): string[] {
  return ['--unit', unitName, '--collect', '--quiet', '--property=Type=exec', `--setenv=TMPDIR=${temporaryDirectory}`, executable, helperPath, planPath];
}

/**
 * alpha.2 官方 workspaceFiles 只读 RPC（点号/斜杠两种写法）。
 *
 * 上游对 read/readAll/readBytes/readRelated/stat 明确不做工作区包含检查
 * （README："The service does not impose workspace containment on file reads"），
 * 且请求只带 workspaceFileScopeId（会话身份）+ path（绝对路径或相对工作区根），
 * 因此「用哪个会话的 scope 读哪个绝对路径」完全由请求方决定：子用户可借官方
 * 通道读取宿主任意可读文件。网关必须在这里做会话授权 + 目标路径归属校验。
 *
 * `changes` 在 0.1.7-alpha.1 里是带 path 的 Remote 流（不是 HTTP unary RPC）。
 * 子用户 Remote 面按 workspaceFileScopeId + path 做会话/工作区授权，并过滤上游
 * 返回的绝对路径；HTTP unary 面仍由 WORKSPACE_FILES_CHANGES_ROUTE_RE 显式 403
 * （不依赖上游对 Remote-only 端点的 signature-invalid 报错）。
 */
const WORKSPACE_FILES_RPC_RE =
  /^\/api\/workspaceFiles[.\/](?:read|readAll|readBytes|readRelated|stat|list|changes)$/;

/**
 * 0.1.7-alpha.1 的 workspaceFiles/changes（Remote 流）HTTP unary 面的精确路径。
 * 子用户一律 403：该能力只经 Remote mux 提供；Remote 面按会话与路径单独授权。
 */
const WORKSPACE_FILES_CHANGES_ROUTE_RE = /^\/api\/workspaceFiles[.\/]changes$/;

/**
 * 会话日志导出路由（GET/HEAD ?sessionId=…）：上游只按 query 的 sessionId 查会话、
 * 不校验归属，且该路由同时属于 official 面与 isGitRequest，因此必须单独做会话
 * 归属校验（缺失/未授权一律 403），不能只靠 allow_git_download 开关。
 */
const SESSION_EXPORT_ROUTE_RE = /^\/api\/session[.\/]export$/;

/**
 * alpha.2 官方交付物路由：变更摘要 / 变更差异 / 在宿主桌面打开变更文件。
 * 坐标全部在 query（sessionId + seq [+ index]），上游只用 sessionId 查会话，
 * 不校验归属——因此不能把 `changes` 命名空间整体当官方面放行。
 */
const CHANGES_ROUTE_RE = /^\/api\/changes[.\/](summary|diff|open)$/;


/**
 * 从 terminal UX 桩请求体里提取可回显的 rpcId；任何不满足严格 client-request
 * 信封的输入返回空串，调用方回落到常规 403：
 *   · body 必须是 JSON 对象且 type === 'client-request'；
 *   · rpcId 必须是 1..200 字符的字符串；
 *   · method 必须与本路径的 RPC 一致（`terminal/<action>`，点号写法归一化）。
 * 刻意只读信封字段：不解析、不回显 payload/args，避免把子用户输入透传出去。
 */
function terminalStubRpcId(chunks: Buffer[], action: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return '';
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return '';
  const envelope = parsed as Record<string, unknown>;
  if (envelope.type !== 'client-request') return '';
  const rpcId = envelope.rpcId;
  if (typeof rpcId !== 'string' || rpcId.length === 0 || rpcId.length > 200) return '';
  const method = envelope.method;
  if (typeof method !== 'string') return '';
  const canonical = method.startsWith('terminal.') ? `terminal/${method.slice('terminal.'.length)}` : method;
  return canonical === `terminal/${action}` ? rpcId : '';
}

/**
 * 0.1.7-alpha.1 readBytes 的 wire `options`（{ range?, baseFile? }）。
 * 只有 `baseFile` 会改变真实读取目标（上游按 `resolve(dirname(baseFile), path)`
 * 解析），因此必须与上游同名 schema 同口径地严格解析：未知键、数组、标量、
 * 非法 baseFile（空/超长/含 NUL）或非整数 range 一律返回 null，调用方 fail-closed。
 * 缺省（undefined）与 `{}` 都表示「无基准文件」，不能凭缺省放宽后续判定。
 */
function workspaceFileByteOptions(value: unknown): { baseFile: string | null } | null {
  if (value === undefined) return { baseFile: null };
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const options = value as Record<string, unknown>;
  for (const key of Object.keys(options)) {
    if (key !== 'range' && key !== 'baseFile') return null;
  }
  const range = options.range;
  if (range !== undefined) {
    if (range === null || typeof range !== 'object' || Array.isArray(range)) return null;
    const window = range as Record<string, unknown>;
    for (const key of Object.keys(window)) {
      if (key !== 'offset' && key !== 'length') return null;
    }
    for (const bound of [window.offset, window.length]) {
      if (bound !== undefined && (typeof bound !== 'number' || !Number.isSafeInteger(bound) || bound < 0)) return null;
    }
  }
  const baseFile = options.baseFile;
  if (baseFile === undefined) return { baseFile: null };
  if (typeof baseFile !== 'string' || baseFile.length === 0 || baseFile.length > 4096) return null;
  if (baseFile.includes('\0')) return null;
  return { baseFile };
}

/**
 * workspaceFiles RPC 的授权输入：会话作用域身份 + 目标路径（readBytes 还带
 * options.baseFile）。只从 client-request 信封的 payload.args 读取（DSH 同源解码，
 * 外层同名字段会被 DSH 丢弃，绝不能作为授权依据）；任何缺失/超长/形状不符返回 null。
 */
function workspaceFileScopeRequest(
  value: unknown,
  readBytes: boolean,
): { scopeId: string; path: string; relativePath: string | null; baseFile: string | null } | null {
  const args = clientConnectionArgs(value);
  if (args === null) return null;
  const scopeId = args.workspaceFileScopeId;
  const requestedPath = args.path;
  if (typeof scopeId !== 'string' || scopeId.length === 0 || scopeId.length > 200) return null;
  if (typeof requestedPath !== 'string' || requestedPath.length === 0 || requestedPath.length > 4096) return null;
  if (requestedPath.includes('\0')) return null;
  const relativePath = args.relativePath;
  if (relativePath !== undefined) {
    if (typeof relativePath !== 'string' || relativePath.length === 0 || relativePath.length > 4096) return null;
    if (relativePath.includes('\0')) return null;
  }
  // options 只属于 0.1.7-alpha.1 的 readBytes；其它方法带 options 不参与路径解析，
  // 不能因为它而改变（或放宽）判定，因此只在该方法上解析。
  let baseFile: string | null = null;
  if (readBytes) {
    const options = workspaceFileByteOptions(args.options);
    if (options === null) return null;
    baseFile = options.baseFile;
  }
  return {
    scopeId,
    path: requestedPath,
    relativePath: typeof relativePath === 'string' ? relativePath : null,
    baseFile,
  };
}

/**
 * 把 workspaceFiles 的目标路径解析成归一化绝对路径：绝对路径（与上游同一个
 * path.isAbsolute 口径）按原样归一化，相对路径按该会话的工作区根拼接；
 * readRelated 的第二个文件与 readBytes 的 options.baseFile 一样，相对「基准文件
 * 所在目录」解析（与上游 resolve(dirname(base), relative) 逐字一致）。
 * 拼接刻意用字符串 + normalizePath（而不是 path.resolve）：后者的相对解析
 * 依赖进程所在平台（Windows 会把 `/root` 解析成当前盘符下的 `D:\root`），
 * 而网关所有路径比较都以 normalizePath 为准，两者必须同口径。
 */
function resolveWorkspaceFileTarget(root: string, requestedPath: string, relativePath: string | null): string | null {
  const normalizedRoot = normalizePath(root);
  const base = isAbsoluteLikePath(requestedPath)
    ? normalizePath(requestedPath)
    : normalizePath(`${normalizedRoot}/${requestedPath}`);
  if (relativePath === null) return base;
  const relative = relativePath.replace(/\\/g, '/');
  // 上游对 readRelated 的 relativePath 与 readBytes 的 baseFile 相对目标使用同一条口径：
  // 必须是相对文件系统路径，绝对路径、盘符路径和 URL scheme 都由上游拒绝。网关必须
  // 使用同一口径，不能把绝对参数拼成工作区内的假路径后误放行。
  if (
    relative.startsWith('/') ||
    /^[a-z][a-z\\d+.-]*:/iu.test(relative)
  ) return null;
  const separator = base.lastIndexOf('/');
  const directory = separator < 0 ? '' : base.slice(0, separator);
  return normalizePath(`${directory}/${relative}`);
}

/** 官方交付物路由的 query 坐标字段（与上游 NUMERIC 口径一致：纯十进制安全整数）。 */
function routeCoordinate(raw: string | null): number | null {
  if (raw === null || !/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

/**
 * alpha.2 changes.summary|diff|open 与 present.open 的坐标：sessionId + seq
 * （diff/open 还要 index）。任何不可解析的坐标返回 null，调用方 fail-closed。
 */
function deliveryRouteCoordinates(
  searchParams: URLSearchParams,
  needsIndex: boolean,
): { sessionId: string; seq: number; index: number | null } | null {
  const sessionId = searchParams.get('sessionId');
  if (sessionId === null || sessionId.length === 0 || sessionId.length > 200) return null;
  const seq = routeCoordinate(searchParams.get('seq'));
  if (seq === null) return null;
  const index = needsIndex ? routeCoordinate(searchParams.get('index')) : null;
  if (needsIndex && index === null) return null;
  return { sessionId, seq, index };
}

/**
 * alpha.2 的 Remote waterfall 结果信封：payload.args = { clientId, eventId, outcome }，
 * outcome = { kind: 'result', value }，审批类 value 就是 ApprovalOutcome 字符串
 * （'allowed-once' 是唯一的授权结果）。受限子用户必须被取消，因此这里把
 * 'allowed-once' 改写为 'rejected'；user-questions 的 value 是 { answers: [...] }
 * 对象，不含任何审批字段，保持可用。返回是否有实际改动。
 */
function forceRejectRemoteEventOutcome(value: unknown): boolean {
  const args = clientConnectionArgs(value);
  const outcome = args === null ? null : args.outcome;
  if (outcome === null || typeof outcome !== 'object' || Array.isArray(outcome)) return false;
  const row = outcome as Record<string, unknown>;
  if (row.kind !== 'result') return false;
  let changed = false;
  if (row.value === 'allowed-once') {
    row.value = 'rejected';
    changed = true;
  }
  // 兼容把审批结果再包一层 { approvalId, outcome } 的形状：复用与旧 /api/respond
  // 完全相同的改写口径，避免两条通道的审批语义漂移。
  if (forceRejectApproval(row.value)) changed = true;
  return changed;
}

function rpcRequestPayload(value: unknown): Record<string, unknown> | null {
  const args = clientConnectionArgs(value);
  if (args === null) return null;
  const request = args.request;
  return request !== null && typeof request === 'object' && !Array.isArray(request)
    ? request as Record<string, unknown>
    : null;
}

function agentPresetFromRequest(value: unknown): string | null {
  const request = rpcRequestPayload(value);
  return request !== null && typeof request.agentPreset === 'string' && request.agentPreset.length > 0
    ? request.agentPreset
    : findStringField(value, 'agentPreset');
}

/** Use a client-preallocated id or add one to a protocol-valid create request. */
function ensureSessionCreateId(value: unknown, generatedId: string): string | null {
  const request = rpcRequestPayload(value);
  if (request === null) return null;
  const existing = request.sessionId;
  if (existing === undefined) {
    request.sessionId = generatedId;
    return generatedId;
  }
  return typeof existing === 'string' && existing.length > 0 && existing.length <= 200 ? existing : null;
}

function hasImageAttachment(value: unknown): boolean {
  const visit = (current: unknown, depth: number): boolean => {
    if (depth > 8 || current === null || typeof current !== 'object') return false;
    if (Array.isArray(current)) return current.some((item) => visit(item, depth + 1));
    const row = current as Record<string, unknown>;
    if (row.type === 'image' && typeof row.data === 'string') return true;
    return Object.values(row).some((item) => visit(item, depth + 1));
  };
  return visit(value, 0);
}

// ── 子用户模型白名单（allowed_models）────────────────────────────────
// DSH 0.1.6-alpha.1 官方协议（只用官方字段，不信任请求里随手加的模型字段）：
//   · session/modelCatalog 无参数，结果 ModelCatalog =
//     { default: {provider,model,reasoningEffort?}, routableProviders,
//       groups: [{id,name,models:[{id,name,...}]}], failures: [{id,name,message}] }
//     provider 身份在 group.id / failure.id，**不在** model 对象里。
//   · session/selectModel 请求 { sessionId, provider, model, reasoningEffort? }。
//   · session/create { workspaceId?|cwd?, sessionId?, agentPreset? }、
//     session/fork { sessionId, atSeq? }、session/prompt { requestId, sessionId, ... }
//     都**没有**模型字段——模型由 Host 从会话投影/默认选择解析。
// 因此网关必须自己记住每个会话的有效模型（见 sessionModelSelection），
// 并在 create/fork/prompt 前用该状态做二次校验。

/** `/api/session/modelCatalog`（点号/斜杠两种写法）；它不在 SESSION_SCOPED_RE 里
 * （无 sessionId，不是会话作用域 RPC），必须单独判定才能做响应过滤。 */
const MODEL_CATALOG_RE = /^\/api\/session[.\/]modelCatalog$/;

/** 规范化后的 `provider/model` 允许项：provider 无斜杠/空白；model 允许含 `/`
 *  （DSH 官方目录 795/1354 个模型 ID 含斜杠，如 openrouter/anthropic/claude-…、
 *  baseten/deepseek-ai/…，自定义模型名同样不受字符集限制），只禁空白。 */
type AllowedModelSpec = { readonly provider: string; readonly model: string };

/**
 * 解析一条 allowlist 记录。允许列表由主用户在权限页保存，必须能在网关侧
 * 单独判定合法性，不能依赖上游（`session/model-unavailable`）报错才发现越权。
 * 分隔符是第一个 `/`：provider 段禁止斜杠（UI 与预设路由恒满足），剩余全部归 model。
 */
function parseAllowedModelSpec(value: unknown): AllowedModelSpec | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 300) return null;
  const separator = trimmed.indexOf('/');
  if (separator <= 0 || separator === trimmed.length - 1) return null;
  const provider = trimmed.slice(0, separator);
  const model = trimmed.slice(separator + 1);
  if (!/^[^/\s]{1,100}$/.test(provider) || !/^[^\s]{1,200}$/.test(model)) return null;
  return { provider, model };
}

/** 规范化并去重 allowlist（保持提交顺序，模型选择器的收敛结果可预测）。 */
function normalizeAllowedModels(value: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    const spec = parseAllowedModelSpec(entry);
    if (spec === null) continue;
    const canonical = `${spec.provider}/${spec.model}`;
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    out.push(canonical);
    if (out.length >= 512) break;
  }
  return out;
}

/** 精确 `provider/model` 匹配：同时校验 provider 与 model，不做通配或前缀放宽。 */
function allowedModelSet(allowed: readonly string[] | null): Set<string> | null {
  if (allowed === null) return null;
  const set = new Set<string>();
  for (const entry of allowed) {
    const spec = parseAllowedModelSpec(entry);
    if (spec !== null) set.add(`${spec.provider}/${spec.model}`);
  }
  return set;
}

function modelPairAllowed(allowed: Set<string> | null, provider: unknown, model: unknown): boolean {
  if (allowed === null) return true;
  if (typeof provider !== 'string' || typeof model !== 'string') return false;
  return allowed.has(`${provider}/${model}`);
}

/** 从官方形状里读取一个模型选择：ModelCatalog.default / ModelSelectionProjection.next
 * / model/selection 事件 data。字段名必须完全一致，避免把任意请求字段当成模型依据。 */
function modelSelectionFrom(value: unknown): AllowedModelSpec | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const row = value as Record<string, unknown>;
  if (typeof row.provider !== 'string' || typeof row.model !== 'string') return null;
  return parseAllowedModelSpec(`${row.provider}/${row.model}`);
}

/** 按 allowlist 过滤官方 modelCatalog 值；主用户（allowed === null）原样返回。 */
function filterModelCatalogValue(value: unknown, allowed: readonly string[] | null): unknown {
  const allowedSet = allowedModelSet(allowed);
  if (allowedSet === null) return value;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return value;
  const catalog = value as Record<string, unknown>;
  const groups: Record<string, unknown>[] = [];
  if (Array.isArray(catalog.groups)) {
    for (const group of catalog.groups) {
      if (group === null || typeof group !== 'object' || Array.isArray(group)) continue;
      const row = group as Record<string, unknown>;
      // provider 身份只在 group.id；model 里没有 provider 字段，不能按 model 反推。
      if (typeof row.id !== 'string' || !Array.isArray(row.models)) continue;
      const models = row.models.filter((model): boolean => {
        if (model === null || typeof model !== 'object' || Array.isArray(model)) return false;
        return modelPairAllowed(allowedSet, row.id, (model as Record<string, unknown>).id);
      });
      if (models.length === 0) continue;
      groups.push({ ...row, models });
    }
  }
  const routable = new Set<string>();
  for (const group of groups) if (typeof group.id === 'string') routable.add(group.id);
  // failures 只带 provider id/name/message；无法可靠关联到允许 provider 时清空，
  // 不能把其它 provider 的名字/错误信息泄露给受限用户。
  const failures = Array.isArray(catalog.failures)
    ? catalog.failures.filter((failure): boolean => {
        if (failure === null || typeof failure !== 'object' || Array.isArray(failure)) return false;
        return typeof (failure as Record<string, unknown>).id === 'string' &&
          routable.has((failure as Record<string, unknown>).id as string);
      })
    : [];
  // 默认模型只允许出现在 allowlist 内；否则按 group 顺序收敛到第一个允许模型，
  // 都没有则为 null（`[]` = 禁止全部），绝不把不可用的 Host 默认暴露给受限用户。
  const upstreamDefault = modelSelectionFrom(catalog.default);
  const converged = upstreamDefault !== null && modelPairAllowed(allowedSet, upstreamDefault.provider, upstreamDefault.model)
    ? catalog.default
    : firstAllowedCatalogModel(groups, allowedSet);
  return {
    ...catalog,
    default: converged,
    routableProviders: Array.isArray(catalog.routableProviders)
      ? catalog.routableProviders.filter((provider): boolean => typeof provider === 'string' && routable.has(provider))
      : [...routable],
    groups,
    failures,
  };
}

/** 收敛用默认模型：按过滤后的 group/model 顺序取第一个允许项（保持 provider+model 成对）。 */
function firstAllowedCatalogModel(
  groups: readonly Record<string, unknown>[],
  allowed: Set<string>,
): AllowedModelSpec | null {
  for (const group of groups) {
    if (typeof group.id !== 'string' || !Array.isArray(group.models)) continue;
    for (const model of group.models) {
      if (model === null || typeof model !== 'object' || Array.isArray(model)) continue;
      const id = (model as Record<string, unknown>).id;
      if (typeof id !== 'string') continue;
      const spec = parseAllowedModelSpec(`${group.id}/${id}`);
      if (spec !== null && allowed.has(`${spec.provider}/${spec.model}`)) return spec;
    }
  }
  return null;
}

/**
 * 从官方会话数据里收集 `model/selection` 事件（session/follow 的 snapshot.records 与
 * 后续 event 帧、session/page 与 session/history 的 records）。按 seq 取最新一条，
 * 与 DSH 的 ModelSelectionProjection（lastUsed / pending→next）语义一致。
 */
function latestModelSelectionInRecords(value: unknown, depth = 0): { spec: AllowedModelSpec; seq: number } | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  if (Array.isArray(value)) {
    let best: { spec: AllowedModelSpec; seq: number } | null = null;
    for (const item of value) {
      const found = latestModelSelectionInRecords(item, depth + 1);
      if (found === null) continue;
      if (best === null || found.seq >= best.seq) best = found;
    }
    return best;
  }
  const row = value as Record<string, unknown>;
  // 事件形状：{ type: 'model/selection', seq, time, data: {provider, model, ...} }
  if (row.type === 'model/selection') {
    const data = modelSelectionFrom(row.data);
    if (data !== null) {
      const seq = typeof row.seq === 'number' && Number.isSafeInteger(row.seq) ? row.seq : -1;
      return { spec: data, seq };
    }
  }
  let found: { spec: AllowedModelSpec; seq: number } | null = null;
  for (const key of ['records', 'event', 'events', 'items']) {
    if (!Object.hasOwn(row, key)) continue;
    const nested = latestModelSelectionInRecords(row[key], depth + 1);
    if (nested === null) continue;
    if (found === null || nested.seq >= found.seq) found = nested;
  }
  return found;
}

const COOKIE_NAME = 'dsh_gateway_token';
/** 语言偏好 cookie（用户在登录页手动切换后持久化） */
const LANG_COOKIE = 'dshpw_lang';

/** 解析页面语言：?lang → cookie → dsh 设置(locale.preference) → 浏览器语言 → zh */
function langOf(req: Request): Lang {
  return resolveGatewayLang({
    queryLang: req.query.lang,
    cookieLang: readCookie(req.headers.cookie, LANG_COOKIE),
    acceptLanguage: req.headers['accept-language'],
  });
}

/**
 * 注入 dsh HTML 的兼容脚本：
 * crypto.randomUUID 是 Web Crypto API，只在安全上下文（HTTPS / localhost）
 * 存在；明文 HTTP 部署下 dsh 前端的 RPC id 生成（如加载 Agent 预设）会报
 * "crypto.randomUUID is not a function"。这里用 getRandomValues（HTTP 下
 * 可用）实现 UUID v4 补齐。
 */
const INJECT_SCRIPT = `<script>
(function () {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID !== 'function' && typeof crypto.getRandomValues === 'function') {
    crypto.randomUUID = function () {
      var b = crypto.getRandomValues(new Uint8Array(16));
      b[6] = (b[6] & 15) | 64;
      b[8] = (b[8] & 63) | 128;
      var h = Array.prototype.map.call(b, function (x) {
        return x.toString(16).padStart(2, '0');
      }).join('');
      return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
    };
  }
})();
</script>`;

function readCookie(cookieHeader: string | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    // Cookie Chaos 加固（P3）：之前 part.trim() 按 JS Unicode 空白语义裁剪 cookie 名，
    // 导致带 Unicode 空白前缀（U+00A0/U+3000/U+2000/U+0085 等）的“伪同名”cookie 在
    // 单字节 latin1 编码下会被 trim 归一化成目标名读入（行为不一致、依赖编码变异）。
    // 现在只剥离 RFC 6265 允许的 OWS（ASCII SP/HTAB，来自 "; " 分隔符或 cookie-pair
    // 前 OWS），cookie 名其余字符必须与目标精确相等——任何非 ASCII 前缀（含 Unicode
    // 空白与单字节 latin1 变体）都不再可能被归一化匹配，一律 fail-closed。
    const trimmed = part.replace(/^[ \t]+/, '');
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq);
    if (key !== name) continue;
    const value = trimmed.slice(eq + 1);
    if (value === '') continue;
    try {
      return decodeURIComponent(value);
    } catch {
      // 畸形百分号编码（如 %zz）：返回原值，JWT 校验自然失败，不抛 URIError 500
      return value;
    }
  }
  return null;
}

/**
 * 防开放重定向：next 只允许站内路径。
 * 拒绝一切浏览器可能解析成跨域的形式：
 *   - 反斜杠（浏览器按 '/' 解析：/\evil.com → //evil.com 协议相对跳转）
 *   - 解码后以 // 开头（%2F%2F 解码后成 //）
 *   - 非 / 开头、控制字符/空白
 */
function safeNext(next: string | undefined): string {
  if (!next) return '/';
  let decoded: string;
  try {
    decoded = decodeURIComponent(next);
  } catch {
    return '/';
  }
  if (decoded.includes('\\')) return '/';
  if (!decoded.startsWith('/') || decoded.startsWith('//')) return '/';
  if (/[\u0000-\u0020\u007f]/.test(decoded)) return '/';
  return decoded;
}

/**
 * 同源判定（浏览器 Origin vs 请求 Host），网关写路由与登出共用同一口径。
 * 跨源攻击的本质是跨主机（攻击者无法在受害者主机名上托管内容），因此只比
 * 主机:端口、不比协议——否则 nginx/caddy 在 80/443 终结 TLS 的反代部署
 * （网关收到明文 HTTP、req.protocol=http，浏览器 Origin=https）会全部误判。
 * Host 只信直接对端：仅当对端是本机回环（受信本地反代）才采纳 X-Forwarded-Host，
 * 公网直连请求不能带伪造头绕过。配置的公开主机（gateway.domain/publicHost）是
 * 服务端显式声明的信任来源：反代改写 Host 后 peer 可能非回环，但 Origin 命中配置
 * 主机时仍须放行；该兜底只比对服务端配置、不读请求头，故不受 peer 回环与否限制。
 * 无 Origin（非浏览器/旧客户端）返回 true，由 HttpOnly+SameSite Cookie 兜底。
 */
type OriginRequest = {
  method?: string;
  url?: string;
  headers: {
    origin?: string | string[];
    host?: string | string[];
    'x-forwarded-host'?: string | string[];
    'sec-fetch-site'?: string | string[];
  };
  socket: { remoteAddress?: string | null };
};

function firstHeader(value: string | string[] | undefined): string {
  return Array.isArray(value) ? value[0] ?? '' : value ?? '';
}

/**
 * 同源校验拒绝时的诊断日志。只记录路由元数据（方法/路径/Host/Origin/对端），
 * 绝不读取或记录 Cookie、Authorization、查询串——避免把凭据写进 journal。
 */
function logOriginRejection(req: OriginRequest, reason: string): void {
  const clean = (value: string): string => value.replace(/[\r\n\t]/g, ' ').slice(0, 120);
  const path = (req.url ?? '').split('?')[0] ?? '';
  console.error(
    '[dsh-passwords] origin-rejected reason=' +
      clean(reason) +
      ' method=' +
      clean(req.method ?? '') +
      ' path=' +
      clean(path) +
      ' peer=' +
      clean(req.socket.remoteAddress ?? '') +
      ' host=' +
      clean(firstHeader(req.headers.host)) +
      ' origin=' +
      clean(firstHeader(req.headers.origin)) +
      ' xfh=' +
      clean(firstHeader(req.headers['x-forwarded-host'])) +
      ' sfs=' +
      clean(firstHeader(req.headers['sec-fetch-site'])),
  );
}

function decodedQueryKey(rawKey: string): string | null {
  try {
    return decodeURIComponent(rawKey.replace(/\+/g, ' '));
  } catch {
    return null;
  }
}

function stripGatewayAuthQuery(rawUrl: string, pathname: string): string {
  const queryIndex = rawUrl.indexOf('?');
  if (queryIndex < 0) return '';
  const rawQuery = rawUrl.slice(queryIndex + 1);
  if (rawQuery === '') return '';

  // DSH uses /plugins/??<module-list>&rev=<hash>. URLSearchParams normalizes the
  // second '?' to %3F and rewrites otherwise-valid business query bytes. Decode
  // keys only for credential matching; output always keeps the original bytes.
  // `token` is an alpha launch credential only at the index entrypoint. Plugins
  // commonly use a business `token` query parameter, which must not be removed.
  const stripLaunchToken = pathname === '/' || pathname === '/index.html';
  const kept = rawQuery.split('&').filter((part) => {
    const equalsIndex = part.indexOf('=');
    const rawKey = equalsIndex < 0 ? part : part.slice(0, equalsIndex);
    const key = decodedQueryKey(rawKey);
    return key !== COOKIE_NAME && !(stripLaunchToken && key === 'token');
  });
  return kept.length === 0 ? '' : `?${kept.join('&')}`;
}

function upstreamCookieHeader(browserCookie: string | undefined, authoritativeCookie: string): string | undefined {
  const authoritativeName = authoritativeCookie.split('=', 1)[0] ?? '';
  const kept: string[] = [];
  for (const part of (browserCookie ?? '').split(';')) {
    const trimmed = part.replace(/^[ \t]+/, '');
    const equalsIndex = trimmed.indexOf('=');
    if (equalsIndex <= 0) continue;
    const name = trimmed.slice(0, equalsIndex);
    // The gateway JWT and DSH browser-auth cookies never belong to arbitrary
    // upstream plugins. Other plugin cookies retain their original pair bytes.
    if (name === COOKIE_NAME || name.startsWith('dsh-auth-') || name === authoritativeName) continue;
    kept.push(trimmed);
  }
  if (authoritativeCookie !== '') kept.push(authoritativeCookie);
  return kept.length === 0 ? undefined : kept.join('; ');
}

function originHostMatches(req: OriginRequest, configuredHosts: readonly string[] = []): boolean {
  const originRaw = firstHeader(req.headers.origin);
  if (originRaw === '') return true;
  // 字面量 `Origin: null` 无法被 new URL 解析，会落进 catch 误记为
  // origin-unparsable；先显式分类为 origin-null，返回值仍为拒绝。
  if (originRaw === 'null') {
    logOriginRejection(req, 'origin-null');
    return false;
  }
  try {
    const origin = new URL(originRaw);
    if (origin.origin === 'null') {
      logOriginRejection(req, 'origin-null');
      return false;
    }
    const peer = req.socket.remoteAddress ?? '';
    const trustedProxy = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    const forwardedHost = firstHeader(req.headers['x-forwarded-host']).split(',')[0].trim();
    const effectiveHost = trustedProxy && forwardedHost !== '' ? forwardedHost : firstHeader(req.headers.host);
    const normalizeHost = (value: string): string => {
      const host = value.trim().toLowerCase();
      if (origin.protocol === 'https:' && host.endsWith(':443')) return host.slice(0, -4);
      if (origin.protocol === 'http:' && host.endsWith(':80')) return host.slice(0, -3);
      return host;
    };
    const originHost = normalizeHost(origin.host);
    if (originHost === normalizeHost(effectiveHost)) return true;
    // 配置的公开主机是服务端显式声明的信任来源：反向代理可能把 Host 改写为内网
    // 地址（peer 非回环），此时 Origin 仍在配置白名单内，必须放行。该兜底只比对
    // 服务端配置值、不含任何请求头，故无需受 peer 是否回环限制；X-Forwarded-Host
    // 的采纳仍限定回环 peer（见上）。
    if (configuredHosts.some((host) => normalizeHost(host) === originHost)) return true;
    logOriginRejection(req, 'host-mismatch');
    return false;
  } catch {
    logOriginRejection(req, 'origin-unparsable');
    return false;
  }
}

// ── CSRF（double-submit token）────────────────────────────────
// 登录/配置表单：GET 渲染时下发 Cookie + 表单隐藏域同一随机值，
// POST 时恒定时间比对。无服务端会话也能防跨站表单伪造。
const CSRF_COOKIE = 'dsh_csrf';

// P0 加固：签名段的服务端规范形式恒为 32 个小写十六进制字符
// （newCsrfToken 用 createHmac(...).digest('hex').slice(0, 32)）。
// 用严格白名单而不是字符串长度做前置判定，杜绝「32 个 JS 字符但 33 个字节」
// 这类多字节变体绕过长度检查、进而在 timingSafeEqual 抛 RangeError。
const CSRF_SIG_RE = /^[0-9a-f]{32}$/;

function newCsrfToken(secret: string): string {
  // 签名双重提交：token 随机 + HMAC 签名。攻击者即使能自选 cookie 值
  // （子域 cookie tossing 等），不知道密钥也伪造不出合法签名。
  const token = randomBytes(16).toString('hex');
  const sig = createHmac('sha256', secret).update(token).digest('hex').slice(0, 32);
  return `${token}.${sig}`;
}

function csrfMatches(secret: string, cookieValue: string | null, fieldValue: string): boolean {
  if (!cookieValue || !fieldValue) return false;
  const cookie = cookieValue.split('.');
  const field = fieldValue.split('.');
  if (cookie.length !== 2 || field.length !== 2) return false;
  const [cookieToken, cookieSig] = cookie as [string, string];
  const [fieldToken, fieldSig] = field as [string, string];
  // 双重提交：cookie 与表单的 token 必须一致，且签名必须等于服务端 HMAC
  if (cookieToken.length === 0 || cookieToken !== fieldToken) return false;
  const expected = createHmac('sha256', secret).update(cookieToken).digest('hex').slice(0, 32);
  // JS `.length` 是 UTF-16 码元数，Buffer/`timingSafeEqual` 用 UTF-8 字节数：
  // 31 个 ASCII + U+00E9 是「32 码元 / 33 字节」，能骗过长度校验并让
  // timingSafeEqual 抛 ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH。三个调用点都在
  // async 路由内，Express 4 不接住 async 拒绝，异常会升级为未处理拒绝 → 进程退出。
  // 因此改用与服务端签名完全一致的白名单：非 32 位小写十六进制一律拒绝。
  if (!CSRF_SIG_RE.test(cookieSig) || !CSRF_SIG_RE.test(fieldSig)) return false;
  return (
    timingSafeEqual(Buffer.from(cookieSig), Buffer.from(fieldSig)) &&
    timingSafeEqual(Buffer.from(cookieSig), Buffer.from(expected))
  );
}

function setCsrfCookie(res: Response, token: string, secure: boolean): void {
  res.setHeader(
    'Set-Cookie',
    `${CSRF_COOKIE}=${token}; Path=/gateway; HttpOnly; SameSite=Lax; Max-Age=3600${
      secure ? '; Secure' : ''
    }`,
  );
}

/**
 * 未认证 / 幽灵会话时，浏览器与爬虫自动探测的精确路径。命中直接 204：不渲染
 * 登录页、不重定向、不下发 cookie、不转发上游，避免匿名探测触发整页渲染与
 * CSRF 轮换。只做精确 Set 匹配（绑定已归一化的 gatePath），刻意不改成前缀、
 * 扩展名或 Sec-Fetch-Dest/Accept 判断，以免扩大匿名可达面。
 */
const ANONYMOUS_STATIC_PROBES: ReadonlySet<string> = new Set([
  '/favicon.ico',
  '/apple-touch-icon.png',
  '/apple-touch-icon-precomposed.png',
  '/manifest.json',
  '/manifest.webmanifest',
  '/browserconfig.xml',
  '/robots.txt',
  '/sitemap.xml',
]);

// ── 主题同步：合理化跟随 dsh 主题 ─────────────────────────────
// dsh 的主题偏好持久化在 <dsh home>/settings.yaml 的 ui-theme.preference
// （light|dark|system，默认 system）。网关在渲染登录/配置页时读取该文件，
// 注入引导脚本在浏览器端解析（system 走 prefers-color-scheme，与 dsh 的
// boot-theme 逻辑一致）。文件不可读时回退 system；可用 MCP_DSH_SETTINGS_FILE
// 显式指定 dsh 设置文件路径（网关与 dsh 不同机时用）。dsh 0.1.7 首次迁移会把旧
// settings.yaml 改名为 settings.yaml.imported，网关在候选位置回退读取该文件。
type ThemePreference = 'light' | 'dark' | 'system';

// 主题偏好每 5 秒最多读一次 settings.yaml：登录/配置页每次渲染都调用本函数，
// 同步磁盘 IO 不应成为每个页面 GET 的固定开销。用户切主题后最多延迟 5 秒生效。
let themePreferenceCache: { value: ThemePreference; at: number } | null = null;
const THEME_CACHE_TTL_MS = 5_000;

function readDshThemePreference(): ThemePreference {
  const now = Date.now();
  if (themePreferenceCache !== null && now - themePreferenceCache.at < THEME_CACHE_TTL_MS) {
    return themePreferenceCache.value;
  }
  const explicit = process.env.MCP_DSH_SETTINGS_FILE?.trim();
  const dshHome = process.env.DSH_HOME?.trim();
  const bases: string[] = explicit
    ? [explicit]
    : [
        ...(dshHome ? [path.join(dshHome, 'settings.yaml')] : []),
        path.join(os.homedir(), '.dsh', 'settings.yaml'),
      ];
  // dsh 0.1.7 首次迁移会把旧 settings.yaml 改名为 settings.yaml.imported：
  // 每个候选位置先读 settings.yaml，再回退同目录的 settings.yaml.imported。
  const candidates: string[] = [];
  for (const base of bases) candidates.push(base, `${base}.imported`);
  let value: ThemePreference = 'system';
  for (const file of candidates) {
    try {
      const text = readFileSync(file, 'utf8');
      // settings.yaml 为扁平结构：顶层命名空间键 + 缩进字段（注释可跟在行尾）
      const block = text.match(/^ui-theme\s*:\s*(?:#.*)?$/m);
      if (!block || block.index === undefined) continue;
      const rest = text.slice(block.index);
      const hit = rest.match(/^\s+preference\s*:\s*["']?(light|dark|system)["']?\s*(?:#.*)?$/m);
      if (hit) {
        value = hit[1] as ThemePreference;
        break;
      }
    } catch {
      // 文件不存在/不可读：继续尝试下一个候选，最终回退 system
    }
  }
  themePreferenceCache = { value, at: now };
  return value;
}

/** 主题引导脚本：在 <head> 内尽早设置 data-theme 与 color-scheme，避免闪烁 */
function themeBootScript(preference: ThemePreference): string {
  return `<script>(function(){var pref=${JSON.stringify(preference)};var mq=window.matchMedia&&matchMedia('(prefers-color-scheme: dark)');function apply(){var dark=pref==='dark'||(pref==='system'&&mq&&mq.matches);document.documentElement.setAttribute('data-theme',dark?'dark':'light');document.documentElement.style.colorScheme=dark?'dark':'light';}apply();if(pref==='system'&&mq){try{mq.addEventListener('change',apply)}catch(e){mq.addListener(apply)}}})();</script>`;
}

/**
 * 登录/配置页共享样式：完全采用 dsh 设计令牌（design-platform.css）
 * - 浅色为默认（dsh 默认主题 = 简约白色）：bg #fff、主文字 rgb(15,17,21)、
 *   品牌蓝 rgb(65,118,230)（deepseek-500）、边框 rgba(0,0,0,.1) 等
 * - html[data-theme=dark] 覆盖为 dsh 暗色令牌（neutral-bluish-950 等）
 * - 输入框修复：-webkit-autofill 会把输入栏刷成白色/黄色（粘贴触发布局），
 *   用 inset 大阴影 + text-fill-color 回压为当前主题输入底色
 * - 动画只动 transform/opacity/box-shadow，并尊重 prefers-reduced-motion
 */
const PAGE_STYLE = `
:root{
  --bg:rgb(255,255,255);
  --card:rgba(255,255,255,.94);
  --field:rgb(255,255,255);
  --txt:rgb(15,17,21);
  --sub:rgb(97,102,107);
  --muted:rgb(129,133,140);
  --caption:rgb(173,178,184);
  --border:rgba(0,0,0,.1);
  --border-soft:rgba(0,0,0,.06);
  --border-strong:rgba(0,0,0,.16);
  --brand:rgb(65,118,230);
  --brand-hi:rgb(86,134,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.08);
  --danger-border:rgba(242,90,90,.3);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.1);
  --warn-border:rgba(247,173,49,.35);
  --ring:rgba(65,118,230,.16);
  --glow-a:rgba(77,147,248,.18);
  --glow-b:rgba(103,65,217,.09);
  --glow-c:rgba(96,165,250,.11);
  --grid-line:rgba(15,17,21,.03);
  --shadow-card:0 24px 48px -24px rgba(15,23,42,.18),0 2px 8px rgba(15,23,42,.05);
  --shadow-field:0 1px 2px rgba(15,23,42,.05);
  --shadow-btn:0 4px 14px -4px rgba(65,118,230,.5);
}
html[data-theme=dark]{
  --bg:rgb(21,21,23);
  --card:rgba(35,35,36,.92);
  --field:rgb(44,44,46);
  --txt:rgb(249,250,251);
  --sub:rgb(207,211,214);
  --muted:rgb(173,178,184);
  --caption:rgb(129,133,140);
  --border:rgba(255,255,255,.12);
  --border-soft:rgba(255,255,255,.06);
  --border-strong:rgba(255,255,255,.2);
  --brand:rgb(86,134,254);
  --brand-hi:rgb(103,158,254);
  --danger:rgb(242,90,90);
  --danger-soft:rgba(242,90,90,.14);
  --danger-border:rgba(242,90,90,.35);
  --ok:rgb(34,197,94);
  --warn:rgb(247,173,49);
  --warn-soft:rgba(247,173,49,.12);
  --warn-border:rgba(247,173,49,.4);
  --ring:rgba(86,134,254,.28);
  --glow-a:rgba(86,134,254,.15);
  --glow-b:rgba(103,65,217,.13);
  --glow-c:rgba(96,165,250,.09);
  --grid-line:rgba(255,255,255,.025);
  --shadow-card:0 24px 60px -20px rgba(0,0,0,.6);
  --shadow-field:0 1px 2px rgba(0,0,0,.3);
  --shadow-btn:0 4px 18px -4px rgba(86,134,254,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei','Helvetica Neue',Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;overflow:hidden;-webkit-font-smoothing:antialiased}
.orbs{position:fixed;inset:0;overflow:hidden;pointer-events:none;z-index:0}
.orbs i{position:absolute;border-radius:50%;filter:blur(80px);will-change:transform;animation:drift 22s ease-in-out infinite}
.orbs .a{width:46vw;height:46vw;max-width:520px;max-height:520px;left:-12vw;top:-14vh;background:radial-gradient(circle,var(--glow-a),transparent 68%)}
.orbs .b{width:40vw;height:40vw;max-width:440px;max-height:440px;right:-10vw;bottom:-12vh;background:radial-gradient(circle,var(--glow-b),transparent 68%);animation-delay:-7s}
.orbs .c{width:30vw;height:30vw;max-width:320px;max-height:320px;right:16vw;top:-16vh;background:radial-gradient(circle,var(--glow-c),transparent 68%);animation-delay:-13s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(4vw,3vh) scale(1.08)}66%{transform:translate(-3vw,2vh) scale(.95)}}
.grid{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(var(--grid-line) 1px,transparent 1px),linear-gradient(90deg,var(--grid-line) 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%);mask-image:radial-gradient(ellipse 90% 70% at 50% 40%,#000 25%,transparent 78%)}
.card{position:relative;z-index:10;width:100%;max-width:400px;margin:0 16px;background:var(--card);border:1px solid var(--border-soft);border-radius:16px;padding:32px 32px 28px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);box-shadow:var(--shadow-card);animation:enter .55s cubic-bezier(.22,1,.36,1) both}
@keyframes enter{from{opacity:0;transform:translateY(20px) scale(.98)}to{opacity:1;transform:translateY(0) scale(1)}}
.logo{width:48px;height:48px;margin:0 auto 16px;border-radius:14px;background:linear-gradient(135deg,var(--brand-hi),var(--brand));display:flex;align-items:center;justify-content:center;box-shadow:0 8px 20px -6px var(--shadow-btn);position:relative}
.logo::after{content:"";position:absolute;inset:-4px;border-radius:18px;border:1px solid var(--ring);opacity:0;animation:ping 4s ease-out infinite}
@keyframes ping{0%{opacity:.7;transform:scale(.92)}55%{opacity:0;transform:scale(1.18)}100%{opacity:0}}
h1{font-size:20px;font-weight:600;letter-spacing:-.01em;text-align:center}
.sub{margin-top:8px;font-size:13px;color:var(--muted);text-align:center;line-height:1.5}
label{display:block;margin-top:14px}
label span{display:block;margin-bottom:6px;font-size:12px;font-weight:500;color:var(--sub)}
input,button{font-family:inherit}
input{width:100%;padding:10px 14px;font-size:14px;line-height:20px;color:var(--txt);background:var(--field);border:1px solid var(--border);border-radius:10px;box-shadow:var(--shadow-field);transition:border-color .16s,box-shadow .16s;caret-color:var(--brand)}
input::placeholder{color:var(--caption)}
input::selection{background:var(--ring)}
input:hover{border-color:var(--border-strong)}
input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px var(--ring),var(--shadow-field)}
input:-webkit-autofill,input:-webkit-autofill:hover,input:-webkit-autofill:focus{-webkit-text-fill-color:var(--txt);-webkit-box-shadow:0 0 0 1000px var(--field) inset;box-shadow:0 0 0 1000px var(--field) inset;caret-color:var(--txt);transition:background-color 999999s ease-in-out 0s}
button{margin-top:22px;width:100%;padding:10px 16px;font-size:14px;font-weight:500;color:#fff;background:linear-gradient(135deg,var(--brand-hi),var(--brand));border:none;border-radius:10px;cursor:pointer;box-shadow:var(--shadow-btn);transition:transform .16s,box-shadow .16s,filter .16s}
button:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 6px 22px -4px var(--shadow-btn)}
button:active:not(:disabled){transform:translateY(0) scale(.99);filter:brightness(.96)}
button:disabled{opacity:.7;cursor:default}
.error-bar{display:none;margin-top:14px;padding:8px 12px;font-size:12px;color:var(--danger);background:var(--danger-soft);border:1px solid var(--danger-border);border-radius:8px;animation:shake .4s}
.db-hint{margin-top:14px;padding:8px 12px;font-size:12px;color:var(--warn);background:var(--warn-soft);border:1px solid var(--warn-border);border-radius:8px}
@keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-10px)}40%{transform:translateX(10px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}}
.rules{margin-top:12px;display:flex;flex-wrap:wrap;gap:4px 12px;font-size:11px;color:var(--caption)}
.rules span{display:inline-flex;align-items:center;gap:4px}
.rules span.on{color:var(--ok)}
.strength{height:4px;margin-top:10px;border-radius:999px;background:var(--field);border:1px solid var(--border-soft);overflow:hidden}
.strength i{display:block;height:100%;width:0;border-radius:999px;background:var(--danger);transition:width .32s cubic-bezier(.22,1,.36,1),background .32s}
.lang-switch{position:absolute;top:14px;right:16px;display:flex;gap:12px;font-size:12px}
.lang-switch a{color:var(--caption);text-decoration:none;transition:color .15s}
.lang-switch a:hover{color:var(--sub)}
.lang-switch a.on{color:var(--brand);font-weight:600}
/* 按钮提交中的加载 spinner：用 currentColor 继承按钮文字色 */
.btn-spin{display:inline-block;width:13px;height:13px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:btnSpin .7s linear infinite;vertical-align:-2px;margin-right:7px}
@keyframes btnSpin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.btn-spin{animation:none!important}}
`;

/** 语言切换链接：中文 / English（当前语言高亮，点击带 ?lang= 走同一个登录路径） */
function langSwitch(lang: Lang, next: string): string {
  const query = next === '' ? '' : `?next=${encodeURIComponent(next)}`;
  const mk = (id: Lang, label: string) =>
    `<a${lang === id ? ' class="on"' : ''} href="/gateway/login${query}${query === '' ? '?' : '&'}lang=${id}">${label}</a>`;
  return `<div class="lang-switch">${mk('zh', '中文')}${mk('en', 'English')}</div>`;
}

/** 页面骨架：共享 head（主题引导 + 样式）+ 背景动画层 + 卡片容器 */
function pageShell(params: { lang: Lang; title: string; body: string; script?: string }): string {
  return `<!doctype html>
<html lang="${params.lang === 'en' ? 'en' : 'zh-CN'}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${params.title}</title>
${themeBootScript(readDshThemePreference())}
<style>${PAGE_STYLE}</style>
</head>
<body>
<div class="orbs" aria-hidden="true"><i class="a"></i><i class="b"></i><i class="c"></i></div>
<div class="grid" aria-hidden="true"></div>
<div class="card">${params.body}</div>
${params.script ?? ''}
</body>
</html>`;
}

function renderLoginPage(params: { lang: Lang; next: string; error?: string; dbHealthy: boolean; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const dbHint = params.dbHealthy
    ? ''
    : `<div class="db-hint">${escapeHtml(tr('gw.dbHint'))}</div>`;
  const body = `
  <div class="logo">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
  ${langSwitch(params.lang, params.next)}
  <h1>${tr('gw.loginTitle')}</h1>
  <p class="sub">${tr('gw.loginSub1')}<br/>${tr('gw.loginSub2')}</p>
  <form method="POST" action="/gateway/login" id="login-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <input type="hidden" name="next" value="${escapeHtml(params.next)}" />
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernamePlaceholder')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" placeholder="${tr('gw.passwordPlaceholder')}" autocomplete="current-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.login')}</button>
  </form>
  ${errorBlock}
  ${dbHint}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleLogin'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  document.getElementById('login-form').addEventListener('submit', () => {
    const btn = document.getElementById('submit-btn');
    // 提交中：文字前加 spinner（不影响布局，防重复点击已有 disabled 兜底）
    btn.innerHTML = '<span class="btn-spin" aria-hidden="true"></span>' + ${JSON.stringify(tr('gw.loggingIn'))};
    btn.disabled = true;
  });
</script>`,
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── 首次配置页（平台未初始化时显示；预设密钥 + 用户名 + 密码） ──
function renderSetupPage(params: { lang: Lang; error?: string; csrf: string }): string {
  const tr = (key: string, tp?: Record<string, string | number>) => t(params.lang, key, tp);
  const errorBlock = params.error
    ? `<div class="error-bar" id="error-bar">${escapeHtml(params.error)}</div>`
    : '';
  const body = `
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" stroke="white" stroke-width="1.6"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="white" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  ${langSwitch(params.lang, '')}
  <h1>${tr('gw.setupTitle')}</h1>
  <p class="sub">${tr('gw.setupSub1')}<br/>${tr('gw.setupSub2')}</p>
  <form method="POST" action="/gateway/setup" id="setup-form">
    <input type="hidden" name="csrf" value="${escapeHtml(params.csrf)}" />
    <label><span>${tr('gw.setupKey')}</span><input type="password" name="setupKey" placeholder="${tr('gw.setupKeyPlaceholder')}" autocomplete="off" required /></label>
    <label><span>${tr('gw.username')}</span><input type="text" name="username" placeholder="${tr('gw.usernameRule')}" autocomplete="username" required /></label>
    <label><span>${tr('gw.password')}</span><input type="password" name="password" id="pw" placeholder="${tr('gw.passwordRule')}" autocomplete="new-password" required /></label>
    <div class="strength"><i id="pw-bar"></i></div>
    <div class="rules" id="pw-rules">
      <span data-r="len">○ ${tr('gw.ruleLen')}</span>
      <span data-r="up">○ ${tr('gw.ruleUp')}</span>
      <span data-r="low">○ ${tr('gw.ruleLow')}</span>
      <span data-r="num">○ ${tr('gw.ruleNum')}</span>
      <span data-r="sym">○ ${tr('gw.ruleSym')}</span>
    </div>
    <label><span>${tr('gw.confirmPassword')}</span><input type="password" name="confirm" placeholder="${tr('gw.confirmPlaceholder')}" autocomplete="new-password" required /></label>
    <button type="submit" id="submit-btn">${tr('gw.initPlatform')}</button>
  </form>
  ${errorBlock}`;
  return pageShell({
    lang: params.lang,
    title: tr('gw.titleSetup'),
    body,
    script: `<script>
  const err = document.getElementById('error-bar');
  if (err) { setTimeout(() => { err.style.display = 'block'; }, 50); }
  const pw = document.getElementById('pw');
  const bar = document.getElementById('pw-bar');
  const COLORS = ['#f25a5a', '#f7ad31', '#f59e0b', '#4d93f8', '#22c55e'];
  pw.addEventListener('input', () => {
    const v = pw.value;
    const rules = {
      len: v.length >= 12, up: /[A-Z]/.test(v), low: /[a-z]/.test(v),
      num: /[0-9]/.test(v), sym: /[^A-Za-z0-9]/.test(v),
    };
    let n = 0;
    document.querySelectorAll('#pw-rules span').forEach((el) => {
      const ok = rules[el.dataset.r];
      if (ok) n++;
      el.className = ok ? 'on' : '';
      el.textContent = (ok ? '✓ ' : '○ ') + el.textContent.replace(/^[✓○] /, '');
    });
    const pct = Math.max(20, (n / 5) * 100);
    bar.style.width = pct + '%';
    bar.style.background = COLORS[Math.max(0, n - 1)];
  });
  document.getElementById('setup-form').addEventListener('submit', (e) => {
    const pwv = pw.value;
    const confirm = document.querySelector('input[name=confirm]').value;
    if (pwv !== confirm) {
      e.preventDefault();
      const err = document.getElementById('error-bar');
      err.textContent = ${JSON.stringify(tr('gw.passwordMismatch'))};
      err.style.display = 'block';
      err.style.animation = 'none';
      void err.offsetWidth;
      err.style.animation = 'shake .4s';
      return;
    }
    const btn = document.getElementById('submit-btn');
    btn.innerHTML = '<span class="btn-spin" aria-hidden="true"></span>' + ${JSON.stringify(tr('gw.initializing'))};
    btn.disabled = true;
  });
</script>`,
  });
}

/** F-A2：递归清洗 JSON 里所有字符串字段的隐藏 Unicode（read 端点返回文件内容） */
function sanitizeHiddenUnicodeJson(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null) return value;
  if (typeof value === 'string') return sanitizeHiddenUnicode(value);
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) out.push(sanitizeHiddenUnicodeJson(item, depth + 1));
    return out;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) out[k] = sanitizeHiddenUnicodeJson(v, depth + 1);
    return out;
  }
  return value;
}

/**
 * 已登记 SSH 端点的 host 字段 SSRF 判定（F-28/F-29，异步版）：
 *   - IP 字面量（含八进制/十六进制/简写段/映射形态）→ isPrivateHost 立即判
 *   - hostname（如 127.0.0.1.nip.io、sslip.io 通配）→ DNS 全量解析后逐地址判定，
 *     任一解析结果命中私网/回环 → 拦截；全部公网 → 返回首个解析 IP 供请求体改写，
 *     把连接目标钉死在已验证地址上，消除「网关判定与插件连接两次解析」的
 *     DNS 重绑定 TOCTOU 窗口。
 *   - 3 秒超时防 DNS 卡死；解析失败/超时一律 fail-closed（返回 null = 拦截）：
 *     无法验证的目标不允许经网关连接，绝不"解析失败即放行"。
 * 触发条件与任何具体插件无关：只要路径命中主用户登记的 SSH HTTP 端点且
 * 请求体带 host 字段（见 MCP_GATEWAY_SSH_ENDPOINTS 的 `http:` 规则）。
 * 返回：'private' = 拦截；IP 字符串 = 校验通过、按它改写 host；null = 解析失败拦截。
 */
function resolveUpstreamHostSafe(host: string): Promise<'private' | string | null> {
  const h = host.trim().toLowerCase();
  if (isPrivateHost(h)) return Promise.resolve('private');
  const lookup = dns.promises
    .lookup(h, { all: true, verbatim: false })
    .then<dns.LookupAddress[] | null>((addrs) => (addrs.length > 0 ? addrs : null))
    .catch(() => null); // 解析失败 = 无法验证 = 拦截（fail-closed）
  const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 3000).unref());
  return Promise.race([lookup, timeout]).then((addrs) => {
    if (addrs === null) return null;
    if (addrs.some((addr) => isPrivateHost(addr.address))) return 'private';
    // verbatim:false 下 Node 已按 RFC6724 排序，首个通常即首选地址
    return addrs[0].address;
  });
}

export function isBackgroundUpdateRequest(gatePath: string): boolean {
  return gatePath === '/api/dsh-passwords/update/status' || gatePath === '/gateway/internal/update';
}

export function createGatewayServer(
  config: PlatformConfig,
  auth: AuthService,
  db: Database,
  updateEngine?: UpdateEngine,
  options: { envFile?: string; endpointReloadIntervalMs?: number } = {},
): http.Server {
  const app = express();
  const configuredOriginHosts = [config.gateway.domain, config.gateway.publicHost].filter(
    (host): host is string => typeof host === 'string' && host.trim() !== '',
  );
  // 宿主进程低频推送的已注册 Remote/HTTP 扩展面。已加载扩展不绑定 allow_ssh；
  // 官方 terminal、SSH 端点和宿主级敏感能力仍由各自边界控制。
  let dynamicPluginManifest: DynamicPluginManifest | undefined;
  // 测试服务器由本机反向代理转发；只信任 loopback，恢复按真实客户端
  // X-Forwarded-For 计算的 req.ip，同时避免信任公网伪造的代理头。
  app.set('trust proxy', 'loopback');
  // 请求是否应视为 HTTPS：网关自身 TLS，或受信本地反代转发的
  // X-Forwarded-Proto=https（trust proxy=loopback 保证只有回环对端生效，公网直连
  // 伪造该头无效）。nginx/caddy 在 80/443 终结 TLS 时网关收到的是明文 HTTP，
  // 仅凭 config.gateway.tls 会把会话/CSRF/语言 Cookie 漏掉 Secure 标志。
  const requestIsSecure = (req: Request): boolean => config.gateway.tls !== null || req.secure;
  // ── 传统端点登记表（代码不内置扩展路径）──
  // owner: 和其余 SSH/宿主登记项都只供主用户使用；
  // DSH 运行时已登记的普通扩展面由动态清单直接放行，不经过这张表。
  //
  // 运行态可变：部署 .env 变更后由文件尾部的热更新定时器就地替换（无需重启
  // 网关）；未显式指定部署环境文件（DSH_PASSWORDS_ENV_FILE）时不做热更新。
  let endpointRules = config.endpointRules ?? [];
  const registryAuthorizedSockets = new Set<Duplex>();
  // 不泄露框架信息
  app.disable('x-powered-by');
  // 仅解析 /gateway 表单请求；代理请求的 body 必须原样透传给上游
  // （全局 express.json/urlencoded 会消费掉请求流，导致上游收到空 body）
  app.use('/gateway', express.urlencoded({ extended: false }));

  // CSRF 签名密钥：从 JWT 密钥域分离派生（服务端私有，登录/配置表单的
  // 双重提交令牌用 HMAC 签名——攻击者无法自选 cookie 伪造合法签名）
  const csrfSecret = createHash('sha256').update('dshpw-csrf:' + config.jwtSecret).digest('hex');

  // HTTPS 模式：全站 HSTS（浏览器强制后续走 HTTPS）+ 会话 Cookie 加 Secure
  //（Cookie 标志在写入处按 requestIsSecure 决定：网关 TLS 或受信反代 https）
  if (config.gateway.tls !== null) {
    app.use((_req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000');
      next();
    });
  }

  // 受反代/编排器调用的最小健康端点：不返回密钥、用户或上游详情。
  app.get('/gateway/healthz', (_req, res) => {
    res.status(200).json({ ok: true, service: 'dsh-passwords' });
  });
  app.get('/gateway/readyz', async (_req, res) => {
    const healthy = await db.health().catch(() => false);
    res.status(healthy ? 200 : 503).json({ ok: healthy, database: healthy });
  });

  // 上游认证 Broker：仅允许同机插件提交已经由 dsh 官方 connection
  // authenticatedUrl() 兑换出的 cookie-pair；不接受启动 token，不返回 Cookie。
  const internalSecretMatches = (req: Request): boolean => {
    const peer = req.socket.remoteAddress ?? '';
    if (peer !== '127.0.0.1' && peer !== '::1' && peer !== '::ffff:127.0.0.1') return false;
    const supplied = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    return a.length === b.length && timingSafeEqual(a, b);
  };
  app.get('/gateway/internal/upstream-auth/health', async (req, res) => {
    if (!internalSecretMatches(req)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    if (upstreamAuthCookie === '') {
      res.status(503).json({ ok: false, authenticated: false });
      return;
    }
    const request = upstreamTransport.request({
      hostname: upstreamHost,
      port: upstreamPort,
      path: '/',
      method: 'GET',
      headers: { host: upstreamAuthority, cookie: upstreamAuthCookie },
      agent: upstreamAgent,
      timeout: 3000,
    }, (upstreamRes) => {
      const status = upstreamRes.statusCode ?? 502;
      upstreamRes.resume();
      res.status(status >= 200 && status < 300 ? 200 : 503).json({ ok: status >= 200 && status < 300, authenticated: status !== 401, upstreamStatus: status });
    });
    request.on('error', () => {
      if (!res.headersSent) res.status(503).json({ ok: false, authenticated: false });
    });
    request.end();
  });
  // 启动协调探针：仅同机插件可读取当前网关绑定的 dsh parent PID。公开
  // healthz 只能证明“有某个 dsh-passwords”，不能证明它属于当前 dsh 进程；
  // 旧 dsh 重启期间必须据此进入等待，而不是误复用旧 child。
  app.post('/gateway/internal/plugin-manifest', express.json({ limit: '256kb' }), (req, res) => {
    if (!internalSecretMatches(req)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const body: unknown = req.body;
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      res.status(400).json({ ok: false, error: 'invalid manifest' });
      return;
    }
    const manifest = body as Record<string, unknown>;
    const expectedParentPid = Number(process.env.DSH_GATEWAY_PARENT_PID ?? '');
    const parentPid = typeof manifest.parentPid === 'number' && Number.isInteger(manifest.parentPid) ? manifest.parentPid : 0;
    if (Number.isInteger(expectedParentPid) && expectedParentPid > 0 && parentPid !== expectedParentPid) {
      res.status(409).json({ ok: false, error: 'stale parent' });
      return;
    }
    const generation = typeof manifest.generation === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(manifest.generation) ? manifest.generation : '';
    const namespaces = Array.isArray(manifest.namespaces) ? manifest.namespaces : [];
    const streams = Array.isArray(manifest.streamEndpoints) ? manifest.streamEndpoints : [];
    const exactPaths = Array.isArray(manifest.exactPaths) ? manifest.exactPaths : [];
    const pathPrefixes = Array.isArray(manifest.pathPrefixes) ? manifest.pathPrefixes : [];
    const validNamespace = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(value);
    const validStream = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,63}\/[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(value);
    const validManifestPath = (value: unknown): value is string => {
      if (typeof value !== 'string' || value.length < 2 || value.length > 256 || !value.startsWith('/') ||
          value.includes('\\') || value.includes('?') || value.includes('#') || /[\u0000-\u001f\u007f]/.test(value)) return false;
      if (value === '/api' || value === '/api/' || value === '/gateway' || value.startsWith('/gateway/') ||
          value === '/api/dsh-passwords' || value.startsWith('/api/dsh-passwords/')) return false;
      const segments = value.split('/').filter((segment) => segment !== '');
      return segments.length > 0 && segments.every((segment) => segment !== '.' && segment !== '..' && /^[A-Za-z0-9_$.-]{1,96}$/.test(segment));
    };
    if (generation === '' || namespaces.length > 512 || streams.length > 512 || exactPaths.length > 512 || pathPrefixes.length > 128 ||
      !namespaces.every(validNamespace) || !streams.every(validStream)) {
      res.status(400).json({ ok: false, error: 'invalid manifest' });
      return;
    }
    // 清单来自同机已加载扩展；单条陈旧/宿主保留路径不能让整份普通
    // 插件清单失效，否则一个 dsh-passwords 自身路由就会让所有扩展 403。
    const acceptedExactPaths = exactPaths.filter(validManifestPath).slice(0, 512);
    const acceptedPathPrefixes = pathPrefixes.filter(validManifestPath).slice(0, 128);
    const acceptedNamespaces = namespaces.filter((namespace): namespace is string =>
      !OFFICIAL_API_NAMESPACES.has(namespace) && !SUBUSER_BLOCKED_API_NAMESPACES.has(namespace));
    const acceptedStreams = streams.filter((endpoint): endpoint is string => {
      const namespace = endpoint.split('/')[0] ?? '';
      return !OFFICIAL_API_NAMESPACES.has(namespace) && !isSubuserBlockedRemoteEndpoint(endpoint);
    });
    const changed = dynamicPluginManifest?.generation !== generation;
    dynamicPluginManifest = {
      generation,
      namespaces: new Set(acceptedNamespaces),
      streamEndpoints: new Set(acceptedStreams),
      exactPaths: new Set(acceptedExactPaths),
      pathPrefixes: new Set(acceptedPathPrefixes),
    };
    if (changed) console.log(`[dsh-passwords] 动态插件清单已同步 generation=${generation} namespaces=${namespaces.length} streams=${streams.length} paths=${exactPaths.length + pathPrefixes.length}`);
    res.json({ ok: true, generation, namespaces: dynamicPluginManifest.namespaces.size, streamEndpoints: dynamicPluginManifest.streamEndpoints.size });
  });
  app.get('/gateway/internal/owner', (req, res) => {
    if (!internalSecretMatches(req)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const rawParentPid = process.env.DSH_GATEWAY_PARENT_PID ?? '';
    const parentPid = Number(rawParentPid);
    res.json({
      ok: true,
      parentPid: Number.isInteger(parentPid) && parentPid > 0 ? parentPid : null,
    });
  });
  app.post('/gateway/internal/upstream-auth', express.json({ limit: '1kb' }), (req, res) => {
    const peer = req.socket.remoteAddress ?? '';
    if (peer !== '127.0.0.1' && peer !== '::1' && peer !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const supplied = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const value = (req.body as { cookie?: unknown } | undefined)?.cookie;
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+=[A-Za-z0-9._~-]+$/.test(value)) {
      res.status(400).json({ ok: false, error: 'invalid cookie' });
      return;
    }
    upstreamAuthCookie = value;
    res.json({ ok: true });
  });

  // 登录/配置页安全响应头（仅 /gateway/* 自有页面；代理的 dsh 响应不强制
  // CSP，避免破坏 dsh 前端）：禁嗅探、禁嵌入、Referrer 仅同源、禁缓存、禁索引
  app.use('/gateway', (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    // 必须用 same-origin：no-referrer 会让真实同源 HTML 表单 POST 变为
    // Origin: null + Sec-Fetch-Site: same-origin，被同源校验误判 403，
    // 登录卡在 /gateway/login。same-origin 仍不向跨源泄露 Referer。
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    // 网关标识：客户端插件探测此头判断是否经 dsh-passwords 远程访问
    res.setHeader('X-Dsh-Gateway', '1');
    // 页面完全自包含（内联 CSS/JS、无外部资源）：可以上严格 CSP
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    next();
  });

  const upstream = new URL(config.gateway.upstream);
  const upstreamHost = upstream.hostname;
  const upstreamAuthority = upstream.host;
  const upstreamPort = Number(upstream.port || (upstream.protocol === 'https:' ? 443 : 80));
  const upstreamIsHttps = upstream.protocol === 'https:';
  const upstreamScheme = upstreamIsHttps ? 'https' : 'http';
  // alpha 的 browser-auth Cookie 只在进程内保存并可由插件通过受保护的
  // loopback/internal-secret 通道更新；外部 dsh-passwords JWT 永远不转发给 dsh。
  let upstreamAuthCookie = (() => {
    const value = process.env.DSH_UPSTREAM_AUTH_COOKIE?.trim() ?? '';
    return /^[A-Za-z0-9_-]+=[A-Za-z0-9._~-]+$/.test(value) ? value : '';
  })();
  /**
   * 登录页内嵌的 dsh-auth cookie 派生公式（与 dsh 自己的 cookieName() 逐字节
   * 一致：`dsh-auth-` + base64url(sha256(authority))）。网关只把它交给浏览器
   * 侧 js 计算本 authority 的 cookie 名，用来判断浏览器是否已直接持有一份可用
   * 的 dsh-auth cookie（官方 Web UI / API / WS 的正规凭据，与网关登录态无关）。
   * 任意参数都能返回一个字符串，泄露面为零。
   */
  const GATEWAY_UPSTREAM_AUTH_COOKIE_NAME = (
    connection: { authenticatedCookie?: unknown } | null | undefined,
    authority: unknown,
  ) => {
    if (typeof connection?.authenticatedCookie !== 'function') return null;
    try {
      const url = new URL(`http://${String(authority)}`);
      if (url.host !== String(authority)) return null;
      const cookie = String((connection.authenticatedCookie as (base: string) => unknown)(`http://${url.host}/`));
      const name = cookie.split('=', 1)[0];
      return /^dsh-auth-[A-Za-z0-9_-]+$/.test(name) ? name : null;
    } catch {
      return null;
    }
  };

  const upstreamTransport = upstreamIsHttps ? https : http;
  // 限制在 loopback，远程拓扑必须自行提供已兑换 Cookie。
  const upstreamAgent = upstreamIsHttps
    ? new https.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 30_000, rejectUnauthorized: process.env.MCP_GATEWAY_UPSTREAM_TLS_VERIFY !== '0' })
    : new http.Agent({ keepAlive: true, maxSockets: 64, keepAliveMsecs: 30_000 });

  const fetchAssignableResources = (): Promise<AssignableResources | null> => new Promise((resolve) => {
    let settled = false;
    const timeoutMs = internalProbeTimeoutMs();
    const deadline = Date.now() + timeoutMs;
    let deadlineTimer: NodeJS.Timeout | undefined;
    const finish = (value: AssignableResources | null): void => {
      if (settled) return;
      settled = true;
      if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      resolve(value);
    };
    const request = upstreamTransport.request({
      hostname: upstreamHost,
      port: upstreamPort,
      path: '/api/dsh-passwords/internal/assignable-resources',
      method: 'GET',
      headers: {
        host: upstreamAuthority,
        'x-internal-secret': config.internalSecret,
        ...(upstreamAuthCookie === '' ? {} : { cookie: upstreamAuthCookie }),
      },
      agent: upstreamAgent,
      timeout: timeoutMs,
    }, (response) => {
      const remainingMs = Math.max(1, deadline - Date.now());
      void readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, remainingMs).then((body) => {
        // body === null 涵盖超限与截断：两者都必须 fail-closed，不得用半截清单授权。
        if (body === null || response.statusCode !== 200) { finish(null); return; }
        finish(parseAssignableResources(body));
      });
    });
    deadlineTimer = setTimeout(() => { request.destroy(); finish(null); }, timeoutMs);
    deadlineTimer.unref?.();
    request.on('error', () => finish(null));
    request.on('timeout', () => { request.destroy(); finish(null); });
    request.end();
  });

  // workspaceId → 规范路径映射：从 workspace.list 响应里收集，供 session.create 用 workspaceId 时解析路径
  const workspacePathById = new Map<string, string>();
  // 请求体上限分档（见 requestBodyLimitFor）：主用户恒为 300 MiB；子用户按
  // allow_upload 决定——关闭时维持默认 64 MiB，开启时才提升到 rc.2 上游一致的
  // 300 MiB。上限在 proxy 层对声明长度与实际收包执行同一口径；媒体上传另由
  // 独立的 allow_chat_media 与魔数校验控制。

  // dsh rc.8 将归档状态放在全局 workspace registry；session.list 自身经常不带该字段，
  // 因此在网关实例内保存最近一次可信 workspace.list 快照，避免归档会话掉进 Ungrouped。
  const archivedSessionSnapshot = new Set<string>();
  let archivedSessionSnapshotReady = false;
  let archivedSessionSnapshotRevision = 0;
  // 只负责「同一用户多个 workspace.list 响应之间的先后顺序」（较早的慢响应不得回滚
  // 更新的快照）。它不是授权版本：授权回写栅栏必须用 userAccessEpoch，绝不能把
  // 这个全局计数器当作授权 revision（详见 replaceUserSessionAccess 的注释）。
  let workspaceListRequestRevision = 0;
  /** 分配一个新的列表请求序号。workspace.list 与归档动作共用它：归档动作也推进序号，
   *  令在途的更旧 workspace.list 响应失去回滚该用户归档投影的资格。 */
  const bumpWorkspaceListRequestRevision = (): number => ++workspaceListRequestRevision;

  // 普通用户各自独立的会话授权快照：不能用全局 sessionId → cwd 映射，
  // 否则一个用户的 workspace.list 会给另一个用户的 session RPC 提供授权依据。
  // A subuser's filtered workspace baseline is the authority for all later
  // workspaceId and sessionId checks. alpha.3 obtains it through Remote
  // workspace/follow, whereas older clients can still populate it via HTTP.
  const userSessionAccess = new Map<number, Map<string, string>>();
  const userWorkspaceIds = new Map<number, Set<string>>();
  const userWorkspacePaths = new Map<number, Map<string, string>>();
  const userArchivedSessionIds = new Map<number, Set<string>>();
  // 每用户授权 epoch：唯一权威、单调递增的「授权/权限已变更」计数。只有实际改变
  // 会话可见性的变更（grant、disabled_sessions、目录白名单、封禁、沙盒、workspace
  // 清理）才推进它；workspace.list / Remote baseline 只是可见性投影，替换快照绝不
  // 推进它——否则在途的 create/fork 响应会借一次列表刷新重新获得回写资格。
  // 请求开始时记录 epoch，响应/回写时与当前 epoch 比对：不相等即授权已变，
  // 旧请求一律不得回写（权限实际变化时旧请求不能回写）。
  const userAccessEpoch = new Map<number, number>();

  // 同一用户 workspace.list 响应的顺序水位（workspaceListRequestRevision 的
  // 用户投影）。与 epoch 完全独立：只用于丢弃乱序的旧列表响应，不参与授权判定。
  const userAccessListOrder = new Map<number, number>();
  /** Session/create has passed path validation but its DSH response is still pending. */
  const pendingCreatedSessions = new Map<number, Map<string, { cwd: string; expiresAt: number }>>();
  const pendingCreatedSessionFor = (userId: number): Map<string, { cwd: string; expiresAt: number }> => {
    let pending = pendingCreatedSessions.get(userId);
    if (pending === undefined) {
      pending = new Map();
      pendingCreatedSessions.set(userId, pending);
    }
    if (pending.size >= 256) {
      const oldest = pending.keys().next().value;
      if (typeof oldest === 'string') pending.delete(oldest);
    }
    return pending;
  };
  const clearPendingCreatedSession = (userId: number, sessionId: string): void => {
    const pending = pendingCreatedSessions.get(userId);
    pending?.delete(sessionId);
    if (pending?.size === 0) pendingCreatedSessions.delete(userId);
  };
  // 子用户刚通过目录选择器成功创建、可登记为工作区的目录（带过期）。
  // workspace/create 只接受「显式分配的精确目录 / 自己创建的工作区子树 / 本表命中」，
  // 杜绝把任意预存在目录登记进自己的白名单（D1 工作流收紧）。
  const pendingCreatedDirectories = new Map<number, Map<string, { expiresAt: number }>>();
  const PENDING_DIRECTORY_TTL_MS = 30 * 60 * 1000;
  const recordPendingCreatedDirectory = (userId: number, canonicalPath: string): void => {
    let pending = pendingCreatedDirectories.get(userId);
    if (pending === undefined) {
      pending = new Map();
      pendingCreatedDirectories.set(userId, pending);
    }
    if (pending.size >= 256 && !pending.has(canonicalPath)) {
      const oldest = pending.keys().next().value;
      if (typeof oldest === 'string') pending.delete(oldest);
    }
    pending.set(canonicalPath, { expiresAt: Date.now() + PENDING_DIRECTORY_TTL_MS });
  };
  const pendingCreatedDirectoryPaths = (userId: number): string[] => {
    const pending = pendingCreatedDirectories.get(userId);
    if (pending === undefined) return [];
    const now = Date.now();
    const out: string[] = [];
    for (const [dir, marker] of pending) {
      if (marker.expiresAt > now) out.push(dir);
      else pending.delete(dir);
    }
    if (pending.size === 0) pendingCreatedDirectories.delete(userId);
    return out;
  };
  const userSessionAccessWaiters = new Map<number, Set<() => void>>();
  const notifyUserSessionAccessWaiters = (userId: number): void => {
    const waiters = userSessionAccessWaiters.get(userId);
    if (waiters === undefined) return;
    for (const resolve of [...waiters]) resolve();
  };
  // alpha.3 opens session.list and workspace/follow independently. session.list must
  // wait for the latter's filtered baseline, but an invalidated old baseline is not a
  // valid replacement. Only replaceUserSessionAccess may wake this wait.
  const awaitUserSessionAccess = (userId: number, timeoutMs = 5_000, requireWorkspacePaths = false): Promise<boolean> => {
    const ready = () => userSessionAccess.has(userId) && (!requireWorkspacePaths || userWorkspacePaths.has(userId));
    if (ready()) return Promise.resolve(true);
    return new Promise((resolve) => {
      let settled = false;
      const finish = (available: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        const waiters = userSessionAccessWaiters.get(userId);
        waiters?.delete(onReady);
        if (waiters?.size === 0) userSessionAccessWaiters.delete(userId);
        resolve(available);
      };
      const onReady = () => {
        if (ready()) finish(true);
      };
      const timeout = setTimeout(() => finish(false), timeoutMs);
      const waiters = userSessionAccessWaiters.get(userId) ?? new Set<() => void>();
      waiters.add(onReady);
      userSessionAccessWaiters.set(userId, waiters);
    });
  };
  // 观测：baseline 有界等待耗时与结果。只记录数值/布尔，不涉及任何请求内容；
  // 时间线关闭时 spanAsync 直接透传原 Promise，不改变语义。
  const waitForUserSessionAccess = (userId: number, timeoutMs?: number, requireWorkspacePaths?: boolean): Promise<boolean> =>
    loadingTimeline.spanAsync(
      'baseline.wait',
      () => awaitUserSessionAccess(userId, timeoutMs, requireWorkspacePaths),
      (ready) => ({ ok: ready }),
    );
  const userSessionAccessFor = (userId: number): Map<string, string> => userSessionAccess.get(userId) ?? new Map();
  const userAccessEpochFor = (userId: number): number => userAccessEpoch.get(userId) ?? 0;
  /** 推进该用户的授权 epoch（授权/权限实际变更时调用）；单调递增，绝不回退。 */
  const bumpUserAccessEpoch = (userId: number): number => {
    const next = userAccessEpochFor(userId) + 1;
    userAccessEpoch.set(userId, next);
    return next;
  };
  /**
   * 用一份可信可见性快照替换该用户的会话授权快照。
   *   · epoch 必须是调用方在「取得该快照的请求开始时」记录的授权 epoch。授权在
   *     请求途中发生过变更（epoch 已推进）时，旧请求一律不得回写。
   *   · order 只做同一用户 workspace.list 响应的先后排序（0 = 不参与排序，例如
   *     Remote baseline）：更旧的响应不得回滚更新的快照。
   * 本函数绝不推进 epoch —— 快照替换不是授权变更，不能改变授权版本。
   *   · 返回是否真正接受本次回写：false = 被 epoch/order 栅栏拒绝。与授权快照
   *     同源的派生集合（如归档标记）必须复用该结果，不能单独绕过栅栏写入。
   */
  const replaceUserSessionAccess = (userId: number, access: Map<string, string>, epoch: number, order = 0): boolean => {
    if (epoch < userAccessEpochFor(userId)) return false;
    if (order !== 0 && order < (userAccessListOrder.get(userId) ?? 0)) return false;
    userSessionAccess.set(userId, access);
    if (order !== 0) userAccessListOrder.set(userId, order);
    notifyUserSessionAccessWaiters(userId);
    return true;
  };
  /** 授权变更后失效内存快照：先推进 epoch（旧请求/旧 baseline 随即失去回写资格），
   *  再清空快照，等待新 baseline 重建。 */
  const invalidateUserSessionAccess = (userId: number): void => {
    bumpUserAccessEpoch(userId);
    userSessionAccess.delete(userId);
    pendingCreatedSessions.delete(userId);
    userWorkspaceIds.delete(userId);
    userWorkspacePaths.delete(userId);
    userArchivedSessionIds.delete(userId);
  };
  /**
   * 权限行已经提交、但后续还要 await 上游沙盒收紧时，立即让在途 create/fork
   * 响应失去回写 grant/access 的资格。刻意不清快照或关闭 mux：待沙盒定向撤销
   * 结束后仍由 invalidateUserSessionAccess 统一刷新，避免窗口内 baseline 读到未撤销 grant。
   */
  const fenceUserAccessEpoch = (userId: number): void => {
    bumpUserAccessEpoch(userId);
  };
  const replaceUserWorkspacePaths = (userId: number, paths: Map<string, string>, epoch: number, order = 0): void => {
    if (epoch < userAccessEpochFor(userId)) return;
    if (order !== 0 && order < (userAccessListOrder.get(userId) ?? 0)) return;
    userWorkspacePaths.set(userId, paths);
    userWorkspaceIds.set(userId, new Set(paths.keys()));
    notifyUserSessionAccessWaiters(userId);
  };
  // Remote workspace/session 订阅在单条 WebSocket 上长期存活。所有已认证用户（含
  // 主用户）都登记，确保登出、改密、改名和删除账户时能立即终止升级时身份。
  const remoteMuxClientsByUser = new Map<number, Set<RemoteMuxUserConnection>>();
  const userWebSocketClients = new Map<number, Set<{ close: (code?: number, reason?: string) => void }>>();
  const registerUserWebSocketClient = (userId: number, client: { close: (code?: number, reason?: string) => void }): (() => void) => {
    const clients = userWebSocketClients.get(userId) ?? new Set<{ close: (code?: number, reason?: string) => void }>();
    clients.add(client);
    userWebSocketClients.set(userId, clients);
    return () => {
      clients.delete(client);
      if (clients.size === 0 && userWebSocketClients.get(userId) === clients) userWebSocketClients.delete(userId);
    };
  };
  const closeUserWebSocketClients = (userId: number, code = 1012, reason = 'Permissions changed'): void => {
    const clients = userWebSocketClients.get(userId);
    if (clients === undefined) return;
    userWebSocketClients.delete(userId);
    // close 回调会注销自身；遍历快照避免同步修改 Set 时跳过其它旧连接。
    for (const client of [...clients]) {
      try { client.close(code, reason); } catch {}
    }
  };
  const closeUserRemoteMuxClients = (userId: number, code = 1012, reason = 'Permissions changed'): void => {
    const clients = remoteMuxClientsByUser.get(userId);
    if (clients === undefined) return;
    remoteMuxClientsByUser.delete(userId);
    // 同上：连接关闭会回调 unregisterClient，必须先复制后逐个关闭。
    for (const connection of [...clients]) {
      // 先经受限 teardown 立即收敛发送器/心跳、锁定 permission-revoked 首因诊断并 arm 5s grace，
      // 再下发既有的 socket close/terminate（保留既有 code/reason 与权限行为）。
      try { connection.teardownCarrier(code); } catch {
        // teardown 失败不能阻断撤销：仍按既有路径关闭连接。
      }
      try {
        if (connection.socket.readyState === WebSocket.OPEN) connection.socket.close(code, reason);
        else connection.socket.terminate();
      } catch {
        // The close event removes already-closed clients; a racing close needs no recovery.
      }
    }
  };

  // sessionId → cwd 映射: 从 session.list/workspace.list/session.create 响应里收集，
  // 供受限子用户的会话作用域 RPC（history/prompt 等）做 cwd 白名单校验——
  // 权限撤销后仍能按 sessionId 直读旧目录会话必须封堵
  const sessionCwdById = new Map<string, string>();
  // 受限子用户的 prompt/fork 必须继承已授权的 agent preset；未知状态不放行。
  // 缓存按用户隔离，避免同一 sessionId 或不同用户的列表响应互相污染授权判断。
  const sessionAgentPresetByUser = new Map<number, Map<string, string>>();
  const sessionAgentPresetMapFor = (userId: number): Map<string, string> => {
    let map = sessionAgentPresetByUser.get(userId);
    if (map === undefined) {
      map = new Map<string, string>();
      sessionAgentPresetByUser.set(userId, map);
    }
    return map;
  };
  const collectSessionAgentPresets = (value: unknown, target: Map<string, string>, depth = 0): void => {
    if (depth > 8 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) collectSessionAgentPresets(item, target, depth + 1);
      return;
    }
    const row = value as Record<string, unknown>;
    const id = typeof row.sessionId === 'string' ? row.sessionId : typeof row.id === 'string' ? row.id : null;
    if (id !== null && typeof row.agentPreset === 'string' && row.agentPreset.length > 0) target.set(id, row.agentPreset);
    for (const child of Object.values(row)) collectSessionAgentPresets(child, target, depth + 1);
  };

  // ── 会话有效模型状态（网关侧授权依据）─────────────────────────────
  // DSH 的 create/fork/prompt 请求体里没有模型字段（模型由 Host 从会话投影或
  // agentDefaultModel 解析），所以网关必须自己维护「这个会话接下来会用哪个
  // provider/model」才能在权限收紧后拦住旧会话。状态只来自官方来源：
  //   1. session/selectModel 成功响应的 result.value.selected（官方规范化结果）
  //   2. session/follow 的 snapshot.projections.values.modelSelection（next）
  //   3. session/follow 事件流里的 model/selection 事件（按 seq 取最新一条）
  // session/page 与 session/history 只是分页窗口，不能作为当前模型的权威来源：
  // 旧窗口可能包含过时选择，响应里的嵌套 ID 也可能来自 fork/插件数据。
  // `default` 表示已通过 follow snapshot 或 create/fork 明确观测到「无选择」。
  type SessionModelState = { kind: 'selection'; provider: string; model: string } | { kind: 'default' };
  const sessionModelById = new Map<string, SessionModelState>();
  const SESSION_MODEL_STATE_MAX = 20_000;
  const recordSessionModelSelection = (sessionId: string, selection: AllowedModelSpec | null): void => {
    if (sessionId.length === 0 || sessionId.length > 200) return;
    if (selection === null) {
      // 明确观测到「无选择」时才写 default；无法判读时保留旧状态（不能把
      // 旧会话的已知选择降级成更宽松的 default）。
      sessionModelById.set(sessionId, { kind: 'default' });
    } else {
      sessionModelById.set(sessionId, { kind: 'selection', provider: selection.provider, model: selection.model });
    }
    if (sessionModelById.size > SESSION_MODEL_STATE_MAX) {
      const oldest = sessionModelById.keys().next().value;
      if (typeof oldest === 'string') sessionModelById.delete(oldest);
    }
  };
  /**
   * 从 session/follow 帧读取官方模型状态：
   *   · snapshot：projections.values.modelSelection.next（null = 无选择 → Host 默认）
   *   · 后续帧：model/selection 事件（event.data 就是完整 ModelSelection）
   * 只在能明确读到时才写入；形状不符（旧版/异常）不篡改已有状态。
   */
  const recordSessionFollowModelSelection = (sessionId: string, value: unknown): void => {
    if (!isPlainJsonRecord(value)) return;
    if (value.type === 'snapshot') {
      const projections = value.projections;
      if (!isPlainJsonRecord(projections)) return;
      const values = projections.values;
      if (!isPlainJsonRecord(values) || !Object.hasOwn(values, 'modelSelection')) return;
      const projection = values.modelSelection;
      if (!isPlainJsonRecord(projection) || !Object.hasOwn(projection, 'next')) return;
      // next 为空（null）= 该会话没有模型选择，Host 用共享默认。
      recordSessionModelSelection(sessionId, modelSelectionFrom(projection.next));
      return;
    }
    const latest = latestModelSelectionInRecords(value);
    if (latest !== null) recordSessionModelSelection(sessionId, latest.spec);
  };
  // Host 共享默认模型：只在网关保存权限前用得上（受限用户的 prompt 校验），
  // 因此只记录真实观测到的 modelCatalog.default，不做任何推测。
  let hostDefaultModel: AllowedModelSpec | null = null;
  let hostDefaultModelKnown = false;
  // 最近一次官方 modelCatalog 原样快照，仅供主用户权限页展示可选模型。
  // 子用户收到的目录仍在代理响应处按 allowed_models 过滤；此快照不参与子用户授权。
  let hostModelCatalog: Record<string, unknown> | null = null;
  const recordHostDefaultModel = (catalog: unknown): void => {
    if (catalog === null || typeof catalog !== 'object' || Array.isArray(catalog)) return;
    hostModelCatalog = { ...(catalog as Record<string, unknown>) };
    hostDefaultModel = modelSelectionFrom((catalog as Record<string, unknown>).default);
    hostDefaultModelKnown = true;
  };
  /**
   * 解析会话的有效模型：已记录的显式选择 → 观测到无选择时的 Host 默认模型 →
   * null（未知）。返回 null 时调用方必须 fail-closed，不能把未知当作「不限制」。
   */
  const effectiveSessionModel = (sessionId: string): AllowedModelSpec | null => {
    const state = sessionModelById.get(sessionId);
    if (state === undefined) return null;
    if (state.kind === 'selection') return { provider: state.provider, model: state.model };
    return hostDefaultModelKnown ? hostDefaultModel : null;
  };
  /**
   * 受限子用户的模型白名单判定（所有模型入口共用的唯一判定）。
   * 返回 'allow' | 'deny'；unknown（会话模型不可解析 / Host 默认未知）按 deny。
   */
  const modelChoiceVerdict = (
    allowed: readonly string[] | null,
    selection: AllowedModelSpec | null,
  ): { ok: boolean; reason: 'unrestricted' | 'allowed' | 'denied' | 'unknown' | 'empty' } => {
    if (allowed === null) return { ok: true, reason: 'unrestricted' };
    const set = allowedModelSet(allowed);
    if (set === null || set.size === 0) return { ok: false, reason: 'empty' };
    if (selection === null) return { ok: false, reason: 'unknown' };
    return set.has(`${selection.provider}/${selection.model}`)
      ? { ok: true, reason: 'allowed' }
      : { ok: false, reason: 'denied' };
  };

  // user_workspaces records subuser-created private workspaces and historical
  // administrator workspaces. Administrators are trusted sharers. An ownership
  // row whose user no longer exists is an orphan from a deleted account: no
  // live tenant remains to protect, and treating it as a conflict would hide
  // the folder from baseline and 403 every registration for it.
  const workspaceOwnersSnapshot = (): ReturnType<Database['listWorkspaceOwners']> => db.listWorkspaceOwners();

  const workspaceOwnedByAnotherSubuser = (userId: number, workspacePath: string): boolean => {
    const owners = workspaceOwnersSnapshot();
    if (owners.length === 0) return false;
    // 等值语义保持不变（不是「父工作区包含他人工作区」），但比较改走 canonical 口径：
    // 归一化 + realpath（解析符号链接 / junction）+ Windows 大小写折叠，避免同一目录
    // 用别名/大小写形态出现时被当成「另一路径」而绕过所有权判定。
    return owners.some((owner) =>
      owner.userId !== userId &&
      db.getUserById(owner.userId)?.role === 'user' &&
      samePathForMatch(owner.path, workspacePath),
    );
  };
  // 「该子用户私有归属的工作区」判定：只有精确相等的注册目录算归属。
  // 不能用子树包含（pathWithin）代替等值：workspaceOwnedByUser 是会话可见性对
  // 显式 grant 的替代依据（session.list / workspace.list 槽位 / Remote baseline /
  // session/follow 与 workspaceFiles 作用域），而 workspaceOwnedByAnotherSubuser
  // 仍是等值语义（见上）。若此处按子树放宽，则「分配目录恰好嵌在该子用户自建目录
  // 之内」时，其中由主用户或另一子用户创建、从未逐条授权的既有会话会被自动判定为
  // 可见（工作区权限 ≠ 会话授权）。子用户自己创建的每一层工作区在登记时都会写入
  // 自己的 user_workspaces 行，因此等值语义不会阻碍合法流程。
  const workspaceOwnedByUser = (userId: number, workspacePath: string): boolean => {
    const normalizedPath = normalizePath(workspacePath);
    return db.listUserWorkspacePaths(userId).some((ownedPath) => normalizePath(ownedPath) === normalizedPath);
  };
  /** 尽力规范化：优先文件系统真实路径（解析符号链接），失败退回字符串归一。 */
  const canonicalizePathBestEffort = (candidate: string): string => {
    try {
      return normalizePath(realpathSync(candidate));
    } catch {
      return normalizePath(candidate);
    }
  };
  /** candidate 是否落在另一子用户（存在且非主用户）创建的工作区子树内（含相等）。
 *  单向判定：共享的分配根下创建兄弟目录不受影响，只有伸进他人子树才拦；
 *  物主已被删除的孤儿行不构成冲突（无存活租户可保护）。 */
  const workspaceSubtreeOverlap = (userId: number, workspacePath: string): boolean => {
    return workspaceOwnersSnapshot().some((owner) =>
      owner.userId !== userId &&
      db.getUserById(owner.userId)?.role === 'user' &&
      pathWithinDeletedTree(workspacePath, owner.path),
    );
  };

  /** 一条会话授权快照条目当前是否仍然完全合法（grant + 未逐会话关闭 + 目录白名单 +
   *  非其它子用户创建的工作区）。baseline 合并与快照回写共用这一套口径。 */
  const sessionAccessStillAuthorized = (
    userId: number,
    perms: UserPermissionsRow,
    grants: ReadonlySet<string>,
    sessionId: string,
    workspacePath: string,
  ): boolean =>
    (grants.has(sessionId) || workspaceOwnedByUser(userId, workspacePath)) &&
    !perms.disabled_sessions.includes(sessionId) &&
    folderAllowed(workspacePath, perms.allowed_folders) &&
    !workspaceOwnedByAnotherSubuser(userId, workspacePath);

  /**
   * 合并「上一份可信快照里仍然合法的条目」与「本次 baseline 新观测到的可见条目」。
   * baseline 只是一次可见性投影：一次不完整/乱序的列表响应不得把仍在授权内的会话
   * 从 HTTP/Remote 授权快照里抹掉，但 grant/禁用/白名单/所有权任一不满足的条目
   * 仍会被丢弃（不构成放宽）。
   */
  const mergeAuthorizedAccess = (
    userId: number,
    perms: UserPermissionsRow,
    grants: ReadonlySet<string>,
    visible: ReadonlyMap<string, string>,
  ): Map<string, string> => {
    const merged = new Map<string, string>();
    for (const [sessionId, workspacePath] of userSessionAccess.get(userId) ?? new Map<string, string>()) {
      if (sessionAccessStillAuthorized(userId, perms, grants, sessionId, workspacePath)) merged.set(sessionId, workspacePath);
    }
    for (const [sessionId, workspacePath] of visible) {
      if (sessionAccessStillAuthorized(userId, perms, grants, sessionId, workspacePath)) merged.set(sessionId, workspacePath);
    }
    return merged;
  };

  /** 同上口径的 workspaceId → path 投影合并：旧映射只在路径仍在白名单内且非其它
   *  子用户的工作区时保留，避免一次不完整 baseline 把仍合法的映射抹掉。 */
  const mergeWorkspacePaths = (
    userId: number,
    perms: UserPermissionsRow,
    visible: ReadonlyMap<string, string>,
  ): Map<string, string> => {
    const merged = new Map<string, string>();
    for (const [workspaceId, workspacePath] of userWorkspacePaths.get(userId) ?? new Map<string, string>()) {
      if (folderAllowed(workspacePath, perms.allowed_folders) && !workspaceOwnedByAnotherSubuser(userId, workspacePath)) {
        merged.set(workspaceId, workspacePath);
      }
    }
    for (const [workspaceId, workspacePath] of visible) merged.set(workspaceId, workspacePath);
    return merged;
  };

  /** 子用户 host SSE 事件按 workspace.list 建立的快照过滤；快照缺失时敏感事件一律丢弃。 */
  const hostEventFilter = (userId: number, perms: UserPermissionsRow): Transform => {
    // 单帧解析缓冲有界（见 SseFrameBuffer），上限与 WS 承载的单条消息上限同口径：
    // 上游不发空行时不能无界增长，同时不影响正常大小的事件帧。
    const frames = new SseFrameBuffer(REMOTE_MUX_MAX_PAYLOAD_BYTES);
    // 按流维护解码状态：多字节 UTF-8 字符跨 Buffer 边界时先留在解码器里，避免被
    // 逐 chunk 解码成 U+FFFD 替换字符而破坏过滤输出。
    const decoder = new StringDecoder('utf8');
    const workspacePathAllowed = (candidate: string): boolean => {
      const currentPerms = db.getPermissions(userId) ?? perms;
      if (!folderAllowed(candidate, currentPerms.allowed_folders)) return false;

      return !workspaceOwnedByAnotherSubuser(userId, candidate);
    };

    // 连接级工作区快照副本：同一用户并行多个 SSE 连接时，单个连接收到
    // workspace-removed 不得影响其他连接的可见性判断。
    const workspaceIdsForEvent = (): Set<string> | undefined => {
      const snapshot = userWorkspaceIds.get(userId);
      return snapshot === undefined ? undefined : new Set(snapshot);
    };

    const sensitiveTypes = new Set([
      'host/session-added',
      'host/session-removed',
      'host/session-status',
      'host/agent-error',
      'host/workspace-changed',
      'host/workspace-removed',
      'host/workspace-order-changed',
      'host/archived-sessions-changed',
      'host/remote-event',
    ]);
    const filterFrame = (frame: string): string => {
      // 按 SSE 行语义归一化：CRLF、LF、裸 CR 都是行终止符，遗漏裸 CR 会把
      // 「注释\rdata: 敏感事件」当成一行而跳过 data: 解析，导致敏感事件被整帧放行。
      const normalized = frame.replace(/\r\n|\r|\n/g, '\n');
      const dataLines = normalized.split('\n').filter((line) => line.startsWith('data:'));
      if (dataLines.length === 0) return frame;
      let envelope: Record<string, unknown>;
      try {
        envelope = JSON.parse(dataLines.map((line) => line.slice(5).trimStart()).join('\n')) as Record<string, unknown>;
      } catch {
        return '';
      }
      const payload = envelope.payload;
      if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return '';
      const event = payload as Record<string, unknown>;
      const type = event.type;
      if (typeof type !== 'string' || !sensitiveTypes.has(type)) return '';
      const currentPerms = db.getPermissions(userId) ?? perms;
      const access = userSessionAccess.get(userId);
      const workspaceIds = workspaceIdsForEvent();
      if (access === undefined || workspaceIds === undefined) return '';
      const allowedSession = (id: unknown): id is string =>
        typeof id === 'string' && access.has(id) && !currentPerms.disabled_sessions.includes(id);
      const sessionIdOf = (event: Record<string, unknown>): string | null =>
        typeof event.sessionId === 'string' ? event.sessionId : null;
      if (type === 'host/session-added') {
        if (!allowedSession(event.sessionId)) return '';
        if (typeof event.sessionId === 'string' && typeof event.agentPreset === 'string') {
          sessionAgentPresetMapFor(userId).set(event.sessionId, event.agentPreset);
        }
        delete event.cwd;
        delete event.parentSessionId;
      } else if (
        type === 'host/session-removed' ||
        type === 'host/session-status' ||
        type === 'host/agent-error'
      ) {
        const sessionId = sessionIdOf(event);
        if (sessionId === null || !allowedSession(sessionId)) return '';
      } else if (type === 'host/workspace-changed') {
        const workspace = event.workspace;
        if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return '';
        const row = workspace as Record<string, unknown>;
        const workspaceId = row.workspaceId;
        const workspacePath = row.path;
        if (
          typeof workspaceId !== 'string' ||
          !workspaceIds.has(workspaceId) ||
          typeof workspacePath !== 'string' ||
          !workspacePathAllowed(workspacePath)
        ) {
          return '';
        }
        if (Array.isArray(row.sessionIds)) row.sessionIds = row.sessionIds.filter(allowedSession);
      } else if (type === 'host/workspace-removed') {
        const id = typeof event.workspaceId === 'string' ? event.workspaceId : event.id;
        if (typeof id !== 'string' || !workspaceIds.has(id)) return '';
      } else if (type === 'host/workspace-order-changed') {
        const ids = event.workspaceIds;
        if (!Array.isArray(ids)) return '';
        event.workspaceIds = ids.filter((id): id is string => typeof id === 'string' && workspaceIds.has(id));
      } else if (type === 'host/archived-sessions-changed') {
        const ids = event.archivedSessionIds;
        if (!Array.isArray(ids)) return '';
        event.archivedSessionIds = ids.filter(allowedSession);
      } else if (type === 'host/remote-event') {
        return '';
      }
      return `data: ${JSON.stringify(envelope)}\n\n`;
    };
    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        for (const frame of frames.push(decoder.write(chunk))) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }
        callback();
      },
      flush(callback) {
        for (const frame of frames.push(decoder.end())) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }
        for (const frame of frames.flush()) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }
        callback();
      },
    });
  };

  /** rc.2 WebSocket 下行事件过滤：协议帧是 server-request，客户端不能上行 RPC。 */
  const filterEventWebSocketFrame = (userId: number, perms: UserPermissionsRow, channel: 'host' | 'mux', data: Buffer): Buffer | null => {
    let envelope: Record<string, unknown>;
    try {
      const parsed = JSON.parse(data.toString('utf8')) as unknown;
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
      envelope = parsed as Record<string, unknown>;
    } catch {
      return null;
    }
    if (envelope.type !== 'server-request' || typeof envelope.rpcId !== 'string') return null;
    const payload = envelope.payload;
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null;
    const event = payload as Record<string, unknown>;
    if (envelope.method !== event.type || typeof event.type !== 'string') return null;
    const current = db.getPermissions(userId) ?? perms;
    const access = userSessionAccess.get(userId);
    const workspaceIds = userWorkspaceIds.get(userId);
    const allowedSession = (id: unknown): id is string =>
      typeof id === 'string' && access !== undefined && access.has(id) && !current.disabled_sessions.includes(id);
    if (channel === 'host') {
      if (workspaceIds === undefined || access === undefined) return null;
      const type = event.type;
      if (type === 'host/session-added') {
        if (!allowedSession(event.sessionId)) return null;
        delete event.cwd;
        delete event.parentSessionId;
      } else if (type === 'host/session-removed' || type === 'host/session-status' || type === 'host/agent-error') {
        if (!allowedSession(event.sessionId)) return null;
      } else if (type === 'host/workspace-changed') {
        const workspace = event.workspace;
        if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return null;
        const row = workspace as Record<string, unknown>;
        if (typeof row.workspaceId !== 'string' || !workspaceIds.has(row.workspaceId) || typeof row.path !== 'string') return null;
        const workspacePath = row.path;
        if (!folderAllowed(workspacePath, current.allowed_folders)) return null;
        if (workspaceOwnedByAnotherSubuser(userId, workspacePath)) return null;
        if (Array.isArray(row.sessionIds)) row.sessionIds = row.sessionIds.filter(allowedSession);
      } else if (type === 'host/workspace-removed') {
        const id = typeof event.workspaceId === 'string' ? event.workspaceId : event.id;
        if (typeof id !== 'string' || !workspaceIds.has(id)) return null;
      } else if (type === 'host/workspace-order-changed') {
        if (!Array.isArray(event.workspaceIds)) return null;
        event.workspaceIds = event.workspaceIds.filter((id): id is string => typeof id === 'string' && workspaceIds.has(id));
      } else if (type === 'host/archived-sessions-changed') {
        if (!Array.isArray(event.archivedSessionIds)) return null;
        event.archivedSessionIds = event.archivedSessionIds.filter(allowedSession);
      } else {
        return null;
      }
    } else {
      const allowedTypes = new Set(['session/event', 'session/subscribed', 'approval/requested', 'approval/resolved', 'question/requested', 'question/resolved', 'session/queue', 'session/jobs', 'session/projection']);
      if (!allowedTypes.has(event.type) || !allowedSession(event.sessionId)) return null;
    }
    return Buffer.from(JSON.stringify(envelope), 'utf8');
  };

  // Keep the carrier limit aligned with ws's default and the official DSH RC.1
  // gateway. History snapshots are one Remote item and can legitimately exceed
  // 1 MiB after compaction; request queue limits remain independent below.
  const REMOTE_MUX_MAX_PAYLOAD_BYTES = 100 * 1024 * 1024;
  const REMOTE_MUX_MAX_STREAMS = 64;
  const REMOTE_MUX_MAX_PENDING_BYTES = 2 * 1024 * 1024;
  // Remote mux 心跳/写停滞期限来自已验证配置（loadConfig 解析 MCP_GATEWAY_MUX_*）；
  // 直接以字面量构造 PlatformConfig 的调用方（测试）缺省时按同一解析器回退默认。
  const remoteMuxConfig = config.mux ?? resolveRemoteMuxConfig();

  const upstreamWsOptions = (): {
    headers: Record<string, string>;
    rejectUnauthorized?: boolean;
    agent?: any;
    maxPayload: number;
    perMessageDeflate: false;
  } => ({
    headers: {
      host: upstreamAuthority,
      origin: `${upstreamScheme}://${upstreamAuthority}`,
      ...(upstreamAuthCookie === '' ? {} : { cookie: upstreamAuthCookie }),
    },
    ...(upstreamIsHttps ? {
      rejectUnauthorized: process.env.MCP_GATEWAY_UPSTREAM_TLS_VERIFY !== '0',
      agent: upstreamAgent,
    } : {}),
    maxPayload: REMOTE_MUX_MAX_PAYLOAD_BYTES,
    perMessageDeflate: false,
  });

  /**
   * RC.1 Remote mux bridge. Administrators may use registered Remote endpoints;
   * subusers additionally pass the per-stream resource filters below.
   * The carrier is intentionally terminated here so authentication and ownership
   * checks remain enforceable, while heartbeat and payload limits mirror DSH.
   */
  const remoteMuxStreamEndpoints = new Set([
    'session/control', 'session/follow', 'workspace/follow', '$events',
    ...OFFICIAL_JOB_REMOTE_ENDPOINTS,
    ...OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS,
  ]);
  /**
   * 子用户 mux 上会被解析、但按逻辑流拒绝的端点（端点 → 拒绝码/文案）。
   * 官方 terminal/follow 与 terminal/retain 由 allowSsh 在下方按连接判断；
   * workspaceFiles/changes 是受会话/路径授权的特殊流，不放进拒绝表。
   * 这里把拒绝从「未知端点 → 关整条 carrier」降级为「该逻辑流 error」，避免一条
   * 被拒流把同 carrier 的 workspace/session/$events 一起重启。
   */
  const remoteMuxSubuserRejectedEndpoints = new Map<string, { code: string; message: string }>([
    ...[...OFFICIAL_TERMINAL_REMOTE_ENDPOINTS].map((endpoint) => [
      endpoint,
      { code: 'terminal/unavailable', message: TERMINAL_UNAVAILABLE_MESSAGE },
    ] as const),

  ]);
  const isRemoteMuxStreamId = (value: unknown): value is string =>
    typeof value === 'string' && value.length > 0 && value.length <= 200 && /^[A-Za-z0-9_-]+$/.test(value);
  /**
   * 逻辑端点名的安全形状（与 DSH 的 segment 字符约束同口径）。
   * 子用户上报的合法形状端点按普通扩展面处理：官方/登记流走各自授权与资源过滤，
   * 其余未知普通端点按通用姿态透明转发（硬拒只由 SUBUSER_BLOCKED namespace 完成）；
   * 真正畸形的帧（空段、点段、非法字符或超长）才按 carrier-level 拒绝。
   */
  const isRemoteMuxEndpointName = (value: unknown): value is string => {
    if (typeof value !== 'string' || value.length === 0 || value.length > 200) return false;
    const segments = value.split('/');
    return segments.every(
      (segment) => segment !== '' && segment !== '.' && segment !== '..' && /^[A-Za-z0-9_$.-]+$/.test(segment),
    );
  };
  const parseRemoteMuxClientFrame = (data: Buffer, allowAnyEndpoint: boolean):
    | { type: 'open'; streamId: string; endpoint: string; payload: unknown }
    | { type: 'cancel'; streamId: string }
    | { type: 'item'; streamId: string; value?: unknown }
    | { type: 'end'; streamId: string }
    | null => {
    let value: unknown;
    try { value = JSON.parse(data.toString('utf8')); } catch { return null; }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const row = value as Record<string, unknown>;
    const keyCount = Object.keys(row).length;
    if (row.type === 'cancel' && keyCount === 2 && isRemoteMuxStreamId(row.streamId)) {
      return { type: 'cancel', streamId: row.streamId };
    }
    // alpha.1 Remote 上行帧（与官方 parseRemoteStreamClientMessage 同口径）：
    // item 是 { type, streamId[, value] }，end 是 { type, streamId }；额外的键、
    // 缺失的 value 位（3 键却不是 value）都算畸形 → 返回 null → carrier 1008。
    if (row.type === 'item' && (keyCount === 2 || keyCount === 3) && isRemoteMuxStreamId(row.streamId)) {
      if (keyCount === 3 && !Object.hasOwn(row, 'value')) return null;
      return { type: 'item', streamId: row.streamId, ...(Object.hasOwn(row, 'value') ? { value: row.value } : {}) };
    }
    if (row.type === 'end' && keyCount === 2 && isRemoteMuxStreamId(row.streamId)) {
      return { type: 'end', streamId: row.streamId };
    }
    if (
      row.type === 'open' && keyCount === 4 && isRemoteMuxStreamId(row.streamId) &&
      (allowAnyEndpoint
        ? typeof row.endpoint === 'string' && row.endpoint.length > 0
        : isRemoteMuxEndpointName(row.endpoint)) &&
      row.payload !== undefined
    ) {
      return { type: 'open', streamId: row.streamId, endpoint: row.endpoint as string, payload: row.payload };
    }
    return null;
  };
  type RemoteMuxServerFrame =
    | { type: 'item'; streamId: string; value?: unknown }
    | { type: 'end'; streamId: string }
    | { type: 'error'; streamId: string; error: Record<string, unknown> };
  const parseRemoteMuxServerFrame = (data: Buffer): RemoteMuxServerFrame | null => {
    let value: unknown;
    try { value = JSON.parse(data.toString('utf8')); } catch { return null; }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const row = value as Record<string, unknown>;
    if (row.type === 'end' && Object.keys(row).length === 2 && isRemoteMuxStreamId(row.streamId)) {
      return { type: 'end', streamId: row.streamId };
    }
    if (row.type === 'item' && isRemoteMuxStreamId(row.streamId) &&
      (Object.keys(row).length === 2 || Object.keys(row).length === 3)) {
      return { type: 'item', streamId: row.streamId, ...(Object.hasOwn(row, 'value') ? { value: row.value } : {}) };
    }
    if (row.type === 'error' && Object.keys(row).length === 3 && isRemoteMuxStreamId(row.streamId) &&
      row.error !== null && typeof row.error === 'object' && !Array.isArray(row.error)) {
      const error = row.error as Record<string, unknown>;
      if (Object.keys(error).length === 3 && typeof error.code === 'string' && typeof error.message === 'string' &&
        error.details !== null && typeof error.details === 'object' && !Array.isArray(error.details)) {
        return { type: 'error', streamId: row.streamId, error };
      }
    }
    return null;
  };

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
     * 发送器与心跳、把诊断首因锁定为 permission-revoked 并 arm 5s grace；物理 socket 关闭仍由
     * gateway 保留。只接受受限的关闭码，不向调用方暴露内部状态；重复调用幂等。
     */
    teardownCarrier: (code?: number) => void;
  };
  type RemoteEventOwnership = {
    userId: number;
    clientId: string;
    sessionId: string;
    expiresAt: number;
  };
  // DSH routes a waterfall answer through a separate HTTP request. Retain the
  // exact browser generation and session that received it so a subuser cannot
  // submit another user's eventId through /api/$events/result.
  const remoteEventOwnership = new Map<string, RemoteEventOwnership>();
  const REMOTE_EVENT_MAX_AGE_MS = 12 * 60 * 60 * 1000;
  const REMOTE_EVENT_MAX_PENDING = 10_000;
  // DSH may deliver one pending waterfall to multiple explicitly authorized
  // Remote clients for a shared session. The Host independently correlates
  // replies by both ids, so the gateway must retain that same compound key.
  const remoteEventOwnershipKey = (eventId: string, clientId: string): string => JSON.stringify([eventId, clientId]);

  const isPlainJsonRecord = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
  const remoteMuxEmptyArgs = (payload: unknown): boolean => {
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return false;
    const row = payload as Record<string, unknown>;
    const args = row.args;
    return Object.keys(row).length === 1 && args !== null && typeof args === 'object' && !Array.isArray(args) &&
      Object.keys(args as Record<string, unknown>).length === 0;
  };
  // alpha.3 opens session/follow as { args: { request: { address }, maxMessages? } }.
  // It is a single ordinary-session history stream, not an empty control/workspace
  // subscription; accept only its exact address shape before checking its persisted grant.
  const remoteMuxFollowAddress = (payload: unknown): ReturnType<typeof parseSessionAddress> => {
    if (!isPlainJsonRecord(payload) || !isPlainJsonRecord(payload.args)) return null;
    const request = payload.args.request;
    if (!isPlainJsonRecord(request)) return null;
    const address = parseSessionAddress(request.address);
    if (address === null) return null;
    const maxMessages = request.maxMessages;
    if (maxMessages !== undefined && (typeof maxMessages !== 'number' || !Number.isSafeInteger(maxMessages) || maxMessages < 1)) return null;
    return address;
  };
  const sessionAuthorizationId = (address: NonNullable<ReturnType<typeof parseSessionAddress>>): string =>
    address.kind === 'session' ? address.sessionId : address.parentSessionId;
  const sessionFollowTargetId = (address: NonNullable<ReturnType<typeof parseSessionAddress>>): string =>
    address.kind === 'session' ? address.sessionId : address.childSessionId;
  const sessionFollowIdentityAllowed = (
    userId: number,
    address: NonNullable<ReturnType<typeof parseSessionAddress>>,
    perms: UserPermissionsRow = effectivePermissions(userId),
  ): boolean => authorizedSubuserSessionRoot(userId, sessionAuthorizationId(address), perms) !== null;
  /**
   * 子用户「该会话现在可否被访问」的唯一判定（HTTP 与 Remote 两条通道同口径）：
   *   · 必须命中该用户的会话授权快照（baseline 已给出可信 cwd）；
   *   · 必须持有持久化 grant（快照可能比 DB 新）；
   *   · 未被管理员逐会话关闭（disabled_sessions）；
   *   · cwd 在文件夹白名单内，且不是另一子用户创建的工作区。
   * 任何一项不可解析/不命中都返回 null，调用方必须 fail-closed（403 或丢弃帧），
   * 不得把「拿不到会话」当作不限制。
   */
  function authorizedSubuserSessionRoot(userId: number, sessionId: unknown, perms: UserPermissionsRow): string | null {
    if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 200) return null;
    const sessionPath = userSessionAccess.get(userId)?.get(sessionId);
    if (sessionPath === undefined) return null;
    if (!db.hasUserSessionGrant(userId, sessionId) && !workspaceOwnedByUser(userId, sessionPath)) return null;
    if (perms.disabled_sessions.includes(sessionId)) return null;
    // 白名单与所有权都按「词法 or 真实路径」复核：快照里的 cwd 与 persisted 记录都
    // 可能以别名/大小写/junction 形态出现，只看一种口径要么误拒合法会话（realpath
    // 失败时 canonicalizePathBestEffort 回退为字符串归一，不会比词法更松懈），
    // 要么让别名形态的他人工作区逃过所有权判定（后者由 canonical 化的
    // workspaceOwnedByAnotherSubuser 兜住）。
    const canonicalSessionPath = canonicalizePathBestEffort(sessionPath);
    if (!folderAllowed(sessionPath, perms.allowed_folders) &&
        !folderAllowed(canonicalSessionPath, perms.allowed_folders)) return null;
    if (workspaceOwnedByAnotherSubuser(userId, sessionPath)) return null;
    return sessionPath;
  }
  /**
   * 把一个只剩绝对路径的官方接口参数（/api/file 的 ?path=）绑回租户工作区：
   * 必须落在某个「仍然授权的会话工作区根」内，且在文件夹白名单内、不伸进其他
   * 子用户创建的工作区子树。只在命中包含关系时才查 grant，避免逐请求全表扫描。
   * 归属判定用单向子树（不是等值）：被分配了父目录 A 的子用户不能借白名单
   * 停留在 /A，再读取 /A/B-child/sub 里物主 B 的内容——等值只在目标恰好等于
   * B 的工作区根时命中，深一层就会漏放。
   */
  const pathBoundToAuthorizedWorkspace = (userId: number, perms: UserPermissionsRow, candidate: string): boolean => {
    const access = userSessionAccess.get(userId);
    if (access === undefined) return false;
    if (!folderAllowed(candidate, perms.allowed_folders) &&
        !folderAllowed(canonicalizePathBestEffort(candidate), perms.allowed_folders)) return false;
    if (workspaceSubtreeOverlap(userId, candidate)) return false;
    for (const [sessionId, sessionRoot] of access) {
      // 词法与真实路径两种形态都做包含性比较：候选路径由请求方给出时（官方
      // /api/file?path=），调用方已对两种形态分别判定；这里同样不因别名/大小写/
      // junction 形态差异而整段误拒一个确实在授权内的路径。
      if (!pathWithin(candidate, sessionRoot) && !pathWithin(candidate, canonicalizePathBestEffort(sessionRoot))) continue;
      if (authorizedSubuserSessionRoot(userId, sessionId, perms) !== null) return true;
    }
    return false;
  };
  const remoteJobRequest = (payload: unknown, endpoint: 'job/list' | 'job/follow'): { sessionId?: string; jobId?: string; from?: number } | null => {
    if (!isPlainJsonRecord(payload) || !isPlainJsonRecord(payload.args)) return null;
    const args = payload.args;
    if (!isPlainJsonRecord(args.request) || Object.keys(args).length !== 1) return null;
    const request = args.request;
    const sessionId = request.sessionId;
    const jobId = request.jobId;
    const from = request.from;
    if (sessionId !== undefined && (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 200)) return null;
    if (endpoint === 'job/list') {
      return typeof sessionId === 'string' && Object.keys(request).length === 1 ? { sessionId } : null;
    }
    if (typeof jobId !== 'string' || jobId.length === 0 || jobId.length > 200) return null;
    if (from !== undefined && (typeof from !== 'number' || !Number.isSafeInteger(from) || from < 0)) return null;
    return { ...(sessionId === undefined ? {} : { sessionId }), jobId, ...(from === undefined ? {} : { from }) };
  };
  const remoteAccountRequestIsEmpty = (payload: unknown): boolean =>
    isPlainJsonRecord(payload) && isPlainJsonRecord(payload.args) && Object.keys(payload.args).length === 0;

  const remoteWorkspaceFileChangeRequest = (payload: unknown): { scopeId: string; path: string } | null => {
    if (!isPlainJsonRecord(payload) || !isPlainJsonRecord(payload.args)) return null;
    const args = payload.args;
    if (Object.keys(args).length !== 2 || typeof args.workspaceFileScopeId !== 'string' || typeof args.path !== 'string') return null;
    if (args.workspaceFileScopeId.length === 0 || args.workspaceFileScopeId.length > 200 ||
      args.path.length === 0 || args.path.length > 4096 || args.path.includes('\0')) return null;
    return { scopeId: args.workspaceFileScopeId, path: args.path };
  };
  const authorizedWorkspaceFileChangeTarget = (
    userId: number,
    perms: UserPermissionsRow,
    request: { scopeId: string; path: string },
  ): { scopeId: string; root: string; target: string; rootCanonical: string; targetCanonical: string } | null => {
    const root = authorizedSubuserSessionRoot(userId, request.scopeId, perms);
    if (root === null) return null;
    const target = resolveWorkspaceFileTarget(root, request.path, null);
    if (target === null) return null;
    const rootCanonical = canonicalizePathBestEffort(root);
    const targetCanonical = canonicalizePathBestEffort(target);
    // 与 HTTP workspaceFiles 检查（proxy.ts 的 needsWorkspaceFilesCheck）同口径：通过
    // 会话根/白名单/归属后仍须拒绝敏感路径。管理员可能把敏感目录的祖先误登记为工作区，
    // 此时目标会同时命中白名单与归属，只有敏感基能挡住文件变化流。
    if (!pathWithin(target, root) || !pathWithin(targetCanonical, rootCanonical) ||
      !folderAllowed(target, perms.allowed_folders) || !folderAllowed(targetCanonical, perms.allowed_folders) ||
      workspaceSubtreeOverlap(userId, target) || isSensitivePath(target) || isSensitivePath(targetCanonical)) return null;
    return { scopeId: request.scopeId, root, target, rootCanonical, targetCanonical };
  };
  const sessionFollowSnapshotMatches = (address: NonNullable<ReturnType<typeof parseSessionAddress>>, value: unknown): boolean => {
    if (!isPlainJsonRecord(value) || value.type !== 'snapshot' || !isPlainJsonRecord(value.header)) return false;
    const header = value.header;
    const targetId = sessionFollowTargetId(address);
    if (header.id !== targetId) return false;
    if (address.kind === 'subagent') {
      return header.origin === 'subagent' && header.parentSession === address.parentSessionId;
    }
    return header.origin !== 'subagent';
  };
  const remoteMuxEventSessionId = (event: string, args: unknown[]): string | null => {
    if (event === 'api-session/added') {
      const summary = args[0];
      if (!isPlainJsonRecord(summary)) return null;
      return typeof summary.sessionId === 'string'
        ? summary.sessionId
        : typeof summary.id === 'string'
          ? summary.id
          : null;
    }
    if (
      event === 'api-session/activity' ||
      event === 'api-session/error' ||
      event === 'api-session/removed' ||
      event === 'api-session/status'
    ) return typeof args[0] === 'string' ? args[0] : null;
    return null;
  };

  /**
   * Filter alpha workspace/session Remote stream items for one subuser.
   * A missing/invalid resource identity is dropped rather than guessed. The
   * caller keeps the physical stream alive, but never forwards the unfiltered
   * value. Workspace IDs are retained per logical stream so later remove/order
   * frames cannot reintroduce an unseen workspace.
   */
  const filterRemoteMuxUserItem = (
    userId: number,
    fallbackPerms: UserPermissionsRow,
    state: RemoteMuxUserStreamState,
    value: unknown,
  ): unknown | null => {
    const perms = db.getPermissions(userId) ?? fallbackPerms;
    if (state.endpoint === 'job/list' || state.endpoint === 'job/follow') {
      if (!isPlainJsonRecord(value)) return null;
      if (state.endpoint === 'job/list') {
        if (value.type !== 'rows' || !Array.isArray(value.jobs)) return null;
        const sessionId = state.jobSessionId;
        if (sessionId === undefined || authorizedSubuserSessionRoot(userId, sessionId, perms) === null) return null;
        const jobs = value.jobs.filter((job): job is Record<string, unknown> =>
          isPlainJsonRecord(job) && typeof job.id === 'string' && job.owner === sessionId,
        );
        return { type: 'rows', jobs };
      }
      if (value.type !== 'opened' && value.type !== 'output' && value.type !== 'status') return null;
      if (value.type === 'opened' || value.type === 'status') {
        if (!isPlainJsonRecord(value.job) || value.job.id !== state.jobId ||
          state.jobSessionId === undefined || value.job.owner !== state.jobSessionId) return null;
        state.jobOwnerConfirmed = true;
      }
      if (value.type === 'output' && (!state.jobOwnerConfirmed || !Array.isArray(value.chunks))) return null;
      return value;
    }
    if (state.endpoint === 'account/watch') {
      return isPlainJsonRecord(value) ? value : null;
    }
    // `$events` establishes the browser connection, but it is also a broadcast
    // carrier. Never transparently forward its later notifications: a Remote
    // event stream is shared by every DSH session on the Host.
    if (state.endpoint === '$events') {
      if (!isPlainJsonRecord(value)) return null;
      if (value.type === 'ready') {
        if (state.remoteEventsReady || Object.keys(value).length !== 3 || typeof value.clientId !== 'string' ||
          value.clientId.length === 0 || value.clientId.length > 200 ||
          !isPlainJsonRecord(value.host) || Object.keys(value.host).length !== 1 || typeof value.host.home !== 'string') return null;
        state.remoteEventsReady = true;
        state.remoteEventsClientId = value.clientId;
        return value;
      }
      if (!state.remoteEventsReady || state.remoteEventsClientId === undefined) return null;
      const currentGrants = new Set(db.listUserSessionGrants(userId));
      const access = userSessionAccess.get(userId);
      const sessionAllowed = (sessionId: string): boolean => {
        const sessionPath = access?.get(sessionId);
        return sessionPath !== undefined &&
          (currentGrants.has(sessionId) || workspaceOwnedByUser(userId, sessionPath)) &&
          !perms.disabled_sessions.includes(sessionId) &&
          folderAllowed(sessionPath, perms.allowed_folders) &&
          !workspaceOwnedByAnotherSubuser(userId, sessionPath);
      };
      const pendingSessionAllowedForEvent = (sessionId: string, args: unknown[]): boolean => {
        const pending = pendingCreatedSessions.get(userId)?.get(sessionId);
        if (pending === undefined || pending.expiresAt <= Date.now()) return false;
        const summary = args[0];
        if (!isPlainJsonRecord(summary) || typeof summary.cwd !== 'string') return false;
        return normalizePath(summary.cwd) === normalizePath(pending.cwd) &&
          folderAllowed(pending.cwd, perms.allowed_folders) && !workspaceOwnedByAnotherSubuser(userId, pending.cwd);
      };
      if (value.type === 'cancel') {
        if (Object.keys(value).length !== 2 || typeof value.eventId !== 'string' || value.eventId.length === 0 || value.eventId.length > 200) return null;
        const ownership = remoteEventOwnership.get(remoteEventOwnershipKey(value.eventId, state.remoteEventsClientId));
        if (ownership === undefined || ownership.userId !== userId || ownership.clientId !== state.remoteEventsClientId) return null;
        remoteEventOwnership.delete(remoteEventOwnershipKey(value.eventId, state.remoteEventsClientId));
        return value;
      }
      if (value.type === 'waterfall') {
        if (
          Object.keys(value).length !== 5 ||
          (value.event !== 'user-questions/request' && value.event !== 'approval/request') ||
          typeof value.eventId !== 'string' || value.eventId.length === 0 || value.eventId.length > 200 ||
          typeof value.agentId !== 'string' || value.agentId.length === 0 || value.agentId.length > 200 ||
          !isPlainJsonRecord(value.request) || Object.hasOwn(value.request, 'agent') || Object.hasOwn(value.request, 'signal') ||
          !sessionAllowed(value.agentId)
        ) return null;
        const ownershipKey = remoteEventOwnershipKey(value.eventId, state.remoteEventsClientId);
        if (remoteEventOwnership.size >= REMOTE_EVENT_MAX_PENDING && !remoteEventOwnership.has(ownershipKey)) return null;
        remoteEventOwnership.set(ownershipKey, {
          userId,
          clientId: state.remoteEventsClientId,
          sessionId: value.agentId,
          expiresAt: Date.now() + REMOTE_EVENT_MAX_AGE_MS,
        });
        return value;
      }
      if (value.type !== 'emit' || Object.keys(value).length !== 3 ||
        typeof value.event !== 'string' || !Array.isArray(value.args)) return null;
      const sessionId = remoteMuxEventSessionId(value.event, value.args);
      if (sessionId === null || (!sessionAllowed(sessionId) &&
        (value.event !== 'api-session/added' || !pendingSessionAllowedForEvent(sessionId, value.args)))) return null;
      if (value.event !== 'api-session/added') return value;
      const summary = value.args[0] as Record<string, unknown>;
      const { cwd: _cwd, parentSessionId: _parentSessionId, ...safeSummary } = summary;
      return { ...value, args: [safeSummary, ...value.args.slice(1)] };
    }
    // session/follow is opened only after its request address was checked. The
    // alpha.1 snapshot still carries the authoritative target header, so verify
    // it before forwarding any v2 records or assistant-stream state. Later
    // frames stay bound to the same authorized stream; if the grant is revoked,
    // the carrier is closed by the permission-save path and this check drops
    // anything racing behind that close.
    if (state.endpoint === 'session/follow') {
      const address = state.followAddress;
      if (address === null || address === undefined || !sessionFollowIdentityAllowed(userId, address, fallbackPerms)) return null;
      if (!state.followSnapshotSeen) {
        if (!sessionFollowSnapshotMatches(address, value)) return null;
        state.followSnapshotSeen = true;
      }
      // 官方模型状态来源（授权依据，只读不写）：
      //   · snapshot.projections.values.modelSelection.next：DSH 权威的“下一个请求
      //     将使用的选择”，null 表示没有选择（用 Host 共享默认）。
      //   · 后续 event 帧里的 model/selection 事件（含 data: {provider, model}）。
      // 子代理流不对应一个普通会话，不写入（其授权按父会话走）。
      if (address.kind === 'session') {
        const target = sessionFollowTargetId(address);
        recordSessionFollowModelSelection(target, value);
      }
      return value;
    }
    const access = userSessionAccess.get(userId);
    const currentGrants = new Set(db.listUserSessionGrants(userId));
    const pending = pendingCreatedSessions.get(userId);
    const pendingSessionAllowed = (id: unknown, workspacePath?: string): id is string => {
      if (typeof id !== 'string' || workspacePath === undefined) return false;
      const candidate = pending?.get(id);
      return candidate !== undefined && candidate.expiresAt > Date.now() && normalizePath(candidate.cwd) === normalizePath(workspacePath) &&
        folderAllowed(candidate.cwd, perms.allowed_folders) && !workspaceOwnedByAnotherSubuser(userId, candidate.cwd);
    };
    const allowedSession = (id: unknown): id is string => {
      if (typeof id !== 'string' || access === undefined || perms.disabled_sessions.includes(id)) return false;
      const workspacePath = access.get(id);
      return workspacePath !== undefined &&
        (currentGrants.has(id) || workspaceOwnedByUser(userId, workspacePath)) &&
        folderAllowed(workspacePath, perms.allowed_folders) &&
        !workspaceOwnedByAnotherSubuser(userId, workspacePath);
    };
    const workspacePathAllowed = (row: Record<string, unknown>): boolean => {
      const pathValue = row.path;
      if (typeof row.workspaceId !== 'string' || typeof pathValue !== 'string' || !folderAllowed(pathValue, perms.allowed_folders)) return false;
      return !workspaceOwnedByAnotherSubuser(userId, pathValue);
    };
    const workspaceAllowed = (row: Record<string, unknown>): boolean => {
      if (!workspacePathAllowed(row)) return false;
      const id = row.workspaceId as string;
      const pathValue = row.path as string;
      const owners = workspaceOwnersSnapshot();
      // 增量 upsert 允许当前用户新建且尚未出现在本连接 baseline 的工作区；
      // 但未知 workspaceId 必须有当前用户的持久化登记，不能只凭目录白名单放行。
      return state.visibleWorkspaces.has(id) || owners.some(
        (owner) => owner.userId === userId && normalizePath(owner.path) === normalizePath(pathValue),
      );
    };
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
    const frame = value as Record<string, unknown>;
    if (state.endpoint === 'workspaceFiles/changes') {
      if (frame.kind === 'ready' && Object.keys(frame).length === 1 && state.workspaceFileReady !== true) {
        state.workspaceFileReady = true;
        return frame;
      }
      if (frame.kind !== 'change' || Object.keys(frame).length !== 2 || state.workspaceFileReady !== true ||
        !isPlainJsonRecord(frame.change)) return null;
      const change = frame.change;
      const absolutePath = change.absolutePath;
      const validChange = typeof absolutePath === 'string' && absolutePath.length > 0 && absolutePath.length <= 4096 &&
        (Object.keys(change).length === 2 && typeof change.version === 'string' && change.version.length <= 200 ||
          Object.keys(change).length === 2 && change.absent === true);
      if (!validChange || state.workspaceFileScopeId === undefined || state.workspaceFileRoot === undefined ||
        state.workspaceFileTarget === undefined || state.workspaceFileRootCanonical === undefined ||
        state.workspaceFileTargetCanonical === undefined) return null;
      const currentRoot = authorizedSubuserSessionRoot(userId, state.workspaceFileScopeId, perms);
      if (currentRoot === null || normalizePath(currentRoot) !== normalizePath(state.workspaceFileRoot)) return null;
      const changedPath = normalizePath(absolutePath);
      const changedCanonical = canonicalizePathBestEffort(changedPath);
      const withinTarget = pathWithin(changedPath, state.workspaceFileTarget) &&
        pathWithin(changedCanonical, state.workspaceFileTargetCanonical);
      const withinRoot = pathWithin(changedPath, state.workspaceFileRoot) &&
        pathWithin(changedCanonical, state.workspaceFileRootCanonical);
      if (!withinTarget || !withinRoot ||
        (!folderAllowed(changedPath, perms.allowed_folders) && !folderAllowed(changedCanonical, perms.allowed_folders)) ||
        isSensitivePath(changedPath) || isSensitivePath(changedCanonical) ||
        workspaceOwnedByAnotherSubuser(userId, changedPath)) return null;
      return frame;
    }
    if (state.endpoint === 'workspace/follow') {
      if (frame.type === 'baseline') {
        const baseline = frame.value;
        if (baseline === null || typeof baseline !== 'object' || Array.isArray(baseline)) return null;
        const source = baseline as Record<string, unknown>;
        if (!Array.isArray(source.items) || !Array.isArray(source.archivedSessionIds)) return null;
        // 0.1.7-alpha.1 的 WorkspaceBaseline 新增 pinnedSessionIds（与 archivedSessionIds
        // 同级的租户枚举面）；出现就必须是数组并逐会话过滤，缺失（0.1.6 及更早）则
        // 不下发该字段，保持旧客户端口径。字段存在但形状不符一律 fail-closed。
        if (Object.hasOwn(source, 'pinnedSessionIds') && !Array.isArray(source.pinnedSessionIds)) return null;
        const hasPinnedIds = Object.hasOwn(source, 'pinnedSessionIds');
        const grantsSeeded = db.isSessionGrantsSeeded(userId);
        // seed 前的授权集合只用于「seed 完成前的可见性过滤」（迁移口径）；
        // seed 之后会重新复读一份最新的 grant 集合（见下方 authorizedAccess）。
        const baselineGrants = new Set(db.listUserSessionGrants(userId));
        state.visibleWorkspaces.clear();
        state.visibleWorkspaceRows.clear();
        const visibleAccess = new Map<string, string>();
        const items: Record<string, unknown>[] = [];
        for (const item of source.items) {
          if (item === null || typeof item !== 'object' || Array.isArray(item)) continue;
          const workspace = { ...(item as Record<string, unknown>) };
          // 首个 baseline 本身就是 DSH 提供的全量工作区快照；管理员授予的
          // 既有工作区不会预先出现在 state.visibleWorkspaces 或 user_workspaces，
          // 不能套用增量 upsert 的“已知 workspaceId”门槛，否则新授权工作区会
          // 连同其会话一起被全部过滤掉（Issue #25）。baseline 只需执行路径白名单
          // 与跨用户所有权校验；后续 upsert 继续使用更严格的 workspaceAllowed。
          if (!workspacePathAllowed(workspace) || !Array.isArray(workspace.sessionIds)) continue;
          const id = workspace.workspaceId;
          const workspacePath = workspace.path;
          if (typeof id !== 'string' || typeof workspacePath !== 'string') continue;
          const sessionIds = workspace.sessionIds.filter((sessionId): sessionId is string => typeof sessionId === 'string');
          // A session/create pending response is not a durable grant. Do not seed
          // it from a concurrent baseline; its later upsert is admitted by path.
          for (const sessionId of sessionIds) {
            if (!pendingSessionAllowed(sessionId, workspacePath)) visibleAccess.set(sessionId, workspacePath);
          }
          // 工作区授权不等于既有会话授权：只有显式 session grant 或本次
          // session/create 产生的 pending 会话可见。baseline 不能把主用户已有会话
          // 自动迁移给子用户，即使该工作区路径已被分配。
          workspace.sessionIds = sessionIds.filter((sessionId) =>
            !perms.disabled_sessions.includes(sessionId) &&
            (pendingSessionAllowed(sessionId, workspacePath) || workspaceOwnedByUser(userId, workspacePath) || baselineGrants.has(sessionId)),
          );
          state.visibleWorkspaces.set(id, workspacePath);
          state.visibleWorkspaceRows.set(id, workspace);
          items.push(workspace);
        }
        // Remote baseline 不会把工作区内的既有会话隐式转成 grant。旧用户只
        // 标记迁移完成，真正可见的既有会话必须来自主用户显式 session grant；
        // session/create 的 pending 会话仍由后续 upsert 纳入。
        if (!grantsSeeded) db.seedUserSessionGrants(userId, []);
        // 复读最新 grant：baseline 里可见但从未被显式授权的会话不得回写.
        const grants = new Set(db.listUserSessionGrants(userId));
        // baseline 只是一次可见性投影：合并「旧快照里仍然合法的条目」与「本次可见
        // 条目」，避免一次不完整/乱序的 baseline 把仍在授权内的会话抹掉；grant/
        // 禁用/白名单/所有权任一不满足的条目仍被丢弃。
        const allowedAccess = mergeAuthorizedAccess(userId, perms, grants, visibleAccess);
        const epoch = userAccessEpochFor(userId);
        replaceUserSessionAccess(userId, allowedAccess, epoch);
        const visibleWorkspacePaths = new Map<string, string>();
        for (const item of items) {
          const workspaceId = item.workspaceId;
          const workspacePath = item.path;
          if (typeof workspaceId === 'string' && typeof workspacePath === 'string') visibleWorkspacePaths.set(workspaceId, workspacePath);
        }
        replaceUserWorkspacePaths(userId, mergeWorkspacePaths(userId, perms, visibleWorkspacePaths), epoch);
        userArchivedSessionIds.set(userId, new Set(
          source.archivedSessionIds.filter((id): id is string =>
            typeof id === 'string' && allowedAccess.has(id) && !perms.disabled_sessions.includes(id),
          ),
        ));
        return { type: 'baseline', value: {
          items,
          archivedSessionIds: source.archivedSessionIds.filter((id) => allowedAccess.has(id) && !perms.disabled_sessions.includes(id)),
          // pinned 与 archived 同口径：只暴露当前用户可见且未被逐会话关闭的身份，
          // 不能让子用户借 pin 集合枚举其他租户的会话 ID。
          ...(hasPinnedIds ? {
            pinnedSessionIds: (source.pinnedSessionIds as unknown[]).filter((id): id is string =>
              typeof id === 'string' && allowedAccess.has(id) && !perms.disabled_sessions.includes(id),
            ),
          } : {}),
        } };
      }
      if (frame.type === 'upsert') {
        const workspace = frame.workspace;
        if (workspace === null || typeof workspace !== 'object' || Array.isArray(workspace)) return null;
        const row = { ...(workspace as Record<string, unknown>) };
        if (!workspaceAllowed(row) || !Array.isArray(row.sessionIds) || typeof row.workspaceId !== 'string') return null;
        const workspacePath = String(row.path);
        row.sessionIds = row.sessionIds.filter((id): id is string => allowedSession(id) || pendingSessionAllowed(id, workspacePath));
        state.visibleWorkspaces.set(row.workspaceId, workspacePath);
        state.visibleWorkspaceRows.set(row.workspaceId, row);
        return { type: 'upsert', workspace: row };
      }
      if (frame.type === 'remove' && typeof frame.workspaceId === 'string') {
        const workspacePath = state.visibleWorkspaces.get(frame.workspaceId);
        if (workspacePath === undefined || !folderAllowed(workspacePath, perms.allowed_folders) ||
          workspaceOwnedByAnotherSubuser(userId, workspacePath)) return null;
        state.visibleWorkspaces.delete(frame.workspaceId);
        state.visibleWorkspaceRows.delete(frame.workspaceId);
        return { type: 'remove', workspaceId: frame.workspaceId };
      }
      if (frame.type === 'order' && Array.isArray(frame.workspaceIds)) {
        const ids = frame.workspaceIds.filter((id): id is string => {
          if (typeof id !== 'string') return false;
          const workspacePath = state.visibleWorkspaces.get(id);
          return workspacePath !== undefined && folderAllowed(workspacePath, perms.allowed_folders) &&
            !workspaceOwnedByAnotherSubuser(userId, workspacePath);
        });
        return { type: 'order', workspaceIds: ids };
      }
      if (frame.type === 'archived' && Array.isArray(frame.archivedSessionIds)) {
        const projected = frame.archivedSessionIds.filter(allowedSession);
        if (access !== undefined) {
          // 归档动作是权威投影：立即刷新该用户的内存归档集合（只含已授权会话），并推进
          // 同一用户列表顺序水位，令在途更旧的 workspace.list 响应无法回滚它。
          userArchivedSessionIds.set(userId, new Set(projected));
          replaceUserSessionAccess(userId, access, userAccessEpochFor(userId), bumpWorkspaceListRequestRevision());
        }
        return { type: 'archived', archivedSessionIds: projected };
      }
      if (frame.type === 'pinned' && Array.isArray(frame.pinnedSessionIds)) {
        return { type: 'pinned', pinnedSessionIds: frame.pinnedSessionIds.filter(allowedSession) };
      }
      return null;
    }
    if (frame.type === 'baseline') {
      const baseline = frame.value;
      if (baseline === null || typeof baseline !== 'object' || Array.isArray(baseline)) return null;
      const source = baseline as Record<string, unknown>;
      // RC.1 的 control baseline 是 { queues, jobs, projections }；alpha.2 只发
      // { jobs, projections }。queues 缺失就不能再当成 shape 不符——否则子用户
      // 的 session/control 流永远拿不到基线（顶栏 jobs/投影一直空）。逐表过滤：
      // 存在的表必须是 plain record 且逐会话过滤后才下发；出现但形状不符时
      // 宁可不发整个基线（fail-closed），也不把未过滤内容透传。
      const filtered: Record<string, unknown> = {};
      for (const key of ['queues', 'jobs', 'projections']) {
        if (!Object.hasOwn(source, key)) continue;
        const table = source[key];
        if (!isPlainJsonRecord(table)) return null;
        const out: Record<string, unknown> = {};
        for (const [id, item] of Object.entries(table)) if (allowedSession(id)) out[id] = item;
        filtered[key] = out;
      }
      if (Object.keys(filtered).length === 0) return null;
      return { type: 'baseline', value: filtered };
    }
    if ((frame.type === 'queue' || frame.type === 'jobs' || frame.type === 'projection') && allowedSession(frame.sessionId)) {
      return frame;
    }
    return null;
  };

  const muxEventFilter = (
    userId: number,
    perms: UserPermissionsRow,
  ): Transform => {
    // 单帧解析缓冲有界（见 SseFrameBuffer），上限与 WS 承载的单条消息上限同口径：
    // 上游不发空行时不能无界增长，同时不影响正常大小的事件帧。
    const frames = new SseFrameBuffer(REMOTE_MUX_MAX_PAYLOAD_BYTES);
    // 按流维护解码状态：多字节 UTF-8 字符跨 Buffer 边界时先留在解码器里，避免被
    // 逐 chunk 解码成 U+FFFD 替换字符而破坏过滤输出。
    const decoder = new StringDecoder('utf8');

    const allowedSession = (sessionId: unknown): boolean => {
      const access = userSessionAccess.get(userId);
      return (
        typeof sessionId === 'string' &&
        access !== undefined &&
        access.has(sessionId) &&
        !perms.disabled_sessions.includes(sessionId)
      );
    };

    const filterFrame = (frame: string): string => {
      // 按 SSE 行语义归一化：CRLF、LF、裸 CR 都是行终止符，遗漏裸 CR 会把
      // 「注释\rdata: 敏感事件」当成一行而跳过 data: 解析，导致敏感事件被整帧放行。
      const normalized = frame.replace(/\r\n|\r|\n/g, '\n');
      const dataLines = normalized
        .split('\n')
        .filter((line) => line.startsWith('data:'));

      if (dataLines.length === 0) return frame;

      let envelope: Record<string, unknown>;
      try {
        envelope = JSON.parse(
          dataLines.map((line) => line.slice(5).trimStart()).join('\n'),
        ) as Record<string, unknown>;
      } catch {
        return '';
      }

      const payload = envelope.payload;
      if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
        return '';
      }

      const event = payload as Record<string, unknown>;
      const type = event.type;

      if (typeof type !== 'string') return '';

      if (
        type === 'session/event' ||
        type === 'session/subscribed' ||
        type === 'approval/requested' ||
        type === 'approval/resolved' ||
        type === 'question/requested' ||
        type === 'question/resolved' ||
        type === 'session/queue' ||
        type === 'session/jobs' ||
        type === 'session/projection'
      ) {
        return allowedSession(event.sessionId)
          ? `data: ${JSON.stringify(envelope)}\n\n`
          : '';
      }

      // stream/error 没有 sessionId，不能确认租户归属时丢弃。
      if (type === 'stream/error') return '';

      // 未知 mux 类型不能安全判断归属。
      return '';
    };

    return new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        for (const frame of frames.push(decoder.write(chunk))) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }

        callback();
      },

      flush(callback) {
        for (const frame of frames.push(decoder.end())) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }

        for (const frame of frames.flush()) {
          const out = filterFrame(frame);
          if (out !== '') this.push(out);
        }

        callback();
      },
    });
  };
  const gatewayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const configuredRoot = process.env.DSH_PASSWORDS_ENV_FILE?.trim()
    ? path.dirname(path.resolve(process.env.DSH_PASSWORDS_ENV_FILE.trim()))
    : gatewayRoot;

  // 敏感路径屏蔽（与 admin.ts /gateway/api/download 同口径，实现见 sensitive-paths.ts）：
  // 基列表与惰性缓存共享，避免两处漂移。workspaceFiles 与 /api/file 在通过会话/白名单/
  // 归属之后仍须独立拒绝这些路径：管理员可能把敏感目录的祖先误登记为工作区，此时目标
  // 会同时命中白名单与归属，只有敏感基能挡住。
  const { isSensitivePath } = createSensitivePathChecker({
    dbPath: config.dbPath,
    dshRoot: config.patch.dshRoot,
    gatewayRoot,
    configuredRoot,
  });

  /**
   * 从 Cookie 校验会话；返回用户或 null（用户已不存在时旧 token 立即失效）。
   * 性能：同一 token 的验签 + 用户存在性查询结果缓存 30 秒——每个代理
   * 请求（含静态资源）都要走鉴权，缓存后只剩一次 Map 查找，避免逐请求
   * 重复 JWT 验签 + SQLite 查询 + HMAC/AES。
   */
  const sessionCache = new Map<
    string,
    { user: { userId: number; username: string }; expireAt: number }
  >();
  const SESSION_CACHE_TTL_MS = 30_000;

  // F-04：登出吊销（内存黑名单）。JWT 无状态，登出只能靠网关侧短期黑名单
  // 使已登出 token 立即失效（TTL 与 JWT 有效期一致，到期自动清理）。
  // 改密/改名已有 credential_version 机制使旧 token 失效，此处只补登出路径。
  // 已知残余（容量权衡）：条目最长保留 12h，持有凭据的用户可反复登录/登出制造
  // 唯一 token 撑大该 Map（成功登录无速率限制）；不能超容量淘汰——未过期条目
  // 必须保持拒绝，否则已登出会话复活。后续可考虑 SQLite TTL 撤销表、随机会话
  // id、或对成功登录/登出加限速（见 PROCESS 步骤 41 残余清单）。
  const revokedTokens = new Map<string, number>();
  const TOKEN_TTL_MS = 12 * 3600 * 1000;

  function revokeToken(token: string): void {
    revokedTokens.set(token, Date.now() + TOKEN_TTL_MS);
    sessionCache.delete(token);
  }

  function isTokenRevoked(token: string): boolean {
    const expiresAt = revokedTokens.get(token);
    if (expiresAt === undefined) return false;
    if (expiresAt > Date.now()) return true;
    revokedTokens.delete(token);
    return false;
  }

  function sessionOf(req: Request): { userId: number; username: string } | null {
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) return null;
    const now = Date.now();
    const hit = sessionCache.get(token);
    if (hit) {
      if (hit.expireAt > now) return hit.user;
      sessionCache.delete(token);
    }
    try {
      const user = auth.verifyToken(token);
      // F-04：登出后的 token 立即拒绝（不重新进入缓存）
      if (isTokenRevoked(token)) return null;
      // 用户被删除/重置/改密后旧会话必须失效（缓存有效期 30 秒内生效）
      // 按 sub（用户 ID）定位，而非按 token.username：否则用户改名后新建同名用户，
      // 旧 token 会以新用户身份（sub 仍是旧 ID）通过校验。ID 命中后仍比对用户名，
      // 确保被指向的用户确实是 token 签发时的那个身份。
      const row = db.getUserById(user.userId);
      if (row === null) return null;
      if (row.username !== user.username) return null;
      if (user.cv !== row.credential_version) return null;
      // 缓存 TTL 与 JWT 到期时间取最小值：否则刚过期就被缓存的 token 会在
      // 命中路径上绕过验签，额外存活最多 30 秒
      const expMs = user.exp !== undefined ? user.exp * 1000 : undefined;
      const cacheTtl =
        expMs !== undefined ? Math.min(SESSION_CACHE_TTL_MS, Math.max(0, expMs - now)) : SESSION_CACHE_TTL_MS;
      if (cacheTtl <= 0) return null; // JWT 已到期：不得进入缓存
      sessionCache.set(token, { user: { userId: user.userId, username: user.username }, expireAt: now + cacheTtl });
      return { userId: user.userId, username: user.username };
    } catch {
      return null;
    }
  }

  /** 子用户权限：缺行时默认关闭全部工作区；已有显式空白名单行仍表示不限目录。 */
  function effectivePermissions(userId: number): UserPermissionsRow {
    const value = db.getPermissions(userId) ?? {
        user_id: userId,
        // 新子用户默认关闭全部工作区；旧的显式空数组权限行仍保留“不限制”兼容语义。
        allowed_folders: ['__deny__'],
        hourly_token_limit: null,
        daily_minutes_limit: null,
        allow_upload: false,
        allow_workspace_create: false,
        allow_ssh: false,
        allowed_agent_presets: null,
        allowed_models: null,
        allow_chat_media: false,
        // F-12 残余: 新子用户默认禁 git 下载（含插件下载等外带通道），
        // 主用户需要时按需开启；已有权限行的子用户不受影响
        allow_git_download: false,
        banned: false,
        sandbox_mode: null,
        disabled_sessions: [],
        updated_at: '',
      };
    return value;
  }

  /** 从会话 cookie 解析完整用户（含角色）；无会话/失效返回 null */
  function authedUser(req: Request): { userId: number; username: string; role: 'admin' | 'user' } | null {
    const s = sessionOf(req);
    if (!s) return null;
    const row = db.getUserById(s.userId);
    if (!row) return null;
    return { userId: row.id, username: row.username, role: row.role === 'admin' ? 'admin' : 'user' };
  }

  /** 统一 403 页面（封禁 / 权限拒绝） */
  function forbiddenPage(lang: Lang, message: string): string {
    return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title></head><body style="font-family:system-ui;background:#0f1115;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="margin:0 0 8px">403</h1><p style="margin:0;opacity:.7">${escapeHtml(message)}</p></div></body></html>`;
  }

  /** 用量节流：每 15 秒最多写一次活跃时间，返回当前用量（用于配额判定） */
  const usageThrottle = new Map<number, number>();
  function touchUsageThrottled(userId: number) {
    const now = Date.now();
    const day = todayLocal();
    const last = usageThrottle.get(userId) ?? 0;
    if (now - last >= 15000) {
      usageThrottle.set(userId, now);
      return db.touchUsage(userId, day, new Date().toISOString());
    }
    return db.getUsage(userId, day);
  }

  // ── 登录页（GET）：平台未初始化时显示首次配置页 ─────────────
  app.get('/gateway/login', async (req, res) => {
    const next = safeNext(typeof req.query.next === 'string' ? req.query.next : undefined);
    const lang = langOf(req);
    const queryLang = typeof req.query.lang === 'string' ? req.query.lang : null;
    const [initialized, dbHealthy] = await Promise.all([
      auth.isInitialized().catch(() => false),
      db.health().catch(() => false),
    ]);
    // Issue #35：favicon 等未认证子请求会被重定向回登录页并再次渲染，若无条件
    // 轮换 token，原登录/首次配置表单里的隐藏域就会与 cookie 失配（403）。
    // 因此仅在现有 cookie 无法通过双重提交校验时才换发新 token；有效则复用。
    const existingCsrf = readCookie(req.headers.cookie, CSRF_COOKIE);
    const csrf =
      existingCsrf !== null && csrfMatches(csrfSecret, existingCsrf, existingCsrf)
        ? existingCsrf
        : newCsrfToken(csrfSecret);
    setCsrfCookie(res, csrf, requestIsSecure(req));
    // 显式 ?lang= 选择持久化到 cookie（语言切换链接点出来的）。
    // 注意 Set-Cookie 头已由 CSRF 占用，这里用数组追加而不是 setHeader 覆盖。
    if (queryLang === 'zh' || queryLang === 'en') {
      const langCookie = `${LANG_COOKIE}=${queryLang}; Path=/gateway; SameSite=Lax; Max-Age=31536000${
        requestIsSecure(req) ? '; Secure' : ''
      }`;
      const existing = res.getHeader('Set-Cookie');
      const prev: string[] = Array.isArray(existing)
        ? existing.map((value) => String(value))
        : existing
          ? [String(existing)]
          : [];
      res.setHeader('Set-Cookie', [...prev, langCookie]);
    }
    if (!initialized) {
      res.type('html').send(renderSetupPage({ lang, csrf }));
      return;
    }
    res.type('html').send(renderLoginPage({ lang, next, dbHealthy, csrf }));
  });

  // ── 首次配置提交（POST）→ 302 回登录页 ────────────────────────
  // 未初始化阶段 setup 端点对全网匿名可达：按 IP 做滑动窗口限速，防止
  // 匿名狂刷 setup_failure 审计日志（审计表无限增长 → 磁盘耗尽）。
  // 预设密钥为 192 位随机值，暴力破解本身不可行；这里只限速、不防爆破。
  const setupAttempts = new Map<string, number[]>();
  const SETUP_WINDOW_MS = 10 * 60_000;
  const SETUP_MAX_PER_WINDOW = 10;

  app.post('/gateway/setup', async (req, res) => {
    // P2 加固：写操作必须同源。浏览器在跨源 POST 上总会带 Origin，这里与 Host 比对
    // （仅回环反代才采纳 X-Forwarded-Host）；非浏览器客户端不带 Origin 时按原样放行，
    // 因此不改变 CLI / 测试行为。这条堵住「子域 toss 一条合法 cookie 后从跨源页面
    // 自动提交」的 cookie-tossing CSRF —— 与 logout、/api/dsh-passwords 写操作同一机制。
    // 必须先于限速：否则跨源的连发请求会打满受害者 IP 的配额，令其无法完成首次配置。
    if (!originHostMatches(req, configuredOriginHosts)) {
      res.status(403).type('text/plain').send('403 Forbidden');
      return;
    }
    const ipKey = req.ip ?? '';
    const nowTs = Date.now();
    const recent = (setupAttempts.get(ipKey) ?? []).filter((t) => nowTs - t < SETUP_WINDOW_MS);
    if (recent.length >= SETUP_MAX_PER_WINDOW) {
      res.status(429).type('html').send('429 Too Many Requests');
      return;
    }
    recent.push(nowTs);
    setupAttempts.set(ipKey, recent);

    const setupKey = typeof req.body?.setupKey === 'string' ? req.body.setupKey : '';
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(csrfSecret, readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, requestIsSecure(req));
      res
        .status(403)
        .type('html')
        .send(renderSetupPage({ lang: langOf(req), error: t(langOf(req), 'gw.csrfFailed'), csrf }));
      return;
    }

    try {
      await auth.setup({ setupKey, username, password }, meta);
      // F-07：初始化成功 → 固话派生密钥 + 轮换 SETUP_KEY + 删 setup-key.txt
      // （失败不阻断初始化，用户仍能进入登录页）
      try {
        hardenSecretsAfterSetup(config);
      } catch (error) {
        console.error('[dsh-passwords] 首次配置密钥加固失败：请立即手动删除 setup-key.txt 并轮换 SETUP_KEY（否则密钥可被派生伪造会话/解密数据）:', error);
      }
      res.redirect(302, '/gateway/login');
    } catch (error) {
      // 真实状态码：409 已初始化 / 401 密钥错误 / 400 参数错误
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.initFailed');
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, requestIsSecure(req));
      res.status(status).type('html').send(renderSetupPage({ lang, error: message, csrf }));
    }
  });

  // ── 登录提交（POST） → Set-Cookie + 302 重定向兼容层 ────────
  // 成功登录限速：持有有效凭据的用户可反复登录/登出制造唯一 JWT，撑大
  // revokedTokens 撤销表（12h TTL，不可超容量淘汰）——每用户名每分钟最多
  // 10 次成功登录（正常多设备使用远低于此）。只在成功后计数：无凭据者
  // 无法用它锁定受害者用户名。
  const loginSuccessRate = new Map<string, number[]>();
  const LOGIN_SUCCESS_MAX_PER_MIN = 10;

  app.post('/gateway/login', async (req, res) => {
    // P2 加固：写操作必须同源（理由见 POST /gateway/setup 处同一段注释）。
    if (!originHostMatches(req, configuredOriginHosts)) {
      res.status(403).type('text/plain').send('403 Forbidden');
      return;
    }
    const next = safeNext(typeof req.body?.next === 'string' ? req.body.next : undefined);
    const username = typeof req.body?.username === 'string' ? req.body.username : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const meta: RequestMeta = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };

    // CSRF 校验（double-submit：Cookie 与表单域一致才放行）
    const csrfField = typeof req.body?.csrf === 'string' ? req.body.csrf : '';
    if (!csrfMatches(csrfSecret, readCookie(req.headers.cookie, CSRF_COOKIE), csrfField)) {
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, requestIsSecure(req));
      res
        .status(403)
        .type('html')
        .send(
          renderLoginPage({ lang: langOf(req), next, error: t(langOf(req), 'gw.csrfFailed'), dbHealthy, csrf }),
        );
      return;
    }

    const previousSession = sessionOf(req);
    try {
      const { token, username: loggedInAs } = await auth.login({ username, password }, meta);
      const loggedInRow = db.getUserByUsername(loggedInAs);
      if (previousSession !== null && loggedInRow !== null && previousSession.userId !== loggedInRow.id) {
        // 浏览器切换主/子身份时，旧身份的 Remote carrier 不能继续携带旧授权快照。
        closeUserWebSocketClients(previousSession.userId, 1008, 'Identity switched');
        closeUserRemoteMuxClients(previousSession.userId, 1008, 'Identity switched');
      }
      const nowTs = Date.now();
      const recent = (loginSuccessRate.get(loggedInAs) ?? []).filter((t) => nowTs - t < 60_000);
      if (recent.length >= LOGIN_SUCCESS_MAX_PER_MIN) {
        loginSuccessRate.set(loggedInAs, recent);
        const dbHealthy = await db.health().catch(() => false);
        const csrf = newCsrfToken(csrfSecret);
        setCsrfCookie(res, csrf, requestIsSecure(req));
        res
          .status(429)
          .type('html')
          .send(renderLoginPage({ lang: langOf(req), next, error: '登录过于频繁，请稍后再试', dbHealthy, csrf }));
        return;
      }
      recent.push(nowTs);
      loginSuccessRate.set(loggedInAs, recent);
      res.setHeader(
        'Set-Cookie',
        `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${
          requestIsSecure(req) ? '; Secure' : ''
        }`,
      );
      // 中文/非 ASCII 路径需重新编码（Node 的 Location 头只接受 latin1，
      // 直接 setHeader 会抛 ERR_INVALID_CHAR → 500）
      res.redirect(302, encodeURI(next));
    } catch (error) {
      // 真实状态码：429 锁定 / 401 凭据错误 / 400 其他
      const status = error instanceof AuthError ? error.status : 400;
      const lang = langOf(req);
      const message =
        error instanceof AuthError
          ? error.localize(lang)
          : error instanceof Error
            ? error.message
            : t(lang, 'gw.loginFailed');
      const dbHealthy = await db.health().catch(() => false);
      const csrf = newCsrfToken(csrfSecret);
      setCsrfCookie(res, csrf, requestIsSecure(req));
      res.status(status).type('html').send(renderLoginPage({ lang, next, error: message, dbHealthy, csrf }));
    }
  });

  // ── 登出（F-24：仅 POST，杜绝 <img>/<form> 跨站 GET 强制登出 CSRF） ──
  // SameSite=Lax 的会话 Cookie 不会被跨站 POST 携带，GET 又已移除，
  // 因此跨站无法再伪造登出请求；同源场景本就是可信上下文。
  // GET 显式回 405（而不是掉到 SPA 代理回 200，避免语义含糊）。
  app.get('/gateway/logout', (_req, res) => {
    res.status(405).type('html').send('405 Method Not Allowed');
  });
  app.post('/gateway/logout', (req, res) => {
    // 同站子域页面可借表单强制登出（SameSite=Lax 只挡跨站、不挡同站子域）：
    // 与网关写路由同口径做 Origin 主机校验，提交方与 Host 不一致时拒绝。
    if (!originHostMatches(req, configuredOriginHosts)) {
      res.status(403).type('text/plain').send('403 Forbidden');
      return;
    }
    // F-04：服务端吊销——登出的 token 立即失效（黑名单 12h），
    // 即使 Cookie 已被攻击者复制，该 token 也无法再通过认证门卫
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    // 必须在吊销前解析会话：revokeToken 会清 sessionCache，之后无法可靠定位旧 WS。
    const session = sessionOf(req);
    if (token) revokeToken(token);
    if (session !== null) {
      closeUserWebSocketClients(session.userId, 1008, 'Session ended');
      closeUserRemoteMuxClients(session.userId, 1008, 'Session ended');
    }
    // 清除会话 Cookie 时必须与写入时同样带 Secure：部分浏览器不允许无 Secure
    // 的 Set-Cookie 覆盖已存在的 Secure Cookie，否则登出后客户端仍持有旧会话。
    res.setHeader(
      'Set-Cookie',
      `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${requestIsSecure(req) ? '; Secure' : ''}`,
    );
    res.redirect(302, '/gateway/login');
  });

  // ── 内部接口：dsh 插件通知网关重载远程设置补丁 ───────────────
  // 仅限本机 dsh 插件调用：要求回环地址 + 恒定时间比对内部密钥
  // （密钥由 SETUP_KEY 派生，泄漏面与安装密钥一致）。响应立即返回，
  // 补丁应用与 dsh 重启异步进行，让设置页的响应先刷给浏览器。
  app.post('/gateway/internal/patch', express.json({ limit: '4kb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(secret);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    res.status(202).json({ ok: true });
    setTimeout(() => {
      try {
        const root = findDshRoot(config.patch.dshRoot);
        if (!root) return;
        const result = applyRemotePatch(root);
        if (result === 'applied' && config.patch.restartService) {
          restartDshWeb(config.patch.restartService, 800);
        }
      } catch (error) {
        console.error('[dsh-passwords] 补丁重载失败:', error);
      }
    }, 500);
  });

  // ── 内部接口：dsh 插件通知网关立即失效某用户的会话缓存 ─────
  // 改密/改名/删除用户后，JWT 的 cv 校验要等 30 秒缓存 TTL 才重新查库；
  // 此接口让插件在操作成功后通知网关同步清理该用户的缓存条目，撤销窗口归零。
  app.post('/gateway/internal/session-invalidate', express.json({ limit: '4kb' }), (req, res) => {
    const remoteIp = req.socket.remoteAddress ?? '';
    if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = config.internalSecret;
    const a = Buffer.from(secret);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const userId = typeof body.userId === 'number' && Number.isSafeInteger(body.userId) ? body.userId : null;
    if (userId !== null) {
      for (const [token, entry] of sessionCache) {
        if (entry.user.userId === userId) sessionCache.delete(token);
      }
      // 插件只会在改密/改名/删除已完成后调用此端点；旧 WS 的升级时身份必须
      // 同步失效，避免 HTTP 已 401 而持续订阅仍读取旧数据。
      closeUserWebSocketClients(userId, 1008, 'Credentials changed');
      closeUserRemoteMuxClients(userId, 1008, 'Credentials changed');
    }
    res.status(200).json({ ok: true });
  });

  // ── 内部接口：自动更新引擎（插件经内部通道调用） ───────
  // 仅限本机 dsh 插件调用（回环 + 恒定时间比对内部密钥）。action：
  //   status — 查询引擎状态（当前/最新版本、下载进度、空闲窗剩余、手动命令）
  //   check  — 立即检查 GitHub 最新 release（只发现版本，不下载）
  //   apply  — 按更新状态机下载或安装（主用户按钮触发）
  //   set-auto — 持久化自动更新开关（仅主用户通过插件调用）
  if (updateEngine !== undefined) {
    app.post('/gateway/internal/update', express.json({ limit: '4kb' }), async (req, res) => {
      // Express 4 不会捕获 async handler 的 rejection：applyNow() 的手动下载分支
      // 会等待 fetchNpmMetadata 等网络调用，失败时若无人捕获会变成未处理 rejection
      // 并可能终止进程。整段限界内包 try/catch，鉴权与响应格式保持不变。
      try {
        const remoteIp = req.socket.remoteAddress ?? '';
        if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
          res.status(403).json({ ok: false, error: 'forbidden' });
          return;
        }
        const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
        const expected = config.internalSecret;
        const a = Buffer.from(secret);
        const b = Buffer.from(expected);
        if (a.length !== b.length || !timingSafeEqual(a, b)) {
          res.status(403).json({ ok: false, error: 'forbidden' });
          return;
        }
        const body = (req.body ?? {}) as Record<string, unknown>;
        const action = typeof body.action === 'string' ? body.action : '';
        if (action === 'status') {
          res.json({ ok: true, status: updateEngine.status() });
          return;
        }
        if (action === 'check') {
          // 手动检查只发现版本；设置页轮询状态展示结果。
          void updateEngine.checkNow({ downloadIfAllowed: false }).catch(() => undefined);
          res.json({ ok: true, started: true });
          return;
        }
        if (action === 'apply') {
          // applyNow 自带 ok/code/message（含冷却与未就绪分支）；网络异常会 reject
          res.json(await updateEngine.applyNow());
          return;
        }
        if (action === 'set-auto') {
          if (typeof body.enabled !== 'boolean') {
            res.status(400).json({ ok: false, code: 'INVALID', error: 'enabled 必须为布尔值' });
            return;
          }
          const effective = updateEngine.setAutoUpdateEnabled(body.enabled);
          res.json({ ok: true, requested: body.enabled, enabled: effective, status: updateEngine.status() });
          return;
        }
        res.status(400).json({ ok: false, code: 'INVALID', error: 'action 无效' });
      } catch (error) {
        res.status(500).json({ ok: false, code: 'INTERNAL', message: error instanceof Error ? error.message : String(error) });
      }
    });
  }

  // ── 内部辅助：API 路由的输入清洗 ───────────────────────────
  // 严格非负整数：拒绝 1e3/0x10/小数/负数/超大值（之前 Number() 静默接受科学
  // 计数与十六进制，1e21 等超大值在 SQLite 64 位整数绑定里精度失真）。
  // Number.isSafeInteger 封顶 2^53-1，天然低于 int64 上限。
  const nullableInt = (v: unknown): number | null => {
    if (typeof v === 'number') {
      return Number.isSafeInteger(v) && v >= 0 ? v : null;
    }
    if (typeof v === 'string') {
      const t = v.trim();
      if (t === '') return null;
      if (!/^\d+$/.test(t)) return null;
      const n = Number(t);
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    }
    return null;
  };
  const stringArray = (v: unknown, max = 64): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, max) : [];

  // 统一 API 鉴权：跨站拒绝 + 同站子域同源校验 + 会话校验 + 可选主用户门控
  const apiAuth = (req: Request, res: Response, requireAdmin = false) => {
    // 兄弟子域 CSRF：Sec-Fetch-Site 只区分 cross-site，同站兄弟子域恒为 same-site；
    // 且全局 express.urlencoded 允许无 CORS 预检的简单表单 POST，攻击者可在
    // sibling.example.com 用纯 HTML 表单借受害者会话完成状态变更。对所有状态变更
    // 方法补做 Origin vs Host 同源校验（与 setup/login/logout 同一口径）：浏览器
    // 跨源写必带 Origin，子域与 Host 不等即拒绝；originHostMatches 对无 Origin 的
    // 非浏览器/旧客户端返回 true（兼容性不变），并保留仅回环反代才采纳
    // X-Forwarded-Host 的可信逻辑。GET/HEAD 等只读方法不改，也不波及有意跨源的路由。
    const stateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method ?? '');
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      // host-mismatch 的拒绝已由 originHostMatches 记录；这里只补跨站标记这一来源。
      logOriginRejection(req, 'sec-fetch-site-cross-site');
      res.status(403).json({ ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
      return null;
    }
    if (stateChanging && !originHostMatches(req, configuredOriginHosts)) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
      return null;
    }
    const user = authedUser(req);
    if (!user) {
      res.status(401).json({ ok: false, code: 'NOT_AUTHENTICATED', error: '未登录或会话已失效' });
      return null;
    }
    if (user.role !== 'admin' && effectivePermissions(user.userId).banned) {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '账号已被封禁' });
      return null;
    }
    if (requireAdmin && user.role !== 'admin') {
      res.status(403).json({ ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
      return null;
    }
    return user;
  };

  const jsonBody = express.json({ limit: '256kb' });

  // ── 沙盒注入器（见 src/proxy.ts）──────────────────────────────────────
  // 与 registerProxyRoutes 内部同源构造，供管理路由向 dsh 注入会话沙盒；
  // 必须在 adminRoutes 注册前定义（deps 按同一引用注入，不做任何包装）。
  const sandboxApplier = createSandboxApplier({
    upstreamTransport,
    upstreamHost,
    upstreamPort,
    internalSecret: config.internalSecret,
  });
  const { applySandboxToSessions } = sandboxApplier;

  // ── 主用户管理路由（见 src/admin.ts）───────────────────────────────────
  // 机械拆分自本文件原有管理路由段：purge → overview → download →
  // fs/delete-directory → permissions → usage/report；注册顺序与拆分前逐字一致。
  // 共享 helper（apiAuth / jsonBody / stringArray / nullableInt）与跨模块可变状态
  // Map 一律按【同一引用】注入，绝不复制；可被热更新替换的运行态经 getter 读取。
  const adminRoutes = registerAdminRoutes(app, {
    db,
    config,
    gatewayRoot,
    configuredRoot,
    apiAuth,
    jsonBody,
    stringArray,
    nullableInt,
    effectivePermissions,
    workspaceSubtreeOverlap,
    normalizeAllowedModels,
    parseAllowedModelSpec,
    verifyAdminPassword: (caller, password, meta) => auth.verifyAdminPassword(caller, password, meta),
    systemdPurgeLaunchArgs,
    getEndpointRules: () => endpointRules,
    getHostModelCatalog: () => hostModelCatalog,
    getUpstreamAuthCookie: () => upstreamAuthCookie,
    upstreamHost,
    upstreamPort,
    upstreamAuthority,
    upstreamScheme,
    upstreamTransport,
    upstreamAgent,
    remoteMuxMaxPayloadBytes: REMOTE_MUX_MAX_PAYLOAD_BYTES,
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
  });

  // ── 聊天媒体路由（sticker / image / video，见 src/media.ts）────────────
  const mediaRoutes = registerMediaRoutes(app, {
    db,
    dbPath: config.dbPath,
    effectivePermissions,
    apiAuth,
    jsonBody,
  });

  // ── 留言 / 消息 / SSE 路由（见 src/messages.ts）────────────────────────
  const messageRoutes = registerMessageRoutes(app, {
    db,
    apiAuth,
    jsonBody,
    chatMediaAllowed: mediaRoutes.chatMediaAllowed,
    nullableInt,
    stringArray,
    // 聊天 SSE 与 WS 同口径登记撤销：封禁/登出/删号/改密/权限变更立即断开。
    registerRevocableClient: registerUserWebSocketClient,
  });

  // ── 认证门卫：非 /gateway 请求必须带有效会话 ─────────────────
  // 路径先用 WHATWG URL 规范化（. / .. / %2e%2e 均被归一），再做前缀判断——
  // 否则 /gateway/../api/xxx 会绕过前缀检查直达上游（dsh 侧 new URL 同样
  // 会归一化该路径，等于未认证调用任意 RPC）。解析失败一律按未认证处理，绝不 500。
  //
  // F-03 补强：WHATWG URL 会折叠 %2e 但【不解码 %2f】，导致 /gateway/..%2fapi/…
  // 在门卫眼里仍以 /gateway/ 开头而被放行，上游解码 %2f 后路径变成 /gateway/../api/…
  // （不匹配 dsh 任何路由 → SPA fallback 200，未认证泄露应用外壳）。
  // 修复要点（复检定位）：
  //   1. 必须从【原始 req.url】取路径——第一次 new URL 归一化时
  //      /gateway//../ 的空段会把 .. 吞掉（WHATWG 语义），再用归一化后的
  //      pathname 二次处理就太晚了；
  //   2. 迭代解码（最多 3 轮）：覆盖 %2f、%252f（双重编码）等；
  //   3. 解码后压平重复斜杠再 new URL 归一化，使 ../ 能正确折叠。
  // 绝对形式 request-target（http://host/...）先解析出 host 再取 pathname。
  function gatePathOf(reqUrl: string): string {
    let rawPath: string;
    if (/^https?:\/\//i.test(reqUrl)) {
      try {
        rawPath = new URL(reqUrl).pathname;
      } catch {
        rawPath = reqUrl;
      }
    } else {
      rawPath = reqUrl.split('?')[0];
    }
    return normalizeDecodedPath(rawPath);
  }

  /** 迭代解码（最多 3 轮）+ 压平重复斜杠 + WHATWG 归一化；畸形编码保持原样 */
  function normalizeDecodedPath(rawPath: string): string {
    let decoded = rawPath;
    for (let i = 0; i < 3; i++) {
      let next: string;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        break; // 畸形百分号编码：保留当前值
      }
      if (next === decoded) break; // 无更多可解
      decoded = next;
    }
    return new URL(decoded.replace(/\/+/g, '/'), 'http://localhost').pathname;
  }

  app.use((req, res, next) => {
    try {
      // Host 格式校验：拒绝含路径/控制字符/超长的畸形 Host（防 CRLF/Header 注入
      // 变体）；不做域名白名单——用户可能用任意域名访问（如未配置 domain 的自定义
      // DNS），只拦畸形头。
      const hostRaw = req.headers.host;
      if (hostRaw !== undefined) {
        const h = String(hostRaw);
        if (h.length > 253 || !/^[A-Za-z0-9.\-\[\]:]+$/.test(h)) {
          res.status(400).type('text/plain').send('400 Bad Request');
          return;
        }
      }
      // F-03：从【原始 req.url】迭代解码 + 压平斜杠 + 归一化后做前缀判定
      // （不能先用 new URL(parsed.pathname)——第一次归一化会把 //../ 的空段吞掉）
      const gatePath = gatePathOf(req.url ?? '/');
      // 自动更新引擎的用户活动刷新：任何非内部通道请求都算用户活动（登录/API/页面/SSE），
      // 内部通道（/gateway/internal/*）是引擎/插件自己的调用，不算使用。
      if (updateEngine !== undefined && !gatePath.startsWith('/gateway/internal/') && !isBackgroundUpdateRequest(gatePath)) {
        updateEngine.bumpActivity();
      }
      // /gateway 精确路径与 /gateway/* 都视为网关自有前缀——但只放行已知路由，
      // 未知子路径（如 /gateway/api/xxx/yyy 误拼接）直接 404，
      // 不透传到上游 dsh（否则未登录也返回 SPA 壳，泄露 window.__DSH_BOOT__ 插件清单）
      if (gatePath === '/gateway' || gatePath.startsWith('/gateway/')) {
        // F-1：编码/压扁变形（/gateway%2Fapi%2Foverview、/gateway//login）——
        // Express 用【原始 URL】匹配路由，%2F 不算分隔符 → 不会命中任何具体路由；
        // 若这里按解码后的白名单放行，请求会落进无鉴权代理 → 转发上游 dsh 返回
        // SPA 壳（泄露 window.__DSH_BOOT__ 插件清单 + 构建 rev，实测 7+ 变体全 200）。
        // 判定：段结构一致性——原始路径按 '/' 分段的段数必须与解码归一化后一致。
        //   %2F 改变段数（/gateway%2Fapi → 原始 2 段 vs 解码 3+ 段）→ 404；
        //   %2f 小写、%252F 双重、// 压扁同理（段数变化）；
        //   段内编码（如 %E7%94%A8 非 ASCII 段，段数不变）→ 放行——为未来含
        //   非 ASCII 段的网关路由留好扩展口（测试方建议：不做过严的字面拒绝）。
        let rawPathOnly = (req.url ?? '/').split('?')[0];
        if (/^https?:\/\//i.test(rawPathOnly)) {
          try {
            rawPathOnly = new URL(rawPathOnly).pathname;
          } catch {
            /* 保持原值 */
          }
        }
        if (rawPathOnly.split('/').length !== gatePath.split('/').length) {
          res.status(404).type('text/plain').send('404 Not Found');
          return;
        }
        // 精确白名单：只放行网关自有路由。
        // /gateway/api/* 不能整段放行——与插件子路径误拼接的路径
        // 会透传到上游 dsh 返回 SPA 壳（泄露 window.__DSH_BOOT__ 插件清单）。
        // 聊天媒体：只放行精确的 init 路径与「合法形状的媒体 ID」子路径——
        // 相机错误拼接、编码变形与带斜杠/点段的路径都 404（不落到代理层）。
        const mediaRouteAllowed =
          gatePath === '/gateway/api/message-media/init' ||
          /^\/gateway\/api\/message-media\/[A-Za-z0-9_-]{8,128}$/.test(gatePath);
        const knownGatewayRoute =
          gatePath === '/gateway' ||
          gatePath === '/gateway/' ||
          /^\/gateway\/(login|setup|logout)(\/|$)/.test(gatePath) ||
          gatePath === '/gateway/api' ||
          gatePath === '/gateway/api/' ||
          gatePath === '/gateway/api/overview' ||
          gatePath === '/gateway/api/permissions' ||
          gatePath === '/gateway/api/usage/report' ||
          gatePath === '/gateway/api/fs/delete-directory' ||
          gatePath === '/gateway/api/dsh-passwords/purge' ||
          gatePath === '/gateway/api/messages' ||
          gatePath.startsWith('/gateway/api/messages/') ||
          mediaRouteAllowed ||
          gatePath.startsWith('/gateway/internal/');
        if (!knownGatewayRoute) {
          res.status(404).type('text/plain').send('404 Not Found');
          return;
        }
        return next();
      }
      // P1-1：dsh 插件 internal 端点仅限网关→dsh 本机 HTTP 调用，
      // 外部请求一律 404（loopback 校验被代理拓扑绕过，不能依赖插件侧防护）
      if (gatePath.startsWith('/api/dsh-passwords/internal/')) {
        res.status(404).json({ ok: false, error: 'not found' });
        return;
      }
      const user = sessionOf(req);
      if (!user) {
        // Issue #35 / 审计 P3：自动探针路径（favicon、apple-touch-icon、manifest、
        // robots 等）未认证时直接 204，不渲染也不重定向；其余路径照原样 302。
        if (ANONYMOUS_STATIC_PROBES.has(gatePath)) {
          res.status(204).end();
          return;
        }
        // 重定向兼容层：记录原始 URL，登录后跳回。根路径是默认落点，
        // 不在地址栏附带 next 参数（不把内部路由目标甩到公开 URL 上）；
        // 登录成功后 safeNext 缺省回首页。
        const original = req.originalUrl;
        const target = original === '/' ? '/gateway/login' : `/gateway/login?next=${encodeURIComponent(original)}`;
        res.redirect(302, target);
        return;
      }
      const row = db.getUserById(user.userId);
      if (!row) {
        if (ANONYMOUS_STATIC_PROBES.has(gatePath)) {
          res.status(204).end();
          return;
        }
        const original = req.originalUrl;
        const target = original === '/' ? '/gateway/login' : `/gateway/login?next=${encodeURIComponent(original)}`;
        res.redirect(302, target);
        return;
      }
      // 所有路径型授权必须使用与上游转发完全相同的规范化路径。若使用 WHATWG
      // 原始 pathname，`/api%2Fsession%2Fhistory` 会在此处躲过检查、却在转发时
      // 解码为真实敏感路由（C-1）。query 仍由 URL 只读解析。
      const parsed = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const requestPath = gatePath;
      // 自身插件的写操作必须同源：Sec-Fetch-Site 可被缺省/伪造，且 text/plain
      // 可避免 CORS 预检；浏览器提供 Origin 时严格与请求 Host 一致。跨源攻击的
      // 本质是跨主机（攻击者无法在受害者主机名上托管内容），因此只比主机:端口、
      // 不比协议——否则 README 支持的 nginx/caddy 终结 TLS 反代部署（网关收到
      // 明文 HTTP、req.protocol=http，而浏览器 Origin=https）会全部误判 403。
      // Host 只信直接对端：仅当对端是本机回环（受信本地反代）才采纳
      // X-Forwarded-Host，公网直连请求不能带伪造头绕过。
      if (
        ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) &&
        requestPath.startsWith('/api/dsh-passwords/') &&
        !requestPath.startsWith('/api/dsh-passwords/internal/') &&
        typeof req.headers.origin === 'string'
      ) {
        if (!originHostMatches(req, configuredOriginHosts)) {
          res.status(403).type('text/plain').send('403 Forbidden');
          return;
        }
      }
      // 记录所有登录用户（含主用户）的用户 id：供 session.create/fork 响应回调
      // 登记 sessionId→cwd 缓存与已登记 SSH 端点的 SSRF 校验使用；权限行仍只挂子用户
      (req as Req).dshpwUser = user.userId;
      (req as Req).dshpwUsername = row.username;
      (req as Req).dshpwIsAdmin = row.role === 'admin';
      if (row.role !== 'admin') {
        const perms = effectivePermissions(user.userId);
        const lang = langOf(req);
        if (perms.banned) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.banned')));
          return;
        }
        // ── alpha.2 交付物路由的对象级授权（changes.summary|diff|open）──────────
        // 这三个官方路由的坐标全部在 query（sessionId + seq [+ index]），而上游只用
        // sessionId 查会话、不校验归属：把它归入官方面（或加进白名单）等于让任何
        // 子用户读走别人的变更摘要/差异，甚至触发宿主应用的打开动作。因此这里做
        // 对象级授权（会话快照 + 持久化 grant + 逐会话关闭 + 白名单目录 + 所有权），
        // 通过后才在分类分支里放行转发；否则直接 403。
        const changesRoute = req.method === 'GET' || req.method === 'POST'
          ? CHANGES_ROUTE_RE.exec(requestPath)
          : null;
        if (changesRoute !== null) {
          // 0.1.7-alpha.1 的 summary/diff 只支持 GET；open 支持 GET 查询关联应用，
          // 也支持 POST 执行打开。两种 open 方法都必须经过同一套会话归属校验。
          const methodAllowed = changesRoute[1] === 'open'
            ? req.method === 'GET' || req.method === 'POST'
            : req.method === 'GET';
          const coordinates = methodAllowed
            ? deliveryRouteCoordinates(parsed.searchParams, changesRoute[1] !== 'summary')
            : null;
          const sessionRoot = coordinates === null
            ? null
            : authorizedSubuserSessionRoot(user.userId, coordinates.sessionId, perms);
          if (sessionRoot === null) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        // ── 会话日志导出（GET/HEAD /api/session.export）的对象级授权 ──────────────
        // 该路由把会话身份放在 query 的 sessionId 里，上游只按它查会话、不校验归属；
        // 它同时属于 session 命名空间（→ official）与 isGitRequest，因此子用户只要
        // 开了 allow_git_download 就能拿到任意其它租户的会话日志。与 changes.* 同口径
        // 做会话归属校验：缺失/不可解析/未授权的 sessionId 一律 403，绝不下载。
        // 主用户不受此限制（上面的分支只对非管理员生效）。
        if (
          (req.method === 'GET' || req.method === 'HEAD') &&
          SESSION_EXPORT_ROUTE_RE.test(requestPath)
        ) {
          const exportSessionId = parsed.searchParams.get('sessionId');
          if (
            exportSessionId === null ||
            authorizedSubuserSessionRoot(user.userId, exportSessionId, perms) === null
          ) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        // ── 0.1.7-alpha.1 workspaceFiles/changes：带 path 的 Remote 流 ──────────────
        // 子用户在 HTTP unary 面一律 403，不依赖上游对 Remote-only 端点报
        // signature-invalid（那是上游行为，不是授权判定，且不保证长期存在）。
        // Remote mux 面在开流时按 workspaceFileScopeId + path 做授权，主用户不受限制。
        if (WORKSPACE_FILES_CHANGES_ROUTE_RE.test(requestPath)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
          return;
        }
        // ── alpha.2 官方 /api/file 直读宿主绝对路径（GET/HEAD ?path=）──
        // 上游只用绝对路径读文件，不做任何工作区包含检查；子用户必须能用
        // 「已授权会话的工作区根」把目标路径绑定住，否则任何宿主可读文件（包括
        // .env、数据库、他人工作区）都能被直接拿走。未提供/无法解析路径一律 403。
        if ((req.method === 'GET' || req.method === 'HEAD') && requestPath === '/api/file') {
          const requestedPath = parsed.searchParams.get('path');
          // 字符串路径与真实路径必须同时绑定到同一授权工作区；否则工作区内的
          // 符号链接可能把 /api/file 读请求带出租户边界。
          const normalizedPath = requestedPath === null ? null : normalizePath(requestedPath);
          const canonicalPath = requestedPath === null ? null : canonicalizePathBestEffort(requestedPath);
          const allowed = requestedPath !== null && requestedPath !== '' &&
            !requestedPath.includes('\0') && isAbsoluteLikePath(requestedPath) &&
            normalizedPath !== null && canonicalPath !== null &&
            pathBoundToAuthorizedWorkspace(user.userId, perms, normalizedPath) &&
            pathBoundToAuthorizedWorkspace(user.userId, perms, canonicalPath);
          if (!allowed) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
          // 通过会话根/白名单/归属之后，仍须拒绝敏感路径：管理员可能把敏感目录的祖先
          // 误登记为工作区，此时目标会同时命中白名单与归属，只有敏感基能挡住。
          if (normalizedPath !== null && isSensitivePath(normalizedPath) ||
            canonicalPath !== null && isSensitivePath(canonicalPath)) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        // ── alpha.2 官方 /api/present.open（在宿主桌面打开声明过的文件）──
        // 请求只带坐标（sessionId + seq + index）而不带目标路径，因此网关可见的
        // 授权面只有「这是哪个会话的声明」：必须把动作绑定到一个仍然授权的会话
        // （快照 + grant + 未关闭 + 白名单目录 + 所有权），坐标/action 不可解析一律
        // 403。上游只注册了 POST，GET 会被上游以 405 拒绝；但归属校验不能依赖
        // 上游的方法表——两条方法走同一套 sessionId/seq/index 判定，避免 GET 成为
        // 绕过路径。action 仍只在 POST（真正执行动作的那条）上校验。
        // 目标路径的解析与工作区包含性由上游的 fs/sandbox 负责。
        if (
          (req.method === 'POST' || req.method === 'GET') &&
          requestPath === '/api/present.open'
        ) {
          const coordinates = deliveryRouteCoordinates(parsed.searchParams, true);
          const action = parsed.searchParams.get('action') ?? 'open';
          const sessionRoot = coordinates === null
            ? null
            : authorizedSubuserSessionRoot(user.userId, coordinates.sessionId, perms);
          if (
            sessionRoot === null ||
            (req.method === 'POST' && action !== 'open' && action !== 'reveal')
          ) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.folderDenied')));
            return;
          }
        }
        // ── 端点分类（不包含任何扩展专属路径）──
        //   owner: 登记 → 403；其余登记 → 需 allow_ssh（主用户登记 + 子用户勾选，
        //   缺一不可）；官方面与普通 DSH 扩展面继续走对象级权限逻辑；普通未知
        //   HTTP 路由直通，敏感宿主面仍拒绝。
        const pathClass = classifySubuserPath(requestPath, {
          endpointRules,
          transport: 'http',
          dynamicManifest: dynamicPluginManifest,
        });
        // 官方 terminal 不依赖登记表：同一个 allowSsh 开关同时控制官方 terminal
        // 与已登记的第三方 SSH/宿主端点。terminal 仍保留硬拒绝分类，避免宽泛
        // 登记规则绕过这里的显式授权分支；本分支是唯一允许子用户进入官方
        // terminal 的入口。
        const officialTerminalHttp = req.method === 'POST' && OFFICIAL_TERMINAL_HTTP_RE.test(requestPath);
        const terminalStub = officialTerminalHttp ? TERMINAL_STUB_RE.exec(requestPath) : null;
        // owner: 规则优先于 SSH 总开关：真实宿主能力始终拒绝；四个无能力 UX 桩
        // 无论 allowSsh 状态都返回固定本地响应，保持客户端恢复流程稳定。
        if (pathClass === 'owner-only' && terminalStub === null) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.adminOnly')));
          return;
        }
        // 子用户硬拒绝的敏感命名空间/端点（pluginManager / settings 写 / 凭据等）：
        // 先于 SSH 授权分支判定，任何登记规则都不能放行。官方 terminal 是唯一例外——
        // 它命中硬拒绝分类，但由下方显式 allowSsh 分支决定能否透传；未知 terminal
        // 方法（不匹配 OFFICIAL_TERMINAL_HTTP_RE）仍落到这里被拒绝。
        if (isSubuserBlockedApiPath(requestPath) && !officialTerminalHttp && terminalStub === null) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.adminOnly')));
          return;
        }
        // allowSsh 关闭时，官方 terminal 的真实方法返回明确的权限错误；四个恢复/
        // 清理桩仍走下面的固定响应，避免客户端进入无休止重试。开启后官方 terminal
        // 直接继续进入通用上游代理。
        if (officialTerminalHttp && pathClass !== 'owner-only' && !perms.allow_ssh && terminalStub === null) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noSsh')));
          return;
        }
        const hasLegacySshRule = endpointAllowed(requestPath, endpointRules, { capability: 'ssh' });
        if (hasLegacySshRule && pathClass !== 'ssh' && !officialTerminalHttp) {
          // 传统 SSH 表中的路径仍受 transport 前缀约束；普通未登记插件
          // 不进入该分支，因此不会被传统表逻辑误伤。
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noSsh')));
          return;
        }
        if (pathClass === 'ssh') {
          if (!perms.allow_ssh) {
            res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noSsh')));
            return;
          }
        } else if (terminalStub !== null && (pathClass === 'owner-only' || !perms.allow_ssh) && changesRoute === null) {
          // ── 子用户 terminal 无能力 UX 桩 ───────────────────────────
          // 官方客户端 TerminalRecovery / 终端面板会调用 list、environment、shells、
          // close。直接回 403 会让 restore/setup 常驻重试，所以这四者只在本地回
          // 「不放开能力」的 server-response，绝不触达上游。
          //   · list        → ok 空成功（value 必须是裸数组；关闭态不会列出宿主终端，
          //                    空列表恒为真，无信息泄露）。
          //   · environment → ok=false + terminal/unavailable（客户端停止等待 shell）。
          //   · shells      → 同上。
          //   · close       → ok 幂等成功且不带 value（alpha.2 z.void）。关闭态不把
          //                    终端清理请求交给上游，只把它作为本地幂等清理桩；不触上游。
          // 严格信封校验（见 terminalStubRpcId）；GET/畸形/超大/方法不匹配一律
          // 回落到下面的常规 403，绝不因为「UX 桩」而放宽任何 terminal 能力。
          if (terminalStub !== null) {
            const action = terminalStub[1];
            const chunks: Buffer[] = [];
            let size = 0;
            let oversized = false;
            req.on('data', (chunk: Buffer) => {
              if (oversized) return;
              size += chunk.length;
              if (size > 64 * 1024) {
                oversized = true;
                return;
              }
              chunks.push(chunk);
            });
            req.on('end', () => {
              if (res.writableEnded) return;
              const rpcId = oversized ? '' : terminalStubRpcId(chunks, action);
              if (rpcId === '') {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.adminOnly')));
                return;
              }
              const result =
                action === 'list' ? { ok: true, value: [] } :
                action === 'close' ? { ok: true } :
                { ok: false, error: { code: 'terminal/unavailable', message: TERMINAL_UNAVAILABLE_MESSAGE, details: {} } };
              res.status(200).type('application/json').send(
                JSON.stringify({ type: 'server-response', rpcId, result }),
              );
            });
            req.on('error', () => {
              if (!res.writableEnded) res.destroy();
            });
            return;
          }
          // 普通插件路径不需要逐插件登记；路径分类已在前面完成 owner/SSH
          // 边界判断，剩余普通面直接进入上游代理。
        }

        // ── 官方上传 / git 下载开关（仅子用户；普通第三方插件不受影响）──────────
        // allow_upload 只决定官方请求体档位：关闭时仍允许 64 MiB 以内的官方上传，
        // 开启时提升到 300 MiB。上传端点的会话归属、工作区白名单和 disabled 状态
        // 仍由 proxy 层独立校验，不能用该档位替代对象级授权。
        // allow_git_download 关闭时官方 git 取数据动词（clone/pull/fetch 等）与
        // session.export 会话日志下载通道一律拒绝。普通第三方插件路径照常转发。
        if (!perms.allow_git_download && isGitRequest(requestPath)) {
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.noGit')));
          return;
        }

        // DSH calls this no-argument initializer when the sidebar has no workspace.
        // It targets a host-global default directory, so a subuser must not invoke
        // the host operation. Return a benign protocol success instead of a noisy
        // 403; real user-selected workspace creation remains guarded below.

        if (req.method === 'POST' && /^\/api\/workspace[.\/]initializeDefault$/.test(requestPath) && !((req as Req).dshpwIsAdmin === true)) {
          const chunks: Buffer[] = [];
          let size = 0;
          let rejected = false;
          req.on('data', (chunk: Buffer) => {
            if (rejected) return;
            size += chunk.length;
            if (size > 64 * 1024) rejected = true;
            else chunks.push(chunk);
          });
          req.on('end', () => {
            if (res.writableEnded) return;
            try {
              const value = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
              const rpcId = typeof value.rpcId === 'string' && value.rpcId.length > 0 && value.rpcId.length <= 200 ? value.rpcId : '';
              if (rejected || value.type !== 'client-request' || value.method !== 'workspace/initializeDefault' || rpcId === '') {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
                return;
              }
              res.status(200).type('application/json').send(JSON.stringify({ type: 'server-response', rpcId, result: { ok: true } }));
            } catch {
              res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
            }
          });
          return;
        }
        const isManagedWorkspaceWrite = isWorkspaceCreate(requestPath) || isWorkspaceDeleteOrRename(requestPath);
        const workspaceOrderWrite = isWorkspaceOrderWrite(requestPath);
        const workspaceManagementAllowed = perms.allow_workspace_create && isManagedWorkspaceWrite;
        // workspace/insertBefore 与 insertSessionBefore 只改变顺序，不创建/删除文件系统内容；
        // 它们走对象级可见性校验，不复用 allow_workspace_create。
        // 新建工作区的目录选择器会先调用 host.createDirectory
        // workspace.* RPC。该调用必须复用同一开关，否则子用户虽不能登记
        // 工作区，仍能在服务器文件系统中创建目录。
        // `allowWorkspaceCreate` 只覆盖创建/删除/重命名；import/move/materialize/
        // adopt 等其它 workspace 写操作不能因共享同一个总写谓词而被顺带放行。
        if (
          (isWorkspaceWrite(requestPath) && !workspaceOrderWrite && (!isManagedWorkspaceWrite || !workspaceManagementAllowed)) ||
          (isWorkspaceDirectoryCreate(requestPath) && !perms.allow_workspace_create)
        ) {
          // Issue #38 审计：关闭 allowWorkspaceCreate 时的目录创建 / 工作区登记拒绝。
          // 用与 proxy 层路径级拒绝同一组事件名与 detail 形状，且不落完整敏感路径
          // （此处仅开关关闭，无用户选定的可记路径）。
          const auditEventType = isWorkspaceDirectoryCreate(requestPath)
            ? 'directory_create_denied'
            : isWorkspaceCreate(requestPath) ? 'workspace_registration_denied' : null;
          if (auditEventType !== null) {
            db.audit(auditEventType, {
              username: row.username,
              ip: req.ip,
              userAgent: req.headers['user-agent'] ?? null,
              detail: JSON.stringify({ result: 'denied', reason: 'create_disabled' }),
            });
          }
          res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.workspaceDenied')));
          return;
        }
        if (!isStaticAsset(requestPath) && !isPollingRequest(requestPath)) {
          // 配额计时从子用户“说第一句话”（发消息锚点）才开始：
          // 未使用过的子用户（无当日记录且非锚点请求）不创建记录、不受配额限制
          const day = todayLocal();
          if (db.getUsage(user.userId, day) !== null || isUsageAnchorRequest(requestPath)) {
            const usage = touchUsageThrottled(user.userId);
            if (usage) {
              if (perms.daily_minutes_limit !== null && usage.active_seconds >= perms.daily_minutes_limit * 60) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.timeLimit')));
                return;
              }
              if (perms.hourly_token_limit !== null && usage.hourly_tokens >= perms.hourly_token_limit) {
                res.status(403).type('html').send(forbiddenPage(lang, t(lang, 'gw.tokenLimit')));
                return;
              }
            }
          }
        }
        // 附上权限，供后续文件夹限制中间件 / 代理 token 计量使用
        (req as Req).dshpwPerms = perms;
      }
      return next();
    } catch {
      res.redirect(302, '/gateway/login');
    }
  });

  // ── 反向代理（HTTP + WebSocket）→ 上游 dsh（见 src/proxy.ts）────────
  // 机械拆分自本文件原有代理段：全部授权状态（Map/Set/函数/常量）按【同一引用】
  // 注入，可被热更新替换的 let 经 getter/访问器读写实时值，本文件不再重复注册
  // 代理中间件与 upgrade 监听器。注册位置在认证门卫之后、server 创建之前。
  const proxyRoutes = registerProxyRoutes(app, {
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
    originHostMatches: (req) => originHostMatches(req, configuredOriginHosts),
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
    REMOTE_MUX_FRAGMENT_BYTES: remoteMuxConfig.fragmentBytes,
    REMOTE_MUX_MAX_PAYLOAD_BYTES,
    REMOTE_MUX_MAX_PENDING_BYTES,
    REMOTE_MUX_MAX_STREAMS,
    REMOTE_MUX_PING_INTERVAL_MS: remoteMuxConfig.pingIntervalMs,
    REMOTE_MUX_PONG_TIMEOUT_MS: remoteMuxConfig.pongTimeoutMs,
    REMOTE_MUX_WRITE_STALL_MS: remoteMuxConfig.writeStallMs,
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
    upstreamHost,
    upstreamIsHttps,
    upstreamPort,
    upstreamScheme,
    upstreamTransport,
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
    internalSecret: config.internalSecret,
    getEndpointRules: () => endpointRules,
    getDynamicPluginManifest: () => dynamicPluginManifest,
    getUpstreamAuthCookie: () => upstreamAuthCookie,
    getHostDefaultModel: () => hostDefaultModel,
    getHostDefaultModelKnown: () => hostDefaultModelKnown,
    getArchivedSessionSnapshotReady: () => archivedSessionSnapshotReady,
    setArchivedSessionSnapshotReady: (v) => { archivedSessionSnapshotReady = v; },
    getArchivedSessionSnapshotRevision: () => archivedSessionSnapshotRevision,
    setArchivedSessionSnapshotRevision: (v) => { archivedSessionSnapshotRevision = v; },
    bumpWorkspaceListRequestRevision,
  });

  const hasTls = config.gateway.tls !== null;
  const server = hasTls
    ? https.createServer(
        {
          // 默认证书（启动时读一次）：不带 SNI 的客户端（如 https://127.0.0.1
          // 直连、插件→网关内部回环调用）不会触发 SNICallback，必须要有默认
          // cert/key 才能完成握手
          cert: readFileSync(config.gateway.tls!.cert),
          key: readFileSync(config.gateway.tls!.key),
          // 证书每次 TLS 握手时从文件动态读取：自动续期写入新文件后
          // 下一个连接即用新证书，无需重启进程
          SNICallback: (_servername, callback) => {
            try {
              callback(
                null,
                createSecureContext({
                  cert: readFileSync(config.gateway.tls!.cert),
                  key: readFileSync(config.gateway.tls!.key),
                  minVersion: 'TLSv1.2',
                }),
              );
            } catch (error) {
              callback(error as Error);
            }
          },
          // 仅允许 TLS 1.2+，拒绝老旧协议与弱套件协商
          minVersion: 'TLSv1.2',
        },
        app,
      )
    : http.createServer(app);

  // slowloris 加固（第四轮 P-note）：显式请求超时 + 并发连接上限
  //   - headersTimeout 20s：半开头部（慢速发头）更快被切断（Node 默认 60s）
  //   - requestTimeout 60s：完整请求体超时（Node 默认 300s；仅影响收包，不影响 SSE/长连接）
  //   - maxConnections 512：防千级慢连接耗尽文件句柄（100 并发压力测试实测无压力）
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.maxConnections = 512;

  // ── 内存结构周期性清理（防长期运行缓慢积累） ───────────────────
  // sessionCache / revokedTokens / usageThrottle / usageReportThrottle /
  // setupAttempts 都以 token / IP / userId 为键，平时按需淘汰，
  // 这里兑底每 10 分钟全量扫一遍过期条目：内存面与活跃用户数成正比，
  // 而不是与进程运行时长成正比。留言限流窗口与聊天媒体回收分别由
  // messageRoutes.sweep() / mediaRoutes.sweepRate()·sweepMedia() 负责。定时器 unref，不阻碍进程退出。
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of sessionCache) if (v.expireAt <= now) sessionCache.delete(k);
    for (const [k, v] of revokedTokens) if (v <= now) revokedTokens.delete(k);
    // 代理模块的周期清理钩子（见 src/proxy.ts）。
    // 注：proxy 的 sweep 当前为空实现——remoteEventOwnership 等容器仍是
    // 与门卫/管理路由共享的授权状态，按该模块注释约定继续在本函数内清理。
    proxyRoutes.sweep(now);
    for (const [k, v] of remoteEventOwnership) if (v.expiresAt <= now) remoteEventOwnership.delete(k);
    for (const [userId, pending] of pendingCreatedSessions) {
      for (const [sessionId, value] of pending) if (value.expiresAt <= now) pending.delete(sessionId);
      if (pending.size === 0) pendingCreatedSessions.delete(userId);
    }
    for (const [k, v] of usageThrottle) if (now - v > 3600_000) usageThrottle.delete(k);
    for (const [k, v] of adminRoutes.usageReportThrottle) if (now - v > 3600_000) adminRoutes.usageReportThrottle.delete(k);
    for (const [k, v] of setupAttempts) {
      const keep = v.filter((t) => now - t < SETUP_WINDOW_MS);
      if (keep.length > 0) setupAttempts.set(k, keep);
      else setupAttempts.delete(k);
    }
    messageRoutes.sweep();
    for (const [k, v] of loginSuccessRate) {
      const keep = v.filter((t) => now - t < 60_000);
      if (keep.length > 0) loginSuccessRate.set(k, keep);
      else loginSuccessRate.delete(k);
    }
    mediaRoutes.sweepRate(now);
    // 极端 token/IP 洪泛下，TTL 尚未到期的键也可能无界增长；保留最新一半，
    // 牺牲极端情况下的短期缓存命中而不牺牲进程可用性。
    // ⚠ revokedTokens 不参与裁剪：它是登出吊销语义（未过期条目=拒绝该 JWT），
    // “淘汰即放行”会让已登出的会话重新可用；其条目仅能由 sweep 按到期时间清理。
    const cap = <T>(map: Map<T, unknown>, limit = 10_000) => {
      if (map.size <= limit) return;
      let drop = Math.ceil(map.size / 2);
      for (const key of map.keys()) {
        map.delete(key);
        if (--drop === 0) break;
      }
    };
    cap(sessionCache);
    cap(usageThrottle);
    cap(adminRoutes.usageReportThrottle);
    cap(setupAttempts);
    // 会话路径缓存按容量裁剪（重启后由 session.list/workspace.list 重建；防长期运行无界增长）
    cap(sessionCwdById);
    cap(workspacePathById, 20_000);
    // 数据库周期清理：登录失败/节流表与注册表幽灵会话（写失败只告警不致命）
    try {
      db.pruneStaleSecurityRows();
    } catch (error) {
      console.warn('[dsh-passwords] 周期清理失败:', String(error));
    }
    // 聊天媒体周期回收（见 src/media.ts）：过期资产 + 长期未提交的 pending 上传。
    mediaRoutes.sweepMedia(now);
  }, 10 * 60_000);
  sweep.unref();
  server.on('close', () => clearInterval(sweep));

  proxyRoutes.attachUpgrade(server);

  // ── 端点登记表热更新（无需重启）──
  // 定期读取部署 .env 并对比运行态：合法且变化则立即生效（规则收紧时同步断开经
  // 登记表授权的子用户 WS）；文件缺失静默忽略；规则非法保留上一次有效快照并只
  // 报错一次。仅在显式指定部署环境文件（DSH_PASSWORDS_ENV_FILE）时启用。
  const reloadEnvFile = options.envFile ?? process.env.DSH_PASSWORDS_ENV_FILE?.trim() ?? '';
  const endpointReloadIntervalMs = options.endpointReloadIntervalMs ?? 5000;
  if (reloadEnvFile !== '' && endpointReloadIntervalMs > 0) {
    let lastEndpointReloadError: string | null = null;
    const applyEndpointRuntime = (): void => {
      const read = readEndpointRuntimeConfig(reloadEnvFile);
      if (read === null) return;
      if (!read.ok) {
        if (read.error !== lastEndpointReloadError) {
          lastEndpointReloadError = read.error;
          console.error(`[dsh-passwords] 端点登记表热更新失败（保留上一次有效规则）：${read.error}`);
        }
        return;
      }
      lastEndpointReloadError = null;
      const changed =
        read.endpointRules.length !== endpointRules.length ||
        read.endpointRules.some((rule, index) => rule !== endpointRules[index]);
      if (!changed) return;
      endpointRules = read.endpointRules;
      console.warn(
        `[dsh-passwords] 端点登记表已热更新：${endpointRules.length} 条规则`,
      );
      for (const socket of registryAuthorizedSockets) {
        try { socket.destroy(); } catch { /* 已断开 */ }
      }
      registryAuthorizedSockets.clear();
    };
    const reloadTimer = setInterval(applyEndpointRuntime, endpointReloadIntervalMs);
    reloadTimer.unref();
    server.once('close', () => { clearInterval(reloadTimer); });
  }

  return server;
}

/**
 * HTTP→HTTPS 301 跳转服务器（仅 TLS 模式且配置了 redirectPort 时创建）。
 * 解决“网关裸奔在 80 明文”问题：80 不再提供任何页面内容，只做跳转。
 * 自动 HTTPS 模式下同时承载 ACME HTTP-01 挑战应答（/.well-known/acme-challenge/*）。
 */
export function createRedirectServer(
  config: PlatformConfig,
  challengeStore?: Map<string, string>,
): http.Server | null {
  if (config.gateway.tls === null || config.gateway.redirectPort === null) return null;
  const server = http.createServer((req, res) => {
    // ACME HTTP-01 挑战应答：优先于跳转处理（Let's Encrypt 校验走这里）
    if (challengeStore) {
      const pathname = (() => {
        try {
          return new URL(req.url ?? '/', 'http://localhost').pathname;
        } catch {
          return '/';
        }
      })();
      const prefix = '/.well-known/acme-challenge/';
      if (pathname.startsWith(prefix)) {
        const token = pathname.slice(prefix.length).split('/')[0];
        const keyAuthz =
          token !== '' && /^[A-Za-z0-9_-]{1,128}$/.test(token)
            ? challengeStore.get(token)
            : undefined;
        if (keyAuthz !== undefined) {
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Length': String(Buffer.byteLength(keyAuthz)),
            'Cache-Control': 'no-store',
            Connection: 'close',
          });
          res.end(keyAuthz);
          return;
        }
        res.writeHead(404, { 'Content-Length': '0', Connection: 'close' });
        res.end();
        return;
      }
    }
    // Host 头部可能带跳转端口或 :80 后缀，跳转目标去掉它们；空 Host 回退主端口
    const strip = new RegExp(`:(${config.gateway.redirectPort}|80)$`);
    const rawHost = (req.headers.host ?? '').replace(strip, '');
    // 防 Host 反射（HTTP/1.0 可伪造 Host: evil.com → Location: https://evil.com/）：
    // 自动 HTTPS 固定用证书域名；否则用配置的公网主机；再否则严格校验请求 Host 格式
    const candidate = config.gateway.domain || config.gateway.publicHost || rawHost;
    const host =
      /^[A-Za-z0-9.\-[\]:]+$/.test(candidate) && candidate !== ''
        ? candidate
        : `127.0.0.1:${config.gateway.port}`;
    const target = `https://${host}${req.url ?? '/'}`;
    res.writeHead(301, {
      Location: target,
      'Content-Length': '0',
      Connection: 'close',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
    });
    res.end();
  });
  // slowloris 加固：80 跳转端口同样设显式超时 + 连接上限（ACME 挑战不受影响）
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.maxConnections = 256;
  return server;
}
