// dsh 主机侧插件：dsh-passwords 在 dsh 里的"席位"
//   1. /api/dsh-passwords/* 用户管理路由：
//      - GET  /state → 自身信息 + 可见用户列表 + 聊天入口偏好（任何登录用户；
//        子用户不可见全量用户列表）
//      - POST /password /username /users /users/remove → 改密码、改用户名、
//        分配/删除子用户
//      - POST /chat-enabled → 本人聊天入口偏好开关
//      走网关 JWT cookie 鉴权。
//   2. /api/dsh-passwords/patch/* 远程设置补丁路由：
//      - GET  /patch/status → 补丁当前状态（任何登录用户可看）
//      - POST /patch/reload → 通知网关重载补丁并重启 dsh 网页服务
//        （仅主用户可触发，10 分钟冷却；补丁强制启用，无开关）
//   3. /api/dsh-passwords/update/* 自动更新路由：
//      - GET  /update/status → 更新状态（当前/最新版本、下载进度、空闲窗、手动命令；任何登录用户可看）
//      - POST /update/check   → 立即检查 GitHub 最新版本（仅主用户；手动检查不触发下载）
//      - POST /update/auto    → 设置自动更新开关（仅主用户）
//      - POST /update/apply   → 立即安装重启（仅主用户，引擎自带 10 分钟冷却；
//        手动模式未下载完成时先触发下载、需再次点击安装；自动模式为平台连续
//        空闲满 1 小时后网关自动安装重启，无需人工干预）
//   4. /api/dsh-passwords/workspaces：工作区路径清单（仅主用户，供子用户白名单
//      下拉选择）。
//   5. /api/dsh-passwords/internal/sandbox：网关内部接口（仅 loopback + 内部
//      密钥），把受限子用户新会话的沙盒降为其真实授权级别。
//      dsh 升级覆盖补丁后，主用户在设置页点"重载补丁"即可，无需登录服务器。
import type { Context } from '@deepseek-ai/cordis';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import jwt from 'jsonwebtoken';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { existsSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { deploymentGatewayEnv, loadConfig, type PlatformConfig } from './config.js';
import { Database, type UserListRow } from './db.js';
import { createFieldCrypto } from './encrypt.js';
import { AuthService, AuthError, assertNoSqlInjection, type AuthedUser, type RequestMeta } from './auth.js';
import { findDshRoot, patchStatus } from './patch.js';
import { updateApplyHttpStatus } from './update.js';
import { OFFICIAL_API_NAMESPACES, SUBUSER_BLOCKED_API_NAMESPACES, isSubuserBlockedRemoteEndpoint } from './permissions.js';

/** 稳定 cordis 插件名（insert 进 cordis.yml 时用同一个名字） */
export const name = 'dsh-passwords';

/** 依赖 dsh 主机侧的 webServer 服务（路由挂载点） */
export const inject = ['webServer', 'connection'];

/** 网关会话 cookie 名（与 gateway.ts 保持一致） */
const COOKIE_NAME = 'dsh_gateway_token';
/** 请求体上限（用户管理 JSON 都很小） */
const MAX_BODY = 4096;

/** 请求体超限专用错误：读完后回 413，而不是销毁 socket 造成代理 502 */
class BodyTooLargeError extends Error {}
class InvalidJsonBodyError extends Error {}

function readCookie(cookieHeader: string | undefined, cookieName: string): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    // Cookie Chaos 加固（P3）：与 gateway.ts 同口径——只剥离 RFC 6265 的 OWS
    // （ASCII SP/HTAB），cookie 名精确匹配，不按 JS Unicode 空白语义 trim，
    // 杜绝 Unicode 空白前缀的“伪同名”cookie 被归一化读入。
    const trimmed = part.replace(/^[ \t]+/, '');
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq);
    if (key !== cookieName) continue;
    const value = trimmed.slice(eq + 1);
    if (value === '') continue;
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return null;
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(text);
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (tooLarge) return; // 已超限：继续排空剩余数据，保持连接可用于回包
      if (size > MAX_BODY) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('close', () => {
      if (!tooLarge) reject(new Error('request aborted'));
    });
    req.on('end', () => {
      if (tooLarge) {
        // 不销毁 socket：在同一连接上回 413，避免网关代理看到连接重置转成 502
        reject(new BodyTooLargeError());
        return;
      }
      try {
        const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new InvalidJsonBodyError());
          return;
        }
        resolve(parsed as Record<string, unknown>);
      } catch {
        reject(new InvalidJsonBodyError());
      }
    });
    req.on('error', reject);
  });
}

/** 通知网关进程：重载补丁 + 延迟重启 dsh-web（fire-and-forget）。导出供定向测试使用。 */
type DynamicTypertDescriptor = {
  namespace?: unknown;
  method?: unknown;
  mode?: unknown;
  invocation?: { mode?: unknown };
};

type DynamicManifest = {
  generation: string;
  parentPid: number;
  namespaces: string[];
  streamEndpoints: string[];
  exactPaths: string[];
  pathPrefixes: string[];
};

/**
 * 取 DSH 当前已经注册的 Remote namespace/stream 面。
 * 这不是静态 node_modules 扫描：未挂载、disabled 或不存在 typert.host 的插件不会进入清单。
 */
function collectDynamicPluginManifest(ctx: Context): DynamicManifest | null {
  const typert = ctx.get('typert') as unknown as
    | { local?: { list?: () => readonly unknown[] } }
    | undefined;
  const webServer = ctx.get('webServer') as unknown as
    | { exact?: unknown; prefixes?: unknown; upgrades?: unknown }
    | undefined;
  const rows = typert?.local?.list?.();
  if (!Array.isArray(rows)) return null;
  const namespaces = new Set<string>();
  const streamEndpoints = new Set<string>();
  const exactPaths = new Set<string>();
  const pathPrefixes = new Set<string>();
  const collectRouteKeys = (value: unknown, target: Set<string>): void => {
    if (value instanceof Map) {
      for (const key of value.keys()) if (typeof key === 'string') target.add(key);
      return;
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      for (const key of Object.keys(value)) target.add(key);
    }
  };
  collectRouteKeys(webServer?.exact, exactPaths);
  collectRouteKeys(webServer?.prefixes, pathPrefixes);
  // WebSocket upgrade routes are ordinary runtime plugin routes too. Reuse the
  // same path sets so HTTP and WS authorization cannot drift.
  collectRouteKeys(webServer?.upgrades, exactPaths);
  for (const value of rows) {
    if (value === null || typeof value !== 'object') continue;
    const row = value as DynamicTypertDescriptor;
    if (typeof row.namespace !== 'string' || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(row.namespace)) continue;
    // 官方 Remote namespace 必须始终走网关自己的授权/过滤分支；
    // 动态清单只描述普通扩展，不能污染 workspace/session baseline 流。
    if (OFFICIAL_API_NAMESPACES.has(row.namespace) || SUBUSER_BLOCKED_API_NAMESPACES.has(row.namespace)) continue;
    namespaces.add(row.namespace);
    const mode = row.mode ?? row.invocation?.mode;
    if (mode === 'stream' && typeof row.method === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(row.method)) {
      const endpoint = `${row.namespace}/${row.method}`;
      if (!isSubuserBlockedRemoteEndpoint(endpoint)) streamEndpoints.add(endpoint);
    }
  }
  const sortedNamespaces = [...namespaces].sort();
  const sortedStreams = [...streamEndpoints].sort();
  const sortedExact = [...exactPaths]
    .filter((value) => value.startsWith('/') && !value.startsWith('/gateway') &&
      !value.startsWith('/api/dsh-passwords') && value !== '/api' && value !== '/api/')
    .sort()
    .slice(0, 512);
  const sortedPrefixes = [...pathPrefixes]
    .filter((value) => value.startsWith('/') && !value.startsWith('/gateway') &&
      !value.startsWith('/api/dsh-passwords') && value !== '/api' && value !== '/api/')
    .sort()
    .slice(0, 128);
  const generation = createHash('sha256')
    .update(JSON.stringify([sortedNamespaces, sortedStreams, sortedExact, sortedPrefixes]))
    .digest('hex')
    .slice(0, 32);
  return {
    generation,
    parentPid: process.pid,
    namespaces: sortedNamespaces,
    streamEndpoints: sortedStreams,
    exactPaths: sortedExact,
    pathPrefixes: sortedPrefixes,
  };
}

function notifyGatewayPluginManifest(cfg: PlatformConfig, manifest: DynamicManifest): void {
  const mod = cfg.gateway.tls !== null ? https : http;
  const body = JSON.stringify(manifest);
  const request = mod.request(
    `${cfg.gateway.tls !== null ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/plugin-manifest`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-internal-secret': cfg.internalSecret,
        'content-length': String(Buffer.byteLength(body)),
      },
      rejectUnauthorized: false,
      timeout: 3000,
    },
    (response) => response.resume(),
  );
  request.on('error', () => { /* 网关尚未就绪时由下一轮同步 */ });
  request.on('timeout', () => request.destroy());
  request.end(body);
}

function startPluginManifestSync(ctx: Context, cfg: PlatformConfig): void {
  ctx.effect(() => {
    let disposed = false;
    const publish = (): void => {
      if (disposed) return;
      try {
        const manifest = collectDynamicPluginManifest(ctx);
        if (manifest !== null) notifyGatewayPluginManifest(cfg, manifest);
      } catch (error) {
        console.warn('[dsh-passwords] 动态插件清单采集失败（保留网关上一份清单）:', String(error));
      }
    };
    const first = setTimeout(publish, 1000);
    first.unref();
    const timer = setInterval(publish, 30_000);
    timer.unref();
    return () => {
      disposed = true;
      clearTimeout(first);
      clearInterval(timer);
    };
  }, 'dsh-passwords: dynamic plugin manifest');
}

export function notifyGateway(cfg: PlatformConfig): void {
  const mod = cfg.gateway.tls !== null ? https : http;
  const url = `${cfg.gateway.tls !== null ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/patch`;
  const body = JSON.stringify({ action: 'apply' });
  const req = mod.request(
    url,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-internal-secret': cfg.internalSecret,
        'content-length': String(Buffer.byteLength(body)),
      },
      // 网关可能用自签证书，内部回环调用豁免校验
      rejectUnauthorized: false,
      timeout: 4000,
    },
    (res) => {
      res.resume();
    },
  );
  req.on('error', () => {
    // 网关没起来时静默：下次网关启动会自动应用补丁
  });
  // 网关进程存活但卡住不回包时，timeout 选项只设置 socket 空闲上限、不会自动
  // 关闭连接；到点主动销毁，避免请求与 socket 被永久挂住。同属静默失败。
  req.on('timeout', () => {
    req.destroy();
  });
  req.end(body);
}

/** 通知网关自动更新引擎（内部通道带响应）：返回 {statusCode, body}；
 *  网关不在线/超时（8s 上限）/非 JSON → null。status 是同步响应，
 *  check/apply 为后台受理（立即返回 started/结果，下载与安装异步推进）。 */
function callGatewayUpdate(
  cfg: PlatformConfig,
  action: 'status' | 'check' | 'apply' | 'set-auto',
  extra: Record<string, unknown> = {},
): Promise<{ statusCode: number; body: Record<string, unknown> } | null> {
  return new Promise((resolve) => {
    const mod = cfg.gateway.tls !== null ? https : http;
    const url = `${cfg.gateway.tls !== null ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/update`;
    const bodyJson = JSON.stringify({ action, ...extra });
    const req = mod.request(
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-internal-secret': cfg.internalSecret,
          'content-length': String(Buffer.byteLength(bodyJson)),
        },
        // 网关可能用自签证书，内部回环调用豁免校验
        rejectUnauthorized: false,
        timeout: 8000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          let body: Record<string, unknown> = {};
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
            if (typeof parsed === 'object' && parsed !== null) body = parsed as Record<string, unknown>;
          } catch {
            /* 非 JSON 按空处理 */
          }
          resolve({ statusCode: res.statusCode ?? 500, body });
        });
      },
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.end(bodyJson);
  });
}

/** 通知网关进程：某用户会话缓存立即失效（改密/改名/删除后，消除 30 秒撤销窗口）。
 *  返回 boolean：仅网关以 2xx 确认清除才为 true；网关不在线/超时（2s 上限）/
 *  非 2xx（旧版本网关无此接口、内部密钥不一致等）都返回 false——调用方不能把
 *  通知失败伪装成“零窗口成功”，但也不回滚已完成的改密（会话缓存 30 秒 TTL
 *  到期后自然重新查库校验 credential_version，残余窗口有界）。 */
function notifyGatewaySessionInvalidate(cfg: PlatformConfig, userId: number): Promise<boolean> {
  return new Promise((resolve) => {
    const mod = cfg.gateway.tls !== null ? https : http;
    const url = `${cfg.gateway.tls !== null ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/session-invalidate`;
    const body = JSON.stringify({ userId });
    const req = mod.request(
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-internal-secret': cfg.internalSecret,
          'content-length': String(Buffer.byteLength(body)),
        },
        // 网关可能用自签证书，内部回环调用豁免校验
        rejectUnauthorized: false,
        timeout: 2000,
      },
      (res) => {
        const ok = res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 300;
        res.resume();
        resolve(ok);
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end(body);
  });
}

/** 改密/改名/删除后通知网关清会话缓存；网关未确认时记告警（旧会话最多 30 秒内仍有效）。 */
async function invalidateGatewaySessions(cfg: PlatformConfig, userId: number): Promise<void> {
  const confirmed = await notifyGatewaySessionInvalidate(cfg, userId);
  if (!confirmed) {
    console.warn(`[dsh-passwords] 网关未确认会话缓存清除（旧会话最多 30 秒内仍有效，凭据版本校验兜底）: userId=${userId}`);
  }
}

/** 网关启动错误码（与 cli.ts 保持一致）：永久配置/补丁错误不能自动重启。 */
const EXIT_CONFIG_INVALID = 1;
const EXIT_CERT_FAILED = 30;
const EXIT_NO_DOMAIN = 31;
const EXIT_PORT_BUSY = 32;
const EXIT_COOKIE_BRIDGE_UNAVAILABLE = 33;
const EXIT_DSH_ROOT_UNAVAILABLE = 34;
const EXIT_PATCH_TARGET_UNAVAILABLE = 35;
const EXIT_PATCH_VERIFICATION_FAILED = 36;
const EXIT_DSH_VERSION_UNSUPPORTED = 37;

const PERMANENT_GATEWAY_EXIT_CODES = new Set([
  EXIT_CONFIG_INVALID,
  EXIT_CERT_FAILED,
  EXIT_NO_DOMAIN,
  EXIT_PORT_BUSY,
  EXIT_COOKIE_BRIDGE_UNAVAILABLE,
  EXIT_DSH_ROOT_UNAVAILABLE,
  EXIT_PATCH_TARGET_UNAVAILABLE,
  EXIT_PATCH_VERIFICATION_FAILED,
  EXIT_DSH_VERSION_UNSUPPORTED,
]);

export function isPermanentGatewayExitCode(reason: number | string): boolean {
  return typeof reason === 'number' && PERMANENT_GATEWAY_EXIT_CODES.has(reason);
}

/**
 * 插件启动快照与部署文件当前关键字段的漂移清单（空数组 = 一致）。
 * 插件在 apply() 时把配置读进内存快照，而它拉起的网关子进程会重新读取部署文件；
 * 两者若撕裂，网关会带着与插件不同的 JWT/内部密钥或内网上游地址运行，必须拒绝误启。
 * 返回具体键名，便于把差异写进诊断日志（而不是一句笼统的“已变更”）。
 */
export function gatewayConfigDrift(current: PlatformConfig, next: PlatformConfig): string[] {
  const drift: string[] = [];
  if (next.dbPath !== current.dbPath) drift.push('MCP_DB_PATH');
  // dbEncKey 留空时从 SETUP_KEY 派生，所以两者任一变化都改变实际加密密钥。
  if ((next.dbEncKey || next.setupKey) !== (current.dbEncKey || current.setupKey)) drift.push('SETUP_KEY/MCP_DB_ENC_KEY');
  if (next.jwtSecret !== current.jwtSecret) drift.push('MCP_JWT_SECRET');
  if (next.internalSecret !== current.internalSecret) drift.push('MCP_INTERNAL_SECRET');
  if (next.gateway.port !== current.gateway.port) drift.push('MCP_GATEWAY_PORT');
  if (next.gateway.upstream !== current.gateway.upstream) drift.push('MCP_GATEWAY_UPSTREAM');
  if (JSON.stringify(next.gateway.tls) !== JSON.stringify(current.gateway.tls)) drift.push('MCP_GATEWAY_TLS_CERT/MCP_GATEWAY_TLS_KEY');
  return drift;
}

/**
 * 部署配置漂移的有界重试上限。给运维留出还原 .env 或重启 dsh 的窗口；
 * 超过上限后明确报告停机风险，绝不静默停止（原实现只打一行日志就 return）。
 */
export const GATEWAY_CONFIG_DRIFT_MAX_RETRIES = 5;
/** 部署配置漂移的重试间隔（毫秒）。 */
export const GATEWAY_CONFIG_DRIFT_RETRY_MS = 5_000;

/** 漂移重试决策：界内继续有界重试，越界后转为已诊断停机，绝不用错配密钥/端口误启。 */
export function gatewayDriftDecision(attempt: number): 'retry' | 'stopped' {
  return attempt > GATEWAY_CONFIG_DRIFT_MAX_RETRIES ? 'stopped' : 'retry';
}

/** 探测网关是否已在监听（防止 dsh 重启/多开时重复拉起） */
function gatewayAlreadyRunning(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port, timeout: 400 });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
  });
}

/**
 * Wait for a port to become free without ever terminating its owner. This is
 * specifically for the dsh restart handoff: the old password-gateway child
 * may still hold 443 while the new dsh process loads the plugin. A bounded
 * wait preserves unrelated listeners and prevents a permanent skip race.
 */
export async function waitForGatewayPortFree(
  port: number,
  timeoutMs = 15_000,
  intervalMs = 250,
): Promise<boolean> {
  const deadline = Date.now() + Math.max(0, timeoutMs);
  do {
    if (!(await gatewayAlreadyRunning(port))) return true;
    const remaining = deadline - Date.now();
    if (remaining <= 0) return false;
    await new Promise<void>((resolve) => setTimeout(resolve, Math.min(intervalMs, remaining)));
  } while (Date.now() <= deadline);
  return false;
}

function gatewayHealthz(cfg: PlatformConfig): Promise<boolean> {
  return new Promise((resolve) => {
    const secure = cfg.gateway.tls !== null;
    const transport = secure ? https : http;
    const request = transport.request(`${secure ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/healthz`, {
      method: 'GET',
      rejectUnauthorized: false,
      timeout: 1000,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        let body: unknown;
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { body = null; }
        const ok = response.statusCode === 200 && typeof body === 'object' && body !== null &&
          (body as { service?: unknown }).service === 'dsh-passwords';
        resolve(ok);
      });
    });
    request.on('error', () => resolve(false));
    request.on('timeout', () => { request.destroy(); resolve(false); });
    request.end();
  });
}

/** Return the owning dsh PID for a password gateway, or null when unavailable. */
function gatewayOwnerPid(cfg: PlatformConfig): Promise<number | null> {
  return new Promise((resolve) => {
    const secure = cfg.gateway.tls !== null;
    const transport = secure ? https : http;
    const request = transport.request(`${secure ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/owner`, {
      method: 'GET',
      headers: { 'x-internal-secret': cfg.internalSecret },
      rejectUnauthorized: false,
      timeout: 1000,
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => chunks.push(chunk));
      response.on('end', () => {
        if (response.statusCode !== 200) { resolve(null); return; }
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok?: unknown; parentPid?: unknown };
          resolve(body.ok === true && typeof body.parentPid === 'number' && Number.isInteger(body.parentPid) && body.parentPid > 0
            ? body.parentPid
            : null);
        } catch {
          resolve(null);
        }
      });
    });
    request.on('error', () => resolve(null));
    request.on('timeout', () => { request.destroy(); resolve(null); });
    request.end();
  });
}

/**
 * Use the alpha.1 Host-side auth bridge when present. `undefined` means the
 * running dsh is an older release with no bridge; `null` means the bridge was
 * present but returned an invalid value. The function never calls the
 * one-time query-token URL, so it is safe to use after a health failure.
 */
function deriveDshBrowserCookie(connection: unknown, baseUrl: string): string | null | undefined {
  if (!isLoopbackUpstream(baseUrl) || connection === null || typeof connection !== 'object') return undefined;
  const method = (connection as { authenticatedCookie?: unknown }).authenticatedCookie;
  if (typeof method !== 'function') return undefined;
  const expectedCookieName = upstreamAuthCookieName(baseUrl);
  if (expectedCookieName === null) return null;
  try {
    const cookie = String(method.call(connection, baseUrl));
    const escapedName = expectedCookieName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&');
    return new RegExp(`^${escapedName}=[A-Za-z0-9._~-]+$`).test(cookie) ? cookie : null;
  } catch (error) {
    console.error('[dsh-passwords] dsh Host Cookie 派生失败：', error);
    return null;
  }
}

/**
 * dsh alpha 的 Web UI/API/WS 都要求先用进程启动 token 换取 authority-bound
 * dsh-auth cookie。插件和网关属于同一个 dsh 进程拓扑：由插件使用 connection
 * 官方 authenticatedUrl() 完成一次交换，再把 cookie 交给网关子进程；不把
 * 一次性 token 暴露给公网，也不绕过 dsh 的浏览器认证。
 */
interface UpstreamBrowserAuth {
  supported: boolean;
  cookie: string | null;
}

function upstreamAuthCookieName(baseUrl: string): string | null {
  try {
    const authority = new URL(baseUrl).host;
    return `dsh-auth-${createHash('sha256').update(authority).digest('base64url')}`;
  } catch {
    return null;
  }
}

function isLoopbackUpstream(baseUrl: string): boolean {
  try {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const hostname = parsed.hostname;
    if (hostname === 'localhost' || hostname === '[::1]') return true;
    const parts = hostname.split('.');
    return parts.length === 4 && parts[0] === '127' && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  } catch {
    return false;
  }
}

function syncGatewayBrowserCookie(cfg: PlatformConfig, cookie: string): Promise<boolean> {
  return new Promise((resolve) => {
    const secure = cfg.gateway.tls !== null;
    const transport = secure ? https : http;
    const body = JSON.stringify({ cookie });
    const request = transport.request(`${secure ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/upstream-auth`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
        'x-internal-secret': cfg.internalSecret,
      },
      rejectUnauthorized: false,
      timeout: 3000,
    }, (response) => {
      const ok = response.statusCode !== undefined && response.statusCode >= 200 && response.statusCode < 300;
      response.resume();
      resolve(ok);
    });
    request.on('error', () => resolve(false));
    request.on('timeout', () => { request.destroy(); resolve(false); });
    request.end(body);
  });
}

function probeGatewayBrowserCookie(cfg: PlatformConfig): Promise<boolean> {
  return new Promise((resolve) => {
    const secure = cfg.gateway.tls !== null;
    const transport = secure ? https : http;
    const request = transport.request(`${secure ? 'https' : 'http'}://127.0.0.1:${String(cfg.gateway.port)}/gateway/internal/upstream-auth/health`, {
      method: 'GET',
      headers: { 'x-internal-secret': cfg.internalSecret },
      rejectUnauthorized: false,
      timeout: 3000,
    }, (response) => {
      const ok = response.statusCode === 200;
      response.resume();
      resolve(ok);
    });
    request.on('error', () => resolve(false));
    request.on('timeout', () => { request.destroy(); resolve(false); });
    request.end();
  });
}

function exchangeDshBrowserCookie(connection: unknown, baseUrl: string): Promise<UpstreamBrowserAuth> {
  // alpha.1 补丁提供可重复调用的 Host-side Cookie 派生；优先使用它，避免
  // 健康恢复或 dsh 代际切换时再次消费一次性 launch token。
  const derived = deriveDshBrowserCookie(connection, baseUrl);
  if (derived !== undefined) return Promise.resolve({ supported: true, cookie: derived });
  // rc.2 及更早版本没有 alpha 的 BrowserAuth API：保持旧版匿名 loopback
  // 上游行为，不能把“能力不存在”误报成 token 交换失败。
  if (!isLoopbackUpstream(baseUrl)) {
    // 保留原有跨容器/远程上游代理能力，但绝不把本机 dsh launch token
    // 自动发送到非回环地址；远程拓扑必须通过显式 Cookie/外部认证流程接入。
    return Promise.resolve({ supported: false, cookie: null });
  }
  if (connection === null || typeof connection !== 'object') return Promise.resolve({ supported: false, cookie: null });
  const authenticatedUrl = (connection as { authenticatedUrl?: unknown }).authenticatedUrl;
  if (typeof authenticatedUrl !== 'function') return Promise.resolve({ supported: false, cookie: null });
  let launchUrl: string;
  try {
    launchUrl = String(authenticatedUrl.call(connection, baseUrl));
  } catch (error) {
    console.error('[dsh-passwords] 无法生成 dsh Web 一次性 token URL：', error);
    return Promise.resolve({ supported: true, cookie: null });
  }
  let parsed: URL;
  let base: URL;
  try {
    parsed = new URL(launchUrl);
    base = new URL(baseUrl);
  } catch {
    console.error('[dsh-passwords] dsh Web token URL 无效，拒绝启动未认证上游代理');
    return Promise.resolve({ supported: true, cookie: null });
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    !isLoopbackUpstream(launchUrl) ||
    parsed.host !== base.host ||
    parsed.protocol !== base.protocol ||
    parsed.pathname !== '/'
  ) {
    console.error('[dsh-passwords] dsh Web token URL authority/path 不符合本机上游，拒绝启动未认证上游代理');
    return Promise.resolve({ supported: true, cookie: null });
  }
  const transport = parsed.protocol === 'https:' ? https : http;
  return new Promise((resolve) => {
    const expectedCookieName = upstreamAuthCookieName(baseUrl);
    if (expectedCookieName === null) {
      resolve({ supported: true, cookie: null });
      return;
    }
    const request = transport.request(parsed, { method: 'GET', headers: { host: parsed.host } }, (response) => {
      const cookies = response.headers['set-cookie'] ?? [];
      response.resume();
      if (response.statusCode !== 303 || cookies.length === 0) {
        console.error(`[dsh-passwords] dsh Web token 交换失败（HTTP ${String(response.statusCode ?? 0)}）`);
        resolve({ supported: true, cookie: null });
        return;
      }
      const cookie = cookies
        .map((value) => value.split(';', 1)[0] ?? '')
        .find((value) => value.startsWith(`${expectedCookieName}=`));
      if (cookie === undefined || !new RegExp(`^${expectedCookieName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}=[A-Za-z0-9._~-]+$`).test(cookie)) {
        console.error('[dsh-passwords] dsh Web token 交换返回无效 cookie');
        resolve({ supported: true, cookie: null });
        return;
      }
      resolve({ supported: true, cookie });
    });
    request.setTimeout(3000, () => request.destroy(new Error('token exchange timeout')));
    request.on('error', (error) => {
      console.error('[dsh-passwords] dsh Web token 交换失败：', error.message);
      resolve({ supported: true, cookie: null });
    });
    request.end();
  });
}

/** startGateway 的可注入运行时依赖：仅用于定向测试，生产走默认实现。 */
export type GatewayLaunchRuntime = {
  spawn: typeof spawn;
  healthz: (cfg: PlatformConfig) => Promise<boolean>;
  ownerPid: (cfg: PlatformConfig) => Promise<number | null>;
  portFree: (port: number) => Promise<boolean>;
  exchangeBrowserCookie: (connection: unknown, upstreamUrl: string) => Promise<UpstreamBrowserAuth>;
  deploymentEnv: typeof deploymentGatewayEnv;
  loadConfig: typeof loadConfig;
};

const defaultGatewayLaunchRuntime: GatewayLaunchRuntime = {
  spawn,
  healthz: gatewayHealthz,
  ownerPid: gatewayOwnerPid,
  portFree: waitForGatewayPortFree,
  exchangeBrowserCookie: exchangeDshBrowserCookie,
  deploymentEnv: deploymentGatewayEnv,
  loadConfig,
};

/** 子进程是否仍被本插件持有（未退出、未报错）。 */
function holdsLiveGatewayChild(child: ChildProcess | null): boolean {
  return child !== null && child.exitCode === null && child.signalCode === null;
}

/**
 * 自动拉起外部密码门：dsh 启动时（本插件被加载）spawn 网关子进程，
 * 无需任何额外启动命令。dsh 退出时（ctx.dispose）子进程随停；
 * 网关侧另有父进程看门狗兜底（宿主被强杀时自己退出）。
 * 导出供定向测试使用（生命周期只在 dsh 进程加载插件时生效）。
 */
export function startGateway(
  ctx: Context,
  cfg: PlatformConfig,
  explicitUpstream: string,
  runtime: GatewayLaunchRuntime = defaultGatewayLaunchRuntime,
): void {
  const installRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const cliPath = path.join(installRoot, 'dist', 'cli.js');
  // dsh/systemd 可能已提供稳定的部署环境文件。npm 更新后插件模块目录会变成
  // /usr/lib/node_modules/...，不能因此把网关切到新包目录下的另一份 .env/数据库。
  const gatewayEnvFile = process.env.DSH_PASSWORDS_ENV_FILE?.trim() || path.join(installRoot, '.env');
  const gatewayPort = cfg.gateway.port;

  ctx.effect(
    () => {
      const noop = () => {};
      if (!existsSync(cliPath)) {
        console.error('[dsh-passwords] 密码门未编译（缺少 dist/cli.js）：请先到安装目录运行 npm install && npm run build');
        return noop;
      }
      if (process.env.DSH_PASSWORDS_NO_AUTOSTART === '1') return noop;
      let disposed = false;
      let child: ChildProcess | null = null;
      let retryTimer: NodeJS.Timeout | null = null;
      let driftTimer: NodeJS.Timeout | null = null;
      let driftRetries = 0;
      let launching = false;
      let poll: NodeJS.Timeout | null = null;
      let refreshInFlight: Promise<boolean> | null = null;

      let upstreamPort = 3080;
      try {
        const wsPort = (ctx.webServer as unknown as { port?: number }).port;
        if (typeof wsPort === 'number' && wsPort > 0) upstreamPort = wsPort;
      } catch {
        // 拿不到就用默认值
      }
      const upstreamUrl = explicitUpstream !== '' ? explicitUpstream : `http://127.0.0.1:${String(upstreamPort)}`;
      const connection = (ctx as unknown as { connection?: unknown }).connection;

      const refreshCookie = async (): Promise<boolean> => {
        const derived = deriveDshBrowserCookie(connection, upstreamUrl);
        if (derived === undefined) return true;
        if (derived === null) return false;
        return syncGatewayBrowserCookie(cfg, derived);
      };

      const startCookiePolling = (): void => {
        if (disposed || poll !== null || deriveDshBrowserCookie(connection, upstreamUrl) === undefined) return;
        poll = setInterval(() => {
          if (disposed || refreshInFlight !== null) return;
          refreshInFlight = probeGatewayBrowserCookie(cfg).then(async (healthy) => {
            if (disposed) return false;
            if (healthy) return true;
            const refreshed = await refreshCookie();
            if (!refreshed) console.error('[dsh-passwords] 上游认证 Cookie 健康检查失败，且 alpha Host Cookie 刷新未成功');
            return refreshed;
          })
            .catch((error: unknown) => {
              console.error('[dsh-passwords] 上游认证 Cookie 健康检查异常:', String(error));
              return false;
            })
            .finally(() => { refreshInFlight = null; });
        }, 15_000);
      };

      const scheduleRetry = (): void => {
        if (disposed || retryTimer !== null) return;
        retryTimer = setTimeout(() => {
          retryTimer = null;
          void launch();
        }, 1000);
        retryTimer.unref();
      };

      // 配置漂移的有界重试：密钥/端口/上游地址不一致时绝不启动（避免误启），
      // 但也不能只打一行日志就永远停下。超过上限后明确报告停机风险。
      const handleConfigDrift = (drift: string[]): void => {
        driftRetries += 1;
        const detail = drift.join('、');
        if (gatewayDriftDecision(driftRetries) === 'stopped') {
          console.error(`[dsh-passwords] 密码门已停止：部署配置与插件快照持续不一致（${detail}）。为避免带着错配的密钥或端口启动，不再自动重试；请同步 .env 后重启 DeepSeek Harness`);
          return;
        }
        console.error(`[dsh-passwords] 部署配置与插件快照不一致（${detail}）；密钥/端口不一致时拒绝启动，第 ${String(driftRetries)}/${String(GATEWAY_CONFIG_DRIFT_MAX_RETRIES)} 次将在 ${String(GATEWAY_CONFIG_DRIFT_RETRY_MS)}ms 后重试`);
        if (disposed || driftTimer !== null) return;
        driftTimer = setTimeout(() => {
          driftTimer = null;
          void launch();
        }, GATEWAY_CONFIG_DRIFT_RETRY_MS);
        driftTimer.unref();
      };

      const launch = async (): Promise<void> => {
        if (disposed || launching || holdsLiveGatewayChild(child)) return;
        launching = true;
        try {
          // 已经是本插件的健康网关时复用它；不能仅凭“端口可连接”就跳过，
          // 因为 dsh 重启时旧 child 可能正占着端口但即将退出。
          const healthy = await runtime.healthz(cfg);
          if (disposed) return;
          if (healthy) {
            const ownerPid = await runtime.ownerPid(cfg);
            if (disposed) return;
            if (ownerPid === process.pid) {
              const cookieReady = await refreshCookie();
              if (disposed) return;
              if (!cookieReady) {
                console.error('[dsh-passwords] 当前网关属于本 dsh，但上游 Cookie 刷新失败，暂不复用');
                scheduleRetry();
                return;
              }
              startCookiePolling();
              console.error(`[dsh-passwords] 密码门已在运行（端口 ${String(gatewayPort)}），复用当前 dsh 实例`);
              return;
            }
            console.error(`[dsh-passwords] 端口 ${String(gatewayPort)} 上存在旧/其他密码门实例，等待其释放后接管`);
          }
          const portFree = await runtime.portFree(gatewayPort);
          if (disposed) return;
          if (!portFree) {
            console.error(`[dsh-passwords] 密码门端口 ${String(gatewayPort)} 被非本插件进程占用，等待超时；未终止占用者，将稍后重试`);
            scheduleRetry();
            return;
          }
          const browserAuth = await runtime.exchangeBrowserCookie(connection, upstreamUrl);
          if (disposed) return;
          if (browserAuth.supported && browserAuth.cookie === null) {
            console.error('[dsh-passwords] dsh Web 一次性 token 交换失败，拒绝启动未认证网关；稍后重试');
            scheduleRetry();
            return;
          }
          const childEnv = runtime.deploymentEnv(gatewayEnvFile, process.env);
          const nextCfg = runtime.loadConfig({ env: childEnv });
          const drift = gatewayConfigDrift(cfg, nextCfg);
          if (drift.length > 0) {
            handleConfigDrift(drift);
            return;
          }
          driftRetries = 0;
          // 越过所有 await 后再确认一次：dispose 期间绝不能再拉起子进程或启动轮询。
          if (disposed) return;
          const gatewayArgs = explicitUpstream !== ''
            ? [cliPath, 'serve-gateway']
            : [cliPath, 'serve-gateway', '--upstream', upstreamUrl];
          const proc = runtime.spawn(process.execPath, gatewayArgs, {
            cwd: installRoot,
            env: {
              ...childEnv,
              DSH_GATEWAY_PARENT_PID: String(process.pid),
              DSH_PASSWORDS_ENV_FILE: gatewayEnvFile,
              ...(browserAuth.cookie === null ? {} : { DSH_UPSTREAM_AUTH_COOKIE: browserAuth.cookie }),
            },
            stdio: ['ignore', 'inherit', 'inherit'],
          });
          child = proc;
          if (browserAuth.cookie !== null) startCookiePolling();
          // spawn 失败（EACCES/ENOENT 等）会先发 error；Node 文档明确 exit 可能不再触发，
          // 所以必须在这里交出所有权，否则下一次 launch 会被残留的 child 永久挡住。
          proc.on('error', (error) => {
            if (child !== proc) return; // 已有更新的子进程：迟到 error 不得夺回所有权
            child = null;
            if (poll !== null) { clearInterval(poll); poll = null; }
            console.error('[dsh-passwords] 密码门拉起失败:', error);
            scheduleRetry();
          });
          proc.on('exit', (code, signal) => {
            if (child !== proc) return; // 旧子进程迟到的 exit：不得清掉或驱动当前子进程
            child = null;
            if (poll !== null) { clearInterval(poll); poll = null; }
            if (disposed) return;
            const reason = code ?? signal ?? 'unknown';
            if (reason === EXIT_CERT_FAILED) {
              console.error('[dsh-passwords] 密码门未启动（错误码 30：HTTPS 证书签发失败）。检查 80/443 端口与网络；或运行 scripts/start-http.mjs 改用明文 HTTP（有被嗅探风险）');
            } else if (reason === EXIT_NO_DOMAIN) {
              console.error('[dsh-passwords] 密码门未启动（错误码 31：无法确定公网 IP/域名）。检查公网 IP/域名；或运行 scripts/start-http.mjs 改用明文 HTTP（有被嗅探风险）');
            } else if (isPermanentGatewayExitCode(reason)) {
              console.error(`[dsh-passwords] 密码门未启动（永久错误码 ${String(reason)}）。检查 DSH 版本、MCP_DSH_ROOT、补丁状态、Cookie 桥与端口配置后重启 dsh；不自动重试以避免重启循环。`);
            } else {
              console.error(`[dsh-passwords] 密码门进程已退出（code=${String(reason)}）。将在端口释放后重试`);
              scheduleRetry();
            }
          });
        } catch (error) {
          console.error('[dsh-passwords] 部署配置读取失败，请修复配置并重启 DeepSeek Harness:', error);
        } finally {
          launching = false;
        }
      };

      void launch();
      return () => {
        disposed = true;
        if (retryTimer !== null) clearTimeout(retryTimer);
        if (driftTimer !== null) clearTimeout(driftTimer);
        if (poll !== null) clearInterval(poll);
        const running = child;
        if (running !== null && holdsLiveGatewayChild(running)) {
          running.kill('SIGTERM');
          const force = setTimeout(() => {
            if (running.exitCode === null) {
              try { running.kill('SIGKILL'); } catch { /* 已退出 */ }
            }
          }, 3000);
          force.unref();
        }
      };
    },
    'dsh-passwords: gateway autostart',
  );
}

export type AssignableWorkspace = {
  path: string;
  title: string;
  sessions: Array<{ id: string; title: string }>;
};

export type AssignableInventory = {
  workspaces: AssignableWorkspace[];
  assignableSessions: Set<string>;
  retainedSessions: Set<string>;
};

type AssignableWorkspaceRegistry = {
  list(): Array<{ path: string; title: string; sessionIds: readonly string[]; status(): Promise<'ok' | 'missing-dir'> }>;
  archivedSessionIds: readonly string[];
};

type AssignableSessions = { get(id: string): unknown };
type AssignableSessionTitles = { get(session: unknown): { title?: string } | undefined };
type AssignableSessionQuery = {
  readSurface(id: string): Promise<{ events: readonly unknown[] }>;
  readTitle?(id: string): Promise<{ title?: string } | undefined>;
  /**
   * Batched title observation (readTitleSnapshots from dsh-session-query): one call
   * drives the upstream internal concurrent worker pool through the persisted corpus,
   * replacing per-id readTitle calls that each loaded and folded the full session log
   * serially. Structurally matches SessionTitleObservationResult; any shape deviation
   * falls back to per-id reads.
   */
  readTitleSnapshots?(ids: readonly string[]): Promise<readonly {
    sessionId: string;
    status: string;
    value?: { title?: { title?: string } };
    reason?: unknown;
  }[]>;
  listEvents?(id: string): Promise<readonly { type: string }[]>;
};

const INITIAL_SESSION_EVENT_TYPES = new Set([
  'session', 'permission/preset', 'sandbox/mode', 'approval/policy', 'subagent/model-selection-policy',
]);

export function isDefiniteMissingSession(error: unknown): boolean {
  if (error === null || typeof error !== 'object') return false;
  const code = (error as { code?: unknown }).code;
  const message = (error as { message?: unknown }).message;
  return code === 'SESSION_QUERY_SESSION_NOT_FOUND' || code === 'SESSION_QUERY_EVENT_NOT_FOUND' ||
    (typeof message === 'string' && /session.*not found/i.test(message));
}

/** Bounded-concurrency map: preserves input order and avoids memory spikes from decompressing several large session logs at once. */
async function mapBounded<T>(items: readonly T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  if (items.length === 0) return;
  let cursor = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const index = cursor;
      if (index >= items.length) return;
      cursor += 1;
      await fn(items[index]);
    }
  });
  await Promise.all(workers);
}

const normalizeTitle = (value: string | undefined): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined;

type TitleSnapshotsResult = Awaited<ReturnType<NonNullable<AssignableSessionQuery['readTitleSnapshots']>>>;

/** 批量读取是外部边界：只有真正的数组才消费，任何非数组返回都视为契约偏离并回退逐条。 */
const isTitleSnapshots = (value: unknown): value is TitleSnapshotsResult => Array.isArray(value);

/**
 * Batched title read: prefer a single readTitleSnapshots call (upstream-internal
 * concurrency), then fill in individually any ids it missed; if the method is absent,
 * returns a non-array, or the whole batch throws, fall back entirely to per-id readTitle,
 * matching the previous implementation.
 */
async function readAssignableTitles(
  sessionQuery: AssignableSessionQuery,
  ids: readonly string[],
): Promise<{ titles: Map<string, string | undefined>; missing: Set<string> }> {
  const titles = new Map<string, string | undefined>();
  const missing = new Set<string>();
  const readOneTitle = async (id: string): Promise<string | undefined> => {
    try {
      return normalizeTitle((await sessionQuery.readTitle?.(id))?.title);
    } catch (error) {
      if (isDefiniteMissingSession(error)) {
        missing.add(id);
        return undefined;
      }
      throw error;
    }
  };
  if (ids.length === 0) return { titles, missing };
  if (sessionQuery.readTitleSnapshots !== undefined) {
    let results: unknown;
    try {
      results = await sessionQuery.readTitleSnapshots(ids);
    } catch (error) {
      console.warn('[dsh-passwords] 批量标题读取失败，退回逐条读取:', error instanceof Error ? error.message : String(error));
      results = undefined;
    }
    if (results !== undefined && !isTitleSnapshots(results)) {
      console.warn('[dsh-passwords] 批量标题返回非数组，退回逐条读取');
    }
    if (isTitleSnapshots(results)) {
      for (const result of results) {
        if (result === null || typeof result !== 'object') continue;
        const sessionId = typeof result.sessionId === 'string' ? result.sessionId : '';
        if (sessionId === '') continue;
        if (result.status === 'fulfilled') {
          titles.set(sessionId, normalizeTitle(result.value?.title?.title));
        } else if (isDefiniteMissingSession(result.reason)) {
          titles.set(sessionId, undefined);
          missing.add(sessionId);
        } else {
          throw result.reason;
        }
      }
      for (const id of ids) {
        if (titles.has(id)) continue;
        titles.set(id, await readOneTitle(id));
      }
      return { titles, missing };
    }
  }
  for (const id of ids) {
    titles.set(id, await readOneTitle(id));
  }
  return { titles, missing };
}

/**
 * DSH-owned assignment inventory. Live blank sessions remain assignable after
 * session.create(); only persisted, untitled initialization-only slots are hidden.
 *
 * Performance contract: persisted sessions get exactly one batched title read, and any
 * session with a non-empty title never calls readSurface. The previous implementation
 * serially called readSurface + readTitle for every session (each a full log load +
 * fold), so a large session corpus dragged /workspaces and internal/assignable-resources
 * into minutes and tripped the gateway's 60s response-header timeout (504) and its 10s
 * internal probe timeout (502).
 */
export async function listAssignableWorkspaces(
  reg: AssignableWorkspaceRegistry,
  sessions: AssignableSessions | undefined,
  sessionTitle: AssignableSessionTitles | undefined,
  sessionQuery: AssignableSessionQuery | undefined,
): Promise<AssignableWorkspace[]> {
  const query = sessionQuery;
  const archived = new Set(reg.archivedSessionIds.map((id) => String(id)));

  // Stage 1: synchronous placeholder assembly — live sessions take their title in place; persisted sessions only register their id.
  const stages: Array<{ path: string; title: string; slots: Array<{ id: string; title?: string }> }> = [];
  const pending: string[] = [];
  const pendingSeen = new Set<string>();
  for (const workspace of reg.list()) {
    if (await workspace.status() !== 'ok') continue;
    const slots: Array<{ id: string; title?: string }> = [];
    for (const rawId of workspace.sessionIds) {
      const id = String(rawId);
      if (archived.has(id)) continue;
      const live = sessions?.get(id);
      if (live !== undefined) {
        slots.push({ id, title: sessionTitle?.get(live)?.title || id });
        continue;
      }
      if (query === undefined) throw new Error('session query unavailable');
      slots.push({ id });
      if (!pendingSeen.has(id)) {
        pendingSeen.add(id);
        pending.push(id);
      }
    }
    stages.push({ path: workspace.path, title: workspace.title, slots });
  }

  // Stage 2: one batched title observation; sessions that already got a title are done here and never read their full log.
  const titleResult = query === undefined
    ? { titles: new Map<string, string | undefined>(), missing: new Set<string>() }
    : await readAssignableTitles(query, pending);

  // Stage 3: only untitled sessions need readSurface/listEvents, to detect initialization-only empty slots.
  const untitled = pending.filter((id) => !titleResult.titles.get(id)?.trim() && !titleResult.missing.has(id));
  const hidden = new Set(titleResult.missing);
  if (query !== undefined && untitled.length > 0) {
    await mapBounded(untitled, 3, async (id) => {
      try {
        const surface = await query.readSurface(id);
        if (surface.events.length === 0 && query.listEvents) {
          const events = await query.listEvents(id);
          if (events.length > 0 && events.every((event) => INITIAL_SESSION_EVENT_TYPES.has(event.type))) {
            hidden.add(id);
          }
        }
      } catch (error) {
        if (isDefiniteMissingSession(error)) {
          hidden.add(id);
          return;
        }
        throw error;
      }
    });
  }

  // Stage 4: emit in the original order; semantics match the previous implementation.
  const output: AssignableWorkspace[] = [];
  for (const stage of stages) {
    const entries: Array<{ id: string; title: string }> = [];
    for (const slot of stage.slots) {
      if (hidden.has(slot.id)) continue;
      entries.push({ id: slot.id, title: slot.title ?? titleResult.titles.get(slot.id) ?? slot.id });
    }
    output.push({ path: stage.path, title: stage.title, sessions: entries });
  }
  return output;
}

/** Registry-authoritative assignable resources for the gateway save path. */
export type RegistryAssignableResources = {
  folders: string[];
  assignableSessions: string[];
  retainedSessions: string[];
};

/**
 * Save-path authority: derive the assignable folder/session sets from the live DSH
 * registry and archive list only. It deliberately reads no session log — no batched
 * title observation and no surface/event probe — so a permission save never cold-reads
 * the persisted corpus (measured at 40-90s on large corpora).
 *
 * The display inventory's initialization-only-slot filter is intentionally not applied
 * here: it is a presentation rule that requires reading titles, and a submitted session
 * id that the live registry lists and the archive does not is already authorized by the
 * gateway's targeted membership check. Archived sessions stay in `retainedSessions` so
 * existing grants keep their archived history, while new grants of them stay rejected
 * because they are absent from `assignableSessions`.
 */
export async function listAssignableResources(
  reg: AssignableWorkspaceRegistry,
): Promise<RegistryAssignableResources> {
  const folders: string[] = [];
  const candidates: string[] = [];
  const seen = new Set<string>();
  for (const workspace of reg.list()) {
    if (await workspace.status() !== 'ok') continue;
    folders.push(workspace.path);
    for (const rawId of workspace.sessionIds) {
      const id = String(rawId);
      if (seen.has(id)) continue;
      seen.add(id);
      candidates.push(id);
    }
  }
  // 归档状态在枚举期间可能改变；在所有 await 完成后只取一次，令两个输出由同一线性化点派生。
  const retainedSessions = [...new Set(reg.archivedSessionIds.map((id) => String(id)))];
  const retained = new Set(retainedSessions);
  return {
    folders,
    assignableSessions: candidates.filter((id) => !retained.has(id)),
    retainedSessions,
  };
}

/**
 * Display inventory loader for /workspaces (the admin UI dropdown). The enumeration
 * above reads the session corpus (measured at 40-90s on large corpora), so it is
 * read-heavy and write-rare.
 *
 * The gateway save path does not use this loader: internal/assignable-resources derives
 * its authority from the live registry via listAssignableResources and never reads
 * session logs, so a save is neither served from this cache nor delayed by it.
 *
 * Two independent mechanisms:
 *   · Single-flight is unconditional, including when MCP_DSH_PASSWORDS_INVENTORY_TTL_MS
 *     is 0. Concurrent requests would otherwise each re-run the same corpus-wide
 *     enumeration. Joining an in-flight call is observationally the same as having the
 *     later request start after the earlier one resolved; a request arriving after
 *     resolution still recomputes when TTL=0.
 *   · Time-based caching is opt-in (> 0): hits within the TTL are served from memory.
 *     0 (the default) therefore keeps "recompute on every request" semantics, minus the
 *     concurrent duplicate work.
 *
 * What is cached is the display inventory, not authorization data: authorization
 * decisions run against the live registry on every save, so up to 60s of staleness only
 * delays showing a freshly created session in the dropdown — it never relaxes a grant.
 */
type AssignableInventoryLoader = {
  (
    reg: AssignableWorkspaceRegistry,
    sessions: AssignableSessions | undefined,
    sessionTitle: AssignableSessionTitles | undefined,
    sessionQuery: AssignableSessionQuery | undefined,
  ): Promise<AssignableWorkspace[]>;
  refresh(
    reg: AssignableWorkspaceRegistry,
    sessions: AssignableSessions | undefined,
    sessionTitle: AssignableSessionTitles | undefined,
    sessionQuery: AssignableSessionQuery | undefined,
  ): Promise<AssignableWorkspace[]>;
};

export function createAssignableInventoryLoader(ttlMs: number): AssignableInventoryLoader {
  let cached: { at: number; workspaces: AssignableWorkspace[] } | null = null;
  let pending: Promise<AssignableWorkspace[]> | null = null;

  const refresh = async (
    reg: AssignableWorkspaceRegistry,
    sessions: AssignableSessions | undefined,
    sessionTitle: AssignableSessionTitles | undefined,
    sessionQuery: AssignableSessionQuery | undefined,
  ): Promise<AssignableWorkspace[]> => {
    if (pending !== null) return pending;
    const request = listAssignableWorkspaces(reg, sessions, sessionTitle, sessionQuery);
    pending = request;
    try {
      const workspaces = await request;
      if (ttlMs > 0) cached = { at: Date.now(), workspaces };
      return workspaces;
    } finally {
      pending = null;
    }
  };

  const load = async (
    reg: AssignableWorkspaceRegistry,
    sessions: AssignableSessions | undefined,
    sessionTitle: AssignableSessionTitles | undefined,
    sessionQuery: AssignableSessionQuery | undefined,
  ): Promise<AssignableWorkspace[]> => {
    if (ttlMs > 0 && cached !== null && Date.now() - cached.at < ttlMs) return cached.workspaces;
    if (ttlMs > 0 && cached !== null) {
      void refresh(reg, sessions, sessionTitle, sessionQuery).catch((error: unknown) => {
        console.warn(`[dsh-passwords] inventory background refresh failed: ${error instanceof Error ? error.message : String(error)}`);
      });
      return cached.workspaces;
    }
    return refresh(reg, sessions, sessionTitle, sessionQuery);
  };
  return Object.assign(load, { refresh });
}

/**
 * Inventory TTL (ms) read from the gateway child's environment. `> 0` enables the
 * time-based cache; anything else — absent, non-numeric, out of (0, 600_000] — disables
 * that cache (0), so every request recomputes (concurrent requests are still coalesced by
 * the loader's single-flight). Exported so tests can join the `.env` source to the value
 * that actually reaches `createAssignableInventoryLoader`.
 */
export function resolveInventoryTtlMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(String(env.MCP_DSH_PASSWORDS_INVENTORY_TTL_MS ?? '0').trim());
  return Number.isFinite(raw) && raw > 0 && raw <= 600_000 ? raw : 0;
}

/** 启动预热的有限重试预算：DSH 惰性暴露 registry，单次 0ms 尝试可能早于它就绪。 */
const PREWARM_MAX_ATTEMPTS = 6;
const PREWARM_RETRY_MS = 500;

export type AssignableInventoryPrewarmOptions = {
  /** registry 查找次数；每次未命中等待 delayMs 后再试。 */
  attempts: number;
  /** 两次 registry 查找之间的延迟。 */
  delayMs: number;
  /** 可注入的延迟实现，测试无需真实计时器。 */
  wait?: (ms: number) => Promise<void>;
  /** 观察刷新失败与预热耗尽，保留错误可观测性。 */
  onError?: (error: unknown) => void;
};

/**
 * 有界启动预热。DSH 惰性暴露 `workspaceRegistry`，一次性的 0ms 尝试可能在 registry
 * 出现前运行并静默丢失预热；改为有限次轮询，registry 就绪后只刷新一次，且每个失败都
 * 上报。返回取消函数以停止后续轮询（插件 dispose 时调用）。刷新失败只观察不重试：重算
 * 由 loader 负责，预热只为让首个设置页请求命中热缓存。
 */
export function prewarmAssignableInventory(
  getRegistry: () => AssignableWorkspaceRegistry | undefined,
  refresh: (registry: AssignableWorkspaceRegistry) => Promise<unknown>,
  options: AssignableInventoryPrewarmOptions,
): () => void {
  let cancelled = false;
  let timer: NodeJS.Timeout | undefined;
  const delay = async (ms: number): Promise<void> => {
    if (options.wait !== undefined) {
      await options.wait(ms);
      return;
    }
    await new Promise<void>((resolve) => {
      timer = setTimeout(resolve, ms);
      timer.unref?.();
    });
  };
  const run = async (): Promise<void> => {
    for (let attempt = 0; attempt < options.attempts; attempt += 1) {
      if (cancelled) return;
      const registry = getRegistry();
      if (registry !== undefined) {
        try {
          await refresh(registry);
        } catch (error) {
          options.onError?.(error);
        }
        return;
      }
      if (attempt + 1 < options.attempts) await delay(options.delayMs);
    }
    if (!cancelled) {
      options.onError?.(new Error(`workspace registry unavailable after ${options.attempts} attempts`));
    }
  };
  void run();
  return () => {
    cancelled = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}

export function apply(ctx: Context): void {
  let cfg: PlatformConfig;
  let explicitUpstream: string;
  /** Assignable inventory TTL cache (ms); 0 = no time-based caching (single-flight still applies) */
  let inventoryTtlMs = 0;
  try {
    const installRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const envFile = process.env.DSH_PASSWORDS_ENV_FILE?.trim() || path.join(installRoot, '.env');
    const gatewayEnv = deploymentGatewayEnv(envFile, process.env);
    cfg = loadConfig({ env: gatewayEnv });
    explicitUpstream = gatewayEnv.MCP_GATEWAY_UPSTREAM?.trim() ?? '';
    inventoryTtlMs = resolveInventoryTtlMs(gatewayEnv);
  } catch (error) {
    // 配置损坏/缺失：记录日志而不是静默返回（否则 dsh 侧无任何提示，排查困难）
    console.error('[dsh-passwords] 加载配置失败，插件未激活:', error);
    return;
  }
  const loadAssignableInventory = createAssignableInventoryLoader(inventoryTtlMs);
  const workspaceRegistry = (): AssignableWorkspaceRegistry | undefined =>
    ctx.get('workspaceRegistry') as unknown as AssignableWorkspaceRegistry | undefined;
  // DSH 惰性暴露 registry；有界重试替代一次性的 0ms 尝试，避免 registry 未就绪时静默丢失预热。
  const cancelAssignableInventoryPrewarm = inventoryTtlMs > 0
    ? prewarmAssignableInventory(
        workspaceRegistry,
        (registry) => loadAssignableInventory.refresh(
          registry,
          ctx.get('sessions') as unknown as AssignableSessions | undefined,
          ctx.get('sessionTitle') as unknown as AssignableSessionTitles | undefined,
          ctx.get('sessionQuery') as unknown as AssignableSessionQuery | undefined,
        ),
        {
          attempts: PREWARM_MAX_ATTEMPTS,
          delayMs: PREWARM_RETRY_MS,
          onError: (error: unknown) => {
            console.warn(`[dsh-passwords] inventory prewarm failed: ${error instanceof Error ? error.message : String(error)}`);
          },
        },
      )
    : () => {};

  // 未配置 .env（SETUP_KEY 为空）时不初始化数据库，用户管理路由返回 503 提示
  const configured =
    cfg.setupKey !== '' && cfg.setupKey !== 'change-me-to-a-strong-random-key';
  /** patch/reload 冷却（10 分钟一次，防认证后横向 DoS） */
  const PATCH_RELOAD_COOLDOWN_MS = 10 * 60 * 1000;
  let lastPatchReload = 0;
  let db: Database | null = null;
  let auth: AuthService | null = null;
  if (configured) {
    try {
      db = new Database(cfg.dbPath, createFieldCrypto(cfg.dbEncKey, cfg.setupKey));
      db.init();
      auth = new AuthService(cfg, db);
    } catch (error) {
      console.error('[dsh-passwords] 网关数据库初始化失败:', error);
      db = null;
      auth = null;
    }
  }

  /** 从网关 JWT cookie 解析调用方身份（含凭据版本校验） */
  const callerOf = (req: IncomingMessage): AuthedUser | null => {
    if (db === null || auth === null) return null;
    const token = readCookie(req.headers.cookie, COOKIE_NAME);
    if (!token) return null;
    try {
      // 算法白名单：只接受 HS256（与 auth.verifyToken 同口径）
      const payload = jwt.verify(token, cfg.jwtSecret, { algorithms: ['HS256'] }) as jwt.JwtPayload;
      const row = db.getUserById(Number(payload.sub));
      if (!row) return null;
      const cv = typeof payload.cv === 'number' ? payload.cv : 0;
      if (cv !== row.credential_version) return null;
      return { userId: row.id, username: row.username, role: row.role };
    } catch {
      return null;
    }
  };

  /** 统一守卫：跨站拒绝 + 配置检查 + 会话校验 */
  const guard = (req: IncomingMessage, res: ServerResponse): AuthedUser | null => {
    if (req.headers['sec-fetch-site'] === 'cross-site') {
      writeJson(res, 403, { ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
      return null;
    }
    // 写操作同源校验：Sec-Fetch-Site 可被缺省，text/plain 可免预检——浏览器
    // 携带 Origin 时严格与 Host 一致（含 null Origin 拒绝），封堵同站兄弟子域
    // 带凭据调用改密/删用户等路由。无 Origin 的非浏览器客户端维持原行为。
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method ?? '')) {
      const origin = typeof req.headers.origin === 'string' ? req.headers.origin : '';
      if (origin !== '') {
        try {
          const parsed = new URL(origin);
          if (parsed.origin === 'null' || parsed.host !== String(req.headers.host ?? '')) {
            writeJson(res, 403, { ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
            return null;
          }
        } catch {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN_CSRF', error: 'forbidden' });
          return null;
        }
      }
      // 状态变更路由只接受 JSON：text/plain 等简单类型可绕过 CORS 预检，
      // 是跨站带凭据发送的常见载体——显式拒绝。
      const ct = String(req.headers['content-type'] ?? '');
      if (ct !== '' && !ct.toLowerCase().startsWith('application/json')) {
        writeJson(res, 415, { ok: false, code: 'INVALID', error: 'Content-Type must be application/json' });
        return null;
      }
    }
    if (db === null || auth === null) {
      writeJson(res, 503, {
        ok: false,
        code: 'NOT_CONFIGURED',
        error: '未配置：请先完成 dsh-passwords 部署（.env 中 SETUP_KEY 等），再重启 dsh',
      });
      return null;
    }
    const caller = callerOf(req);
    if (!caller) {
      writeJson(res, 401, { ok: false, code: 'NOT_AUTHENTICATED', error: '未登录或会话已失效' });
      return null;
    }
    return caller;
  };

  const metaOf = (req: IncomingMessage): RequestMeta => ({
    ip: 'gateway',
    userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
  });

  const requireMethod = (req: IncomingMessage, res: ServerResponse, method: string): boolean => {
    if (req.method === method) return true;
    res.setHeader('Allow', method);
    writeJson(res, 405, { ok: false, code: 'METHOD_NOT_ALLOWED', error: 'Method not allowed' });
    return false;
  };

  /** 错误响应：携带稳定 code（设置页卡片按 dsh 语言本地化）+ 中文兜底文案 */
  const failJson = (res: ServerResponse, error: unknown): void => {
    if (error instanceof InvalidJsonBodyError) {
      writeJson(res, 400, { ok: false, code: 'INVALID', error: '请求体必须是 JSON 对象' });
      return;
    }
    if (error instanceof AuthError) {
      writeJson(res, error.status, { ok: false, code: error.code, error: error.message });
      return;
    }
    if (error instanceof BodyTooLargeError) {
      writeJson(res, 413, { ok: false, code: 'BODY_TOO_LARGE', error: '请求体过大（上限 4KB）' });
      return;
    }
    writeJson(res, 500, {
      ok: false,
      code: 'INTERNAL',
      error: error instanceof Error ? error.message : '内部错误',
    });
  };

  const internalRequestAuthorized = (req: IncomingMessage): boolean => {
    const peer = req.socket.remoteAddress ?? '';
    if (peer !== '127.0.0.1' && peer !== '::1' && peer !== '::ffff:127.0.0.1') return false;
    const supplied = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
    const expected = cfg.internalSecret;
    const a = Buffer.from(supplied);
    const b = Buffer.from(expected);
    return a.length === b.length && timingSafeEqual(a, b);
  };



  // ── /api/dsh-passwords/* 路由（exact 路由先于连接插件的 /api 前缀命中） ──
  const routes: WebRoute[] = [
    {
      kind: 'exact',
      path: '/api/dsh-passwords/state',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'GET')) return;
        // F-05：全量用户列表仅主用户可见；子用户只见自己 + 有消息往来的用户
        // （避免多租户场景下的用户名目录泄露给低权限账号）
        // F-10：子用户的“自己”行用安全投影（getUserListRowById），不泄露 password_hash
        const me = caller.role === 'admin' ? null : db!.getUserListRowById(caller.userId);
        const users: UserListRow[] =
          caller.role === 'admin' ? db!.listUsers() : [...(me ? [me] : []), ...db!.listMessageContacts(caller.userId)];
        writeJson(res, 200, {
          ok: true,
          me: { username: caller.username, role: caller.role },
          users,
          // 聊天入口为按用户同步的显示偏好：未设置默认开启；用户跨设备登录同一账号时一致。
          chatEnabled: db!.getSetting(`chat_enabled:${String(caller.userId)}`) !== '0',
          // 媒体权限与 allowUpload 独立：主用户始终可用，子用户按当前权限实时读取；
          // 网关仍会在 init/PUT/发送/读取各阶段再次强制校验。
          mediaEnabled: caller.role === 'admin' || db!.getPermissions(caller.userId)?.allow_chat_media === true,
          // 文件下载（右侧栏文件列表的下载按钮）：主用户不受限，子用户需
          // allow_git_download；目录白名单与敏感路径仍由 /gateway/api/download 强制。
          fileDownload: caller.role === 'admin' || db!.getPermissions(caller.userId)?.allow_git_download === true,
        });
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/password',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        try {
          const body = await readJsonBody(req);
          const hasTarget = Object.prototype.hasOwnProperty.call(body, 'target');
          if (hasTarget && (typeof body.target !== 'string' || body.target === '')) {
            writeJson(res, 400, { ok: false, code: 'INVALID', error: 'target 无效' });
            return;
          }
          const target = hasTarget ? (body.target as string) : caller.username;
          assertNoSqlInjection(target, 'target'); // 与 /users/remove 同口径的纵深防御
          const password = typeof body.password === 'string' ? body.password : '';
          // F-06：自助改密（target 为自己）需携带当前密码，服务端 bcrypt 校验
          const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : undefined;
          const targetUser = db!.getUserByUsername(target);
          await auth!.changePassword(caller, target, password, metaOf(req), currentPassword);
          // 改密后旧会话全部失效：等网关确认清掉缓存（未确认时告警，TTL 兜底）
          if (targetUser) await invalidateGatewaySessions(cfg, targetUser.id);
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/username',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        try {
          const body = await readJsonBody(req);
          const hasTarget = Object.prototype.hasOwnProperty.call(body, 'target');
          if (hasTarget && (typeof body.target !== 'string' || body.target === '')) {
            writeJson(res, 400, { ok: false, code: 'INVALID', error: 'target 无效' });
            return;
          }
          const target = hasTarget ? (body.target as string) : caller.username;
          assertNoSqlInjection(target, 'target'); // 与 /users/remove 同口径的纵深防御
          const username = typeof body.username === 'string' ? body.username : '';
          assertNoSqlInjection(username, 'username');
          const targetUser = db!.getUserByUsername(target);
          await auth!.renameUser(caller, target, username, metaOf(req));
          // 改名同样 bump credential_version：等网关清缓存（未确认时告警，TTL 兜底）
          if (targetUser) await invalidateGatewaySessions(cfg, targetUser.id);
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/users',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        try {
          const body = await readJsonBody(req);
          const username = typeof body.username === 'string' ? body.username : '';
          const password = typeof body.password === 'string' ? body.password : '';
          assertNoSqlInjection(username, 'username');
          await auth!.addSubUser(caller, username, password, metaOf(req));
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/users/remove',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        try {
          const body = await readJsonBody(req);
          const target = typeof body.target === 'string' ? body.target : '';
          assertNoSqlInjection(target, 'target');
          const targetUser = db!.getUserByUsername(target);
          // DB 删除会级联媒体元数据；先取出服务端生成的对象键，删除成功后
          // 再从固定私有目录清理文件本体。客户端文件名/路径从不参与拼接。
          const mediaKeys = targetUser ? db!.peekUserMediaRemoval(targetUser.id).storage_keys : [];
          await auth!.removeUser(caller, target, metaOf(req));
          if (targetUser) {
            const mediaDir = path.join(path.dirname(cfg.dbPath), 'message-media', 'objects');
            for (const key of mediaKeys) {
              if (!/^[A-Za-z0-9_-]{8,128}$/.test(key)) continue;
              try {
                unlinkSync(path.join(mediaDir, key));
              } catch (error) {
                // 数据删除已成功；文件清理可由网关 sweep/运维再次处理。
                console.warn(`[dsh-passwords] 删除用户媒体文件失败 key=${key}:`, String(error));
              }
            }
            await invalidateGatewaySessions(cfg, targetUser.id);
          }
          writeJson(res, 200, { ok: true });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/chat-enabled',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        try {
          const body = await readJsonBody(req);
          if (typeof body.enabled !== 'boolean') {
            writeJson(res, 400, { ok: false, code: 'INVALID', error: 'enabled 必须为布尔值' });
            return;
          }
          // 显示偏好按用户持久化，而非全局开关：任意账号只能控制自己的聊天入口。
          db!.setSetting(`chat_enabled:${String(caller.userId)}`, body.enabled ? '1' : '0');
          writeJson(res, 200, { ok: true, chatEnabled: body.enabled });
        } catch (error) {
          failJson(res, error);
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/patch/status',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'GET')) return;
        try {
          const root = findDshRoot(cfg.patch.dshRoot);
          const status = root ? patchStatus(root) : null;
          writeJson(res, 200, { ok: true, status });
        } catch {
          writeJson(res, 200, { ok: true, status: null });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/patch/reload',
      handler: (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        // 仅主用户可触发 + 冷却（10 分钟一次）：防止任意登录用户（含只读沙盒子用户）
        // 反复重启 dsh 网页服务造成认证后横向 DoS
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        const now = Date.now();
        const last = lastPatchReload;
        if (now - last < PATCH_RELOAD_COOLDOWN_MS) {
          const remainMin = Math.ceil((PATCH_RELOAD_COOLDOWN_MS - (now - last)) / 60000);
          writeJson(res, 429, { ok: false, code: 'RATE_LIMITED', error: `补丁重载过于频繁，请 ${remainMin} 分钟后再试` });
          return;
        }
        lastPatchReload = now;
        // 补丁强制启用，重载只是重新应用 + 重启 dsh 网页服务
        notifyGateway(cfg);
        writeJson(res, 202, { ok: true, message: '补丁重载中：dsh 网页服务即将重启（约 3-5 秒）' });
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/update/status',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'GET')) return;
        const result = await callGatewayUpdate(cfg, 'status');
        if (result === null) {
          writeJson(res, 502, { ok: false, code: 'BAD_GATEWAY', error: '更新服务不可用（网关未就绪）' });
          return;
        }
        const body = caller.role === 'admin'
          ? result.body
          : { ...result.body, manualCommand: '' };
        writeJson(res, 200, body);
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/update/check',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        // 手动检查只发现 GitHub 最新版本；下载和安装由更新工作流单独触发。
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        const result = await callGatewayUpdate(cfg, 'check');
        if (result === null) {
          writeJson(res, 502, { ok: false, code: 'BAD_GATEWAY', error: '更新服务不可用（网关未就绪）' });
          return;
        }
        writeJson(res, 202, result.body);
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/update/auto',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        try {
          const body = await readJsonBody(req);
          if (typeof body.enabled !== 'boolean') {
            writeJson(res, 400, { ok: false, code: 'INVALID', error: 'enabled 必须为布尔值' });
            return;
          }
          const result = await callGatewayUpdate(cfg, 'set-auto', { enabled: body.enabled });
          if (result === null) {
            writeJson(res, 502, { ok: false, code: 'BAD_GATEWAY', error: '更新服务不可用（网关未就绪）' });
            return;
          }
          writeJson(res, result.statusCode >= 200 && result.statusCode < 300 ? 200 : result.statusCode, result.body);
        } catch (error) {
          writeJson(res, 400, { ok: false, code: 'INVALID', error: error instanceof Error ? error.message : String(error) });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/update/apply',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'POST')) return;
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        const result = await callGatewayUpdate(cfg, 'apply');
        if (result === null) {
          writeJson(res, 502, { ok: false, code: 'BAD_GATEWAY', error: '更新服务不可用（网关未就绪）' });
          return;
        }
        const status = updateApplyHttpStatus(result.body);
        const body = status >= 400 && typeof result.body.error !== 'string' && typeof result.body.message === 'string'
          ? { ...result.body, error: result.body.message }
          : result.body;
        writeJson(res, status, body);
      },
    },

    {
      kind: 'exact',
      path: '/api/dsh-passwords/agent-presets',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'GET')) return;
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        try {
          const registry = ctx.get('agentPresets') as unknown as
            | { list(): Promise<Array<{ id: string; trust: 'system' | 'user'; isDefault: boolean; name?: string; description?: string; broken?: string }>> }
            | undefined;
          const presets = registry === undefined ? [] : await registry.list();
          writeJson(res, 200, { ok: true, presets });
        } catch (error) {
          writeJson(res, 502, { ok: false, code: 'PRESETS_UNAVAILABLE', error: error instanceof Error ? error.message : 'Agent preset 暂不可用' });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/workspaces',
      handler: async (req, res) => {
        const caller = guard(req, res);
        if (!caller) return;
        if (!requireMethod(req, res, 'GET')) return;
        if (caller.role !== 'admin') {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: '仅主用户可操作' });
          return;
        }
        try {
          const registry = ctx.get('workspaceRegistry') as unknown as AssignableWorkspaceRegistry | undefined;
          if (registry === undefined) throw new Error('workspace registry unavailable');
          const sessions = ctx.get('sessions') as unknown as AssignableSessions | undefined;
          const sessionTitle = ctx.get('sessionTitle') as unknown as AssignableSessionTitles | undefined;
          const sessionQuery = ctx.get('sessionQuery') as unknown as AssignableSessionQuery | undefined;
          const workspaces = await loadAssignableInventory(registry, sessions, sessionTitle, sessionQuery);
          writeJson(res, 200, { ok: true, workspaces });
        } catch (error) {
          writeJson(res, 502, {
            ok: false,
            code: 'WORKSPACES_UNAVAILABLE',
            error: error instanceof Error ? error.message : '工作区暂不可用',
          });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/internal/assignable-resources',
      handler: async (req, res) => {
        if (!internalRequestAuthorized(req)) {
          writeJson(res, 403, { ok: false, code: 'FORBIDDEN', error: 'forbidden' });
          return;
        }
        if (!requireMethod(req, res, 'GET')) return;
        try {
          const registry = ctx.get('workspaceRegistry') as unknown as AssignableWorkspaceRegistry | undefined;
          if (registry === undefined) throw new Error('workspace registry unavailable');
          // 保存路径的权威来自实时 registry/archive，不读会话日志、不经过展示缓存；
          // 历史 grant 的保留判定在 admin 侧结合当前 DB 集合完成。
          const { folders, assignableSessions, retainedSessions } = await listAssignableResources(registry);
          writeJson(res, 200, {
            ok: true,
            folders,
            sessions: assignableSessions,
            assignableSessions,
            retainedSessions,
          });
        } catch (error) {
          writeJson(res, 502, {
            ok: false,
            code: 'RESOURCES_UNAVAILABLE',
            error: error instanceof Error ? error.message : '可分配资源暂不可用',
          });
        }
      },
    },
    {
      kind: 'exact',
      path: '/api/dsh-passwords/internal/sandbox',
      handler: (req, res) => {
        if (!requireMethod(req, res, 'POST')) return;
        // F-26：仅网关进程（loopback + 内部密钥）可调——把受限子用户新会话的
        // 沙盒从 dsh 默认的 workspace-write 降为其真实授权级别（append sandbox/mode）。
        const remoteIp = req.socket.remoteAddress ?? '';
        if (remoteIp !== '127.0.0.1' && remoteIp !== '::1' && remoteIp !== '::ffff:127.0.0.1') {
          writeJson(res, 403, { ok: false, error: 'forbidden' });
          return;
        }
        const secret = typeof req.headers['x-internal-secret'] === 'string' ? req.headers['x-internal-secret'] : '';
        const a = Buffer.from(secret);
        const b = Buffer.from(cfg.internalSecret);
        if (a.length !== b.length || !timingSafeEqual(a, b)) {
          writeJson(res, 403, { ok: false, error: 'forbidden' });
          return;
        }
        readJsonBody(req)
          .then((body) => {
            const sessionId = typeof body.sessionId === 'string' ? body.sessionId : '';
            const mode = typeof body.mode === 'string' ? body.mode : '';
            if (!sessionId || (mode !== 'read-only' && mode !== 'workspace-write' && mode !== 'danger-full-access')) {
              writeJson(res, 400, { ok: false, error: 'invalid' });
              return;
            }
            const sessions = ctx.get('sessions') as unknown as
              | { get: (id: string) => { append: (type: string, data: unknown) => void } | undefined }
              | undefined;
            const session = sessions?.get(sessionId);
            if (!session) {
              writeJson(res, 404, { ok: false, error: 'no session' });
              return;
            }
            session.append('sandbox/mode', { mode });
            writeJson(res, 200, { ok: true });
          })
          .catch((error) => failJson(res, error))
          .catch(() => writeJson(res, 400, { ok: false, error: 'bad body' }));
      },
    },
  ];

  ctx.effect(
    () => {
      const disposers = routes.map((route) => ctx.webServer.register(route));
      return () => {
        cancelAssignableInventoryPrewarm();
        for (const dispose of disposers) dispose();
      };
    },
    'dsh-passwords: user management routes',
  );

  // 自动拉起密码门（.env 未配置时跳过，避免在未安装的环境里误启）
  if (configured) {
    startGateway(ctx, cfg, explicitUpstream);
    startPluginManifestSync(ctx, cfg);
  }
}
