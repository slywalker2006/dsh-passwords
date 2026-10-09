// 模型限制 + 聊天媒体投放的端到端契约测试（本轮新增交付）。
//
// 设计依据：docs/plans/2026-09-15-model-restrictions-chat-media-design.md
// 两项能力都必须由网关强制，前端隐藏控件不是授权边界。
//
// ── 模型 allowlist（allowed_models）契约 ────────────────────────────────
//   - 权限 API 接受 allowed_models：null = 不限制、[] = 禁止全部、
//     非空数组 = 只允许 `provider/model` 稳定 ID。
//   - 网关在 session/modelCatalog 上按 allowlist 过滤返回项。
//   - session/selectModel、session/create、session/fork、session/prompt
//     在请求命中 allowlist 之外的模型时必须 403，且不得到达上游。
//   - 主用户不受限制；权限收紧后旧会话不能继续使用被撤销模型。
//
// ── 聊天媒体（allow_chat_media）契约 ──────────────────────────────────
//   - allow_chat_media 独立于 allow_upload：关闭时 init/上传/携带媒体发消息
//     全部拒绝；开启时才放行。
//   - init 校验类型、大小，PUT 校验魔数与 MIME，纯媒体消息（空文本 + 媒体）
//     必须可发送。
//   - 媒体读取按关联消息的可见性鉴权（IDOR / 私信可见性），不做永久公开 URL。
//   - 视频读取支持 Range。
//
// 注意：本文件是新增测试，只锁定「已批准设计」的对外契约，不修改生产代码。
// 若网关尚未实现对应分支，失败用例就是红测，期望接口见各用例断言与文件头的
// 契约说明（端点名 / 字段名 / 状态码均为设计文档口径）。

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, ReadStream, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options?: { noServer?: boolean }) => any;
  WebSocket: { new (url: string, options?: { headers?: Record<string, string> }): any };
};

import { createGatewayServer, internalProbeTimeoutMs } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import type { PlatformConfig } from '../src/config.js';

test('internal assignable-resource probe timeout keeps a bounded default', () => {
  assert.equal(internalProbeTimeoutMs({}), 10_000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '' }), 10_000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '999' }), 10_000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '1000' }), 1000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '600000' }), 600_000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '600001' }), 10_000);
  assert.equal(internalProbeTimeoutMs({ MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: 'invalid' }), 10_000);
});

const HASH = '$2a$10$dummyhashdummyhashdummyhashdu';

/** 中文文本消息正文（纯文本兼容性回归用） */
const TEXT_ONLY_BODY = { content: '纯文本留言' };

/** 1×1 PNG 的真实字节（魔数 89 50 4E 47 0D 0A 1A 0A） */
const PNG_BYTES = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64',
);

/** 最小 MP4（ftyp box 魔数：00 00 00 18 66 74 79 70 6D 70 34 32） */
const MP4_BYTES = Buffer.concat([
  Buffer.from([0x00, 0x00, 0x00, 0x18]),
  Buffer.from('ftypmp42', 'binary'),
  Buffer.alloc(64, 0x00),
]);

/** 伪装成 PNG 的 HTML（魔数校验必须拒绝：MIME 声明不可信） */
const FAKE_PNG_HTML = Buffer.from('<html><body>not an image</body></html>', 'utf8');

let tempDir: string;
let db: Database;
let upstream: http.Server;
let gateway: http.Server;
let gatewayPort = 0;
let adminCookie = '';
let adminId = 0;
let adminUsername = '';
let restrictedCookie = '';
let restrictedId = 0;
let restrictedUsername = '';
let otherCookie = '';
let otherId = 0;
let otherUsername = '';
/** 上游收到的请求 URL 列表（用于断言「未到达上游」） */
let upstreamCalls: string[] = [];
/** session/modelCatalog 的官方形状（DSH 0.1.6-alpha.1）：
 *  provider 身份在 group.id，model 只有 id/name，default/routableProviders/failures 同理。 */
let modelCatalogGroups: Array<Record<string, unknown>> = [
  { id: 'openai', name: 'OpenAI', models: [{ id: 'gpt-5', name: 'GPT-5' }] },
  { id: 'anthropic', name: 'Anthropic', models: [{ id: 'claude-sonnet-4', name: 'Claude Sonnet 4' }] },
  { id: 'deepseek', name: 'DeepSeek', models: [{ id: 'deepseek-chat', name: 'DeepSeek Chat' }] },
];
let modelCatalogDefault: Record<string, unknown> = { provider: 'openai', model: 'gpt-5' };
/** session/history 与 session/page 的官方 records 窗口；空窗口不代表会话没有模型选择。 */
let historyPageRecords: unknown[] = [];

/** 权限保存的可分配资源核验快照（会话 ID 列表）：用例可临时替换以模拟归档/并发新增。 */
let assignableSessionIds: string[] = ['session-visible'];
/** 资源核验请求到达时的钩子。权限保存会在 `await fetchAssignableResources()` 处让出
 *  事件循环，钩子用于确定性地模拟该窗口内子用户 session/create 的并发 grant 追加。 */
let duringAssignableResources: (() => void) | null = null;

/** 全部 catalog 的 provider/model 稳定 ID（不受 allowlist 影响） */
function allCatalogModelIds(): string[] {
  return modelCatalogGroups.flatMap((group) =>
    ((group.models as Array<{ id: string }> | undefined) ?? []).map((model) => `${String(group.id)}/${model.id}`),
  );
}

/** 从过滤后的 catalog 里取出可见的 provider/model 稳定 ID */
function visibleCatalogModelIds(value: unknown): string[] {
  if (value === null || typeof value !== 'object') return [];
  const groups = (value as { groups?: unknown }).groups;
  if (!Array.isArray(groups)) return [];
  return groups.flatMap((group) => {
    const row = group as { id?: unknown; models?: unknown };
    if (typeof row.id !== 'string' || !Array.isArray(row.models)) return [];
    return (row.models as Array<{ id?: unknown }>)
      .map((model) => (typeof model?.id === 'string' ? `${row.id as string}/${model.id}` : ''))
      .filter((id) => id !== '');
  });
}
/** 官方 alpha.3 ClientConnection 信封。业务参数必须嵌在 payload.args.request：
 *  网关刻意跳过 args 层（它是 dsh 不消费的伪字段），只有 args.request 里的
 *  字段才被当作真实 wire 参数；认证/归属校验与上游转发都按这个形状工作。 */
function rpcEnvelope(method: string, request: Record<string, unknown>): Record<string, unknown> {
  return { type: 'client-request', rpcId: `rpc-${method}`, method, payload: { args: { request } } };
}

/** 从测试用的 ClientConnection 信封里取业务参数（payload.args.request） */
function rpcRequestPayloadOfTest(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object') return {};
  const payload = (value as { payload?: unknown }).payload;
  if (payload === null || typeof payload !== 'object') return {};
  const args = (payload as { args?: unknown }).args;
  if (args === null || typeof args !== 'object') return {};
  const request = (args as { request?: unknown }).request;
  return request !== null && typeof request === 'object' ? (request as Record<string, unknown>) : (args as Record<string, unknown>);
}

/** 上游是否收到过某个 RPC（兼容点号/斜杠两种写法） */
function upstreamSaw(rpc: string): boolean {
  const pattern = new RegExp(`^/api/${rpc.replace('.', '[./]')}([?/]|$)`);
  return upstreamCalls.some((url) => pattern.test(url));
}

/** 把 provider/model 拼成设计文档中的稳定 ID */
function modelId(provider: string, model: string): string {
  return `${provider}/${model}`;
}

interface Res {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: Record<string, unknown>;
}

function req(
  method: string,
  url: string,
  options: { cookie?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<Res> {
  const payload = options.body === undefined ? undefined : JSON.stringify(options.body);
  return new Promise((resolve, reject) => {
    const r = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        method,
        path: url,
        headers: {
          cookie: options.cookie ?? adminCookie,
          ...(payload !== undefined
            ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) }
            : {}),
          ...options.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(body) as Record<string, unknown>;
          } catch {
            /* 非 JSON 响应（403 页面等）保持空对象 */
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body, json });
        });
      },
    );
    r.on('error', reject);
    r.end(payload);
  });
}

/** 二进制 PUT（媒体上传用：不能走 JSON 序列化） */
function putBytes(
  url: string,
  bytes: Buffer,
  options: { cookie?: string; headers?: Record<string, string> } = {},
): Promise<Res> {
  return new Promise((resolve, reject) => {
    const r = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        method: 'PUT',
        path: url,
        headers: {
          cookie: options.cookie ?? adminCookie,
          'content-type': 'application/octet-stream',
          'content-length': String(bytes.length),
          ...options.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(body) as Record<string, unknown>;
          } catch {
            /* 非 JSON 响应 */
          }
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body, json });
        });
      },
    );
    r.on('error', reject);
    r.end(bytes);
  });
}

/** 从 init 响应里取 upload ID（契约字段：uploadId） */
function uploadIdOf(res: Res): string {
  const uploadId = res.json.uploadId;
  if (typeof uploadId === 'string' && uploadId.length > 0) return uploadId;
  const mediaId = res.json.mediaId;
  return typeof mediaId === 'string' ? mediaId : '';
}

/** 从消息响应里取媒体 ID 列表（兼容 `media` / `mediaIds` 两种投影） */
function mediaIdsOf(message: Record<string, unknown> | undefined): string[] {
  if (message === undefined) return [];
  const media = message.media;
  if (Array.isArray(media)) {
    return media
      .map((item) => (item !== null && typeof item === 'object' ? (item as Record<string, unknown>).id : undefined))
      .filter((id): id is string => typeof id === 'string' && id.length > 0);
  }
  const ids = message.mediaIds;
  return Array.isArray(ids) ? ids.filter((id): id is string => typeof id === 'string') : [];
}

/** 完成一次「init → PUT → 返回媒体 ID」上传，失败时用例自行断言 */
async function uploadMedia(
  cookie: string,
  kind: 'sticker' | 'image' | 'video',
  mimeType: string,
  bytes: Buffer,
  fileName = 'asset.bin',
): Promise<{ init: Res; put: Res; mediaId: string }> {
  const init = await req('POST', '/gateway/api/message-media/init', {
    cookie,
    body: { kind, mimeType, byteSize: bytes.length, fileName },
  });
  const mediaId = uploadIdOf(init);
  if (init.status !== 200 || mediaId === '') return { init, put: init, mediaId: '' };
  const put = await putBytes(`/gateway/api/message-media/${encodeURIComponent(mediaId)}`, bytes, {
    cookie,
    headers: { 'content-type': mimeType },
  });
  return { init, put, mediaId };
}

/** 建立子用户的 workspace/session 访问快照：走与生产相同的 Remote mux workspace/follow
 *  基线路径（access 映射只由 workspace/follow 基线/workspace.list 投影建立）。 */
function seedRemoteBaseline(cookieValue: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = new NodeWebSocket(`ws://127.0.0.1:${String(gatewayPort)}/api/remote.mux`, {
      headers: { cookie: cookieValue, origin: 'http://127.0.0.1', host: '127.0.0.1' },
    });
    const timer = setTimeout(() => {
      client.terminate();
      reject(new Error('Remote mux baseline timeout'));
    }, 3000);
    client.once('error', (error: Error) => {
      clearTimeout(timer);
      reject(error);
    });
    client.once('open', () => {
      client.send(
        JSON.stringify({ type: 'open', streamId: 'baseline-seed', endpoint: 'workspace/follow', payload: { args: {} } }),
      );
    });
    client.once('message', () => {
      clearTimeout(timer);
      client.close();
      resolve();
    });
  });
}

function subCookie(user: { id: number; username: string }): string {
  return `dsh_gateway_token=${jwt.sign(
    { sub: String(user.id), username: user.username, cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  )}`;
}

/** 直接写权限行（模拟主用户在设置页保存），避免每个用例都走一遍权限 API */
function setPerms(userId: number, extra: Record<string, unknown>): void {
  db.setPermissions(userId, {
    allowedFolders: ['/workspaces/visible'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    allowSsh: false,
    allowedAgentPresets: null,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
    ...extra,
  });
}

/** 新建一个开启聊天媒体的隔离子用户（配额用例专用，避免与其它用例的媒体互相干扰） */
function freshMediaUser(name: string): { id: number; cookie: string } {
  const user = db.createUser(`model-media-${name}`, HASH, 'user');
  setPerms(user.id, { allowedModels: null, allowChatMedia: true });
  return { id: user.id, cookie: subCookie(user) };
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-model-media-'));
  db = new Database(path.join(tempDir, 'test.db'), createFieldCrypto('test-key', 'test-key'));
  db.init();

  const admin = db.createUser('model-media-admin', HASH, 'admin');
  adminId = admin.id;
  adminUsername = admin.username;
  const restricted = db.createUser('model-media-restricted', HASH, 'user');
  restrictedId = restricted.id;
  restrictedUsername = restricted.username;
  const other = db.createUser('model-media-other', HASH, 'user');
  otherId = other.id;
  otherUsername = other.username;

  // 受限子用户：允许一个模型、开启聊天媒体；上传档位保持关闭以验证两权限独立。
  setPerms(restrictedId, {
    allowedModels: [modelId('openai', 'gpt-5')],
    allowChatMedia: true,
  });
  // 另一个子用户：禁止全部模型 + 关闭聊天媒体。
  setPerms(otherId, {
    allowedModels: [],
    allowChatMedia: false,
  });
  // 会话授权：可见会话落在授权目录内。
  db.replaceUserSessionGrants(restrictedId, ['session-visible']);
  db.markSessionGrantsSeeded(restrictedId);
  db.replaceUserSessionGrants(otherId, ['session-visible']);
  db.markSessionGrantsSeeded(otherId);

  // Remote mux：workspace/follow 的 baseline 响应（子用户访问快照的来源）
  const remoteMux = new WebSocketServer({ noServer: true });
  remoteMux.on('connection', (client: any) => {
    client.on('message', (data: Buffer) => {
      let frame: { type?: string; streamId?: string; endpoint?: string };
      try {
        frame = JSON.parse(data.toString()) as typeof frame;
      } catch {
        return;
      }
      if (frame.type !== 'open' || typeof frame.streamId !== 'string' || frame.endpoint !== 'workspace/follow') return;
      client.send(
        JSON.stringify({
          type: 'item',
          streamId: frame.streamId,
          value: {
            type: 'baseline',
            value: {
              items: [
                {
                  workspaceId: 'workspace-visible',
                  path: '/workspaces/visible',
                  title: 'Visible',
                  sessionIds: ['session-visible'],
                },
              ],
              archivedSessionIds: [],
            },
          },
        }),
      );
    });
  });

  upstream = http.createServer((request, res) => {
    upstreamCalls.push(request.url ?? '');
    const url = request.url ?? '';
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      // 权限保存的可分配资源核验（网关内部通道）：授权目录必须存在于快照中
      if (url.startsWith('/api/dsh-passwords/internal/assignable-resources')) {
        const hook = duringAssignableResources;
        duringAssignableResources = null;
        hook?.();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, folders: ['/workspaces/visible'], sessions: assignableSessionIds, retainedSessions: [] }));
        return;
      }
      if (url.startsWith('/api/workspace.list')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            result: {
              ok: true,
              value: {
                items: [
                  {
                    workspaceId: 'workspace-visible',
                    path: '/workspaces/visible',
                    title: 'Visible',
                    sessionIds: ['session-visible'],
                  },
                ],
                archivedSessionIds: [],
              },
            },
          }),
        );
        return;
      }
      if (url.startsWith('/api/session.list')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            result: {
              ok: true,
              value: {
                items: [
                  { sessionId: 'session-visible', cwd: '/workspaces/visible', model: modelId('openai', 'gpt-5') },
                ],
              },
            },
          }),
        );
        return;
      }
      if (/^\/api\/session[.\/]modelCatalog/.test(url)) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            result: {
              ok: true,
              value: {
                default: modelCatalogDefault,
                routableProviders: modelCatalogGroups.map((group) => group.id),
                groups: modelCatalogGroups,
                failures: [],
              },
            },
          }),
        );
        return;
      }
      if (/^\/api\/session[.\/](?:history|page)$/.test(url)) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          type: 'server-response',
          rpcId: 'history-page-mock',
          result: { ok: true, value: { records: historyPageRecords, hasMore: false } },
        }));
        return;
      }
      if (/^\/api\/session[.\/]create$/.test(url)) {
        // 网关会预分配会话标识并在响应中校验一致性（identity mismatch → 502），
        // 所以 mock 必须回显请求里的 sessionId。
        let sessionId = 'created-session';
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
          const request = rpcRequestPayloadOfTest(parsed);
          if (typeof request.sessionId === 'string' && request.sessionId.length > 0) sessionId = request.sessionId;
        } catch {
          /* 保持默认 */
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({ result: { ok: true, value: { sessionId, cwd: '/workspaces/visible' } } }),
        );
        return;
      }
      if (/^\/api\/session[.\/]selectModel/.test(url)) {
        // 官方成功形状：result.value.selected = { provider, model, ... }
        // 网关从真实成功响应登记会话有效模型（不能靠请求体猜）。
        let selection: Record<string, unknown> = {};
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
          const args = rpcRequestPayloadOfTest(parsed);
          if (typeof args.provider === 'string' && typeof args.model === 'string') {
            selection = { provider: args.provider, model: args.model };
          }
        } catch {
          /* 保持空选择 */
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ result: { ok: true, value: { selected: selection } } }));
        return;
      }
      // 其余会话 RPC：一律 200 成功（若看到这些请求说明网关没拦住）
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ result: { ok: true, value: { accepted: true } } }));
    });
  });
  upstream.on('upgrade', (request, socket, head) => {
    if ((request.url ?? '').startsWith('/api/remote.mux')) {
      remoteMux.handleUpgrade(request, socket, head, (client: any) => remoteMux.emit('connection', client, request));
      return;
    }
    socket.destroy();
  });
  upstream.on('close', () => remoteMux.close());
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
  const upstreamPort = (upstream.address() as { port: number }).port;

  const config: PlatformConfig = {
    setupKey: 'test-setup-key',
    dbPath: path.join(tempDir, 'test.db'),
    dbEncKey: 'test-key',
    gateway: {
      host: '127.0.0.1',
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null,
      redirectPort: null,
      publicHost: '',
      domain: 'localhost',
      autoTls: false,
      acmeEmail: '',
      acmeStaging: false,
    },
    jwtSecret: 'test-secret',
    internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
  gatewayPort = (gateway.address() as { port: number }).port;

  adminCookie = `dsh_gateway_token=${jwt.sign(
    { sub: String(adminId), username: adminUsername, cv: 0 },
    config.jwtSecret,
    { expiresIn: '12h' },
  )}`;
  restrictedCookie = subCookie({ id: restrictedId, username: restrictedUsername });
  otherCookie = subCookie({ id: otherId, username: otherUsername });

  // 建立 workspace/session 授权快照（部分用例依赖基线已就绪）。
  // 子用户的访问快照由 Remote mux 的 workspace/follow 基线建立（与生产同路径），
  // 仅靠 HTTP workspace.list 不足以建立会话级访问映射。
  await seedRemoteBaseline(restrictedCookie);
  await seedRemoteBaseline(otherCookie);
});

after(() => {
  gateway?.close();
  upstream?.close();
  try {
    db?.close();
  } catch {
    /* 已关闭 */
  }
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* Windows 上 node:sqlite 句柄可能未释放，清理尽力而为 */
  }
});

// ══════════════════════════════════════════════════════════════════════
// 一、allowed_models 持久化语义：NULL / [] / 指定 allow
// ══════════════════════════════════════════════════════════════════════

test('allowed_models：NULL 表示不限制，[] 表示禁止全部，非空数组按稳定 ID 白名单', () => {
  const user = db.createUser('model-semantics-user', HASH, 'user');

  // 缺行时 effectivePermissions 兜底为 NULL（老用户行为不变）
  assert.equal(db.getPermissions(user.id), null, '新用户不应有隐式权限行');

  setPerms(user.id, { allowedModels: null });
  assert.equal(db.getPermissions(user.id)?.allowed_models, null, 'NULL = 不限制');

  setPerms(user.id, { allowedModels: [] });
  assert.deepEqual(db.getPermissions(user.id)?.allowed_models, [], '[] = 禁止全部模型');

  setPerms(user.id, { allowedModels: [modelId('openai', 'gpt-5'), modelId('deepseek', 'deepseek-chat')] });
  assert.deepEqual(
    db.getPermissions(user.id)?.allowed_models,
    [modelId('openai', 'gpt-5'), modelId('deepseek', 'deepseek-chat')],
    '非空数组保留稳定 ID',
  );

  // 省略 allowedModels 必须保留现值（部分更新语义），显式 null 才清除
  setPerms(user.id, {});
  assert.deepEqual(
    db.getPermissions(user.id)?.allowed_models,
    [modelId('openai', 'gpt-5'), modelId('deepseek', 'deepseek-chat')],
    '省略 allowedModels 不得清除既有白名单',
  );
  setPerms(user.id, { allowedModels: null });
  assert.equal(db.getPermissions(user.id)?.allowed_models, null, '显式 null 才恢复不限制');
});

test('allowed_models：非法 ID 被丢弃，去重并保留合法项', () => {
  const user = db.createUser('model-sanitize-user', HASH, 'user');
  setPerms(user.id, {
    allowedModels: [
      modelId('openai', 'gpt-5'),
      modelId('openai', 'gpt-5'), // 重复
      'no-slash', // 缺 provider
      '/leading', // provider 为空
      'trailing/', // model 为空
      'with space/model', // provider 含空白
      modelId('anthropic', 'claude-sonnet-4'),
    ],
  });
  assert.deepEqual(
    db.getPermissions(user.id)?.allowed_models,
    [modelId('openai', 'gpt-5'), modelId('anthropic', 'claude-sonnet-4')],
    '只保留合法且去重后的 provider/model',
  );
});

// ══════════════════════════════════════════════════════════════════════
// 二、permissions API roundtrip（allowed_models + allowChatMedia）
// ══════════════════════════════════════════════════════════════════════

test('权限 API：allowed_models 与 allowChatMedia 可 roundtrip，省略时保留现值', async () => {
  const user = db.createUser('model-roundtrip-user', HASH, 'user');

  const saved = await req('POST', '/gateway/api/permissions', {
    body: {
      userId: user.id,
      allowedFolders: ['/workspaces/visible'],
      allowChatMedia: true,
      allowedModels: [modelId('openai', 'gpt-5')],
    },
  });
  assert.equal(saved.status, 200, saved.body);
  const row = db.getPermissions(user.id);
  assert.deepEqual(row?.allowed_models, [modelId('openai', 'gpt-5')], 'API 必须持久化 allowed_models');
  assert.equal(row?.allow_chat_media, true, 'API 必须持久化 allowChatMedia');

  // 只改无关字段：两个新字段都必须保持
  const partial = await req('POST', '/gateway/api/permissions', {
    body: { userId: user.id, allowedFolders: ['/workspaces/visible'], hourlyTokenLimit: 100 },
  });
  assert.equal(partial.status, 200, partial.body);
  const after = db.getPermissions(user.id);
  assert.deepEqual(after?.allowed_models, [modelId('openai', 'gpt-5')], '省略 allowedModels 不得清除');
  assert.equal(after?.allow_chat_media, true, '省略 allowChatMedia 不得清除');

  // 显式 null / false 才清除
  const cleared = await req('POST', '/gateway/api/permissions', {
    body: {
      userId: user.id,
      allowedFolders: ['/workspaces/visible'],
      allowedModels: null,
      allowChatMedia: false,
    },
  });
  assert.equal(cleared.status, 200, cleared.body);
  assert.equal(db.getPermissions(user.id)?.allowed_models, null, '显式 null 恢复不限制');
  assert.equal(db.getPermissions(user.id)?.allow_chat_media, false, '显式 false 关闭媒体');
});

test('权限 API：非法 allowed_models 载荷被拒绝且不清除既有策略', async () => {
  const user = db.createUser('model-invalid-user', HASH, 'user');
  const base = await req('POST', '/gateway/api/permissions', {
    body: {
      userId: user.id,
      allowedFolders: ['/workspaces/visible'],
      allowedModels: [modelId('openai', 'gpt-5')],
      allowChatMedia: true,
    },
  });
  assert.equal(base.status, 200, base.body);

  // 非数组、非 null：必须 400（不能静默归一成「不限制」）
  const notArray = await req('POST', '/gateway/api/permissions', {
    body: { userId: user.id, allowedFolders: ['/workspaces/visible'], allowedModels: 'openai/gpt-5' },
  });
  assert.equal(notArray.status, 400, 'allowedModels 必须是数组或 null');
  // 非布尔 allowChatMedia：必须 400
  const notBoolean = await req('POST', '/gateway/api/permissions', {
    body: { userId: user.id, allowedFolders: ['/workspaces/visible'], allowChatMedia: 'yes' },
  });
  assert.equal(notBoolean.status, 400, 'allowChatMedia 必须是布尔值');

  const row = db.getPermissions(user.id);
  assert.deepEqual(row?.allowed_models, [modelId('openai', 'gpt-5')], '拒绝的请求不得改动白名单');
  assert.equal(row?.allow_chat_media, true, '拒绝的请求不得改动媒体开关');
});

// ══════════════════════════════════════════════════════════════════════
// 三、modelCatalog 过滤
// ══════════════════════════════════════════════════════════════════════

test('session/modelCatalog：子用户只看到 allowlist 内的模型，主用户看到全部', async () => {
  const sub = await req('POST', '/api/session/modelCatalog', { cookie: restrictedCookie, body: {} });
  assert.equal(sub.status, 200, sub.body);
  const subValue = (sub.json.result as { value?: unknown } | undefined)?.value;
  assert.ok(subValue, `modelCatalog 必须返回 value：${sub.body}`);
  assert.deepEqual(
    visibleCatalogModelIds(subValue),
    [modelId('openai', 'gpt-5')],
    '受限子用户只应看到被允许的模型',
  );
  assert.deepEqual(
    (subValue as { routableProviders?: unknown }).routableProviders,
    ['openai'],
    'routableProviders 不得泄露未授权 provider',
  );
  assert.deepEqual(
    (subValue as { default?: unknown }).default,
    { provider: 'openai', model: 'gpt-5' },
    'default 必须收敛到允许的模型',
  );

  const admin = await req('POST', '/api/session/modelCatalog', { cookie: adminCookie, body: {} });
  assert.equal(admin.status, 200, admin.body);
  const adminValue = (admin.json.result as { value?: unknown } | undefined)?.value;
  assert.deepEqual(visibleCatalogModelIds(adminValue), allCatalogModelIds(), '主用户不受模型 allowlist 限制');

  // 设置页通过 overview 读取模型目录：主用户的官方请求也必须填充网关快照，
  // 不能因为 reqAs.dshpwPerms 对 admin 为 undefined 而永远返回 modelCatalog=null。
  const overview = await req('GET', '/gateway/api/overview', { cookie: adminCookie });
  assert.equal(overview.status, 200, overview.body);
  const overviewCatalog = (overview.json as { modelCatalog?: { groups?: unknown } }).modelCatalog;
  assert.ok(overviewCatalog !== null && Array.isArray(overviewCatalog?.groups), 'overview 必须暴露已观测到的 modelCatalog');
});

test('session/modelCatalog：[] 白名单的子用户看不到任何模型', async () => {
  const res = await req('POST', '/api/session/modelCatalog', { cookie: otherCookie, body: {} });
  assert.equal(res.status, 200, res.body);
  const value = (res.json.result as { value?: unknown } | undefined)?.value;
  assert.deepEqual(visibleCatalogModelIds(value), [], '[] = 禁止全部模型');
  assert.equal((value as { default?: unknown }).default, null, '无可用模型时 default 必须为 null');
  assert.deepEqual((value as { routableProviders?: unknown }).routableProviders, []);
});

// ══════════════════════════════════════════════════════════════════════
// 四、selectModel / create / fork / prompt 绕过拒绝
// ══════════════════════════════════════════════════════════════════════

test('session/selectModel：allowlist 外的模型 403 且不到达上游，允许的模型放行', async () => {
  upstreamCalls = [];
  const blocked = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'anthropic', model: 'claude-sonnet-4' }),
  });
  assert.equal(blocked.status, 403, `未授权模型必须 403：${blocked.body}`);
  assert.equal(upstreamSaw('session.selectModel'), false, '被拒绝的 selectModel 不得转发到上游');

  const allowed = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'openai', model: 'gpt-5' }),
  });
  assert.equal(allowed.status, 200, allowed.body);
  assert.equal(upstreamSaw('session.selectModel'), true, '允许的 selectModel 应转发到上游');
});

test('session/create：[] 白名单（禁止全部）拒绝创建，非空白名单允许创建', async () => {
  // [] = 禁止全部模型：建了也永远用不了，提前 fail-closed
  setPerms(otherId, { allowedModels: [], allowChatMedia: false });
  // other 需要 workspace 授权快照才能走到模型判定
  await seedRemoteBaseline(otherCookie);
  upstreamCalls = [];
  const blocked = await req('POST', '/api/session/create', {
    cookie: otherCookie,
    body: rpcEnvelope('session/create', { workspaceId: 'workspace-visible', cwd: '/workspaces/visible' }),
  });
  assert.equal(blocked.status, 403, `[] 白名单必须拒绝创建：${blocked.body}`);
  assert.equal(upstreamSaw('session.create'), false, '被拒绝的 create 不得转发到上游');

  // 非空白名单：create 本身不带模型，允许创建（后续 prompt 在模型未收敛时仍会拦）
  await seedRemoteBaseline(restrictedCookie);
  upstreamCalls = [];
  const allowed = await req('POST', '/api/session/create', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/create', { workspaceId: 'workspace-visible', cwd: '/workspaces/visible' }),
  });
  assert.equal(allowed.status, 200, `非空白名单应允许创建：${allowed.body}`);
  assert.equal(upstreamSaw('session.create'), true, '允许的 create 应转发到上游');
});

test('session/prompt：网关登记的会话模型被撤销后旧会话 prompt 拒绝', async () => {
  // 重新建立访问快照（前面的 setPerms/权限保存会失效旧快照）
  await seedRemoteBaseline(restrictedCookie);
  // 让网关通过官方 selectModel 成功响应登记 session-visible 的有效模型
  const select = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'openai', model: 'gpt-5' }),
  });
  assert.equal(select.status, 200, select.body);
  upstreamCalls = [];
  const before = await req('POST', '/api/session/prompt', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/prompt', { requestId: 'p-1', sessionId: 'session-visible', content: { type: 'text', text: 'hi' } }),
  });
  assert.equal(before.status, 200, `已登记授权模型下 prompt 可放行：${before.body}`);

  // 撤销该模型 → 同一旧会话的 prompt 必须被拒（旧会话不能继续用被撤销模型）
  setPerms(restrictedId, { allowedModels: [modelId('deepseek', 'deepseek-chat')], allowChatMedia: true });
  await seedRemoteBaseline(restrictedCookie);
  upstreamCalls = [];
  const blocked = await req('POST', '/api/session/prompt', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/prompt', { requestId: 'p-2', sessionId: 'session-visible', content: { type: 'text', text: 'hi' } }),
  });
  assert.equal(blocked.status, 403, `模型被撤销后旧会话 prompt 必须 403：${blocked.body}`);
  assert.equal(upstreamSaw('session.prompt'), false, '被拒绝的 prompt 不得转发到上游');

  // 恢复现场，避免影响后续用例
  setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
});

test('session/history：旧分页窗口不得覆盖实时模型授权状态', async () => {
  setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  await seedRemoteBaseline(restrictedCookie);
  const catalog = await req('POST', '/api/session/modelCatalog', { cookie: restrictedCookie, body: {} });
  assert.equal(catalog.status, 200, catalog.body);
  const selected = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'openai', model: 'gpt-5' }),
  });
  assert.equal(selected.status, 200, selected.body);

  historyPageRecords = [
    { type: 'event', event: { type: 'session-log-deepseek/delivery-accepted', seq: 4, data: { sessionId: 'session-visible' } } },
    { type: 'event', event: { type: 'model/selection', seq: 5, data: { provider: 'anthropic', model: 'claude-sonnet-4' } } },
  ];
  try {
    const history = await req('POST', '/api/session/history', {
      cookie: restrictedCookie,
      body: rpcEnvelope('session/history', { sessionId: 'session-visible' }),
    });
    assert.equal(history.status, 200, history.body);

    upstreamCalls = [];
    const prompt = await req('POST', '/api/session/prompt', {
      cookie: restrictedCookie,
      body: rpcEnvelope('session/prompt', { requestId: 'history-model-check', sessionId: 'session-visible', content: { type: 'text', text: 'hi' } }),
    });
    assert.equal(prompt.status, 200, `旧 history 窗口不得覆盖实时已授权模型：${prompt.body}`);
    assert.equal(upstreamSaw('session.prompt'), true, '实时模型仍允许时 prompt 应正常转发');
  } finally {
    historyPageRecords = [];
    setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  }
});

test('session/page：窗口没有 model/selection 时不得把已知模型降级为 Host 默认', async () => {
  setPerms(restrictedId, {
    allowedModels: [modelId('openai', 'gpt-5'), modelId('deepseek', 'deepseek-chat')],
    allowChatMedia: true,
  });
  await seedRemoteBaseline(restrictedCookie);
  const catalog = await req('POST', '/api/session/modelCatalog', { cookie: restrictedCookie, body: {} });
  assert.equal(catalog.status, 200, catalog.body);
  const selected = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'deepseek', model: 'deepseek-chat' }),
  });
  assert.equal(selected.status, 200, selected.body);

  setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  await seedRemoteBaseline(restrictedCookie);
  historyPageRecords = [
    { type: 'event', event: { type: 'session-log-deepseek/delivery-accepted', seq: 9, data: { sessionId: 'session-visible' } } },
    { type: 'event', event: { type: 'user/message', seq: 10, data: 'hi' } },
  ];
  try {
    const page = await req('POST', '/api/session/page', {
      cookie: restrictedCookie,
      body: rpcEnvelope('session/page', { sessionId: 'session-visible', throughSeq: 10, maxMessages: 2 }),
    });
    assert.equal(page.status, 200, page.body);

    upstreamCalls = [];
    const prompt = await req('POST', '/api/session/prompt', {
      cookie: restrictedCookie,
      body: rpcEnvelope('session/prompt', { requestId: 'page-model-check', sessionId: 'session-visible', content: { type: 'text', text: 'hi' } }),
    });
    assert.equal(prompt.status, 403, `分页窗口未见选择事件不得放宽为 Host 默认：${prompt.body}`);
    assert.equal(upstreamSaw('session.prompt'), false, '被拒绝的 prompt 不得转发到上游');
  } finally {
    historyPageRecords = [];
    setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  }
});

test('session/history：受限子用户的沙盒降级不被响应清洗短路', async () => {
  // 守卫：history 响应必须先经过 clampSessionHistorySandbox 再清洗隐藏 Unicode。
  // 若在前面插入更宽的 history/page 缓冲分支并提前 return，降级会变成死代码，
  // 子用户打开共享的 full-access 会话时就会从历史里继承提权 preset。
  setPerms(restrictedId, { allowedModels: null, allowChatMedia: true, sandboxMode: 'read-only' });
  await seedRemoteBaseline(restrictedCookie);
  historyPageRecords = [
    { type: 'event', event: { type: 'permission/preset', seq: 3, data: { preset: 'danger-full-access' } } },
    { type: 'event', event: { type: 'sandbox/mode', seq: 4, data: { mode: 'danger-full-access' } } },
  ];
  try {
    const history = await req('POST', '/api/session/history', {
      cookie: restrictedCookie,
      body: rpcEnvelope('session/history', { sessionId: 'session-visible' }),
    });
    assert.equal(history.status, 200, history.body);
    assert.equal(history.body.includes('danger-full-access'), false, '历史里的超授权 preset/mode 必须被降级');
    assert.equal(history.body.includes('read-only'), true, `降级为子用户授权的 read-only：${history.body}`);
  } finally {
    historyPageRecords = [];
    setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  }
});

test('session/selectModel：[] 白名单拒绝任何模型（包括主机默认）', async () => {
  const emptyUser = db.createUser('model-empty-user', HASH, 'user');
  setPerms(emptyUser.id, { allowedModels: [], allowChatMedia: false });
  db.replaceUserSessionGrants(emptyUser.id, ['session-visible']);
  db.markSessionGrantsSeeded(emptyUser.id);
  const emptyCookie = subCookie({ id: emptyUser.id, username: emptyUser.username });
  await seedRemoteBaseline(emptyCookie);

  upstreamCalls = [];
  const res = await req('POST', '/api/session/selectModel', {
    cookie: emptyCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'openai', model: 'gpt-5' }),
  });
  assert.equal(res.status, 403, `[] 白名单必须拒绝任何模型选择：${res.body}`);
  assert.equal(upstreamSaw('session.selectModel'), false, '被拒绝的 selectModel 不得转发到上游');

  // 缺字段/格式非法的选择同样拒绝（不能只靠上游报错）
  const missing = await req('POST', '/api/session/selectModel', {
    cookie: emptyCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible' }),
  });
  assert.equal(missing.status, 403, '缺 provider/model 的选择必须拒绝');
});

test('session/fork：父会话模型被撤销后 fork 拒绝，重新授权后放行', async () => {
  await seedRemoteBaseline(restrictedCookie);
  // 登记 session-visible 的有效模型（官方 selectModel 成功响应）
  const select = await req('POST', '/api/session/selectModel', {
    cookie: restrictedCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'openai', model: 'gpt-5' }),
  });
  assert.equal(select.status, 200, select.body);

  // 收紧白名单：让该会话当前模型变得未授权
  setPerms(restrictedId, { allowedModels: [modelId('deepseek', 'deepseek-chat')], allowChatMedia: true });
  await seedRemoteBaseline(restrictedCookie);
  upstreamCalls = [];
  const blocked = await req('POST', '/api/session/fork', {
    cookie: restrictedCookie,
    body: { sessionId: 'session-visible' },
  });
  assert.equal(blocked.status, 403, `父会话模型被撤销后 fork 必须 403：${blocked.body}`);
  assert.equal(upstreamSaw('session.fork'), false, '被拒绝的 fork 不得转发到上游');

  // 恢复授权后应放行
  setPerms(restrictedId, { allowedModels: [modelId('openai', 'gpt-5')], allowChatMedia: true });
  await seedRemoteBaseline(restrictedCookie);
  upstreamCalls = [];
  const allowed = await req('POST', '/api/session/fork', {
    cookie: restrictedCookie,
    body: { sessionId: 'session-visible' },
  });
  assert.equal(allowed.status, 200, `授权模型应允许 fork：${allowed.body}`);
});

test('模型限制：主用户不受 allowlist 限制', async () => {
  // 主用户的 allowed_models 永远为 null（不能修改主用户权限），且 [] 的子用户被拦不影响主用户
  setPerms(otherId, { allowedModels: [], allowChatMedia: false });
  const res = await req('POST', '/api/session/selectModel', {
    cookie: adminCookie,
    body: rpcEnvelope('session/selectModel', { sessionId: 'session-visible', provider: 'deepseek', model: 'deepseek-chat' }),
  });
  assert.equal(res.status, 200, `主用户必须不受模型 allowlist 限制：${res.body}`);
});

// ══════════════════════════════════════════════════════════════════════
// 五、聊天媒体 init：权限开关、类型、魔数、大小
// ══════════════════════════════════════════════════════════════════════

test('媒体 init：allow_chat_media 关闭时拒绝，开启时放行（独立于 allow_upload）', async () => {
  // other 用户：allowChatMedia=false（且按 API 契约，即使 allowUpload=true 也不得放行）
  const closed = await req('POST', '/gateway/api/message-media/init', {
    cookie: otherCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName: 'a.png' },
  });
  assert.equal(closed.status, 403, `媒体关闭时必须拒绝 init：${closed.body}`);

  // 显式验证独立性：allowUpload=true 但 allowChatMedia=false 仍然拒绝
  setPerms(otherId, { allowedModels: [], allowUpload: true, allowChatMedia: false });
  const uploadOnly = await req('POST', '/gateway/api/message-media/init', {
    cookie: otherCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName: 'a.png' },
  });
  assert.equal(uploadOnly.status, 403, 'allow_upload 不得隐式授予聊天媒体权限');

  // restricted：allowChatMedia=true 时放行
  const opened = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName: 'a.png' },
  });
  assert.equal(opened.status, 200, `媒体开启时应放行 init：${opened.body}`);
  assert.notEqual(uploadIdOf(opened), '', 'init 必须返回 upload ID');
});

test('媒体 init：不支持的 kind/MIME 与超限大小被拒绝', async () => {
  const badKind = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'document', mimeType: 'image/png', byteSize: 100, fileName: 'a.png' },
  });
  assert.equal(badKind.status, 400, 'kind 只允许 sticker/image/video');

  // SVG/HTML 等可承载脚本的类型在任何 kind 下都必须拒绝
  for (const mimeType of ['image/svg+xml', 'text/html', 'application/xml', 'application/zip']) {
    const res = await req('POST', '/gateway/api/message-media/init', {
      cookie: restrictedCookie,
      body: { kind: 'image', mimeType, byteSize: 100, fileName: 'x' },
    });
    assert.equal(res.status, 400, `${mimeType} 不得被接受为聊天媒体`);
  }

  // sticker 上限 2 MiB、image 上限 10 MiB、video 上限 100 MiB
  const oversizedSticker = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'sticker', mimeType: 'image/png', byteSize: 2 * 1024 * 1024 + 1, fileName: 's.png' },
  });
  assert.equal(oversizedSticker.status, 400, 'sticker 超过 2 MiB 必须拒绝');
  const oversizedImage = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: 10 * 1024 * 1024 + 1, fileName: 'i.png' },
  });
  assert.equal(oversizedImage.status, 400, 'image 超过 10 MiB 必须拒绝');
  const oversizedVideo = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'video', mimeType: 'video/mp4', byteSize: 100 * 1024 * 1024 + 1, fileName: 'v.mp4' },
  });
  assert.equal(oversizedVideo.status, 400, 'video 超过 100 MiB 必须拒绝');
  const zero = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: 0, fileName: 'i.png' },
  });
  assert.equal(zero.status, 400, '空文件必须拒绝');

  // 危险原始文件名（路径穿越 / 可执行扩展名）只作展示元数据也必须拒绝
  const dangerous = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: 100, fileName: '../../evil.php' },
  });
  assert.equal(dangerous.status, 400, '危险原始文件名必须拒绝');
});

test('媒体上传：合法 PNG 通过魔数与 MIME 校验并转为 ready', async () => {
  const { init, put, mediaId } = await uploadMedia(restrictedCookie, 'image', 'image/png', PNG_BYTES, 'cat.png');
  assert.equal(init.status, 200, init.body);
  assert.equal(put.status, 200, `PUT 应接受真实 PNG：${put.body}`);
  const asset = db.getMediaAssetFile(mediaId);
  assert.notEqual(asset, null, '上传成功后必须落库');
  assert.equal(asset?.state, 'ready', '校验通过后必须变为 ready');
  assert.equal(asset?.owner_id, restrictedId, '媒体必须归属于上传者');
  assert.equal(asset?.mime_type, 'image/png');
});

test('媒体上传：魔数不匹配的伪装文件被拒绝且不落 ready', async () => {
  const init = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: FAKE_PNG_HTML.length, fileName: 'evil.png' },
  });
  assert.equal(init.status, 200, init.body);
  const mediaId = uploadIdOf(init);
  assert.notEqual(mediaId, '', 'init 必须返回 upload ID');

  const put = await putBytes(`/gateway/api/message-media/${encodeURIComponent(mediaId)}`, FAKE_PNG_HTML, {
    cookie: restrictedCookie,
    headers: { 'content-type': 'image/png' },
  });
  assert.equal(put.status, 415, `HTML 伪装成 PNG 必须被魔数校验拒绝：${put.body}`);
  assert.notEqual(db.getMediaAsset(mediaId)?.state, 'ready', '被拒绝的上传不得变为 ready');
});

 test('媒体上传：声明的 Content-Type 不在该类型白名单时在写入前被拒绝', async () => {
  const init = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName: 'a.png' },
  });
  assert.equal(init.status, 200, init.body);
  const mediaId = uploadIdOf(init);
  // 真实内容合法，但 PUT 的 Content-Type 声明非法（图片声明为可执行/文本）
  const put = await putBytes(`/gateway/api/message-media/${encodeURIComponent(mediaId)}`, PNG_BYTES, {
    cookie: restrictedCookie,
    headers: { 'content-type': 'text/html' },
  });
  assert.equal(put.status, 415, `PUT 的非法 Content-Type 必须被拒：${put.body}`);
  assert.notEqual(db.getMediaAsset(mediaId)?.state, 'ready');
});

test('媒体上传：上传其他用户的 upload ID 被拒绝（IDOR）', async () => {
  const init = await req('POST', '/gateway/api/message-media/init', {
    cookie: restrictedCookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName: 'a.png' },
  });
  assert.equal(init.status, 200, init.body);
  const mediaId = uploadIdOf(init);

  // 主用户与另一个子用户都不能写入别人签发的 upload ID
  const asAdmin = await putBytes(`/gateway/api/message-media/${encodeURIComponent(mediaId)}`, PNG_BYTES, {
    cookie: adminCookie,
  });
  assert.equal(asAdmin.status, 404, `非所有者不得写入该 upload ID：${asAdmin.body}`);
  const asOther = await putBytes(`/gateway/api/message-media/${encodeURIComponent(mediaId)}`, PNG_BYTES, {
    cookie: otherCookie,
  });
  assert.equal(asOther.status, 404, `非所有者不得写入该 upload ID：${asOther.body}`);
  assert.notEqual(db.getMediaAsset(mediaId)?.state, 'ready', '越权上传不得把资产变为 ready');
});

// ═══════════════════════════════════════════════════════
// 五之一、媒体上传并发准入（MEDIA_MAX_CONCURRENT_UPLOADS）
// ═══════════════════════════════════════════════════════

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** 打开一个不结束 body 的 PUT（chunked），保持连接占用一个并发槽位。 */
function openHeldPut(url: string, cookieValue: string, firstChunk: Buffer): { destroy: () => void } {
  const r = http.request({
    host: '127.0.0.1',
    port: gatewayPort,
    method: 'PUT',
    path: url,
    headers: { cookie: cookieValue, 'content-type': 'image/png', 'transfer-encoding': 'chunked' },
  });
  r.on('error', () => { /* 用例结束时主动 destroy，忽略 */ });
  r.write(firstChunk);
  return { destroy: () => { try { r.destroy(); } catch { /* 已关闭 */ } } };
}

test('媒体上传：并发 PUT 超过上限时按 MEDIA_BUSY 拒绝（PUT 入口准入，而非只依赖 init）', async () => {
  const user = freshMediaUser('media-busy');
  // 先一次签发 4 个 pending 资产：此时没有打开的 PUT，init 的并发检查不会拦。
  const ids: string[] = [];
  for (let i = 0; i < 4; i += 1) {
    const init = await initMedia(user.cookie, `busy-${String(i)}.png`);
    assert.equal(init.status, 200, init.body);
    ids.push(uploadIdOf(init));
  }
  const held: Array<{ destroy: () => void }> = [];
  try {
    // 打开 3 个不结束的 PUT：服务端收到请求头即占用并发槽位。
    for (let i = 0; i < 3; i += 1) {
      held.push(openHeldPut(`/gateway/api/message-media/${encodeURIComponent(ids[i]!)}`, user.cookie, PNG_BYTES.subarray(0, 8)));
    }
    await delay(200); // 等 3 个请求头到达并被处理器计数
    const busy = await putBytes(`/gateway/api/message-media/${encodeURIComponent(ids[3]!)}`, PNG_BYTES, {
      cookie: user.cookie,
      headers: { 'content-type': 'image/png' },
    });
    assert.equal(busy.status, 429, `第 4 个并发 PUT 必须被拒：${busy.body}`);
    assert.equal(busy.json.code, 'MEDIA_BUSY', '并发超限应回 MEDIA_BUSY');
    // 被拒的资产必须仍是 pending（可重试），不得被标记 failed。
    assert.equal(db.getMediaAsset(ids[3]!)?.state, 'pending', '并发背压不得失败化上传资产');
  } finally {
    for (const handle of held) handle.destroy();
  }
});

// ══════════════════════════════════════════════════════════════════════
// 五之二、媒体上传配额（MEDIA_MAX_PENDING_ASSETS_PER_USER）
// ══════════════════════════════════════════════════════════════════════

const MEDIA_QUOTA_MAX = 20;

/** 发起一次 init（不 PUT，用于 pending 配额） */
function initMedia(cookie: string, fileName: string): Promise<Res> {
  return req('POST', '/gateway/api/message-media/init', {
    cookie,
    body: { kind: 'image', mimeType: 'image/png', byteSize: PNG_BYTES.length, fileName },
  });
}

test('媒体配额：已发送到消息的 20 个媒体不再占用 init 配额', async () => {
  const user = freshMediaUser('quota-sent');
  for (let i = 0; i < MEDIA_QUOTA_MAX; i += 1) {
    const { init, put, mediaId } = await uploadMedia(user.cookie, 'image', 'image/png', PNG_BYTES, `sent-${i}.png`);
    assert.equal(init.status, 200, `第 ${i + 1} 次 init 应放行：${init.body}`);
    assert.equal(put.status, 200, `第 ${i + 1} 次上传应成功：${put.body}`);
    // 直接经数据层绑定到消息（与 HTTP 发送写的是同一张 message_media 表）；
    // 避免触发与本用例无关的留言频率限制，使 20 条发送的建立保持确定性。
    db.addMessageWithMedia({
      senderId: user.id,
      recipientId: adminId,
      content: '',
      tags: [],
      mediaIds: [mediaId],
    });
    assert.equal(db.mediaAttachedToAnyMessage(mediaId), true, `第 ${i + 1} 个媒体应已绑定到消息`);
  }

  // 20 个媒体均已绑定到消息：配额应已释放，init 必须继续可用（协议不得 429）
  const after = await initMedia(user.cookie, 'after-20-sent.png');
  assert.equal(after.status, 200, `已发送的媒体不得继续占用配额：${after.body}`);
  assert.notEqual(uploadIdOf(after), '', 'init 必须返回 upload ID');
});

test('媒体配额：未绑定的 20 个 ready 资产触发 429 MEDIA_QUOTA', async () => {
  const user = freshMediaUser('quota-unbound');
  for (let i = 0; i < MEDIA_QUOTA_MAX; i += 1) {
    const { init, put } = await uploadMedia(user.cookie, 'image', 'image/png', PNG_BYTES, `unbound-${i}.png`);
    assert.equal(init.status, 200, `第 ${i + 1} 次 init 应放行：${init.body}`);
    assert.equal(put.status, 200, `第 ${i + 1} 次上传应成功：${put.body}`);
  }

  // 上传成功但一次未发送：达到上限后新的 init 必须被配额拦下
  const blocked = await initMedia(user.cookie, 'blocked.png');
  assert.equal(blocked.status, 429, `未绑定 ready 资产达到上限必须 429：${blocked.body}`);
  assert.equal(blocked.json.code, 'MEDIA_QUOTA', '必须返回稳定的 MEDIA_QUOTA 错误码');
});

test('媒体配额：只 init 不 PUT 的 pending 资产同样计入，不能绕过配额', async () => {
  const user = freshMediaUser('quota-pending');
  for (let i = 0; i < MEDIA_QUOTA_MAX; i += 1) {
    const init = await initMedia(user.cookie, `pending-${i}.png`);
    assert.equal(init.status, 200, `第 ${i + 1} 次 init 应放行：${init.body}`);
    assert.equal(db.getMediaAsset(uploadIdOf(init))?.state, 'pending', '未 PUT 的资产应停留在 pending');
  }

  const blocked = await initMedia(user.cookie, 'blocked.png');
  assert.equal(blocked.status, 429, `pending 资产同样占用配额，不得绕过：${blocked.body}`);
  assert.equal(blocked.json.code, 'MEDIA_QUOTA');
});

// ══════════════════════════════════════════════════════════════════════
// 六、纯媒体消息、IDOR 与私信可见性
// ══════════════════════════════════════════════════════════════════════

test('纯媒体消息：空文本 + 至少一个媒体可发送，图片消息可被收件人读取', async () => {
  const { put, mediaId } = await uploadMedia(restrictedCookie, 'image', 'image/png', PNG_BYTES, 'pure.png');
  assert.equal(put.status, 200, put.body);

  const sent = await req('POST', '/gateway/api/messages', {
    cookie: restrictedCookie,
    body: { mediaIds: [mediaId] },
  });
  assert.equal(sent.status, 200, `纯媒体消息（空文本）必须可发送：${sent.body}`);
  const message = sent.json.message as Record<string, unknown> | undefined;
  assert.ok(message, `发送成功后应返回消息体：${sent.body}`);
  assert.equal(message?.content, '', '纯媒体消息文本为空');
  assert.deepEqual(mediaIdsOf(message), [mediaId], '消息应关联刚上传的媒体');

  // 子用户只能私信主用户：发件人与收件人（主用户）都能读取媒体
  const asAdmin = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, { cookie: adminCookie });
  assert.equal(asAdmin.status, 200, `私信收件人必须可读取媒体：${asAdmin.body}`);
});

test('媒体读取：无关联消息的媒体 ID 不泄露存在性（404）', async () => {
  const res = await req('GET', `/gateway/api/message-media/${'x'.repeat(32)}`, { cookie: adminCookie });
  assert.equal(res.status, 404, '未知/未关联的媒体必须 404，不泄露存在性');
});

test('媒体读取：非收件人非发件人的第三方被拒绝（私信可见性）', async () => {
  const { put, mediaId } = await uploadMedia(restrictedCookie, 'image', 'image/png', PNG_BYTES, 'private.png');
  assert.equal(put.status, 200, put.body);
  const sent = await req('POST', '/gateway/api/messages', { cookie: restrictedCookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);

  // other 是另一个子用户，既不是发件人也不是收件人（收件人是主用户）
  const asOther = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, { cookie: otherCookie });
  assert.equal(asOther.status, 404, '私信第三方不得读取媒体（不做权限存在性区分）');
});

test('媒体读取：响应为 inline + nosniff + private/no-store，且不暴露原始文件名', async () => {
  const { put, mediaId } = await uploadMedia(restrictedCookie, 'image', 'image/png', PNG_BYTES, 'secret-name.png');
  assert.equal(put.status, 200, put.body);
  const sent = await req('POST', '/gateway/api/messages', { cookie: restrictedCookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);

  const res = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, { cookie: restrictedCookie });
  assert.equal(res.status, 200, res.body);
  assert.match(String(res.headers['content-type'] ?? ''), /^image\/png/, '必须回声明为图片的实际 MIME');
  assert.match(String(res.headers['content-disposition'] ?? ''), /^inline/, '图片使用 inline');
  assert.equal(res.headers['x-content-type-options'], 'nosniff', '必须带 nosniff');
  assert.match(String(res.headers['cache-control'] ?? ''), /private/, '媒体必须 private（不得公开缓存）');
  assert.match(String(res.headers['cache-control'] ?? ''), /no-store/, '媒体不得被中间层长期缓存');
  assert.equal(
    /secret-name\.png/.test(JSON.stringify(res.headers)),
    false,
    '读取响应不得回显用户提供的原始文件名（防路径/展示层二次消费）',
  );
});

// ══════════════════════════════════════════════════════════════════════
// 七、视频 Range
// ══════════════════════════════════════════════════════════════════════

test('视频 Range：返回 206 + Content-Range，无 Range 时返回 200 全量', async () => {
  const { init, put, mediaId } = await uploadMedia(restrictedCookie, 'video', 'video/mp4', MP4_BYTES, 'clip.mp4');
  assert.equal(init.status, 200, init.body);
  assert.equal(put.status, 200, `MP4 应通过魔数校验：${put.body}`);
  const sent = await req('POST', '/gateway/api/messages', { cookie: restrictedCookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);

  const full = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, { cookie: restrictedCookie });
  assert.equal(full.status, 200, full.body);
  assert.equal(full.headers['accept-ranges'], 'bytes', '视频必须声明支持 Range');
  assert.equal(Number(full.headers['content-length']), MP4_BYTES.length, '无 Range 时返回完整文件');
  assert.equal(Buffer.byteLength(full.body, 'utf8'), MP4_BYTES.length, '无 Range 时响应体长度必须等于文件大小');

  // 区间结束超出 EOF：按 RFC 9110 夹取到文件末尾（不是错误）
  const ranged = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, {
    cookie: restrictedCookie,
    headers: { range: 'bytes=0-9999' },
  });
  assert.equal(ranged.status, 206, `Range 请求必须返回 206：${ranged.body}`);
  assert.equal(
    ranged.headers['content-range'],
    `bytes 0-${MP4_BYTES.length - 1}/${MP4_BYTES.length}`,
    'Content-Range 必须夹取到文件末尾并报告总长',
  );
  assert.equal(Number(ranged.headers['content-length']), MP4_BYTES.length, 'Range 响应长度必须等于实际返回字节');

  // 严格子区间：长度等于请求区间
  const head = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, {
    cookie: restrictedCookie,
    headers: { range: 'bytes=0-9' },
  });
  assert.equal(head.status, 206, head.body);
  assert.equal(head.headers['content-range'], `bytes 0-9/${MP4_BYTES.length}`);
  assert.equal(Number(head.headers['content-length']), 10, 'Range 响应长度必须等于请求区间');
});

test('视频 Range：越界区间返回 416 且不泄露文件内容', async () => {
  const { put, mediaId } = await uploadMedia(restrictedCookie, 'video', 'video/mp4', MP4_BYTES, 'clip2.mp4');
  assert.equal(put.status, 200, put.body);
  const sent = await req('POST', '/gateway/api/messages', { cookie: restrictedCookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);
  const res = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, {
    cookie: restrictedCookie,
    headers: { range: `bytes=${MP4_BYTES.length + 100}-${MP4_BYTES.length + 200}` },
  });
  assert.equal(res.status, 416, '越界 Range 必须 416');
  assert.equal(res.headers['content-range'], `bytes */${MP4_BYTES.length}`, '416 必须回报总长且不返回内容');
});

test('视频 Range：图片不参与 Range（避免无意义的攻击面）', async () => {
  const { put, mediaId } = await uploadMedia(restrictedCookie, 'image', 'image/png', PNG_BYTES, 'no-range.png');
  assert.equal(put.status, 200, put.body);
  const sent = await req('POST', '/gateway/api/messages', { cookie: restrictedCookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);
  const res = await req('GET', `/gateway/api/message-media/${encodeURIComponent(mediaId)}`, {
    cookie: restrictedCookie,
    headers: { range: 'bytes=0-9' },
  });
  assert.equal(res.status, 200, '图片带 Range 头仍返回完整 200');
  assert.equal(Number(res.headers['content-length']), PNG_BYTES.length);
  assert.equal(
    res.headers['accept-ranges'],
    undefined,
    '图片未实现 Range，不得声明 Accept-Ranges（否则下载器误以为支持断点续传）',
  );
});

test('媒体读取：客户端中途断开必须销毁源流（不泄漏 fd）', async () => {
  // 大文件 + 客户端只读首批数据就断开：pipe 只会 unpipe 源流，被背压 pause 的
  // ReadStream 若不显式 destroy 会永久挂住 fd。用只统计 message-media 源流的
  // destroy 探针断言清理真的发生（正常 autoClose 路径不会调用 destroy）。
  const bigBytes = Buffer.concat([MP4_BYTES, Buffer.alloc(6 * 1024 * 1024, 0x5a)]);
  const user = freshMediaUser('abort');
  const { put, mediaId } = await uploadMedia(user.cookie, 'video', 'video/mp4', bigBytes, 'big.mp4');
  assert.equal(put.status, 200, put.body);
  const sent = await req('POST', '/gateway/api/messages', { cookie: user.cookie, body: { mediaIds: [mediaId] } });
  assert.equal(sent.status, 200, sent.body);

  const destroyedFds: number[] = [];
  const originalDestroy = ReadStream.prototype.destroy;
  // 传 fd 创建时 stream.path 为 undefined，改用运行时的 fd 识别服务端源流
  ReadStream.prototype.destroy = function (this: ReadStream, error?: Error): ReadStream {
    const fd = (this as { fd?: unknown }).fd;
    if (typeof fd === 'number') destroyedFds.push(fd);
    return originalDestroy.call(this, error) as ReadStream;
  };
  try {
    await new Promise<void>((resolve, reject) => {
      const r = http.request(
        {
          host: '127.0.0.1',
          port: gatewayPort,
          path: `/gateway/api/message-media/${encodeURIComponent(mediaId)}`,
          headers: { cookie: user.cookie },
        },
        (res) => {
          if ((res.statusCode ?? 0) !== 200) {
            r.destroy();
            reject(new Error(`媒体读取必须 200：${String(res.statusCode)}`));
            return;
          }
          res.once('data', () => {
            res.pause(); // 不再继续读：让服务端写满 socket 缓冲后暂停源流
            r.destroy(); // 客户端中途断开
            resolve();
          });
        },
      );
      r.on('error', () => resolve());
      r.end();
    });

    const deadline = Date.now() + 3000;
    while (destroyedFds.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(destroyedFds.length > 0, '客户端断开后必须 destroy 源流，否则 fd 一直开着');
  } finally {
    ReadStream.prototype.destroy = originalDestroy;
  }
});

// ══════════════════════════════════════════════════════════════════════
// 八、文本消息兼容（旧 JSON 形状继续可读）
// ══════════════════════════════════════════════════════════════════════

test('文本消息兼容：无媒体仍可发送，且旧客户端只读 content/tags 不受影响', async () => {
  const sent = await req('POST', '/gateway/api/messages', { cookie: adminCookie, body: { ...TEXT_ONLY_BODY, broadcast: true } });
  assert.equal(sent.status, 200, sent.body);
  const message = sent.json.message as Record<string, unknown> | undefined;
  assert.equal(message?.content, TEXT_ONLY_BODY.content, '文本内容保持不变');
  assert.deepEqual(mediaIdsOf(message), [], '无媒体消息的 media 必须为空');
  assert.equal((message as { media?: unknown[] }).media !== undefined || message?.mediaIds !== undefined, true, '消息体必须含媒体字段（空数组）');
});

test('文本消息兼容：只有媒体 ID 而没有已就绪媒体时拒绝（不产生空消息）', async () => {
  const res = await req('POST', '/gateway/api/messages', {
    cookie: restrictedCookie,
    body: { mediaIds: ['never-uploaded-media-id'] },
  });
  assert.equal(res.status, 403, `未就绪/不存在的媒体 ID 必须拒绝：${res.body}`);
  assert.equal((res.json.code as string | undefined), 'MEDIA_NOT_OWNED', '应返回稳定的媒体错误码');
});

// ══════════════════════════════════════════════════════════════════
// 九、含斜杠的模型 ID（添加提供方/自定义提供方场景）
// 官方目录 795/1354 个模型 ID 含 '/'（openrouter/baseten/huggingface 等预设
// 与自定义模型名都不受字符集限制），provider 段仍无斜杠（UI 强制小写 slug）。
// 稳定 ID 形如 `openrouter/anthropic/claude-x`：第一个 '/' 前是 provider，
// 其余全部归 model。
// ══════════════════════════════════════════════════════════════════

test('含斜杠模型 ID：DB 清洗与权限 API 均接受（不再 400/丢弃）', async () => {
  const user = db.createUser('model-slash-user', HASH, 'user');
  const slashId = modelId('openrouter', 'anthropic/claude-sonnet-4.5');
  const multiSlashId = modelId('baseten', 'deepseek-ai/DeepSeek-V4-Pro-0813');

  setPerms(user.id, { allowedModels: [slashId, multiSlashId] });
  assert.deepEqual(
    db.getPermissions(user.id)?.allowed_models,
    [slashId, multiSlashId],
    '含斜杠的 model 段必须原样保留（不能截断成 provider/前半段）',
  );

  const saved = await req('POST', '/gateway/api/permissions', {
    body: { userId: user.id, allowedFolders: ['/workspaces/visible'], allowedModels: [slashId] },
  });
  assert.equal(saved.status, 200, `权限 API 必须接受含斜杠模型：${saved.body}`);
  assert.deepEqual(db.getPermissions(user.id)?.allowed_models, [slashId]);

  // provider 段仍禁止含斜杠：a/b/c 里 a 是 provider，b/c 是 model ——
  // 但 provider 本身带斜杠的写法（如 'x/y/z' 试图当成 provider='x/y'）
  // 在字符串格式里不可表达，由「第一个 '/' 分割」语义天然拒绝歧义。
  setPerms(user.id, { allowedModels: null });
});

test('含斜杠模型 ID：modelCatalog 过滤与 selectModel 强制均按完整 ID 判定', async () => {
  // 换上含斜杠模型的目录（自定义提供方 e2e-custom + 预设风格 openrouter）
  const originalGroups = modelCatalogGroups;
  const originalDefault = modelCatalogDefault;
  modelCatalogGroups = [
    { id: 'e2e-custom', name: 'E2E Custom', models: [
      { id: 'e2e/nested/model', name: 'Nested' },
      { id: 'custom-plain', name: 'Plain' },
    ] },
    { id: 'openrouter', name: 'OpenRouter', models: [
      { id: 'anthropic/claude-sonnet-4.5', name: 'Claude' },
      { id: 'openai/gpt-5o', name: 'GPT' },
    ] },
  ];
  modelCatalogDefault = { provider: 'e2e-custom', model: 'e2e/nested/model' };

  const user = db.createUser('model-slash-e2e-user', HASH, 'user');
  const allowedSlash = modelId('e2e-custom', 'e2e/nested/model');
  const allowedPreset = modelId('openrouter', 'anthropic/claude-sonnet-4.5');
  setPerms(user.id, { allowedModels: [allowedSlash, allowedPreset] });
  db.replaceUserSessionGrants(user.id, ['session-visible']);
  db.markSessionGrantsSeeded(user.id);
  const cookie = subCookie({ id: user.id, username: user.username });
  await seedRemoteBaseline(cookie);

  try {
    // 目录过滤：两个含斜杠模型都在白名单内，其余被过滤
    const catalog = await req('POST', '/api/session/modelCatalog', { cookie, body: {} });
    assert.equal(catalog.status, 200, catalog.body);
    const value = (catalog.json.result as { value?: unknown } | undefined)?.value;
    assert.deepEqual(
      visibleCatalogModelIds(value),
      [allowedSlash, allowedPreset],
      '含斜杠模型必须按完整 provider/model 判定，不能把 model 前半段当独立模型',
    );
    const defaultRow = (value as { default?: Record<string, unknown> } | undefined)?.default;
    assert.equal(
      `${defaultRow?.provider}/${defaultRow?.model}`,
      allowedSlash,
      '目录 default 收敛必须保留含斜杠模型',
    );

    // selectModel：白名单内的含斜杠模型放行
    upstreamCalls = [];
    const allowedSel = await req('POST', '/api/session/selectModel', {
      cookie,
      body: rpcEnvelope('session/selectModel', {
        sessionId: 'session-visible', provider: 'e2e-custom', model: 'e2e/nested/model',
      }),
    });
    assert.equal(allowedSel.status, 200, `白名单内的含斜杠模型必须放行：${allowedSel.body}`);
    assert.equal(upstreamSaw('session/selectModel'), true, '必须到达上游');

    // selectModel：同 provider 下另一个（无斜杠）模型不在白名单 → 403
    upstreamCalls = [];
    const deniedPlain = await req('POST', '/api/session/selectModel', {
      cookie,
      body: rpcEnvelope('session/selectModel', {
        sessionId: 'session-visible', provider: 'e2e-custom', model: 'custom-plain',
      }),
    });
    assert.equal(deniedPlain.status, 403, '同 provider 的其他模型仍必须拒绝');
    assert.equal(upstreamSaw('session/selectModel'), false, '拒绝时不得到达上游');

    // selectModel：把含斜杠模型的前半段当 model 名试探（不完整 ID）→ 403
    upstreamCalls = [];
    const halfModel = await req('POST', '/api/session/selectModel', {
      cookie,
      body: rpcEnvelope('session/selectModel', {
        sessionId: 'session-visible', provider: 'e2e-custom', model: 'e2e',
      }),
    });
    assert.equal(halfModel.status, 403, '截断的 model 段不得被当作已授权模型');
  } finally {
    modelCatalogGroups = originalGroups;
    modelCatalogDefault = originalDefault;
    setPerms(user.id, { allowedModels: null });
  }
});

test('/gateway/api/message-media/* 是网关自有路由：未知子路径不得透传到上游', async () => {
  upstreamCalls = [];
  const res = await req('GET', '/gateway/api/message-media/unknown/sub/path', { cookie: adminCookie });
  assert.equal(res.status, 404, `未知媒体子路径必须 404：${res.body}`);
  assert.equal(
    upstreamCalls.some((url) => url.includes('message-media')),
    false,
    '网关自有媒体前缀不得透传到上游 dsh',
  );
});

// ══════════════════════════════════════════════════════════════════════
// 三、会话授权并发保护（POST /gateway/api/permissions）
//
// 网关把 `allowedSessionIds` 当作全量集合做 DELETE+INSERT，而子用户
// session/create 会在任意时刻追加 grant。管理员草稿只是某个时间点的快照，
// 直接写入会静默撤销自己从未见过的会话。约定：
//   - 任何「删除了仍然可分配的既有 grant 且未在 disabledSessions 中显式禁用」
//     的提交都是冲突 → 409 SESSION_GRANTS_CONFLICT，绝不写入；
//   - 请求 `await` 资源核验期间被并发改写的集合也走同一错误（DB 层基线校验）；
//   - 省略 allowedSessionIds 的部分更新、以及「显式 [] + 逐个禁用」的
//     fail-closed 撤销语义保持不变。
// ══════════════════════════════════════════════════════════════════════

test('Issue #25：过期权限草稿不得静默撤销并发新增的会话授权', async () => {
  const user = db.createUser('grant-stale-draft-user', HASH, 'user');
  setPerms(user.id, { allowedSessionIds: ['session-visible', 'session-concurrent'] });
  db.markSessionGrantsSeeded(user.id);
  const originalSessions = assignableSessionIds;
  assignableSessionIds = ['session-visible', 'session-concurrent'];
  try {
    // 管理员草稿只见过 session-visible；session-concurrent 既不在草稿里，
    // 也不在 disabledSessions 中（UI 撤销必然同时写 disabledSessions）。
    const res = await req('POST', '/gateway/api/permissions', {
      body: {
        userId: user.id,
        allowedFolders: ['/workspaces/visible'],
        allowedSessionIds: ['session-visible'],
        disabledSessions: [],
      },
    });
    assert.equal(res.status, 409, res.body);
    assert.equal(res.json.code, 'SESSION_GRANTS_CONFLICT');
    assert.deepEqual(
      db.listUserSessionGrants(user.id),
      ['session-concurrent', 'session-visible'],
      '冲突必须保留服务端 grant，不得按旧草稿覆盖',
    );
    assert.deepEqual(
      res.json.allowedSessionIds,
      ['session-concurrent', 'session-visible'],
      '409 响应必须回显服务端当前授权供客户端重新同步',
    );
  } finally {
    assignableSessionIds = originalSessions;
  }
});

test('Issue #25：显式空授权仍可 fail-closed 撤销，但必须逐个显式禁用', async () => {
  const user = db.createUser('grant-explicit-empty-user', HASH, 'user');
  setPerms(user.id, { allowedSessionIds: ['session-visible'] });
  db.markSessionGrantsSeeded(user.id);

  // 未显式禁用的既有 grant → 视为过期草稿，拒绝
  const conflict = await req('POST', '/gateway/api/permissions', {
    body: {
      userId: user.id,
      allowedFolders: ['/workspaces/visible'],
      allowedSessionIds: [],
      disabledSessions: [],
    },
  });
  assert.equal(conflict.status, 409, conflict.body);
  assert.equal(conflict.json.code, 'SESSION_GRANTS_CONFLICT');
  assert.deepEqual(db.listUserSessionGrants(user.id), ['session-visible']);

  // 显式 [] + 逐个禁用 → 必须是权威撤销，不能退化为 no-op
  const revoked = await req('POST', '/gateway/api/permissions', {
    body: {
      userId: user.id,
      allowedFolders: ['/workspaces/visible'],
      allowedSessionIds: [],
      disabledSessions: ['session-visible'],
    },
  });
  assert.equal(revoked.status, 200, revoked.body);
  assert.deepEqual(db.listUserSessionGrants(user.id), []);
});

test('Issue #25：不带 allowedSessionIds 的部分更新不触碰会话授权', async () => {
  const user = db.createUser('grant-partial-update-user', HASH, 'user');
  setPerms(user.id, { allowedSessionIds: ['session-visible', 'session-concurrent'] });
  db.markSessionGrantsSeeded(user.id);
  const originalSessions = assignableSessionIds;
  assignableSessionIds = ['session-visible', 'session-concurrent'];
  try {
    const res = await req('POST', '/gateway/api/permissions', {
      body: { userId: user.id, allowedFolders: ['/workspaces/visible'], allowSsh: true },
    });
    assert.equal(res.status, 200, res.body);
    assert.equal(db.getPermissions(user.id)?.allow_ssh, true);
    assert.deepEqual(
      db.listUserSessionGrants(user.id),
      ['session-concurrent', 'session-visible'],
      '省略 allowedSessionIds 时并发新增的 grant 必须原样保留',
    );
  } finally {
    assignableSessionIds = originalSessions;
  }
});

test('Issue #25：资源核验期间并发追加的 grant 不被整表替换覆盖', async () => {
  const user = db.createUser('grant-race-user', HASH, 'user');
  setPerms(user.id, { allowedSessionIds: ['session-visible'] });
  db.markSessionGrantsSeeded(user.id);
  // 模拟权限保存 `await fetchAssignableResources()` 期间子用户 session/create 追加 grant
  duringAssignableResources = () => {
    db.replaceUserSessionGrants(user.id, ['session-visible', 'session-raced']);
  };
  try {
    const res = await req('POST', '/gateway/api/permissions', {
      body: {
        userId: user.id,
        allowedFolders: ['/workspaces/visible'],
        allowedSessionIds: ['session-visible'],
        disabledSessions: [],
      },
    });
    assert.equal(res.status, 409, res.body);
    assert.equal(res.json.code, 'SESSION_GRANTS_CONFLICT');
    assert.deepEqual(
      db.listUserSessionGrants(user.id),
      ['session-raced', 'session-visible'],
      '请求窗口内追加的 grant 必须保留',
    );
  } finally {
    duringAssignableResources = null;
  }
});
