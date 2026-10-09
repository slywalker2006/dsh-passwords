// 核心 Remote mux 流不被通用 SSH 登记规则误伤（配套 src/proxy.ts 的
// isOfficialRemoteCoreEndpoint 判定，修复见 proxy.ts 的核心集合分支）：
//
//   1) 主用户登记了一张**广谱** SSH 表（/api/*，同时命中 /api/session.control
//      这类点号形状）。旧实现会把 session/control、session/follow、
//      workspace/follow、$events、job/list、account/watch 这些官方核心流当成
//      「已登记 ssh 能力」逐流拒绝（gateway/forbidden / Remote endpoint is not
//      available for this user），客户端因此反复重连。核心集合必须绕过通用 SSH
//      登记检查，改由各流自己的官方授权逻辑（会话 grant / 所有权 / baseline /
//      空 request 形状）判定。
//   2) 非核心的已登记端点在 mux 上仍逐流拒绝：广谱登记不会把 carrier 变成
//      无授权的透明直通（现有行为保持）。
//
// 断言口径：核心流必须转发到上游 /api/remote.mux（上游收到 open 帧）且不下发
// error 帧；被拒流必须回 gateway/forbidden 且不触上游，且不撕裂同 carrier 的其它
// 流。子用户的会话授权由 workspace.list 基线建立——广谱登记命中 /api/workspace.list
// 时它被归类为 ssh 端点，子用户开了 allowSsh 即可照常透传，与真实部署一致。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import jwt from 'jsonwebtoken';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options?: { noServer?: boolean }) => any;
  WebSocket: (new (url: string, options?: { headers?: Record<string, string> }) => any) & { OPEN: number };
};

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { parseEndpointAllowlist } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

/** 广谱 SSH 登记：`/*` 只匹配直接子路径，因此同时命中 /api/$events 与
 *  /api/session.control、/api/workspace.follow 这些点号形状的 mux 端点路径。 */
const BROAD_SSH_RULE = '/api/*';
/** 已登记但非核心的 mux 逻辑端点：其点号路径 /api/plugin.ssh 命中广谱规则。 */
const REGISTERED_NON_CORE_MUX_ENDPOINT = 'plugin/ssh';
const AUTHORIZED_SESSION_ID = 'core-session';
const WORKSPACE_PATH = '/work/core';
const UNAVAILABLE_MESSAGE = 'Remote endpoint is not available for this user';

interface CoreStream {
  endpoint: string;
  payload?: unknown;
}

/** 六个核心网关授权流；payload 严格按其官方形状构造。 */
const CORE_STREAMS: readonly CoreStream[] = [
  { endpoint: 'session/control' },
  {
    endpoint: 'session/follow',
    payload: { args: { request: { address: { kind: 'session', sessionId: AUTHORIZED_SESSION_ID } } } },
  },
  { endpoint: 'workspace/follow' },
  { endpoint: '$events' },
  { endpoint: 'job/list', payload: { args: { request: { sessionId: AUTHORIZED_SESSION_ID } } } },
  { endpoint: 'account/watch' },
];

let appDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let upstreamWss: any;
let upstreamRemoteFrames: Array<Record<string, unknown>> = [];
let gatewayPort = 0;
let subuserId = 0;
let subuserCookie = '';
let baselineStatus = 0;
const openMuxHandles: any[] = [];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

/** 子用户：广谱登记下 /api/workspace.list 属 ssh 类别，开 allowSsh 后照常透传。 */
function setPerms(): void {
  db.setPermissions(subuserId, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    allowSsh: true, banned: false, sandboxMode: null,
  });
}

/** 以子用户身份 POST /api/workspace.list，建立会话授权基线（seed grant + access）。 */
function workspaceListSnapshot(): Promise<{ status: number; body: string }> {
  const body = '{}';
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: gatewayPort, path: '/api/workspace.list', method: 'POST',
      headers: { cookie: subuserCookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

interface MuxHandle {
  client: any;
  frames: Array<Record<string, unknown>>;
  closed: Promise<{ code: number; reason: string }>;
  openStream: (streamId: string, endpoint: string, payload: unknown) => void;
}

/** 打开一条 /api/remote.mux carrier 并收集下行帧。 */
function openMux(cookie: string): Promise<MuxHandle> {
  return new Promise((resolve, reject) => {
    const client = new NodeWebSocket(`ws://127.0.0.1:${gatewayPort}/api/remote.mux`, {
      headers: { cookie, origin: 'http://127.0.0.1', host: '127.0.0.1' },
    });
    openMuxHandles.push(client);
    const frames: Array<Record<string, unknown>> = [];
    let settleClose: (value: { code: number; reason: string }) => void = () => {};
    const closed = new Promise<{ code: number; reason: string }>((r) => { settleClose = r; });
    const timer = setTimeout(() => { client.terminate(); reject(new Error('remote.mux 连接超时')); }, 4000);
    client.on('message', (data: Buffer) => {
      try { frames.push(JSON.parse(data.toString('utf8')) as Record<string, unknown>); } catch { /* ignore */ }
    });
    client.on('close', (code: number, reason: Buffer) => {
      clearTimeout(timer);
      settleClose({ code, reason: reason?.toString() ?? '' });
    });
    client.on('error', (error: Error) => { clearTimeout(timer); reject(error); });
    client.on('open', () => {
      clearTimeout(timer);
      resolve({
        client,
        frames,
        closed,
        openStream: (streamId, endpoint, payload = { args: {} }) => {
          client.send(JSON.stringify({ type: 'open', streamId, endpoint, payload }));
        },
      });
    });
  });
}

/** 轮询等待某个 streamId 的下行帧（error / item 均可能）。 */
async function waitForStreamFrame(handle: MuxHandle, streamId: string, timeoutMs = 2000): Promise<Record<string, unknown> | null> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const found = handle.frames.find((frame) => frame.streamId === streamId);
    if (found !== undefined) return found;
    if (Date.now() >= deadline) return null;
    await wait(20);
  }
}

/** 轮询等待上游 Remote mux 收到某个端点的 open 帧至少 count 次。 */
async function waitForUpstreamOpen(endpoint: string, count = 1, timeoutMs = 2000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (upstreamRemoteFrames.filter((frame) => frame.type === 'open' && frame.endpoint === endpoint).length >= count) return true;
    if (Date.now() >= deadline) return false;
    await wait(20);
  }
}

const upstreamOpenCount = (endpoint: string): number =>
  upstreamRemoteFrames.filter((frame) => frame.type === 'open' && frame.endpoint === endpoint).length;

/** 优雅关闭一条 mux carrier 并等待网关侧（含其上游连接）收尾。 */
async function closeMux(handle: MuxHandle): Promise<void> {
  try { handle.client.close(); } catch { /* 已关闭 */ }
  await Promise.race([handle.closed, wait(1000)]);
  try { handle.client.terminate(); } catch { /* 已关闭 */ }
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-mux-core-'));
  const dbPath = path.join(appDir, 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const subuser = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  subuserId = subuser.id;
  setPerms();

  upstream = http.createServer((req, res) => {
    if (req.url?.startsWith('/api/workspace.list')) {
      // 基线：一个可见工作区 + 一个待 seed 的既有会话。
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({
        result: {
          value: {
            items: [{
              workspaceId: 'core-workspace', path: WORKSPACE_PATH, title: 'Core',
              sessionIds: [AUTHORIZED_SESSION_ID],
              createdAt: '2026-08-28T00:00:00.000Z', updatedAt: '2026-08-28T00:00:00.000Z',
            }],
            archivedSessionIds: [],
          },
        },
      }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end('{}');
  });
  upstreamWss = new WebSocketServer({ noServer: true });
  upstreamWss.on('connection', (client: any, req: http.IncomingMessage) => {
    const isRemoteMux = String(req?.url ?? '').startsWith('/api/remote.mux');
    client.on('message', (data: Buffer) => {
      if (!isRemoteMux) return;
      try { upstreamRemoteFrames.push(JSON.parse(data.toString('utf8')) as Record<string, unknown>); } catch { /* ignore */ }
    });
  });
  upstream.on('upgrade', (req, socket, head) => {
    upstreamWss.handleUpgrade(req, socket, head, (client: any) => upstreamWss.emit('connection', client, req));
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;

  const config: PlatformConfig = {
    setupKey: 'test-setup-key', dbPath, dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    // 广谱 SSH 登记（等价 MCP_GATEWAY_SSH_ENDPOINTS=/api/*）。
    endpointRules: parseEndpointAllowlist(BROAD_SSH_RULE, 'TEST'),
  };
  subuserCookie = `dsh_gateway_token=${jwt.sign({ sub: String(subuser.id), username: subuser.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;

  // 基线：建立 userSessionAccess（否则 session/control、session/follow、job 会被合法延迟）。
  const snapshot = await workspaceListSnapshot();
  baselineStatus = snapshot.status;
});

after(async () => {
  await Promise.all(openMuxHandles.map((client) => (async () => {
    try { client.close(); } catch { /* 已关闭 */ }
    await wait(50);
    try { client.terminate(); } catch { /* 已关闭 */ }
  })()));
  for (const client of [...(upstreamWss?.clients ?? [])]) {
    try { client.terminate(); } catch { /* 已关闭 */ }
  }
  try { upstreamWss?.close(); } catch { /* 上游 WS 已随连接关闭 */ }
  gateway?.close();
  (gateway as http.Server & { closeAllConnections?: () => void })?.closeAllConnections?.();
  upstream?.close();
  (upstream as http.Server & { closeAllConnections?: () => void })?.closeAllConnections?.();
  db?.close();
  try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 文件占用：忽略 */ }
});

test('基线：广谱 /api/* 登记下子用户仍能建立 workspace.list 会话授权基线', () => {
  assert.equal(baselineStatus, 200, 'workspace.list 基线必须成功（allowSsh=true 时已登记 ssh 端点照常透传）');
  assert.equal(db.hasUserSessionGrant(subuserId, AUTHORIZED_SESSION_ID), true, '基线必须 seed 出显式会话授权，供后续核心流判定');
});

test('核心 Remote mux 流在广谱 /api/* 登记下仍逐流转发上游且不下发 gateway/forbidden', async () => {
  upstreamRemoteFrames = [];
  const mux = await openMux(subuserCookie);
  try {
    CORE_STREAMS.forEach((stream, index) => {
      mux.openStream(`core-${index}`, stream.endpoint, stream.payload ?? { args: {} });
    });

    for (const [index, stream] of CORE_STREAMS.entries()) {
      const streamId = `core-${index}`;
      const forwarded = await waitForUpstreamOpen(stream.endpoint);
      assert.equal(forwarded, true, `${stream.endpoint} 必须被转发到上游，而不是被通用 SSH 登记检查拒绝`);

      const errorFrame = mux.frames.find((frame) => frame.streamId === streamId && frame.type === 'error');
      assert.equal(errorFrame, undefined, `${stream.endpoint} 不得下发 error 帧（尤其不得回 gateway/forbidden / "${UNAVAILABLE_MESSAGE}"）`);
      assert.equal(upstreamOpenCount(stream.endpoint), 1, `${stream.endpoint} 上游 open 帧应恰好一次`);
    }

    assert.equal(mux.client.readyState, NodeWebSocket.OPEN, '核心流全部放行后 carrier 必须保持打开');
    assert.equal(
      mux.frames.some((frame) => frame.type === 'error'),
      false,
      '核心流场景下不应出现任何 error 帧',
    );
  } finally {
    await closeMux(mux);
  }
});

test('非核心的已登记 Remote mux 端点仍逐流拒绝，且拒绝不撕裂同 carrier', async () => {
  upstreamRemoteFrames = [];
  const mux = await openMux(subuserCookie);
  try {
    // 先确认 carrier 上一条核心流可转发（证明授权上下文已就绪，不是靠 baseline 缺失误判）。
    mux.openStream('coexist-events', '$events', { args: {} });
    assert.equal(await waitForUpstreamOpen('$events'), true, '$events 必须被转发，用于证明 carrier 与基线就绪');

    // 非核心已登记端点：仍逐流拒绝，绝不转发。
    mux.openStream('non-core', REGISTERED_NON_CORE_MUX_ENDPOINT, { args: {} });
    const frame = await waitForStreamFrame(mux, 'non-core');
    assert.ok(frame, '非核心已登记端点必须收到逻辑流响应帧');
    assert.equal(frame?.type, 'error', '非核心已登记端点必须以 error 帧结束该逻辑流，而不是撕裂 carrier');
    const error = frame?.error as { code?: string; message?: string } | undefined;
    assert.equal(error?.code, 'gateway/forbidden', '非核心已登记端点必须回 gateway/forbidden');
    assert.equal(error?.message, UNAVAILABLE_MESSAGE, '非核心已登记端点必须回固定文案');
    assert.equal(upstreamOpenCount(REGISTERED_NON_CORE_MUX_ENDPOINT), 0, '非核心已登记端点不得转发上游');
    assert.equal(mux.client.readyState, NodeWebSocket.OPEN, '逐流拒绝不得关闭 carrier');

    // 拒绝之后，同 carrier 的核心流仍可继续转发：登记检查只影响该逻辑流。
    mux.openStream('coexist-events-2', '$events', { args: {} });
    assert.equal(await waitForUpstreamOpen('$events', 2), true, '拒绝非核心流后核心流仍应转发');
    assert.equal(upstreamOpenCount('$events'), 2, '$events 应收到两次 open（拒绝前后各一次）');
  } finally {
    await closeMux(mux);
  }
});
