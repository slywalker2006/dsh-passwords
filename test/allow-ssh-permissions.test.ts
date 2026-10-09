// allowSsh HTTP + Remote 权限回归（期望语义 = v2.7.5「官方 terminal 与已登记第三方
// SSH 共用 allowSsh」；协议 = 当前 DSH 0.2.1-alpha.1）：
//
//   allowSsh=false（子用户）：
//     · 官方 terminal 真实方法（create/write/resize/rename）→ 403，不触上游；
//     · 官方 terminal UX 桩（list/environment/shells/close）→ 200 固定响应，不触上游；
//     · Remote terminal/follow、terminal/retain → 逐逻辑流 error（terminal/unavailable），
//       不转发到上游，且不撕裂同一 carrier 的其它流；
//     · 登记在 MCP_GATEWAY_SSH_ENDPOINTS 的第三方 SSH → HTTP 与 WS 均 403。
//   allowSsh=true（子用户）：
//     · 官方 terminal 全部已知 HTTP unary RPC → 透传上游；
//     · Remote terminal/follow、terminal/retain → 放行并转发到上游；
//     · 登记第三方 SSH → HTTP 与 WS 均放行。
//   主用户：始终放行（官方 terminal、登记第三方 SSH、Remote terminal 流）。
//   allowSsh true→false：旧 Remote mux 被服务端关闭，且新 terminal 流继续被拒。
//
// 本文件锁定「已批准语义」的对外契约，不修改生产代码：allowSsh=true 组的断言验证
// 当前已恢复的实现确实放行官方 terminal / 已登记第三方 SSH，而不是把 allowSsh 当作
// legacy no-op。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options?: { noServer?: boolean }) => any;
  WebSocket: new (url: string, options?: { headers?: Record<string, string> }) => any;
};

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { parseEndpointAllowlist } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

/** 已登记的第三方 SSH 端点（HTTP 与 WS 两条通道共用同一条规则）。 */
const REGISTERED_SSH_PATH = '/api/plugin/ssh';
/** 与 gateway 侧固定的不可用文案保持一致，避免断言字符串漂移。 */
const TERMINAL_UNAVAILABLE_MESSAGE = 'Remote terminal is not available for this user';

let appDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let upstreamWss: any;
let upstreamHits: string[] = [];
let upstreamBodies: Array<{ url: string; body: string }> = [];
let upstreamRemoteFrames: Array<Record<string, unknown>> = [];
let gatewayPort = 0;
let subuserId = 0;
let adminCookie = '';
let subuserCookie = '';
const openMuxHandles: any[] = [];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

const envelope = (rpcId: string, method: string, args: Record<string, unknown>) => ({
  type: 'client-request', rpcId, method, payload: { args },
});

function post(url: string, body: unknown, cookie: string): Promise<{ status: number; json: Record<string, unknown>; body: string }> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1', port: gatewayPort, method: 'POST', path: url,
        headers: { cookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)), connection: 'close' },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: Record<string, unknown> = {};
          try { json = JSON.parse(text) as Record<string, unknown>; } catch { /* 403 页面等非 JSON */ }
          resolve({ status: res.statusCode ?? 0, json, body: text });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

/** 普通 GET（用于已登记第三方 SSH 的 HTTP 通道）。 */
function get(url: string, cookie: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method: 'GET', path: url, headers: { cookie, connection: 'close' } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/** 原始 WS 握手：拒绝时按普通 HTTP 响应返回状态码，放行时返回 101。 */
function wsHandshake(pathname: string, cookie: string): Promise<{ status: number; socket: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: gatewayPort, path: pathname,
      headers: {
        host: '127.0.0.1',
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': randomBytes(16).toString('base64'),
        'sec-websocket-version': '13',
        cookie,
        origin: 'http://127.0.0.1',
      },
    });
    req.on('upgrade', (res, socket) => resolve({ status: res.statusCode ?? 0, socket }));
    req.on('response', (res) => { res.resume(); resolve({ status: res.statusCode ?? 0, socket: null }); });
    req.on('error', reject);
    req.end();
  });
}

/** 直接写权限行（其余字段保持与 gateway-terminal-stub 基线一致）。 */
function setPerms(allowSsh: boolean): void {
  db.setPermissions(subuserId, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    allowSsh, banned: false, sandboxMode: null,
  });
}

interface MuxHandle {
  client: any;
  frames: Array<Record<string, unknown>>;
  closed: Promise<{ code: number; reason: string }>;
  openStream: (streamId: string, endpoint: string, payload?: unknown) => void;
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

/** 轮询等待上游 Remote mux 收到某个端点的 open 帧。 */
async function waitForUpstreamOpen(endpoint: string, timeoutMs = 2000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (upstreamRemoteFrames.some((frame) => frame.type === 'open' && frame.endpoint === endpoint)) return true;
    if (Date.now() >= deadline) return false;
    await wait(20);
  }
}

/** 优雅关闭一条 mux carrier 并等待网关侧（含其上游连接）收尾，避免残留 socket 拖住进程退出。 */
async function closeMux(handle: MuxHandle): Promise<void> {
  try { handle.client.close(); } catch { /* 已关闭 */ }
  await Promise.race([handle.closed, wait(1000)]);
  try { handle.client.terminate(); } catch { /* 已关闭 */ }
}

const upstreamOpenCount = (endpoint: string): number =>
  upstreamRemoteFrames.filter((frame) => frame.type === 'open' && frame.endpoint === endpoint).length;

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-allowssh-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const subuser = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  subuserId = subuser.id;
  setPerms(false);

  upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      upstreamHits.push(String(req.url));
      upstreamBodies.push({ url: String(req.url), body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({ type: 'server-response', rpcId: 'upstream', result: { ok: true, value: [] } }));
    });
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
    // 所有上游升级都交给真实的 WS server：登记 SSH 路径也需要正常参与 close 握手，
    // 否则网关侧 upstreamWs.close() 永远等不到回包，残留 socket 会拖住测试进程退出。
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
    // 已登记的第三方 SSH 端点：验证 allowSsh 开关是唯一的子用户放行依据。
    endpointRules: parseEndpointAllowlist(REGISTERED_SSH_PATH, 'TEST'),
  };
  const tokenFor = (user: { id: number; username: string }) =>
    `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  adminCookie = tokenFor(admin);
  subuserCookie = tokenFor(subuser);

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(async () => {
  await Promise.all(openMuxHandles.map((client) => (async () => {
    try { client.close(); } catch { /* 已关闭 */ }
    await wait(50);
    try { client.terminate(); } catch { /* 已关闭 */ }
  })()));
  // 升级后的 WS 与 HTTP server 解耦：close()/closeAllConnections() 不会终止它们。
  // 快照后再 terminate（边遍历边删除会跳过元素），否则残留上游连接会拖住进程退出。
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

test('allowSsh=false：官方 terminal 真实方法 403，UX 桩 200 且均不触上游', async () => {
  setPerms(false);
  // 真实宿主能力：allowSsh 关闭必须 fail-closed。
  for (const method of ['create', 'write', 'resize', 'rename'] as const) {
    upstreamHits = [];
    const res = await post(`/api/terminal/${method}`, envelope(`rpc-${method}`, `terminal/${method}`, { agentId: 'a' }), subuserCookie);
    assert.equal(res.status, 403, `allowSsh=false：terminal/${method} 必须 403`);
    assert.equal(upstreamHits.length, 0, `allowSsh=false：terminal/${method} 不得到达上游`);
  }
  // 客户端恢复流程的 UX 桩：固定本地响应，绝不触上游。
  for (const [url, method] of [
    ['/api/terminal/list', 'terminal/list'],
    ['/api/terminal/environment', 'terminal/environment'],
    ['/api/terminal/shells', 'terminal/shells'],
    ['/api/terminal/close', 'terminal/close'],
  ] as const) {
    upstreamHits = [];
    const res = await post(url, envelope(`rpc-${method}`, method, { sessionId: 'session-x', agentId: 'a' }), subuserCookie);
    assert.equal(res.status, 200, `allowSsh=false：${method} 必须回本地 UX 桩`);
    assert.equal(res.json.rpcId, `rpc-${method}`, 'rpcId 必须逐字回显');
    const result = res.json.result as { ok?: boolean; value?: unknown; error?: { code?: string } } | undefined;
    if (method === 'terminal/list') {
      assert.equal(result?.ok, true, 'list 为空成功桩');
      assert.deepEqual(result?.value, [], 'value 必须是裸数组');
    } else if (method === 'terminal/close') {
      assert.equal(result?.ok, true, 'close 为幂等成功桩');
      assert.equal(Object.hasOwn(result ?? {}, 'value'), false, 'close 不得带 value');
    } else {
      assert.equal(result?.ok, false, `${method} 必须 ok=false`);
      assert.equal(result?.error?.code, 'terminal/unavailable', `${method} 必须回 terminal/unavailable`);
    }
    assert.equal(upstreamHits.length, 0, `allowSsh=false：${method} 桩不得到达上游`);
  }
});

test('allowSsh=false：Remote terminal/follow、terminal/retain 逐流拒绝且不触上游', async () => {
  setPerms(false);
  upstreamRemoteFrames = [];
  const mux = await openMux(subuserCookie);
  try {
    for (const endpoint of ['terminal/follow', 'terminal/retain'] as const) {
      const streamId = `deny-${endpoint.replace('/', '-')}`;
      mux.openStream(streamId, endpoint, { args: {} });
      const frame = await waitForStreamFrame(mux, streamId);
      assert.ok(frame, `${endpoint} 必须收到逻辑流响应帧`);
      assert.equal(frame?.type, 'error', `${endpoint} 必须以 error 帧结束该逻辑流，而不是撕裂 carrier`);
      const error = frame?.error as { code?: string; message?: string; details?: unknown } | undefined;
      assert.equal(error?.code, 'terminal/unavailable', `${endpoint} 必须回 terminal/unavailable`);
      assert.equal(error?.message, TERMINAL_UNAVAILABLE_MESSAGE, `${endpoint} 必须回固定文案`);
      assert.deepEqual(error?.details, {}, `${endpoint} details 必须是 plain object`);
    }
    assert.equal(upstreamOpenCount('terminal/follow'), 0, 'allowSsh=false：terminal/follow 不得转发上游');
    assert.equal(upstreamOpenCount('terminal/retain'), 0, 'allowSsh=false：terminal/retain 不得转发上游');
  } finally {
    await closeMux(mux);
  }
});

test('allowSsh=false：登记第三方 SSH HTTP 403、WS 403', async () => {
  setPerms(false);
  upstreamHits = [];
  const httpRes = await get(REGISTERED_SSH_PATH, subuserCookie);
  assert.equal(httpRes.status, 403, 'allowSsh=false：登记 SSH 的 HTTP 通道必须 403');
  assert.equal(upstreamHits.length, 0, 'allowSsh=false：登记 SSH HTTP 不得到达上游');
  const ws = await wsHandshake(REGISTERED_SSH_PATH, subuserCookie);
  try {
    assert.equal(ws.status, 403, 'allowSsh=false：登记 SSH 的 WS 通道必须 403');
  } finally {
    ws.socket?.destroy();
  }
});

test('allowSsh=true：官方 terminal 全部已知 HTTP unary RPC 透传上游', async () => {
  setPerms(true);
  try {
    const methods = ['environment', 'shells', 'list', 'create', 'write', 'resize', 'rename', 'close'] as const;
    for (const method of methods) {
      upstreamHits = [];
      upstreamBodies = [];
      const body = envelope(`rpc-sub-${method}`, `terminal/${method}`, { agentId: 'agent-sub', id: 'term-sub' });
      const res = await post(`/api/terminal/${method}`, body, subuserCookie);
      assert.equal(res.status, 200, `allowSsh=true：terminal/${method} 必须透传：${res.body.slice(0, 160)}`);
      assert.equal((res.json.result as { ok?: unknown } | undefined)?.ok, true, `terminal/${method} 必须是上游成功响应`);
      assert.deepEqual(upstreamHits, [`/api/terminal/${method}`], `terminal/${method} 必须恰好到达上游一次`);
      assert.equal(upstreamBodies[0]?.body, JSON.stringify(body), `terminal/${method} body 必须逐字透传`);
    }
  } finally {
    setPerms(false);
  }
});

test('allowSsh=true：官方 terminal Remote terminal/follow、terminal/retain 放行到上游', async () => {
  setPerms(true);
  upstreamRemoteFrames = [];
  const mux = await openMux(subuserCookie);
  try {
    for (const endpoint of ['terminal/follow', 'terminal/retain'] as const) {
      const streamId = `allow-${endpoint.replace('/', '-')}`;
      mux.openStream(streamId, endpoint, { args: {} });
      assert.equal(await waitForUpstreamOpen(endpoint), true, `allowSsh=true：${endpoint} 必须转发到上游`);
      // 放行时不回 error 帧：给一个短暂窗口让潜在的本地拒绝帧到达（如已到则立刻返回）。
      const frame = await waitForStreamFrame(mux, streamId, 300);
      assert.equal(frame, null, `${endpoint} 放行时不得回 error 帧`);
    }
  } finally {
    await closeMux(mux);
    setPerms(false);
  }
});

test('allowSsh=true：登记第三方 SSH HTTP 与 WS 均放行', async () => {
  setPerms(true);
  try {
    upstreamHits = [];
    const httpRes = await get(REGISTERED_SSH_PATH, subuserCookie);
    assert.equal(httpRes.status, 200, 'allowSsh=true：登记 SSH 的 HTTP 通道必须放行');
    assert.equal(upstreamHits.some((url) => url.startsWith(REGISTERED_SSH_PATH)), true, 'allowSsh=true：登记 SSH HTTP 必须到达上游');
    const ws = await wsHandshake(REGISTERED_SSH_PATH, subuserCookie);
    try {
      assert.equal(ws.status, 101, 'allowSsh=true：登记 SSH 的 WS 通道必须放行');
    } finally {
      ws.socket?.destroy();
    }
  } finally {
    setPerms(false);
  }
});

test('主用户始终放行：官方 terminal、登记第三方 SSH、Remote terminal 流', async () => {
  setPerms(false); // 子用户权限不应影响主用户
  // 官方 terminal HTTP
  upstreamHits = [];
  const terminal = await post('/api/terminal/retain', envelope('rpc-admin-retain', 'terminal/retain', { agentId: 'a' }), adminCookie);
  assert.equal(terminal.status, 200, `主用户 terminal/retain 必须透传：${terminal.body.slice(0, 160)}`);
  assert.equal(upstreamHits.includes('/api/terminal/retain'), true, '主用户 terminal 必须到达上游');
  // 登记第三方 SSH HTTP
  upstreamHits = [];
  const sshHttp = await get(REGISTERED_SSH_PATH, adminCookie);
  assert.equal(sshHttp.status, 200, '主用户登记 SSH HTTP 必须放行');
  assert.equal(upstreamHits.some((url) => url.startsWith(REGISTERED_SSH_PATH)), true, '主用户登记 SSH 必须到达上游');
  // 登记第三方 SSH WS
  const sshWs = await wsHandshake(REGISTERED_SSH_PATH, adminCookie);
  try {
    assert.equal(sshWs.status, 101, '主用户登记 SSH WS 必须放行');
  } finally {
    sshWs.socket?.destroy();
  }
  // Remote terminal 流
  upstreamRemoteFrames = [];
  const mux = await openMux(adminCookie);
  try {
    mux.openStream('admin-retain', 'terminal/retain', { args: {} });
    assert.equal(await waitForUpstreamOpen('terminal/retain'), true, '主用户 Remote terminal/retain 必须转发上游');
  } finally {
    await closeMux(mux);
  }
});

test('allowSsh true→false：旧 Remote mux 被服务端关闭，重连后 terminal 流仍被拒', async () => {
  // 载体层面的撤销语义：sshChanged 必须关闭该用户的旧 Remote carrier，避免撤销后
  // 继续持有升级时的授权快照。这里用一条普通 workspace/follow 流证明 carrier 活跃，
  // 不依赖 allowSsh=true 的 terminal 放行（后者由上面的红测单独覆盖）。
  setPerms(true);
  upstreamRemoteFrames = [];
  const carried = await openMux(subuserCookie);
  try {
    carried.openStream('before-revoke-work', 'workspace/follow', { args: {} });
    await wait(50);

    const saved = await post('/gateway/api/permissions', { userId: subuserId, allowSsh: false }, adminCookie);
    assert.equal(saved.status, 200, `权限保存必须成功：${saved.body.slice(0, 160)}`);

    const closed = await Promise.race([
      carried.closed.then((value) => value),
      wait(2000).then(() => null),
    ]);
    assert.ok(closed, 'allowSsh 从 true 改为 false 后旧 Remote mux 必须被服务端关闭');
    assert.equal(closed?.code, 1012, '关闭码应为权限变更的 1012');
  } finally {
    await closeMux(carried);
  }

  // 撤销后重连：同一条 terminal 流不得再放行到上游。
  upstreamRemoteFrames = [];
  const reconnected = await openMux(subuserCookie);
  try {
    reconnected.openStream('after-revoke', 'terminal/retain', { args: {} });
    const frame = await waitForStreamFrame(reconnected, 'after-revoke');
    assert.equal(frame?.type, 'error', '撤销后新的 terminal/retain 必须回 error 帧');
    assert.equal((frame?.error as { code?: string } | undefined)?.code, 'terminal/unavailable', '撤销后必须回 terminal/unavailable');
    assert.equal(upstreamOpenCount('terminal/retain'), 0, '撤销后 terminal/retain 不得再转发上游');
  } finally {
    await closeMux(reconnected);
    setPerms(false);
  }
});

test('allowSsh true→false：撤销诊断首因锁定 permission-revoked/1012、回收上游腿且不泄漏敏感值', async () => {
  setPerms(true);

  const upstreamBaseline = upstreamWss.clients.size;
  const carried = await openMux(subuserCookie);

  // 只在撤销窗口内捕获诊断，避免与其它 carrier 的输出混在一起。
  const captured: string[] = [];
  const originalError = console.error;
  console.error = (...args: unknown[]) => {
    captured.push(args.map((arg) => (typeof arg === 'string' ? arg : String(arg))).join(' '));
  };
  let closed: { code: number; reason: string } | null = null;
  try {
    // 一条 workspace/follow 流确保 carrier 在网关与上游两侧均已活跃。
    carried.openStream('diag-work', 'workspace/follow', { args: {} });
    await wait(50);

    const saved = await post('/gateway/api/permissions', { userId: subuserId, allowSsh: false }, adminCookie);
    assert.equal(saved.status, 200, `权限保存必须成功：${saved.body.slice(0, 160)}`);

    closed = await Promise.race([
      carried.closed.then((value) => value),
      wait(2000).then(() => null),
    ]);
  } finally {
    console.error = originalError;
  }

  assert.ok(closed, 'allowSsh 由 true 改为 false 后旧 Remote carrier 必须被关闭');
  assert.equal(closed?.code, 1012, '关闭码应为权限变更的 1012');

  // 诊断：撤销的首因必须锁定为 permission-revoked，而不是关闭握手完成时的 client-close。
  const closeLogs = captured.filter((line) => line.includes('[dsh-passwords] remote.mux close'));
  assert.equal(closeLogs.length, 1, `每个 carrier 只应记录一次关闭诊断，实际：${JSON.stringify(captured)}`);
  const closeLog = closeLogs[0]!;
  assert.match(closeLog, /source=permission-revoked\b/, '首因诊断必须是 permission-revoked');
  assert.match(closeLog, /direction=both\b/, '撤销诊断方向应为 both');
  assert.match(closeLog, /code=1012\b/, '诊断关闭码应为 1012');
  assert.ok(!closeLog.includes('source=client-close'), '关闭握手不得把首因诊断改写为 client-close');

  // 不泄漏敏感值：原始理由文案、会话 token 与 JWT 段都不得进入受限诊断。
  const token = subuserCookie.slice(subuserCookie.indexOf('=') + 1);
  for (const secret of ['Permissions changed', 'dsh_gateway_token', token, 'eyJ']) {
    assert.ok(!closeLog.includes(secret), `诊断不得包含敏感值 ${secret}`);
  }

  // 回收：撤销后上游腿应随关闭握手收尾，连接数回到基线。
  const recycleDeadline = Date.now() + 2000;
  while (upstreamWss.clients.size > upstreamBaseline && Date.now() < recycleDeadline) {
    await wait(20);
  }
  assert.equal(upstreamWss.clients.size, upstreamBaseline, '撤销后 carrier 的上游腿必须被回收');

  try { carried.client.terminate(); } catch { /* 已关闭 */ }
  setPerms(false);
});
