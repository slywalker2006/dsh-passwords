// allowSsh Remote mux 边界回归（配套 src/proxy.ts 的 owner/ssh mux 判定）：
//
//   1) owner: 登记的 terminal Remote 流（terminal/follow、terminal/retain）即使
//      子用户 allowSsh=true 也必须逐逻辑流拒绝，绝不绕过 owner-only 触达上游；
//   2) 已登记 ssh 能力的非 terminal Remote 流不随 allowSsh 放开：v2.7.5 既定
//      语义是 mux 只由 allowSsh 放行官方 terminal，登记（owner:/ssh）在 mux 上
//      仍是一道收紧边界，false / true 两态均逐流拒绝，不凭空转发；
//   3) 主用户不受登记表与 allowSsh 影响：owner: terminal 与 ssh 登记流均原样转发。
//
// 本文件锁定「owner: 永远拒绝」与「不凭空放开普通/未知 Remote 流」两条边界，
// 官方 terminal 的 allowSsh 门控由 allow-ssh-permissions.test.ts 覆盖。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
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

/** owner: 登记的 terminal 命名空间：覆盖 terminal/follow 与 terminal/retain。 */
const OWNER_TERMINAL_RULE = 'owner:/api/terminal/*';
/** 已登记 ssh 能力的第三方路径；其 Remote mux 逻辑端点为 plugin/ssh。 */
const REGISTERED_SSH_PATH = '/api/plugin/ssh';
const REGISTERED_SSH_MUX_ENDPOINT = 'plugin/ssh';
const OWNER_ONLY_MESSAGE = 'Remote host capability is owner-only';
const UNAVAILABLE_MESSAGE = 'Remote endpoint is not available for this user';

let appDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let upstreamWss: any;
let upstreamRemoteFrames: Array<Record<string, unknown>> = [];
let gatewayPort = 0;
let subuserId = 0;
let adminCookie = '';
let subuserCookie = '';
const openMuxHandles: any[] = [];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

/** 直接写权限行（其余字段与 allow-ssh-permissions 基线保持一致）。 */
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

/** 优雅关闭一条 mux carrier 并等待网关侧（含其上游连接）收尾。 */
async function closeMux(handle: MuxHandle): Promise<void> {
  try { handle.client.close(); } catch { /* 已关闭 */ }
  await Promise.race([handle.closed, wait(1000)]);
  try { handle.client.terminate(); } catch { /* 已关闭 */ }
}

const upstreamOpenCount = (endpoint: string): number =>
  upstreamRemoteFrames.filter((frame) => frame.type === 'open' && frame.endpoint === endpoint).length;

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-allowssh-mux-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const subuser = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  subuserId = subuser.id;
  setPerms(false);

  upstream = http.createServer((req, res) => {
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
    // owner: 登记 terminal 命名空间 + 一条已登记 ssh 端点（其 mux 逻辑端点为 plugin/ssh）。
    endpointRules: parseEndpointAllowlist(`${OWNER_TERMINAL_RULE},${REGISTERED_SSH_PATH}`, 'TEST'),
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

test('owner: 登记的 terminal Remote mux 在 allowSsh=true 时仍逐流拒绝且不触上游', async () => {
  setPerms(true);
  upstreamRemoteFrames = [];
  const mux = await openMux(subuserCookie);
  try {
    for (const endpoint of ['terminal/follow', 'terminal/retain'] as const) {
      const streamId = `owner-${endpoint.replace('/', '-')}`;
      mux.openStream(streamId, endpoint, { args: {} });
      const frame = await waitForStreamFrame(mux, streamId);
      assert.ok(frame, `${endpoint} 必须收到逻辑流响应帧`);
      assert.equal(frame?.type, 'error', `${endpoint} 必须以 error 帧结束该逻辑流，而不是撕裂 carrier`);
      const error = frame?.error as { code?: string; message?: string; details?: unknown } | undefined;
      assert.equal(error?.code, 'gateway/forbidden', `${endpoint} 必须回 gateway/forbidden`);
      assert.equal(error?.message, OWNER_ONLY_MESSAGE, `${endpoint} 必须回 owner-only 文案`);
      assert.deepEqual(error?.details, {});
      assert.equal(mux.client.readyState, NodeWebSocket.OPEN, 'owner: 逻辑流拒绝不得关闭 carrier');
    }
    assert.equal(upstreamOpenCount('terminal/follow'), 0, 'owner: terminal/follow 不得转发上游');
    assert.equal(upstreamOpenCount('terminal/retain'), 0, 'owner: terminal/retain 不得转发上游');
  } finally {
    await closeMux(mux);
    setPerms(false);
  }
});

test('已登记 ssh 的 Remote mux 端点不随 allowSsh 放开：false/true 两态均逐流拒绝', async () => {
  for (const allowSsh of [false, true] as const) {
    setPerms(allowSsh);
    upstreamRemoteFrames = [];
    const mux = await openMux(subuserCookie);
    try {
      const streamId = `ssh-mux-${String(allowSsh)}`;
      mux.openStream(streamId, REGISTERED_SSH_MUX_ENDPOINT, { args: {} });
      const frame = await waitForStreamFrame(mux, streamId);
      assert.ok(frame, `allowSsh=${String(allowSsh)}：登记 ssh mux 必须收到逻辑流响应帧`);
      assert.equal(frame?.type, 'error', `allowSsh=${String(allowSsh)}：登记 ssh mux 必须以 error 帧结束该逻辑流`);
      const error = frame?.error as { code?: string; message?: string } | undefined;
      assert.equal(error?.code, 'gateway/forbidden', `allowSsh=${String(allowSsh)}：必须回 gateway/forbidden`);
      assert.equal(error?.message, UNAVAILABLE_MESSAGE, `allowSsh=${String(allowSsh)}：必须回固定文案`);
      assert.equal(upstreamOpenCount(REGISTERED_SSH_MUX_ENDPOINT), 0, `allowSsh=${String(allowSsh)}：登记 ssh mux 不得转发上游`);
      assert.equal(mux.client.readyState, NodeWebSocket.OPEN, `allowSsh=${String(allowSsh)}：登记 ssh mux 拒绝不得关闭 carrier`);
    } finally {
      await closeMux(mux);
    }
  }
  setPerms(false);
});

test('主用户始终放行：owner: 登记的 terminal 与 ssh 登记的 Remote mux 均转发上游', async () => {
  setPerms(false); // 子用户权限不应影响主用户
  upstreamRemoteFrames = [];
  const mux = await openMux(adminCookie);
  try {
    mux.openStream('admin-owner-terminal', 'terminal/follow', { args: {} });
    assert.equal(await waitForUpstreamOpen('terminal/follow'), true, '主用户 owner: terminal/follow 必须转发上游');
    mux.openStream('admin-ssh-mux', REGISTERED_SSH_MUX_ENDPOINT, { args: {} });
    assert.equal(await waitForUpstreamOpen(REGISTERED_SSH_MUX_ENDPOINT), true, '主用户 ssh 登记 mux 必须转发上游');
  } finally {
    await closeMux(mux);
  }
});
