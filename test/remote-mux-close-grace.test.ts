// Remote mux 关闭握手回归（报告 R2）。
//
// 场景：`closeCarrier` 同时关闭两条腿（浏览器腿 + 上游腿）。当上游腿**先**完成关闭握手，
// 而浏览器腿仍处于 CLOSING（优雅关闭握手进行中）时，既有的上游 close 回调会把浏览器腿
// 直接 terminate，绕过 5s grace，并丢弃已入队的 Close——浏览器因此只能观察到 1006。
//
// 本文件用可控的真实 ws + TCP relay 夹具，把「服务端腿 close 事件」与「客户端观察到的
// 关闭码」分开观测：
//   1. 浏览器腿停读（下行积压 ~250ms）：上游腿先完成关闭后，浏览器腿应继续握手，恢复读取
//      后观察到网关下发的 1003（而不是被 terminate 的 1006）；
//   2. 下行被 relay 阻塞（Close 送不到浏览器）：仍在 grace 到期后才强制回收（接近 5s），
//      而不是在上游腿 close 事件后立即回收。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import jwt from 'jsonwebtoken';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options?: { noServer?: boolean }) => any;
  WebSocket: { new (url: string, options?: { headers?: Record<string, string> }): any };
};

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { parseEndpointAllowlist } from '../src/permissions.js';
import type { PlatformConfig, RemoteMuxConfig } from '../src/config.js';

const JWT_SECRET = 'gw-mux-close-grace-secret';
const MIB = 1024 * 1024;

/** 稳定期限：足够长，避免心跳/写停滞干扰关闭用例。 */
const STABLE_MUX: RemoteMuxConfig = { fragmentBytes: 16 * 1024, pingIntervalMs: 30_000, pongTimeoutMs: 60_000, writeStallMs: 10_000 };

const sleep = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

/** 有界轮询：超时以断言失败退出，绝不无限等待。 */
async function waitFor(predicate: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() >= deadline) assert.ok(false, `超时未满足：${label}`);
    await sleep(10);
  }
}

let appDir = '';
let db: Database;
let adminId = 0;
let cookie = '';

before(() => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-mux-close-'));
  db = new Database(path.join(appDir, 'test.db'), createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  adminId = admin.id;
  cookie = `dsh_gateway_token=${jwt.sign({ sub: String(adminId), username: admin.username, cv: 0 }, JWT_SECRET, { expiresIn: '12h' })}`;
});

after(() => {
  db?.close();
  try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 文件占用：忽略 */ }
});

function makeConfig(upstreamPort: number): PlatformConfig {
  return {
    setupKey: 'test-setup-key',
    dbPath: path.join(appDir, 'test.db'),
    dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: JWT_SECRET, internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: parseEndpointAllowlist('', 'TEST'),
    mux: STABLE_MUX,
  };
}

/** mock 上游：`/api/remote.mux` 的 WS 服务端；记录服务端腿（上游腿）的 close 事件。 */
type UpstreamHandle = {
  port: number;
  connections: any[];
  /** 服务端腿收到/完成 close 的时间戳（毫秒）；未发生为 null。 */
  serverSideCloseAt: () => number | null;
  close: () => Promise<void>;
};

async function startUpstream(options: {
  onConnection?: (client: any) => void;
} = {}): Promise<UpstreamHandle> {
  const connections: any[] = [];
  let closeAt: number | null = null;
  const wsServer = new WebSocketServer({ noServer: true });
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end('{}');
  });
  server.on('upgrade', (req, socket, head) => {
    wsServer.handleUpgrade(req, socket as net.Socket, head, (client: any) => {
      connections.push(client);
      // 服务端腿 close 事件：这是报告关心的「服务端腿 close 事件」，与客户端观察到的关闭码分开。
      client.on('close', () => { closeAt = Date.now(); });
      options.onConnection?.(client);
      wsServer.emit('connection', client, req);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    connections,
    serverSideCloseAt: () => closeAt,
    close: async () => {
      for (const client of connections) { try { client.terminate(); } catch { /* 已关闭 */ } }
      try { wsServer.close(); } catch { /* 已关闭 */ }
      (server as http.Server & { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

type GatewayHandle = { port: number; close: () => Promise<void> };

async function startGateway(upstreamPort: number): Promise<GatewayHandle> {
  const config = makeConfig(upstreamPort);
  const auth = new AuthService(config, db);
  const server = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    close: async () => {
      (server as http.Server & { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** 浏览器腿的请求头：Host 必须与 Origin 主机一致，否则网关按跨源拒绝。 */
const muxHeaders = (): Record<string, string> => ({ cookie, origin: 'http://127.0.0.1', host: '127.0.0.1' });

type MuxHandle = {
  client: any;
  frames: Array<Record<string, unknown>>;
  closed: Promise<{ code: number; reason: string }>;
  isClosed: () => boolean;
  send: (text: string) => void;
  sendBinary: (data: Buffer) => void;
  terminate: () => void;
};

function openMux(port: number): Promise<MuxHandle> {
  return new Promise((resolve, reject) => {
    const client = new NodeWebSocket(`ws://127.0.0.1:${String(port)}/api/remote.mux`, { headers: muxHeaders() });
    const frames: Array<Record<string, unknown>> = [];
    let closedInfo: { code: number; reason: string } | null = null;
    let settleClose: (value: { code: number; reason: string }) => void = () => {};
    const closed = new Promise<{ code: number; reason: string }>((resolveClose) => { settleClose = resolveClose; });
    const timer = setTimeout(() => { client.terminate(); reject(new Error('remote.mux 连接超时')); }, 4000);
    client.on('message', (data: Buffer) => {
      try { frames.push(JSON.parse(data.toString('utf8')) as Record<string, unknown>); } catch { /* 忽略非 JSON */ }
    });
    client.on('close', (code: number, reason: Buffer) => {
      clearTimeout(timer);
      closedInfo = { code, reason: reason?.toString() ?? '' };
      settleClose(closedInfo);
    });
    client.on('error', (error: Error) => { clearTimeout(timer); reject(error); });
    client.on('open', () => {
      clearTimeout(timer);
      resolve({
        client,
        frames,
        closed,
        isClosed: () => closedInfo !== null,
        send: (text: string) => client.send(text),
        sendBinary: (data: Buffer) => client.send(data),
        terminate: () => { try { client.terminate(); } catch { /* 已关闭 */ } },
      });
    });
  });
}

/** 有界等待 carrier 关闭；超时以断言失败退出。 */
async function expectClose(mux: MuxHandle, timeoutMs: number, label: string): Promise<{ code: number; reason: string }> {
  const result = await Promise.race([mux.closed, sleep(timeoutMs).then(() => null)]);
  assert.ok(result !== null, `超时未关闭：${label}`);
  return result;
}

/** 让浏览器停止读取下行（制造网关侧下行积压）。 */
const pauseClientRead = (client: any): void => { client._socket?.pause(); };
const resumeClientRead = (client: any): void => { client._socket?.resume(); };

const openFrame = (streamId: string, payload: unknown): string =>
  JSON.stringify({ type: 'open', streamId, endpoint: '$events', payload });

/**
 * 简单 TCP relay：可切换「只丢弃下行（网关→浏览器）」。丢弃时仍读取字节（避免 TCP 背压），
 * 但不向浏览器转发——用于建模「网关下发的 Close 送不到浏览器」。
 */
type RelayHandle = { port: number; blockDownlink: () => void; close: () => void };

async function startRelay(targetPort: number): Promise<RelayHandle> {
  let blockedDown = false;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((downstream) => {
    const upstream = net.connect({ host: '127.0.0.1', port: targetPort });
    sockets.add(downstream);
    sockets.add(upstream);
    downstream.on('data', (chunk: Buffer) => { if (!upstream.destroyed) upstream.write(chunk); });
    upstream.on('data', (chunk: Buffer) => { if (!blockedDown && !downstream.destroyed) downstream.write(chunk); });
    downstream.on('error', () => { /* 测试端关闭 */ });
    upstream.on('error', () => { /* 网关关闭 */ });
    downstream.on('close', () => upstream.destroy());
    upstream.on('close', () => downstream.destroy());
    upstream.on('end', () => downstream.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    blockDownlink: () => { blockedDown = true; },
    close: () => { for (const socket of sockets) socket.destroy(); try { server.close(); } catch { /* 已关闭 */ } },
  };
}

// ---------------------------------------------------------------------------
// 1. 上游腿先完成关闭握手时不提前 terminate 仍 CLOSING 的浏览器腿
// ---------------------------------------------------------------------------

test('R2 关闭握手：上游腿先完成关闭后浏览器腿继续握手，观察到 1003 而非 1006', async () => {
  const item = 'z'.repeat(4 * MIB);
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port);
  const relay = await startRelay(gateway.port);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(relay.port);
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    mux.send(openFrame('A', { args: {} }));
    await sleep(200);
    // 浏览器停读后再让上游回传大 item：整条 item 落在网关→浏览器腿上形成下行积压，
    // 使随后 closeCarrier 下发的 Close 排在积压之后（复现「Close 已入队但被同一次 teardown 丢弃」）。
    pauseClientRead(mux.client);
    upstream.connections[0].send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data: item } }));
    await sleep(150);
    // 触发 closeCarrier：二进制帧 → 1003 text messages required，两条腿一起优雅关闭。
    mux.sendBinary(Buffer.from([0x00, 0x01, 0x02]));
    // 服务端腿（上游）先完成关闭握手并触发既有 upstream close 回调。
    await waitFor(() => upstream.serverSideCloseAt() !== null, 2000, '上游腿应先完成关闭握手');
    await sleep(250); // 报告要求：浏览器暂停读取约 250ms
    assert.equal(mux.isClosed(), false, '浏览器腿仍应在 CLOSING 握手中，不得被上游 close 回调提前 terminate');
    resumeClientRead(mux.client);
    const close = await expectClose(mux, 4000, '恢复读取后应完成优雅关闭');
    assert.equal(close.code, 1003, `浏览器腿应观察到网关下发的 1003（而非被 terminate 的 1006），实际：${JSON.stringify(close)}`);
    assert.match(close.reason, /text messages required/, '关闭原因应为受限文案 text messages required');
    assert.ok(mux.frames.length >= 1, '积压的 item 应在 Close 之前按 FIFO 送达');
  } finally {
    mux?.terminate();
    relay.close();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 2. 下行阻塞时 5s grace 不被绕过
// ---------------------------------------------------------------------------

test('R2 grace：下行被阻塞时仍等待 grace 到期才强制回收（不提前 terminate）', async () => {
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port);
  const relay = await startRelay(gateway.port);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(relay.port);
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    // relay 丢弃下行：网关下发的 Close 送不到浏览器，浏览器腿无法回 Close，只能依赖 grace 回收。
    relay.blockDownlink();
    const startedAt = Date.now();
    mux.sendBinary(Buffer.from([0x00]));
    // 服务端腿（上游）关闭事件在毫秒级触发。若上游 close 回调提前 terminate 浏览器腿，客户端会
    // 立刻（<1s）观察到 1006；正确行为是保持 CLOSING 直到 grace 到期，故关闭时间应接近 5s。
    await waitFor(() => upstream.serverSideCloseAt() !== null, 2000, '上游腿应先完成关闭握手');
    const close = await expectClose(mux, 9000, 'grace 到期应强制回收');
    const elapsed = Date.now() - startedAt;
    assert.equal(close.code, 1006, `下行阻塞下浏览器只能观察到异常断开（1006），实际：${JSON.stringify(close)}`);
    assert.ok(elapsed >= 4000, `应至少等待 grace 再强制回收（实际 ${elapsed}ms）`);
    assert.ok(elapsed <= 8500, `不应显著超过 grace（实际 ${elapsed}ms）`);
  } finally {
    mux?.terminate();
    relay.close();
    await gateway.close();
    await upstream.close();
  }
});
