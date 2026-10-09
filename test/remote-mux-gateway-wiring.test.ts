// Remote mux **网关接线** 集成测试（真实 `createGatewayServer` 的 /api/remote.mux 两条腿）。
//
// 写入范围：仅本文件；不改任何生产源码（`src/**`）。目的：把 `remote-mux-sender` /
// `remote-mux-heartbeat` 的单腿契约放回真实接线里验证——
//   浏览器腿(ws server) ⇄ MuxSender / MuxHeartbeat ⇄ 上游腿(ws client)
// 而不是只对独立 Sender/Heartbeat 做单元验证。夹具复用既有形态（`createGatewayServer`
// + mock 上游 WS + JWT cookie + TCP relay），不改任何生产路径。
//
// 覆盖（对齐规格验收清单，见 dsh-mux-heartbeat-review-and-loading-plan §6）：
//   1. 压缩未协商：浏览器腿与上游腿都不启用 permessage-deflate；
//   2. pending（上游未 open）→ Sender 转移的共享 2 MiB 预算：不超限、转移后不残留；
//   3. 上行停读（TCP 背压）：网关侧队列按接受预算有界，超限后按背压 1013 关闭（不无限增长）；
//   4. 上行写入停滞：上游停读单个大消息时按独立写入期限以 1011 关闭（浏览器侧可观察）；
//   5. cancel 与在途消息 FIN 顺序：cancel 不得截断已开始发送的消息；
//   6. error 与 FIN 顺序：上游 error 帧必须排在在途 item 的 FIN 之后（FIFO 不交错）；
//   7. 服务器先回收后 finally 销毁：网关先收敛 carrier 并下发 Close，测试端才销毁客户端；
//   8. 5s grace 资源回收：对端链路堵塞（Close 送不出去）时仍在 grace 到期后强制回收；
//   9. 兄弟流大 item 回归（R1）：A 在途（且已被 cancel）时，兄弟流 B 的合法大 item
//      必须能排队等待，不得因队列字节预算被 1013 误关整条 carrier。
//
// 未稳定覆盖项在文件末尾以注释记录（不在本文件伪断言）。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import jwt from 'jsonwebtoken';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options?: { noServer?: boolean; perMessageDeflate?: boolean }) => any;
  WebSocket: {
    new (url: string, options?: { headers?: Record<string, string>; perMessageDeflate?: boolean }): any;
    OPEN: number;
  };
};

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { parseEndpointAllowlist } from '../src/permissions.js';
import type { PlatformConfig, RemoteMuxConfig } from '../src/config.js';

const JWT_SECRET = 'gw-mux-wiring-secret';
const OPEN = NodeWebSocket.OPEN;
const MIB = 1024 * 1024;

/** 稳定期限：足够长，避免心跳/写停滞干扰非心跳用例。 */
const STABLE_MUX: RemoteMuxConfig = { fragmentBytes: 16 * 1024, pingIntervalMs: 30_000, pongTimeoutMs: 60_000, writeStallMs: 10_000 };
/** 写停滞用例：短写入期限，分片小以确保快速越过高水位。 */
const STALL_MUX: RemoteMuxConfig = { fragmentBytes: 16 * 1024, pingIntervalMs: 30_000, pongTimeoutMs: 60_000, writeStallMs: 1_500 };

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
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-mux-wiring-'));
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

function makeConfig(upstreamPort: number, mux: RemoteMuxConfig): PlatformConfig {
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
    mux,
  };
}

/** mock 上游：`/api/remote.mux` 的 WS 服务端；可选延迟握手（制造「上游未 open」）。 */
type UpstreamHandle = {
  port: number;
  connections: any[];
  lastUpgradeHeaders: () => http.IncomingHttpHeaders;
  releaseUpgrade: () => void;
  close: () => Promise<void>;
};

async function startUpstream(options: {
  holdUpgrade?: boolean;
  onConnection?: (client: any, req: http.IncomingMessage) => void;
} = {}): Promise<UpstreamHandle> {
  let holding = options.holdUpgrade === true;
  const held: Array<{ req: http.IncomingMessage; socket: net.Socket; head: Buffer }> = [];
  const connections: any[] = [];
  let headers: http.IncomingHttpHeaders = {};
  const wsServer = new WebSocketServer({ noServer: true });
  const accept = (req: http.IncomingMessage, socket: net.Socket, head: Buffer): void => {
    headers = req.headers;
    wsServer.handleUpgrade(req, socket, head, (client: any) => {
      connections.push(client);
      options.onConnection?.(client, req);
      wsServer.emit('connection', client, req);
    });
  };
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end('{}');
  });
  server.on('upgrade', (req, socket, head) => {
    if (holding) { held.push({ req, socket: socket as net.Socket, head }); return; }
    accept(req, socket as net.Socket, head);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    connections,
    lastUpgradeHeaders: () => headers,
    releaseUpgrade: () => { holding = false; for (const item of held.splice(0)) accept(item.req, item.socket, item.head); },
    close: async () => {
      for (const client of connections) { try { client.terminate(); } catch { /* 已关闭 */ } }
      for (const item of held.splice(0)) { try { item.socket.destroy(); } catch { /* 已关闭 */ } }
      try { wsServer.close(); } catch { /* 已关闭 */ }
      (server as http.Server & { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

type GatewayHandle = { port: number; close: () => Promise<void> };

async function startGateway(upstreamPort: number, mux: RemoteMuxConfig): Promise<GatewayHandle> {
  const config = makeConfig(upstreamPort, mux);
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
  close: () => void;
  terminate: () => void;
};

function openMux(port: number, headers: Record<string, string>, options: { perMessageDeflate?: boolean } = {}): Promise<MuxHandle> {
  return new Promise((resolve, reject) => {
    const client = new NodeWebSocket(`ws://127.0.0.1:${String(port)}/api/remote.mux`, {
      headers,
      ...(options.perMessageDeflate === undefined ? {} : { perMessageDeflate: options.perMessageDeflate }),
    });
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
        close: () => { try { client.close(); } catch { /* 已关闭 */ } },
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

/** 让浏览器停止读取下行（TCP 背压，制造网关侧写积压）。 */
const pauseClientRead = (client: any): void => { client._socket?.pause(); };
const resumeClientRead = (client: any): void => { client._socket?.resume(); };

const openFrame = (streamId: string, payload: unknown): string =>
  JSON.stringify({ type: 'open', streamId, endpoint: '$events', payload });

/**
 * 简单 TCP relay：可切换「应用层阻塞」。阻塞时仍读取两侧字节（避免 TCP 背压），
 * 但不向下游转发——用于建模「对端链路堵塞、网关下发的 Close 送不到浏览器」。
 */
type RelayHandle = { port: number; setBlocked: (value: boolean) => void; close: () => void };

async function startRelay(targetPort: number): Promise<RelayHandle> {
  let blocked = false;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((downstream) => {
    const upstream = net.connect({ host: '127.0.0.1', port: targetPort });
    sockets.add(downstream);
    sockets.add(upstream);
    downstream.on('data', (chunk: Buffer) => { if (!blocked && !upstream.destroyed) upstream.write(chunk); });
    upstream.on('data', (chunk: Buffer) => { if (!blocked && !downstream.destroyed) downstream.write(chunk); });
    downstream.on('error', () => { /* 测试端关闭 */ });
    upstream.on('error', () => { /* 网关关闭 */ });
    downstream.on('close', () => upstream.destroy());
    upstream.on('close', () => downstream.destroy());
    upstream.on('end', () => downstream.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    setBlocked: (value: boolean) => { blocked = value; },
    close: () => { for (const socket of sockets) socket.destroy(); try { server.close(); } catch { /* 已关闭 */ } },
  };
}

/** 记录上游收到的所有帧到 `sink`；返回同一个数组，便于引用同一份记录。 */
function recordUpstreamFrames(client: any, sink: Array<Record<string, unknown>> = []): Array<Record<string, unknown>> {
  client.on('message', (data: Buffer) => {
    try { sink.push(JSON.parse(data.toString('utf8')) as Record<string, unknown>); } catch { /* 忽略 */ }
  });
  return sink;
}

// ---------------------------------------------------------------------------
// 1. 压缩未协商
// ---------------------------------------------------------------------------

test('压缩未协商：浏览器腿与上游腿都不启用 permessage-deflate', async () => {
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders(), { perMessageDeflate: true });
    // 浏览器腿：客户端主动 offer permessage-deflate；网关 ws server（未显式开启压缩）不得协商。
    assert.equal(mux.client.extensions, '', '浏览器腿不得协商任何扩展（含 permessage-deflate）');
    // 上游腿：网关以 perMessageDeflate:false 连接上游，握手请求不得携带扩展 offer。
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    assert.equal(
      upstream.lastUpgradeHeaders()['sec-websocket-extensions'],
      undefined,
      '上游腿不得携带 Sec-WebSocket-Extensions offer（perMessageDeflate:false）',
    );
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 2. pending → Sender 转移预算
// ---------------------------------------------------------------------------

test('pending→Sender 转移：未 open 上游时按共享 2 MiB 预算入队，open 后原样转交且不残留', async () => {
  const upstreamFrames: Array<Record<string, unknown>> = [];
  const upstream = await startUpstream({
    holdUpgrade: true,
    onConnection: (client) => { recordUpstreamFrames(client, upstreamFrames); },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  const blob = 'x'.repeat(400_000);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    for (let i = 0; i < 4; i += 1) mux.send(openFrame(`p-${i}`, { args: { blob } }));
    // 上游握手被挂起：4 帧全部落在网关 pending（约 1.6 MiB，未超 2 MiB），不得转发也不得关闭。
    await sleep(300);
    assert.equal(upstreamFrames.filter((frame) => frame.type === 'open').length, 0, '上游未 open 前不得转发任何 open');
    assert.equal(mux.isClosed(), false, '未超共享 2 MiB 预算不得关闭 carrier');
    // 释放握手：pending 原子转入 Sender（转出即从共享预算扣减），并送达上游。
    upstream.releaseUpgrade();
    await waitFor(() => upstreamFrames.filter((frame) => frame.type === 'open').length === 4, 5000, 'pending 应全部转交上游');
    // 转移后共享预算已释放：再发同样规模的一批仍被接受并送达（无残留双计）。
    for (let i = 0; i < 4; i += 1) mux.send(openFrame(`q-${i}`, { args: { blob } }));
    await waitFor(() => upstreamFrames.filter((frame) => frame.type === 'open').length === 8, 5000, '转交后的一批也应送达');
    assert.equal(mux.client.readyState, OPEN, 'carrier 应保持打开');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

test('pending 预算不超 2 MiB：上游未 open 时超限即按 1009 关闭', async () => {
  const upstream = await startUpstream({ holdUpgrade: true });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  const blob = 'x'.repeat(400_000);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    // 6 × 400 KiB ≈ 2.4 MiB > 2 MiB：共享 pending 预算必须在第 6 帧越界时收敛。
    for (let i = 0; i < 6; i += 1) mux.send(openFrame(`o-${i}`, { args: { blob } }));
    const close = await expectClose(mux, 5000, '超 2 MiB pending 应关闭 carrier');
    assert.equal(close.code, 1009, `应回 1009 queue too large，实际：${JSON.stringify(close)}`);
    assert.match(close.reason, /queue too large/, '关闭原因应为受限文案 queue too large');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 3. 上行 item 溢出 → 只拒绝该逻辑流（不再整 carrier 1013）
// ---------------------------------------------------------------------------

test('上行 item 溢出只拒绝该逻辑流：carrier 不被 1013 关闭，持续停读由写入停滞期限以 1011 收敛', async () => {
  // 上游持续停读最终会耗尽网关→上游 Sender 的接受预算。修复后这是**该逻辑流**的应用级
  // 失败（受限 error + 向上游补 cancel），不再把整条 carrier 按 1013 关掉；真正的传输停滞
  // 另由独立的 write-stall 期限以 1011 收敛。
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port, STALL_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    const upstreamClient = upstream.connections[0];
    const received: Array<Record<string, unknown>> = recordUpstreamFrames(upstreamClient);
    // 上游停止消费：网关→上游腿出现真实 TCP 背压，Sender 队列按接受预算（102 MiB）有界。
    upstreamClient._socket?.pause();
    // 5 MiB × 22 ≈ 110 MiB > 102 MiB 接受预算：越界发生在第 21 条（≈105 MiB）时，队列不会无界增长。
    const chunk = 'y'.repeat(5 * MIB);
    for (let i = 0; i < 22; i += 1) mux.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: i, data: chunk } }));
    // 浏览器腿正常读取：可直接观察到流 A 的受限 error（而不是整条 carrier 的 1013）。
    await waitFor(() => mux!.frames.some((frame) => frame.type === 'error' && frame.streamId === 'A'), 8000, '流 A 溢出应只拒绝该逻辑流');
    assert.equal(mux.isClosed(), false, 'item 溢出不得按 1013 关闭整条 carrier');
    assert.ok(received.filter((frame) => frame.type === 'item').length < 22, '网关不得把全部积压无界写入');
    // 上游仍不消费：独立的写入停滞期限最终以 1011 收敛整条 carrier。
    const close = await expectClose(mux, 8000, '持续停读应由写入停滞期限收敛');
    assert.equal(close.code, 1011, `持续停读应由 1011 write-stall 收敛，实际：${JSON.stringify(close)}`);
    assert.match(close.reason, /stalled|write/i, '关闭原因应体现写入停滞');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 4. 上行写入停滞（上游停读单个大消息）
// ---------------------------------------------------------------------------

test('上行写入停滞：上游停读单个大消息时按独立写入期限以 1011 关闭', async () => {
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port, STALL_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    const upstreamClient = upstream.connections[0];
    const received = recordUpstreamFrames(upstreamClient);
    // 上游停止消费：网关上游腿（单个大消息，非队列溢出）进入 busy 且无写入进展 → 写停滞。
    upstreamClient._socket?.pause();
    mux.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data: 'w'.repeat(4 * MIB) } }));
    // 浏览器腿正常读取，可观察到网关按 1011 主动下发 Close。
    const close = await expectClose(mux, 6000, '上行写停滞应关闭 carrier');
    assert.equal(close.code, 1011, `上行写停滞应回 1011，实际：${JSON.stringify(close)}`);
    assert.match(close.reason, /write stalled|stalled/i, '关闭原因应体现写入停滞');
    assert.ok(received.filter((frame) => frame.type === 'item').length <= 1, '停读期间不得无界写入上游');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 5. cancel 与在途 FIN 顺序
// ---------------------------------------------------------------------------

test('cancel 与在途 FIN 顺序：cancel 不得截断已开始发送的消息', async () => {
  const data = 'c'.repeat(4 * MIB);
  const upstream = await startUpstream({
    onConnection: (client) => {
      client.on('message', (buffer: Buffer) => {
        let frame: Record<string, unknown>;
        try { frame = JSON.parse(buffer.toString('utf8')) as Record<string, unknown>; } catch { return; }
        if (frame.type === 'open' && frame.streamId === 'A') {
          client.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data } }));
        }
      });
    },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    pauseClientRead(mux.client); // 冻结下行，确保 item 处于「已开始发送」状态
    mux.send(openFrame('A', { args: {} }));
    await sleep(500);
    mux.send(JSON.stringify({ type: 'cancel', streamId: 'A' }));
    await sleep(200);
    resumeClientRead(mux.client);
    await waitFor(() => mux!.frames.length >= 1 || mux!.isClosed(), 15_000, '在途消息应完整到达 FIN');
    assert.equal(mux.isClosed(), false, 'cancel 在途流不得关闭 carrier');
    assert.equal(mux.frames.length, 1, 'cancel 只应影响未开始/后续帧，不得截断在途消息');
    assert.equal(mux.frames[0].type, 'item');
    assert.equal((mux.frames[0].value as { data?: string }).data?.length, data.length, '在途消息必须完整送达（发到 FIN）');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 6. error 与 FIN 顺序
// ---------------------------------------------------------------------------

test('error 与 FIN 顺序：上游 error 帧排在在途 item 的 FIN 之后（FIFO 不交错）', async () => {
  const data = 'e'.repeat(1 * MIB);
  const upstream = await startUpstream({
    onConnection: (client) => {
      client.on('message', (buffer: Buffer) => {
        let frame: Record<string, unknown>;
        try { frame = JSON.parse(buffer.toString('utf8')) as Record<string, unknown>; } catch { return; }
        if (frame.type !== 'open' || frame.streamId !== 'A') return;
        // 背靠背：先大 item（会在 Sender 内分片），紧接着同流 error。
        client.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data } }));
        client.send(JSON.stringify({ type: 'error', streamId: 'A', error: { code: 'host/failed', message: 'boom', details: {} } }));
      });
    },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    await waitFor(() => mux!.frames.length >= 2 || mux!.isClosed(), 8000, '应收到 item 与 error 两帧');
    assert.equal(mux.isClosed(), false, '承载同流的 carrier 不应关闭');
    assert.equal(mux.frames.length, 2, '应恰好收到 item 与 error 两帧，无交错');
    assert.equal(mux.frames[0].type, 'item', 'error 必须排在在途 item 的 FIN 之后');
    assert.equal((mux.frames[0].value as { data?: string }).data?.length, data.length, 'item 必须完整送达');
    assert.equal(mux.frames[1].type, 'error');
    assert.equal(mux.frames[1].streamId, 'A');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 7. 服务器先回收后 finally 销毁
// ---------------------------------------------------------------------------

test('服务器先回收后 finally 销毁：网关先收敛 carrier 并下发 Close，测试端才销毁客户端', async () => {
  const upstream = await startUpstream({
    onConnection: (client) => {
      client.on('message', (buffer: Buffer) => {
        let frame: Record<string, unknown>;
        try { frame = JSON.parse(buffer.toString('utf8')) as Record<string, unknown>; } catch { return; }
        if (frame.type === 'open' && frame.streamId === 'A') {
          client.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data: 'ok' } }));
        }
      });
    },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    await waitFor(() => mux!.frames.length >= 1, 3000, '先建立一条活跃流');
    // 上游断开：网关必须先收敛 carrier（dispose 两条腿）并主动下发 Close，测试端才在 finally 销毁。
    upstream.connections[0].terminate();
    const close = await expectClose(mux, 4000, '网关应主动下发 Close');
    assert.equal(close.code, 1011, `网关应先回收并按 1011 关闭，实际：${JSON.stringify(close)}`);
    assert.match(close.reason, /upstream closed/);
    assert.equal(mux.isClosed(), true, '服务器侧回收应先于 finally 的客户端销毁');
  } finally {
    mux?.terminate(); // 服务器已先回收；此处仅确保测试句柄收敛
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 8. 5s grace 资源回收（堵塞链路）
// ---------------------------------------------------------------------------

test('5s grace 资源回收：对端链路堵塞（Close 送不出）时仍在 grace 到期后强制回收', async () => {
  const upstream = await startUpstream();
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  const relay = await startRelay(gateway.port);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(relay.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    await waitFor(() => upstream.connections.length === 1, 3000, '网关应先连上上游');
    // 应用层阻塞浏览器腿：网关下发的 Close 被 relay 读取后丢弃，绝不送达浏览器；
    // 浏览器也无法回 Close，故 closeCarrier 只能依赖 grace 到期强制回收。
    relay.setBlocked(true);
    const startedAt = Date.now();
    upstream.connections[0].terminate();
    const close = await expectClose(mux, 9000, 'grace 到期应强制回收');
    const elapsed = Date.now() - startedAt;
    assert.equal(close.code, 1006, `堵塞链路下客户端只能观察到异常断开（1006），实际：${JSON.stringify(close)}`);
    assert.ok(elapsed >= 4000, `应至少等待 grace 再强制回收（实际 ${elapsed}ms）`);
    assert.ok(elapsed <= 8500, `不应显著超过 grace（实际 ${elapsed}ms）`);
  } finally {
    mux?.terminate();
    relay.close();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 9. 兄弟流大 item 回归（R1）
// ---------------------------------------------------------------------------

test('R1 回归：A 在途且已 cancel 时，兄弟流 B 的合法大 item 不得被队列预算 1013 误杀', async () => {
  const aData = 'a'.repeat(3 * MIB);
  const bData = 'b'.repeat(3 * MIB);
  let upstreamClient: any = null;
  const forwarded: Array<Record<string, unknown>> = [];
  const upstream = await startUpstream({
    onConnection: (client) => { upstreamClient = client; recordUpstreamFrames(client, forwarded); },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    // 两条兄弟流先 open 并转发到上游（admin 走透明转发路径）。
    mux.send(openFrame('A', { args: {} }));
    mux.send(openFrame('B', { args: {} }));
    await waitFor(() => upstreamClient !== null, 3000, '网关应先连上上游');
    await waitFor(() => forwarded.filter((frame) => frame.type === 'open').length === 2, 3000, 'A、B 的 open 应先转发到上游');

    // 冻结下行：A 的 3 MiB item 进入「已开始发送」，停留在 MuxSender.current。
    pauseClientRead(mux.client);
    upstreamClient.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 1, data: aData } }));
    await sleep(500);
    // 取消 A：在途消息仍须发到 FIN，只是删除其后续/未开始的排队项。
    mux.send(JSON.stringify({ type: 'cancel', streamId: 'A' }));
    await sleep(200);

    // 兄弟流 B 的合法大 item：修复前 queueBytes(0) + 3 MiB > 2 MiB 队列字节上限
    // → queue-full → 误将整条 carrier 按 1013 关闭。总接受量仅 6 MiB，远低于 102 MiB。
    upstreamClient.send(JSON.stringify({ type: 'item', streamId: 'B', value: { type: 'event', seq: 1, data: bData } }));
    await sleep(500);
    assert.equal(mux.isClosed(), false, '兄弟流合法大 item 不得因队列字节预算误关 carrier');

    // 恢复读取：A（先）与 B（后）必须按 FIFO 各自完整送达 FIN，不截断、不交错。
    resumeClientRead(mux.client);
    await waitFor(() => mux!.frames.length >= 2 || mux!.isClosed(), 15_000, 'A、B 两条 item 应完整送达');
    assert.equal(mux.isClosed(), false, '恢复后 carrier 必须保持打开');
    assert.equal(mux.frames.length, 2, '应恰好收到 A、B 两条 item，兄弟流不被丢弃');
    assert.equal(mux.frames[0].streamId, 'A');
    assert.equal((mux.frames[0].value as { data?: string }).data?.length, aData.length, 'A 必须完整发到 FIN');
    assert.equal(mux.frames[1].streamId, 'B');
    assert.equal((mux.frames[1].value as { data?: string }).data?.length, bData.length, 'B 必须完整发到 FIN');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 10. 下行 item queue-full 只拒绝该逻辑流（兄弟流 carrier 保持打开）
// ---------------------------------------------------------------------------

test('下行 item queue-full 只拒绝该逻辑流：兄弟流 carrier 保持打开', async () => {
  const aData = 'a'.repeat(3 * MIB);
  let upstreamClient: any = null;
  const forwarded: Array<Record<string, unknown>> = [];
  const upstream = await startUpstream({
    onConnection: (client) => { upstreamClient = client; recordUpstreamFrames(client, forwarded); },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    mux.send(openFrame('B', { args: {} }));
    await waitFor(() => upstreamClient !== null, 3000, '网关应先连上上游');
    await waitFor(() => forwarded.filter((frame) => frame.type === 'open').length === 2, 3000, 'A、B 的 open 应先转发到上游');
    // 冻结下行：A 的首条大 item 占住下行 Sender 的 current，后续 item 只能排队。
    pauseClientRead(mux.client);
    upstreamClient.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 0, data: aData } }));
    await sleep(300);
    // 灌满 8192 条等待槽（REMOTE_MUX_MAX_STREAMS 64 × 128），再发一条触发 queue-full。
    // 修复前：整条 carrier 被 1013 关闭；修复后：只拒绝流 A（向浏览器发受限 error、向上游补 cancel）。
    for (let i = 1; i <= 8200; i += 1) {
      upstreamClient.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: i, data: 'x' } }));
    }
    await waitFor(() => forwarded.some((frame) => frame.type === 'cancel' && frame.streamId === 'A'), 8000, '流 A 溢出后应向上游补 cancel');
    assert.equal(mux.isClosed(), false, '流 A 队列溢出不得按 1013 关闭整条 carrier');
    // 兄弟流 B 仍在同一 carrier 上：排队槽已被流 A 的取消释放，B 的 item 应被接受。
    upstreamClient.send(JSON.stringify({ type: 'item', streamId: 'B', value: { type: 'event', seq: 1, data: 'sibling' } }));
    await sleep(200);
    assert.equal(mux.isClosed(), false, '兄弟流 B 的 item 不得触发误关');
    // 恢复读取：A 的在途大 item（FIN）、A 的 error、B 的 item 依次完整送达。
    resumeClientRead(mux.client);
    await waitFor(() => mux!.frames.some((frame) => frame.type === 'error' && frame.streamId === 'A'), 15_000, '应收到流 A 的受限 error');
    await waitFor(() => mux!.frames.some((frame) => frame.type === 'item' && frame.streamId === 'B'), 15_000, '兄弟流 B 的 item 应送达');
    assert.equal(mux.isClosed(), false, '恢复后 carrier 必须保持打开');
    const aItem = mux.frames.find((frame) => frame.type === 'item' && frame.streamId === 'A');
    assert.equal((aItem?.value as { data?: string } | undefined)?.data?.length, aData.length, 'A 的在途 item 必须完整发到 FIN');
    assert.ok(mux.frames.some((frame) => frame.type === 'error' && frame.streamId === 'A'), '流 A 被拒绝时应下发受限 error');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 11. 上行 item queue-full 只拒绝该逻辑流（兄弟流 carrier 保持打开）
// ---------------------------------------------------------------------------

test('上行 item queue-full 只拒绝该逻辑流：兄弟流 carrier 保持打开', async () => {
  let upstreamClient: any = null;
  const received: Array<Record<string, unknown>> = [];
  const upstream = await startUpstream({
    onConnection: (client) => { upstreamClient = client; recordUpstreamFrames(client, received); },
  });
  const gateway = await startGateway(upstream.port, STABLE_MUX);
  let mux: MuxHandle | null = null;
  try {
    mux = await openMux(gateway.port, muxHeaders());
    mux.send(openFrame('A', { args: {} }));
    mux.send(openFrame('B', { args: {} }));
    await waitFor(() => upstreamClient !== null, 3000, '网关应先连上上游');
    await waitFor(() => received.filter((frame) => frame.type === 'open').length === 2, 3000, 'A、B 的 open 应转发到上游');
    // 上游停读：A 的首条大 item 占住上行 Sender 的 current，后续 item 只能排队。
    upstreamClient._socket?.pause();
    mux.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: 0, data: 'a'.repeat(3 * MIB) } }));
    await sleep(300);
    for (let i = 1; i <= 8200; i += 1) {
      mux.send(JSON.stringify({ type: 'item', streamId: 'A', value: { type: 'event', seq: i, data: 'x' } }));
    }
    // 浏览器腿正常读取：可观察到流 A 的受限 error（整条 carrier 的 1013 不会出现）。
    await waitFor(() => mux!.frames.some((frame) => frame.type === 'error' && frame.streamId === 'A'), 8000, '流 A 溢出应只拒绝该逻辑流');
    assert.equal(mux.isClosed(), false, 'item 溢出不得按 1013 关闭整条 carrier');
    // 恢复上游读取并发送兄弟流 B：A 的在途 item、A 的 cancel、B 的 item 依次送达（FIFO 不交错）。
    upstreamClient._socket?.resume();
    mux.send(JSON.stringify({ type: 'item', streamId: 'B', value: { type: 'event', seq: 1, data: 'sibling' } }));
    await waitFor(() => received.some((frame) => frame.type === 'item' && frame.streamId === 'B'), 8000, '兄弟流 B 的 item 应送达上游');
    assert.equal(mux.isClosed(), false, 'carrier 必须保持打开');
    assert.ok(received.some((frame) => frame.type === 'cancel' && frame.streamId === 'A'), '流 A 应向上游补 cancel');
  } finally {
    mux?.terminate();
    await gateway.close();
    await upstream.close();
  }
});

// ---------------------------------------------------------------------------
// 未稳定覆盖项（不在本文件伪断言，供后续人工/线上验收）：
//   · 浏览器腿停读（下行写停滞）时网关按 1011 关两条腿，但浏览器腿本身不读取下行，其 Close
//     无法完成握手，只能在 grace 到期后被强制回收，故浏览器侧观察到的仍是 1006。上游腿先完成
//     关闭时不得提前 terminate 仍 CLOSING 的浏览器腿、不得绕过 5s grace——该关闭握手不变量已由
//     remote-mux-close-grace.test.ts 专门覆盖（区分服务端腿 close 事件与客户端观察到的关闭码）。
//     本文件改由「上行写入停滞」（上游停读大消息）覆盖同一 MuxSender/MuxHeartbeat 写停滞期限，
//     此时浏览器腿正常读取，可真实观察到 1011。
//   · 「大历史加载期间文件/终端操作」的实际完成时间（规格 §6 清单）：需要真实 dsh 上游与浏览器
//     时序，mock 上游无法代表；本文件只验证 carrier 级 FIFO/预算不变量。
//   · 「Ping 排队 / 迟到 Pong / 关闭后回调」在真实 ws 上的端到端时序：已由
//     remote-mux-heartbeat.test.ts 的注入时钟确定性覆盖；真实 ws 上注入非确定，故不在本文件重复。
//   · `REMOTE_MUX_CLOSE_GRACE_MS`（5s）当前为 proxy.ts 内常量、不可注入；grace 用例需真实等待
//     ~5s，属可接受但偏慢的定点用例。
// ---------------------------------------------------------------------------
