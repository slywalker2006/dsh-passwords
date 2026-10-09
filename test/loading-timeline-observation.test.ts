// 加载时间线观测（《dsh-mux-heartbeat-review-and-loading-plan》第 139–150 节）：
// 观测工具本体在 src/loading-timeline.ts（纯观测、默认关闭、结构白名单），本文件是它的
// 集成用例。观测目标：把「上游快照准备 / baseline 有界等待 / 首个完整 item /
// 网关同步分段（parse/filter/stringify） / 终端首输出 / 事件循环延迟 / HTTP 整段缓冲」
// 分开计时，并保证观测记录不泄漏正文、Cookie、JWT 或完整 URL。
//
// 采样口径分两层：
//   · 进程外采样：HTTP 客户端首个响应、WS 客户端首个 item，通过既有公开入口观测；
//   · 生产埋点：src/loading-timeline.ts 的共享实例被在 history/page、mux 上游首帧与
//     baseline 等待处按需写入；埋点默认关闭（DSH_LOADING_TIMELINE=1 才记录），
//     不改变任何请求/响应协议。用例在需要时临时开启环境变量并复位共享实例来验证埋点。
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
import type { PlatformConfig } from '../src/config.js';
import { LoadingTimeline, loadingTimeline, eventLoopDelaySampler } from '../src/loading-timeline.js';

// 观测工具见 src/loading-timeline.ts（LoadingTimeline / loadingTimeline 共享实例 /
// eventLoopDelaySampler）。本文件只保留集成夹具与用例。

// ─────────────────────────────────────────────────────────────────────────────
// 测试夹具：网关 + stub 上游（HTTP 与 WS 同一端口）
// ─────────────────────────────────────────────────────────────────────────────

const HISTORY_BODY_MARKER = 'HISTORY-BODY-MARKER';
const PAGE_BODY_MARKER = 'PAGE-BODY-MARKER';
const SNAPSHOT_BODY_MARKER = 'SNAPSHOT-BODY-MARKER';
const TERMINAL_BODY_MARKER = 'TERMINAL-BODY-MARKER';
const SNAPSHOT_PAD_BYTES = 4096;
const WAIT_WINDOW_MS = 250;

let appDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let upstreamWss: any;
let gatewayPort = 0;
let adminCookie = '';
let adminToken = '';
/** 'hold'：上游下发首个 item / 响应头后不结束（用于证明「缓冲 vs 增量」）。 */
let upstreamMode: 'ok' | 'hold' = 'ok';
/** 被 hold 住的上游 HTTP 响应：测试在断言后显式放行。 */
const heldResponses: Array<{ res: http.ServerResponse; payload: string }> = [];
const openMuxClients: any[] = [];

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

function releaseHeldResponses(): void {
  while (heldResponses.length > 0) {
    const held = heldResponses.shift()!;
    try { held.res.end(held.payload); } catch { /* 已结束 */ }
  }
}

interface PendingHttp {
  /** 首个响应（含整段 body）到达时 resolve；顺序等价于客户端「拿到整段」。 */
  response: Promise<{ status: number; body: string }>;
  abort: () => void;
}

function startHistoryRequest(pathname: string): PendingHttp {
  const req = http.request({
    host: '127.0.0.1', port: gatewayPort, method: 'POST', path: pathname,
    headers: { cookie: adminCookie, 'content-type': 'application/json' },
  });
  const response = new Promise<{ status: number; body: string }>((resolve, reject) => {
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
  });
  req.end(JSON.stringify({ type: 'client-request', rpcId: 'obs', method: 'session/history', payload: { args: {} } }));
  return { response, abort: () => { try { req.destroy(); } catch { /* 已结束 */ } } };
}

/** 以指定 Cookie 发一条 JSON RPC，供子用户 baseline 等待等场景使用。 */
function gatewayPost(pathname: string, cookieHeader: string, envelope: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: gatewayPort, method: 'POST', path: pathname,
      headers: { cookie: cookieHeader, 'content-type': 'application/json' },
    });
    req.on('response', (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(JSON.stringify(envelope));
  });
}

/** 临时开启共享事件线（生产埋点）并在结束时复位记录、还原环境变量。 */
async function withProductionTimeline<T>(fn: () => Promise<T>): Promise<T> {
  const saved = process.env.DSH_LOADING_TIMELINE;
  process.env.DSH_LOADING_TIMELINE = '1';
  loadingTimeline.reset();
  try {
    return await fn();
  } finally {
    loadingTimeline.reset();
    if (saved === undefined) delete process.env.DSH_LOADING_TIMELINE; else process.env.DSH_LOADING_TIMELINE = saved;
  }
}

/** 在 ms 内是否已 settle；超时返回 false（不取消底层请求）。 */
function settlesWithin<T>(promise: Promise<T>, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: boolean): void => { if (!settled) { settled = true; resolve(value); } };
    promise.then(() => finish(true), () => finish(true));
    setTimeout(() => finish(false), ms);
  });
}

interface Mux {
  client: any;
  frames: Array<Record<string, unknown>>;
  close: () => void;
}

function openMux(): Promise<Mux> {
  return new Promise((resolve, reject) => {
    const client = new NodeWebSocket(`ws://127.0.0.1:${String(gatewayPort)}/api/remote.mux`, {
      headers: { cookie: adminCookie, origin: 'http://127.0.0.1', host: '127.0.0.1' },
    });
    openMuxClients.push(client);
    const frames: Array<Record<string, unknown>> = [];
    const timer = setTimeout(() => { try { client.terminate(); } catch { /* 已关闭 */ } reject(new Error('remote.mux open timeout')); }, 3000);
    client.on('message', (data: Buffer) => {
      try { frames.push(JSON.parse(data.toString('utf8')) as Record<string, unknown>); } catch { /* 忽略非 JSON */ }
    });
    client.once('error', (error: Error) => { clearTimeout(timer); reject(error); });
    client.once('open', () => {
      clearTimeout(timer);
      resolve({ client, frames, close: () => { try { client.close(); } catch { /* 已关闭 */ } } });
    });
  });
}

function sendOpen(mux: Mux, streamId: string, endpoint: string, payload: unknown): void {
  mux.client.send(JSON.stringify({ type: 'open', streamId, endpoint, payload }));
}

async function waitForFrame(
  mux: Mux,
  predicate: (frame: Record<string, unknown>) => boolean,
  timeoutMs = 1500,
): Promise<Record<string, unknown> | null> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const found = mux.frames.find(predicate);
    if (found !== undefined) return found;
    if (Date.now() >= deadline) return null;
    await wait(10);
  }
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-timeline-'));
  const dbPath = path.join(appDir, 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');

  upstream = http.createServer((req, res) => {
    const url = req.url ?? '';
    if (url.startsWith('/api/session.history') || url.startsWith('/api/session.page')) {
      const marker = url.startsWith('/api/session.history') ? HISTORY_BODY_MARKER : PAGE_BODY_MARKER;
      const payload = JSON.stringify({ result: { ok: true, value: { records: [{ type: 'event', text: marker }] } } });
      if (upstreamMode === 'hold') {
        // 只回响应头、不回 body 也不结束：整段缓冲路径此时不应把任何字节交给客户端。
        res.writeHead(200, { 'content-type': 'application/json' });
        res.flushHeaders();
        heldResponses.push({ res, payload });
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
      res.end(payload);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', connection: 'close' });
    res.end('{}');
  });
  upstreamWss = new WebSocketServer({ noServer: true });
  upstreamWss.on('connection', (client: any) => {
    client.on('message', (data: Buffer) => {
      let frame: { type?: string; streamId?: string; endpoint?: string };
      try { frame = JSON.parse(data.toString('utf8')) as typeof frame; } catch { return; }
      if (frame.type !== 'open' || typeof frame.streamId !== 'string') return;
      if (frame.endpoint === 'session/follow') {
        client.send(JSON.stringify({
          type: 'item', streamId: frame.streamId,
          value: {
            type: 'snapshot', header: { id: 'obs-session' }, cursor: 1,
            records: [{ type: 'event', event: { type: 'user/message', seq: 1, time: 1, data: `${SNAPSHOT_BODY_MARKER}${'x'.repeat(SNAPSHOT_PAD_BYTES)}` } }],
            hasMore: false, projections: { asOfSeq: 1, values: {} },
          },
        }));
        if (upstreamMode !== 'hold') client.send(JSON.stringify({ type: 'end', streamId: frame.streamId }));
        return;
      }
      if (frame.endpoint === 'terminal/follow') {
        client.send(JSON.stringify({
          type: 'item', streamId: frame.streamId,
          value: { type: 'terminal/output', terminalId: 'obs-term', data: TERMINAL_BODY_MARKER },
        }));
        if (upstreamMode !== 'hold') client.send(JSON.stringify({ type: 'end', streamId: frame.streamId }));
        return;
      }
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
    endpointRules: [],
  };
  adminToken = jwt.sign({ sub: String(admin.id), username: admin.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' });
  adminCookie = `dsh_gateway_token=${adminToken}`;

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(async () => {
  eventLoopDelaySampler.stop();
  for (const client of openMuxClients) {
    try { client.close(); } catch { /* 已关闭 */ }
    await wait(20);
    try { client.terminate(); } catch { /* 已关闭 */ }
  }
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

// ─────────────────────────────────────────────────────────────────────────────
// 用例
// ─────────────────────────────────────────────────────────────────────────────

test('观测工具默认关闭：未显式开启时不记录、不输出', () => {
  const off = new LoadingTimeline({ enabled: false });
  off.mark('http.history.firstByte', { elapsedMs: 1, bytesIn: 10, bytesOut: 20, records: 3, ok: true });
  assert.deepEqual(off.records(), [], '关闭状态下不得产生任何记录');
  assert.equal(off.summaryJson(), '[]');

  // 默认构造跟随环境变量：CI / 本地默认关闭。
  const auto = new LoadingTimeline();
  assert.equal(auto.enabled, process.env.DSH_LOADING_TIMELINE === '1');
});

test('HTTP session.history / session.page 是整段缓冲：上游未结束前客户端拿不到首字节', async () => {
  // 上游只回响应头并 hold；若两条路径是流式，客户端应立刻收到响应。
  // 缓冲路径（bufferUpstream 在 onEnd 才 writeHead）应保持沉默，直到整段到达。
  upstreamMode = 'hold';
  const recorder = new LoadingTimeline({ enabled: true });
  try {
    for (const [endpoint, firstByteStage, completeStage] of [
      ['/api/session.history', 'http.history.firstByte', 'http.history.complete'],
      ['/api/session.page', 'http.page.firstByte', 'http.page.complete'],
    ] as const) {
      const pending = startHistoryRequest(endpoint);
      const started = Date.now();
      const early = await settlesWithin(pending.response, WAIT_WINDOW_MS);
      assert.equal(early, false, `${endpoint}: 上游整段尚未结束，缓冲路径不得提前把响应交给客户端`);
      recorder.mark(firstByteStage, { elapsedMs: Date.now() - started, ok: false });

      // 放行上游整段：网关应完成解压/清洗/序列化后返回已改写响应。
      releaseHeldResponses();
      const response = await pending.response;
      assert.equal(response.status, 200, `${endpoint} 应在上游结束后正常返回`);
      const parsed = JSON.parse(response.body) as { result?: { ok?: boolean; value?: { records?: unknown[] } } };
      assert.equal(parsed.result?.ok, true, `${endpoint} 返回体应为合法业务信封`);
      const completeRecords = parsed.result?.value?.records;
      recorder.mark(completeStage, {
        elapsedMs: Date.now() - started,
        bytesOut: Buffer.byteLength(response.body),
        records: Array.isArray(completeRecords) ? completeRecords.length : 0,
        ok: true,
      });
    }
  } finally {
    upstreamMode = 'ok';
    releaseHeldResponses();
  }
  recorder.emit();
});

test('remote mux 快照 / 终端是增量：上游未结束即收到首个输出', async () => {
  // 上游下发首个 item 后 hold、不 end。gateway 的 mux 下行逐帧转发，
  // 因此首个 item 应在上游结束之前到达客户端——与 HTTP 整段缓冲形成对照。
  upstreamMode = 'hold';
  const recorder = new LoadingTimeline({ enabled: true });
  const mux = await openMux();
  try {
    const snapshotStart = Date.now();
    sendOpen(mux, 'obs-snapshot', 'session/follow', {
      args: { request: { address: { kind: 'session', sessionId: 'obs-session' } } },
    });
    const snapshotItem = await waitForFrame(mux, (frame) => frame.streamId === 'obs-snapshot' && frame.type === 'item');
    assert.ok(snapshotItem, 'session/follow 首个 item 必须在上游 end 之前到达（增量证据）');
    const snapshotRecords = (snapshotItem.value as { records?: unknown[] }).records;
    recorder.mark('mux.session.follow.firstItem', {
      elapsedMs: Date.now() - snapshotStart,
      bytesOut: Buffer.byteLength(JSON.stringify(snapshotItem)),
      records: Array.isArray(snapshotRecords) ? snapshotRecords.length : 0,
      ok: true,
    });

    const terminalStart = Date.now();
    sendOpen(mux, 'obs-terminal', 'terminal/follow', { args: {} });
    const terminalItem = await waitForFrame(mux, (frame) => frame.streamId === 'obs-terminal' && frame.type === 'item');
    assert.ok(terminalItem, 'terminal/follow 首个输出必须到达');
    recorder.mark('mux.terminal.follow.firstOutput', {
      elapsedMs: Date.now() - terminalStart,
      bytesOut: Buffer.byteLength(JSON.stringify(terminalItem)),
      ok: true,
    });
  } finally {
    upstreamMode = 'ok';
    mux.close();
  }
  recorder.emit();
});

test('历史传输与终端首输出按逻辑流分别计时，且观测记录不泄漏敏感内容', async () => {
  upstreamMode = 'hold';
  const recorder = new LoadingTimeline({ enabled: true });
  const mux = await openMux();
  try {
    sendOpen(mux, 'c-snapshot', 'session/follow', {
      args: { request: { address: { kind: 'session', sessionId: 'obs-session' } } },
    });
    sendOpen(mux, 'c-terminal', 'terminal/follow', { args: {} });

    const snapshotItem = await waitForFrame(mux, (frame) => frame.streamId === 'c-snapshot' && frame.type === 'item');
    const terminalItem = await waitForFrame(mux, (frame) => frame.streamId === 'c-terminal' && frame.type === 'item');
    assert.ok(snapshotItem, '同一 carrier 上历史快照首个 item 必须到达');
    assert.ok(terminalItem, '同一 carrier 上终端首个输出必须到达');

    // §148：终端首个输出到达时，共享连接是否仍在传输历史（快照流尚未 end）。
    const historyInFlight = !mux.frames.some((frame) => frame.streamId === 'c-snapshot' && frame.type === 'end');
    recorder.mark('mux.history.inFlightAtTerminalOutput', { historyInFlight });
    assert.equal(historyInFlight, true, '上游未 end，历史仍在同一 carrier 上传输');
  } finally {
    upstreamMode = 'ok';
    mux.close();
  }

  // 隐私：真实流程的观测记录不得包含 JWT、正文标记、完整 URL 或方案前缀。
  const out = recorder.summaryJson();
  for (const forbidden of [
    adminToken, 'dsh_gateway_token',
    HISTORY_BODY_MARKER, PAGE_BODY_MARKER, SNAPSHOT_BODY_MARKER, TERMINAL_BODY_MARKER,
    '/api/session.history', '/api/session.page', '/api/remote.mux',
    'http://', 'ws://', '?',
  ]) {
    assert.equal(out.includes(forbidden), false, `观测记录不得包含敏感内容：${forbidden}`);
  }

  // 即使调用方把敏感字段塞进 mark()，白名单也会丢弃未知字段。
  const leaky = new LoadingTimeline({ enabled: true });
  leaky.mark('http.history.firstByte', {
    elapsedMs: 5, bytesIn: 10, bytesOut: 20, ok: true,
    url: `/api/session.history?token=${adminToken}`,
    cookie: adminToken,
    body: SNAPSHOT_BODY_MARKER,
  } as unknown as Parameters<LoadingTimeline['mark']>[1]);
  assert.deepEqual(leaky.records(), [{ stage: 'http.history.firstByte', elapsedMs: 5, bytesIn: 10, bytesOut: 20, ok: true }]);
  const leakyOut = leaky.summaryJson();
  for (const forbidden of [adminToken, SNAPSHOT_BODY_MARKER, '/api/session.history']) {
    assert.equal(leakyOut.includes(forbidden), false, `白名单外的字段不得进入记录：${forbidden}`);
  }

  recorder.emit();
});

// ─────────────────────────────────────────────────────────────────────────────
// 生产埋点（默认关闭；用例临时开启共享时间线后复位）
// ─────────────────────────────────────────────────────────────────────────────

test('生产埋点：history/page 的 parse/filter/stringify 分段、输入/输出字节与事件循环延迟，且不泄漏', async () => {
  await withProductionTimeline(async () => {
    // 首次请求：事件循环直方图刚被按需启用、窗口未填充，故样本在稍后的请求才产生。
    const history = await startHistoryRequest('/api/session.history').response;
    assert.equal(history.status, 200, history.body);
    const page = await startHistoryRequest('/api/session.page').response;
    assert.equal(page.status, 200, page.body);
    await wait(120);
    await startHistoryRequest('/api/session.history').response;

    const records = loadingTimeline.records();
    const stages = new Set(records.map((record) => record.stage));
    for (const stage of [
      'gateway.history.parse', 'gateway.history.filter', 'gateway.history.stringify',
      'gateway.page.parse', 'gateway.page.filter', 'gateway.page.stringify',
    ]) {
      assert.ok(stages.has(stage), `缺少同步分段记录：${stage}`);
    }
    const parse = records.find((record) => record.stage === 'gateway.history.parse');
    const stringify = records.find((record) => record.stage === 'gateway.history.stringify');
    assert.equal(typeof parse?.bytesIn, 'number', 'parse 应记录输入字节');
    assert.equal(typeof stringify?.bytesOut, 'number', 'stringify 应记录输出字节');
    assert.ok((stringify?.bytesOut as number) > 0, '输出字节应大于 0');

    assert.ok(stages.has('gateway.eventLoop.delay'), '应记录事件循环延迟样本');
    const loop = records.find((record) => record.stage === 'gateway.eventLoop.delay');
    assert.ok(Number.isFinite(loop?.eventLoopDelayMs as number), '事件循环延迟应为有限数值');

    // 隐私：生产埋点记录同样不得含正文/URL/JWT。
    const out = loadingTimeline.summaryJson();
    for (const forbidden of [adminToken, 'dsh_gateway_token', HISTORY_BODY_MARKER, PAGE_BODY_MARKER, '/api/session.history', '/api/session.page', 'http://', '?']) {
      assert.equal(out.includes(forbidden), false, `生产埋点记录不得包含敏感内容：${forbidden}`);
    }
  });
});

test('生产埋点：上游快照准备（open 转发 → 上游首个 item）', async () => {
  upstreamMode = 'hold';
  const mux = await openMux();
  try {
    await withProductionTimeline(async () => {
      sendOpen(mux, 'prep-snapshot', 'session/follow', {
        args: { request: { address: { kind: 'session', sessionId: 'obs-session' } } },
      });
      const item = await waitForFrame(mux, (frame) => frame.streamId === 'prep-snapshot' && frame.type === 'item');
      assert.ok(item, '上游首个 item 必须到达');
      const prep = loadingTimeline.records().find((record) => record.stage === 'mux.upstream.snapshot.prepare');
      assert.ok(prep, '应记录上游快照准备');
      assert.equal(typeof prep?.elapsedMs, 'number');
      assert.equal(typeof prep?.bytesIn, 'number');
      assert.ok((prep?.elapsedMs as number) >= 0);
    });
  } finally {
    upstreamMode = 'ok';
    mux.close();
  }
});

test('生产埋点：baseline 有界等待（子用户无基线 → 可重试 503）', async () => {
  const subUser = db.createUser('timeline-baseline-user', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [],
  });
  const subCookie = `dsh_gateway_token=${jwt.sign({ sub: String(subUser.id), username: subUser.username, cv: 0 }, 'test-secret', { expiresIn: '12h' })}`;

  await withProductionTimeline(async () => {
    const started = Date.now();
    const response = await gatewayPost('/api/session.list', subCookie, {
      type: 'client-request', rpcId: 'obs-baseline', method: 'session/list', payload: { args: {} },
    });
    const elapsed = Date.now() - started;
    assert.equal(response.status, 503, response.body);
    assert.equal((JSON.parse(response.body) as { code?: string }).code, 'BASELINE_PENDING');

    const record = loadingTimeline.records().find((entry) => entry.stage === 'baseline.wait');
    assert.ok(record, '应记录 baseline 等待');
    assert.equal(record?.ok, false, '基线未到达应记为 ok=false');
    assert.equal(typeof record?.elapsedMs, 'number');
    assert.ok(elapsed >= 1000, `基线等待应为有界超时，实测 ${elapsed}ms`);
  });
});
