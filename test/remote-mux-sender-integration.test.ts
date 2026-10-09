// Remote mux 串行分片发送器（MuxSender）集成测试。
//
// 写入范围：仅本文件；不改生产源码。`proxy.ts` 尚未把 MuxSender 接入业务发送路径，
// 因此本文件直接对 src/remote-mux-sender.ts 的公开契约做集成验证，夹具自建、不依赖
// 尚未完成的接线，也不会拖慢/阻塞主全量测试（所有等待都有期限，句柄在 finally 收敛）。
//
// 两个夹具层：
//   A. 可控 socket + 注入调度面（最小独立工厂 ManualSocket/FakeTimers）：确定性验证分片、
//      UTF-8 跨片重组、FIFO、单在途、接受/队列两套预算、cancel/FIN 顺序、send error、
//      关闭后的迟到回调、水位排水闸门（实测 bufferedAmount 下降计进度）、dispose 幂等。
//   B. 真实 ws + 有界 TCP relay：验证真实分片重组、服务端腿（网关→浏览器）与客户端腿
//      （网关→上游）两种角色的掩码方向、分片帧序列，以及停读→恢复的有界行为。
//
// 对齐规格不变量：一条业务文本消息 = 一条 WebSocket 文本消息；每方向至多一条未完成消息；
// 一次只提交一片并等其本地写回调；接受预算按完整消息计费一次、末片回调后才归还。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import {
  MuxSender,
  type MuxFragmentSocket,
  type MuxSenderOptions,
  type MuxSenderSnapshot,
} from '../src/remote-mux-sender.js';

const require = createRequire(import.meta.url);
const { WebSocketServer, WebSocket: NodeWebSocket } = require('ws') as {
  WebSocketServer: new (options: {
    host?: string;
    port?: number;
    server?: http.Server;
    perMessageDeflate?: boolean;
  }) => any;
  WebSocket: new (url: string) => any;
};

const OPEN = 1;

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

/** 有界轮询：超时以断言失败退出，绝不无限等待。 */
async function waitFor(predicate: () => boolean, timeoutMs: number, label: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return;
    if (Date.now() >= deadline) assert.ok(false, `超时未满足：${label}`);
    await wait(10);
  }
}

// ---------------------------------------------------------------------------
// A. 可控 socket + 注入调度面
// ---------------------------------------------------------------------------

/** 记录每次写出（含分片选项）的 stub socket；写入回调由测试显式完成。 */
class ManualSocket implements MuxFragmentSocket {
  readyState = OPEN;
  bufferedAmount = 0;
  readonly frames: Array<{ data: Buffer; fin: boolean; binary: boolean }> = [];
  private readonly flushes: Array<(error?: Error) => void> = [];

  send(data: Buffer, options: { readonly binary: false; readonly fin: boolean }, onFlush?: (error?: Error) => void): void {
    this.frames.push({ data, fin: options.fin, binary: options.binary });
    if (onFlush !== undefined) this.flushes.push(onFlush);
  }

  get pendingFlushes(): number {
    return this.flushes.length;
  }

  /** 完成最早一次未决写入；`error` 模拟本地写入失败（不是进度）。 */
  flush(error?: Error): void {
    const cb = this.flushes.shift();
    assert.ok(cb !== undefined, '必须存在未决写入回调');
    cb(error);
  }

  /** 反复完成写入直到没有未决回调；有界循环避免排水阻塞时死循环。 */
  flushAll(): void {
    for (let guard = 0; this.flushes.length > 0 && guard < 100_000; guard += 1) {
      this.flushes.shift()?.();
    }
  }
}

/** 受控调度面：按 due 顺序触发；与 MuxSender 默认使用同一时间轴。 */
class FakeTimers {
  private current = 0;
  private seq = 0;
  private readonly timers = new Map<number, { due: number; order: number; fn: () => void }>();

  readonly schedule = (fn: () => void, delayMs: number): (() => void) => {
    const id = ++this.seq;
    this.timers.set(id, { due: this.current + delayMs, order: id, fn });
    return () => { this.timers.delete(id); };
  };

  get size(): number {
    return this.timers.size;
  }

  advance(ms: number): void {
    const target = this.current + ms;
    for (;;) {
      const next = [...this.timers.entries()]
        .filter(([, timer]) => timer.due <= target)
        .sort((a, b) => a[1].due - b[1].due || a[1].order - b[1].order)[0];
      if (next === undefined) break;
      const [id, timer] = next;
      this.timers.delete(id);
      this.current = timer.due;
      timer.fn();
    }
    this.current = target;
  }
}

/** 全字段必填配置（模块按原值使用、不做兜底）。 */
const baseOptions = (overrides: Partial<MuxSenderOptions> = {}): MuxSenderOptions => ({
  fragmentBytes: 5,
  highWaterBytes: 1 << 20,
  lowWaterBytes: 0,
  maxMessageBytes: 1 << 20,
  acceptBudgetBytes: 4 << 20,
  maxQueueMessages: 256,
  maxQueueBytes: 4 << 20,
  drainPollIntervalMs: 5,
  ...overrides,
});

type Harness = {
  sender: MuxSender;
  socket: ManualSocket;
  timers: FakeTimers;
  progress: () => number;
  busy: () => number;
  idle: () => number;
  failures: Array<Error | undefined>;
  snap: () => MuxSenderSnapshot;
};

function makeSender(overrides: Partial<MuxSenderOptions> = {}, socket = new ManualSocket()): Harness {
  const timers = new FakeTimers();
  let progress = 0;
  let busy = 0;
  let idle = 0;
  const failures: Array<Error | undefined> = [];
  const sender = new MuxSender(socket, baseOptions({
    schedule: timers.schedule,
    onProgress: () => { progress += 1; },
    onBusy: () => { busy += 1; },
    onIdle: () => { idle += 1; },
    onFailure: (error) => { failures.push(error); },
    ...overrides,
  }));
  return { sender, socket, timers, progress: () => progress, busy: () => busy, idle: () => idle, failures, snap: () => sender.snapshot() };
}

test('fragmentBytes=0：整条消息单帧 fin=true，且不做排水等待', () => {
  const h = makeSender({ fragmentBytes: 0 });
  h.socket.bufferedAmount = 10_000_000; // 远超高水位：单帧模式必须忽略它
  assert.equal(h.sender.enqueue('hello世界'), 'accepted');
  assert.equal(h.socket.frames.length, 1, '单帧模式只写出一次');
  assert.equal(h.socket.frames[0].binary, false, '文本帧');
  assert.equal(h.socket.frames[0].fin, true, '单帧即末片');
  assert.equal(h.socket.frames[0].data.toString('utf8'), 'hello世界');
  assert.equal(h.snap().draining, false, '单帧模式不进入排水等待');
  assert.equal(h.snap().inFlight, true);
  assert.equal(h.snap().acceptedBytes, Buffer.byteLength('hello世界'));

  h.socket.flush();
  assert.deepEqual([h.snap().inFlight, h.snap().acceptedBytes, h.snap().busy], [false, 0, false]);
  assert.deepEqual([h.busy(), h.idle(), h.progress()], [1, 1, 1], '单帧一次写回调 = 一次进度、一次 busy/idle 边沿');
});

test('分片：UTF-8 跨片按字节切分，重组后等于原文、末片 fin=true', () => {
  const h = makeSender({ fragmentBytes: 4 });
  const text = '你好世界ABC'; // 15 字节；4 字节切片会切断多字节字符
  assert.equal(h.sender.enqueue(text), 'accepted');

  assert.equal(h.socket.frames.length, 1, '同方向至多一条在途：只提交首片');
  assert.equal(h.socket.frames[0].fin, false, '首片 fin 必须为 false');
  h.socket.flushAll();

  const frames = h.socket.frames;
  assert.equal(frames.length, Math.ceil(Buffer.byteLength(text) / 4), '按字节切成 4 片');
  assert.deepEqual(frames.map((f) => f.fin), [false, false, false, true], '仅末片 fin=true');
  assert.ok(frames.every((f) => f.binary === false), '所有片都是文本帧');
  // 逐片解码会丢字符——证明确实切在多字节字符中间；不逐片解码是契约要求。
  assert.ok(frames[1].data.toString('utf8').includes('\uFFFD'), '第 2 片应切断多字节字符');
  // 接收端按整条消息重组后必须与原文逐字节一致。
  assert.equal(Buffer.concat(frames.map((f) => f.data)).toString('utf8'), text);
  assert.equal(h.snap().acceptedBytes, 0);
  assert.equal(h.progress(), frames.length, '每个成功片回调各记一次进度');
});

test('FIFO 且同方向至多一条在途：前一条发到 FIN 前不启动后一条', () => {
  const h = makeSender({ fragmentBytes: 2 });
  assert.equal(h.sender.enqueue('AAAA'), 'accepted'); // 2 片
  assert.equal(h.sender.enqueue('BB'), 'accepted');   // 1 片
  assert.deepEqual(
    [h.socket.frames.length, h.snap().queuedMessages, h.snap().inFlight, h.snap().acceptedBytes],
    [1, 1, true, 6],
    '只提交 A 的首片，B 仍在队列；接受预算按完整消息计',
  );

  h.socket.flushAll();
  assert.deepEqual(h.socket.frames.map((f) => f.data.toString('utf8')), ['AA', 'AA', 'BB'], '严格 FIFO，不交错');
  assert.deepEqual(h.socket.frames.map((f) => f.fin), [false, true, true]);
});

test('两套预算分离：单消息 oversized、接受预算 overflow、队列条数/字节 queue-full', () => {
  const oversized = makeSender({ maxMessageBytes: 4 });
  assert.equal(oversized.sender.enqueue('abcde'), 'oversized');

  const overflow = makeSender({ maxMessageBytes: 1_000, acceptBudgetBytes: 5, fragmentBytes: 4 });
  assert.equal(overflow.sender.enqueue('abc'), 'accepted');
  assert.equal(overflow.sender.enqueue('def'), 'overflow', '3+3>5 必须拒绝，不静默丢帧');

  const byCount = makeSender({ maxQueueMessages: 1, fragmentBytes: 4 });
  assert.equal(byCount.sender.enqueue('abcd'), 'accepted'); // 在途
  assert.equal(byCount.sender.enqueue('abcd'), 'accepted'); // 队列 1
  assert.equal(byCount.sender.enqueue('abcd'), 'queue-full');

  const byBytes = makeSender({ maxQueueBytes: 4, fragmentBytes: 4 });
  assert.equal(byBytes.sender.enqueue('abcd'), 'accepted'); // 在途，队列字节 0
  assert.equal(byBytes.sender.enqueue('abcd'), 'accepted'); // 队列字节 4
  assert.equal(byBytes.sender.enqueue('abcd'), 'queue-full');
});

test('预算转移：队列→在途只减队列字节，末片回调后才扣一次接受字节', () => {
  const h = makeSender({ fragmentBytes: 2 });
  h.sender.enqueue('AAAA');
  h.sender.enqueue('BBBB');
  assert.deepEqual(
    [h.snap().acceptedBytes, h.snap().queuedMessages, h.snap().queuedBytes, h.snap().inFlight],
    [8, 1, 4, true],
    '两条消息都在接受预算里；B 占队列字节',
  );

  h.socket.flush(); // 完成 A 的第 1 片，提交第 2 片
  assert.deepEqual([h.snap().acceptedBytes, h.snap().queuedMessages, h.snap().inFlight], [8, 1, true], 'A 未 FIN，A/B 都仍计费');

  h.socket.flush(); // A 第 2 片 FIN：A 出账，B 提升为在途
  assert.deepEqual(
    [h.snap().acceptedBytes, h.snap().queuedMessages, h.snap().queuedBytes, h.snap().inFlight, h.snap().fragmentOffset],
    [4, 0, 0, true, 0],
    'A 只扣一次；B 转移为在途只减队列字节、接受字节不变',
  );

  h.socket.flush();
  h.socket.flush();
  assert.deepEqual([h.snap().acceptedBytes, h.snap().inFlight, h.snap().busy], [0, false, false]);
  assert.deepEqual([h.busy(), h.idle()], [1, 1], 'busy/idle 只在边沿各触发一次，不随入队重复触发');
});

test('cancel：只删未开始的同 tag，在途发到 FIN，兄弟流不受影响', () => {
  const h = makeSender({ fragmentBytes: 2 });
  h.sender.enqueue('AAAA', { tag: 's1' }); // 在途
  h.socket.flush();                         // 提交 A 的第 2 片
  h.sender.enqueue('BB', { tag: 's1' });    // 未开始
  h.sender.enqueue('CC', { tag: 's2' });    // 未开始，兄弟流

  const s2 = h.sender.cancel('s2');
  assert.deepEqual(s2, { removedMessages: 1, removedBytes: 2, started: false }, '未开始同 tag 可整项删除');
  assert.equal(h.snap().acceptedBytes, 6, 'A(4)+B(2)');

  const s1 = h.sender.cancel('s1');
  assert.deepEqual(s1, { removedMessages: 1, removedBytes: 2, started: true }, 'started 告知调用方在途消息必须发到 FIN');
  assert.equal(h.snap().acceptedBytes, 4, '只退回 B');

  h.socket.flushAll();
  assert.deepEqual(h.socket.frames.map((f) => f.data.toString('utf8')), ['AA', 'AA'], 'A 完整到 FIN；B/C 从未写出');
  assert.equal(h.snap().acceptedBytes, 0);
});

test('send 回调带 error：按 carrier 失败收敛、dispose、不再写后续片', () => {
  const h = makeSender({ fragmentBytes: 2 });
  h.sender.enqueue('AAAA');
  h.socket.flush(new Error('local write failed'));
  assert.equal(h.failures.length, 1);
  assert.equal(h.failures[0]?.message, 'local write failed');
  assert.equal(h.snap().disposed, true, '发送失败即 dispose');
  assert.deepEqual([h.snap().queuedBytes, h.snap().acceptedBytes, h.snap().inFlight], [0, 0, false]);
  assert.equal(h.socket.frames.length, 1, '失败后不再提交剩余片');
  assert.equal(h.sender.enqueue('later'), 'closed', '关闭后拒绝新消息');
});

test('同步 throw 与非 OPEN 均进入 carrier 失败路径', () => {
  const threw = makeSender({ fragmentBytes: 2 });
  threw.socket.send = () => { throw new Error('sync boom'); };
  threw.sender.enqueue('AAAA');
  assert.equal(threw.failures.length, 1);
  assert.equal(threw.failures[0]?.message, 'sync boom');
  assert.equal(threw.snap().disposed, true);

  const closed = makeSender({ fragmentBytes: 2 });
  closed.socket.readyState = 0; // CONNECTING
  closed.sender.enqueue('AAAA');
  assert.equal(closed.failures.length, 1, 'socket 非 OPEN 即失败，不静默丢弃');
  assert.equal(closed.snap().disposed, true);
  assert.equal(closed.socket.frames.length, 0);
});

test('dispose 后的迟到回调是 no-op，不重复扣费、不再写、不再失败', () => {
  const h = makeSender({ fragmentBytes: 2 });
  h.sender.enqueue('AAAA');
  h.sender.dispose(); // 服务器/carrier 先行回收
  assert.equal(h.socket.pendingFlushes, 1, 'dispose 前已有一片在途');
  const before = h.socket.frames.length;
  h.socket.flush(); // 关闭后才到达的本地写回调
  assert.equal(h.failures.length, 0, '迟到回调不得触发失败');
  assert.equal(h.socket.frames.length, before, '迟到回调不得继续写入');
  assert.deepEqual([h.snap().acceptedBytes, h.snap().disposed], [0, true]);
});

test('水位排水闸门：超 HIGH 停止提交、降到 LOW 后继续（可控慢读）', () => {
  const h = makeSender({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 });
  h.socket.bufferedAmount = 100;
  h.sender.enqueue('AAAAAAAA'); // 8 字节 → 2 片
  assert.equal(h.socket.frames.length, 0, '超 HIGH 必须停止提交');
  assert.equal(h.snap().draining, true);
  assert.ok(h.timers.size >= 1, '等待排水期间应有一个可取消的等待器');

  h.timers.advance(5);
  assert.equal(h.socket.frames.length, 0, '水位未回落，继续等待');
  assert.ok(h.timers.size >= 1);

  h.socket.bufferedAmount = 2; // 降到 LOW
  h.timers.advance(5);
  assert.equal(h.socket.frames.length, 1, '降到 LOW 后恢复提交下一片');
  assert.equal(h.snap().draining, false);

  h.socket.bufferedAmount = 100; // 再次超 HIGH
  h.socket.flush();              // 完成第 1 片 → 尝试第 2 片 → 再次等待
  assert.equal(h.socket.frames.length, 1);
  assert.equal(h.snap().draining, true);

  h.socket.bufferedAmount = 0;
  h.timers.advance(5);
  h.socket.flush();
  assert.deepEqual(h.socket.frames.map((f) => f.data.toString('utf8')), ['AAAA', 'AAAA']);
  assert.deepEqual(h.socket.frames.map((f) => f.fin), [false, true]);
  assert.equal(h.snap().acceptedBytes, 0);
});

test('排水实测 bufferedAmount 下降上报一次进度，未下降不误报也不失败', () => {
  const h = makeSender({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 });
  h.socket.bufferedAmount = 100;
  h.sender.enqueue('AAAAAAAA');
  assert.equal(h.snap().draining, true);
  assert.equal(h.socket.frames.length, 0, '超 HIGH 不提交');

  h.timers.advance(5);
  assert.equal(h.progress(), 0, '水位未下降不得伪造进度');

  h.socket.bufferedAmount = 2;
  h.timers.advance(5);
  assert.equal(h.progress(), 1, '实测下降上报一次进度');
  assert.equal(h.socket.frames.length, 1, '降到 LOW 后继续提交');
  assert.deepEqual(h.failures, []);
});

test('dispose 清理排水等待且幂等，关闭后 enqueue 返回 closed', () => {
  const h = makeSender({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 });
  h.socket.bufferedAmount = 100;
  h.sender.enqueue('AAAAAAAA');
  assert.equal(h.snap().draining, true);
  assert.ok(h.timers.size >= 1);

  h.sender.dispose();
  assert.equal(h.snap().draining, false, 'dispose 必须取消排水等待');
  assert.equal(h.timers.size, 0, '不得残留定时器/等待器');
  assert.deepEqual([h.snap().disposed, h.snap().queuedBytes, h.snap().acceptedBytes], [true, 0, 0]);

  h.sender.dispose(); // 幂等
  assert.equal(h.sender.enqueue('x'), 'closed');
});

// ---------------------------------------------------------------------------
// B. 真实 ws + 有界 TCP relay
// ---------------------------------------------------------------------------

async function startWss(): Promise<{ wss: any; port: number }> {
  // 关闭压缩：与生产一致，也让 relay 帧解析只面对未压缩帧（RSV1=0）。
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0, perMessageDeflate: false });
  await once(wss, 'listening');
  return { wss, port: (wss.address() as { port: number }).port };
}

/** 与生产 proxy.ts 的 fragmentSocketOf 同形：把 ws 连接适配成 MuxFragmentSocket。 */
const fragmentSocketOf = (ws: any): MuxFragmentSocket => ({
  get readyState(): number { return ws.readyState; },
  get bufferedAmount(): number { return ws.bufferedAmount; },
  send: (data: Buffer, options: { binary: false; fin: boolean }, onFlush?: (error?: Error) => void) =>
    ws.send(data, options, onFlush),
});

function closeWss(wss: any): void {
  for (const client of wss.clients ?? []) {
    try { client.terminate(); } catch { /* 已关闭 */ }
  }
  try { wss.close(); } catch { /* 已关闭 */ }
}

/** 解析一个方向的 WebSocket 帧（跳过 HTTP 握手），记录 fin/opcode/mask 与解掩码后的载荷。 */
class FrameTap {
  readonly frames: Array<{ fin: boolean; opcode: number; masked: boolean; payload: Buffer }> = [];
  private buffer = Buffer.alloc(0);
  private handshakeDone = false;

  push(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    if (!this.handshakeDone) {
      const end = this.buffer.indexOf('\r\n\r\n');
      if (end === -1) return;
      this.buffer = this.buffer.subarray(end + 4);
      this.handshakeDone = true;
    }
    this.parse();
  }

  private parse(): void {
    for (;;) {
      if (this.buffer.length < 2) return;
      const b0 = this.buffer[0];
      const b1 = this.buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let length = b1 & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (this.buffer.length < offset + 2) return;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) return;
        length = Number(this.buffer.readBigUInt64BE(offset));
        offset += 8;
      }
      const maskBytes = masked ? 4 : 0;
      const total = offset + maskBytes + length;
      if (this.buffer.length < total) return;
      const maskKey = masked ? this.buffer.subarray(offset, offset + 4) : null;
      const payload = Buffer.from(this.buffer.subarray(offset + maskBytes, total));
      if (maskKey !== null) {
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= maskKey[i & 3];
      }
      this.frames.push({ fin, opcode, masked, payload });
      this.buffer = this.buffer.subarray(total);
    }
  }
}

type Relay = {
  port: number;
  c2s: FrameTap;
  s2c: FrameTap;
  /** 模拟慢读：暂停向客户端方向转发（应用层停读，内核仍可能先缓存/ACK 一段）。 */
  pauseS2c: () => void;
  resumeS2c: () => void;
  close: () => void;
};

/** 有界 TCP relay：两个方向都记录帧；可暂停 s2c 方向读取以制造应用层停读。 */
async function startRelay(targetPort: number): Promise<Relay> {
  const c2s = new FrameTap();
  const s2c = new FrameTap();
  const sockets = new Set<net.Socket>();
  const upstreams = new Set<net.Socket>();
  const server = net.createServer((downstream) => {
    const upstream = net.connect({ host: '127.0.0.1', port: targetPort });
    sockets.add(downstream);
    sockets.add(upstream);
    upstreams.add(upstream);
    downstream.on('data', (chunk: Buffer) => { c2s.push(chunk); if (!upstream.destroyed) upstream.write(chunk); });
    upstream.on('data', (chunk: Buffer) => { s2c.push(chunk); if (!downstream.destroyed) downstream.write(chunk); });
    downstream.on('error', () => { /* 测试端关闭 */ });
    upstream.on('error', () => { /* 目标端关闭 */ });
    downstream.on('close', () => upstream.destroy());
    upstream.on('close', () => downstream.destroy());
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    port: (server.address() as net.AddressInfo).port,
    c2s,
    s2c,
    pauseS2c: () => { for (const s of upstreams) s.pause(); },
    resumeS2c: () => { for (const s of upstreams) s.resume(); },
    close: () => {
      for (const s of sockets) s.destroy();
      try { server.close(); } catch { /* 已关闭 */ }
    },
  };
}

test('真实 ws 浏览器腿（服务端角色）：跨片 UTF-8 重组为单条文本、FIFO 保序', async () => {
  const { wss, port } = await startWss();
  const received: string[] = [];
  let failure: unknown;
  let senderResolve: (sender: MuxSender) => void = () => {};
  const senderReady = new Promise<MuxSender>((resolve) => { senderResolve = resolve; });
  wss.on('connection', (ws: any) => {
    senderResolve(new MuxSender(fragmentSocketOf(ws), baseOptions({
      fragmentBytes: 5,
      onFailure: (error) => { failure = error; },
    })));
  });
  const client = new NodeWebSocket(`ws://127.0.0.1:${port}`);
  client.on('message', (data: Buffer) => { received.push(data.toString('utf8')); });
  try {
    await once(client, 'open');
    const sender = await senderReady;
    const messages = ['你好，世界！UTF-8 跨片重组', 'second-ascii', '第三'];
    for (const message of messages) assert.equal(sender.enqueue(message), 'accepted');
    await waitFor(() => failure !== undefined || received.length === messages.length, 5000, '浏览器腿应完成发送');
    assert.equal(failure, undefined, `真实 ws 上 Sender 失败（onFailure=${String(failure)}）：成功写入回调为 null，不得当作 error`);
    assert.deepEqual(received, messages, 'ws 把 continues 重组为同一条文本消息，内容与顺序一致');
  } finally {
    try { client.terminate(); } catch { /* 已关闭 */ }
    closeWss(wss);
  }
});

test('真实 ws 上游腿（客户端角色）：分片重组成立，客户端帧按协议加掩码', async () => {
  const { wss, port } = await startWss();
  const received: string[] = [];
  let failure: unknown;
  let serverReady: () => void = () => {};
  const connected = new Promise<void>((resolve) => { serverReady = resolve; });
  wss.on('connection', (serverSide: any) => {
    serverSide.on('message', (data: Buffer) => { received.push(data.toString('utf8')); });
    serverReady();
  });
  const client = new NodeWebSocket(`ws://127.0.0.1:${port}`);
  try {
    await once(client, 'open');
    await connected;
    // 网关→上游腿：MuxSender 包装的是 ws 客户端连接（帧必须加掩码，否则 ws 服务端会以 1002 关闭）。
    const sender = new MuxSender(fragmentSocketOf(client), baseOptions({
      fragmentBytes: 3,
      onFailure: (error) => { failure = error; },
    }));
    const messages = ['上游腿-a', 'upstream-b', '边-界'];
    for (const message of messages) assert.equal(sender.enqueue(message), 'accepted');
    await waitFor(() => failure !== undefined || received.length === messages.length, 5000, '上游腿应完成发送');
    assert.equal(failure, undefined, `真实 ws 上 Sender 失败（onFailure=${String(failure)}）：成功写入回调为 null，不得当作 error`);
    assert.deepEqual(received, messages);
  } finally {
    try { client.terminate(); } catch { /* 已关闭 */ }
    closeWss(wss);
  }
});

test('真实 ws + TCP relay：服务端帧不加掩码、客户端帧加掩码，分片帧序列正确', async () => {
  const { wss, port: serverPort } = await startWss();
  const outbound = '分片消息-带多字节-abcdefghij';
  let failure: unknown;
  let sender: MuxSender | null = null;
  wss.on('connection', (ws: any) => {
    sender = new MuxSender(fragmentSocketOf(ws), baseOptions({
      fragmentBytes: 6,
      onFailure: (error) => { failure = error; },
    }));
    ws.on('message', () => { sender?.enqueue(outbound); });
  });
  const relay = await startRelay(serverPort);
  const client = new NodeWebSocket(`ws://127.0.0.1:${relay.port}`);
  const received: string[] = [];
  client.on('message', (data: Buffer) => { received.push(data.toString('utf8')); });
  try {
    await once(client, 'open');
    client.send('ping'); // 触发一条客户端→服务端数据帧，用于断言客户端掩码方向
    await waitFor(() => failure !== undefined || (received.length === 1 && relay.c2s.frames.length >= 1), 5000, 'relay 应捕获两方向帧并完成下行重组');
    assert.equal(failure, undefined, `真实 ws 上 Sender 失败（onFailure=${String(failure)}）：成功写入回调为 null，不得当作 error`);

    const down = relay.s2c.frames;
    const last = down[down.length - 1];
    assert.ok(last, '必须捕获到下行帧');
    assert.equal(down[0].masked, false, '服务端→客户端帧不得加掩码');
    assert.equal(down[0].opcode, 1, '首片是文本帧（opcode 1）');
    assert.equal(down[0].fin, false, '首片 fin=false');
    assert.ok(down.slice(1).every((f) => f.opcode === 0), '后续片由 ws 生成为 continuation（opcode 0）');
    assert.equal(last.fin, true, '末片 fin=true');
    assert.equal(Buffer.concat(down.map((f) => f.payload)).toString('utf8'), outbound, '按帧重组等于原文');

    assert.equal(relay.c2s.frames[0].masked, true, '客户端→服务端帧必须加掩码');
  } finally {
    try { client.terminate(); } catch { /* 已关闭 */ }
    relay.close();
    closeWss(wss);
  }
});

test('真实 ws + relay 停读→恢复：排水闸门暂停提交，恢复后完整送达，服务器先回收再销毁客户端', async () => {
  const { wss, port: serverPort } = await startWss();
  const big = 'A'.repeat(3 * 1024 * 1024); // 3 MiB，足以让停读方向积压越过 HIGH
  let failure: unknown;
  const createdSenders: MuxSender[] = [];
  const senderReady = new Promise<MuxSender>((resolve) => {
    wss.on('connection', (ws: any) => {
      const sender = new MuxSender(fragmentSocketOf(ws), baseOptions({
        fragmentBytes: 16 * 1024,
        highWaterBytes: 64 * 1024,
        lowWaterBytes: 16 * 1024,
        maxMessageBytes: 64 * 1024 * 1024,
        acceptBudgetBytes: 128 * 1024 * 1024,
        maxQueueBytes: 128 * 1024 * 1024,
        onFailure: (error) => { failure = error; },
      }));
      createdSenders.push(sender);
      resolve(sender);
    });
  });
  const relay = await startRelay(serverPort);
  const client = new NodeWebSocket(`ws://127.0.0.1:${relay.port}`);
  const received: string[] = [];
  client.on('message', (data: Buffer) => { received.push(data.toString('utf8')); });
  try {
    await once(client, 'open');
    const active = await senderReady;

    relay.pauseS2c(); // 模拟慢读：relay 停止向客户端转发（应用层停读）
    assert.equal(active.enqueue(big), 'accepted');
    // 停读期间数据不得送达：内核可能先吸收一段，但应用层读取已停，客户端不应收到消息。
    await wait(300);
    assert.equal(failure, undefined, `真实 ws 上 Sender 失败（onFailure=${String(failure)}）：成功写入回调为 null，不得当作 error`);
    assert.equal(received.length, 0, '停读期间不应送达完整消息');

    relay.resumeS2c();
    await waitFor(() => received.length === 1 && active.snapshot().acceptedBytes === 0, 15_000, '恢复读取后应完整送达');
    assert.equal(received[0], big);

    // 关键顺序：先断言服务器侧有界回收（carrier 关闭语义），再在 finally 销毁测试客户端。
    active.dispose();
    const snap = active.snapshot();
    assert.deepEqual(
      [snap.disposed, snap.queuedBytes, snap.acceptedBytes, snap.draining, snap.inFlight],
      [true, 0, 0, false, false],
      'dispose 必须清空队列/接受预算、取消排水等待并停止在途',
    );
  } finally {
    for (const sender of createdSenders) { try { sender.dispose(); } catch { /* 已释放 */ } }
    try { client.terminate(); } catch { /* 已关闭 */ }
    relay.close();
    closeWss(wss);
  }
});
