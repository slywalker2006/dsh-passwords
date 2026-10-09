// Remote mux 串行分片发送器单测（第一阶段核心）。使用 stub socket 与受控调度面，确定性验证：
// 一条业务文本消息还原为一条 WebSocket 文本消息（分片重组、非 ASCII 跨片、末片 FIN）、
// 同方向 FIFO 不交错且同时至多一条未完成消息、每次只提交一片并等本地写入回调、
// fragmentBytes=0 单帧模式、高/低水位排水（并实测 bufferedAmount 下降计进度、未下降不判 stall）、
// 三种独立预算与「一条消息只按接受计费一次」、单流 cancel 只删未开始消息、dispose 后迟到回调
// no-op，以及 busy/idle/progress/失败回调。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MuxSender,
  MuxSenderBudget,
  type MuxAcceptOutcome,
  type MuxFragmentSendOptions,
  type MuxFragmentSocket,
  type MuxSenderOptions,
} from '../src/remote-mux-sender.js';

const OPEN = 1;

/** 记录每个分片（含其本地写入回调）的 stub socket；`auto` 为 true 时 send 同步回调成功。 */
class StubSocket implements MuxFragmentSocket {
  readyState = OPEN;
  bufferedAmount = 0;
  readonly frames: Array<{ data: Buffer; binary: boolean; fin: boolean; done: (error?: Error) => void }> = [];
  constructor(readonly auto: boolean) {}
  send(data: Buffer, options: MuxFragmentSendOptions, onFlush?: (error?: Error) => void): void {
    const done = onFlush ?? (() => {});
    this.frames.push({ data: Buffer.from(data), binary: options.binary, fin: options.fin, done });
    if (this.auto) done();
  }
  finish(index: number, error?: Error): void {
    this.frames[index]!.done(error);
  }
}

/** 受控调度面：按 due 顺序触发，用于确定性地推进排水轮询。 */
class FakeTimers {
  private current = 0;
  private seq = 0;
  private readonly timers = new Map<number, { due: number; order: number; fn: () => void }>();

  readonly schedule = (fn: () => void, delayMs: number): (() => void) => {
    const id = ++this.seq;
    this.timers.set(id, { due: this.current + delayMs, order: id, fn });
    return () => this.timers.delete(id);
  };

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

type Events = { busy: number; idle: number; progress: number; failures: Array<Error | undefined>; rejects: Array<{ kind: string; messageBytes: number }> };

type Harness = {
  sender: MuxSender;
  socket: StubSocket;
  timers: FakeTimers;
  events: Events;
};

function makeHarness(senderOverrides: Partial<MuxSenderOptions> = {}, auto = true): Harness {
  const socket = new StubSocket(auto);
  const timers = new FakeTimers();
  const events: Events = { busy: 0, idle: 0, progress: 0, failures: [], rejects: [] }; 
  const sender = new MuxSender(socket, {
    fragmentBytes: 4,
    highWaterBytes: 8,
    lowWaterBytes: 2,
    maxMessageBytes: 1_000,
    acceptBudgetBytes: 1_020,
    maxQueueMessages: 4,
    maxQueueBytes: 2_000,
    drainPollIntervalMs: 10,
    onBusy: () => { events.busy += 1; },
    onIdle: () => { events.idle += 1; },
    onProgress: () => { events.progress += 1; },
    onFailure: (error) => { events.failures.push(error); },
    onReject: (kind, messageBytes) => { events.rejects.push({ kind, messageBytes }); },
    schedule: timers.schedule,
    ...senderOverrides,
  });
  return { sender, socket, timers, events };
}

/** 按 FIN 边界把分片重组成完整消息，并校验全部为 text frame、末片 FIN。 */
function reassemble(socket: StubSocket): Array<{ text: string; frameCount: number }> {
  const out: Array<{ text: string; frameCount: number }> = [];
  let parts: Buffer[] = [];
  for (const frame of socket.frames) {
    assert.equal(frame.binary, false, '分片必须是 text frame（binary:false）');
    parts.push(frame.data);
    if (frame.fin) {
      out.push({ text: Buffer.concat(parts).toString('utf8'), frameCount: parts.length });
      parts = [];
    }
  }
  assert.equal(parts.length, 0, '最后一片必须是 FIN，不能留下未闭合的 continuation');
  return out;
}

test('进程级 Sender 预算在接受、取消、完成和 dispose 后准确释放', () => {
  const budget = new MuxSenderBudget(10);
  const h = makeHarness({ sharedBudget: budget, fragmentBytes: 4, acceptBudgetBytes: 100, maxQueueBytes: 10 }, false);
  assert.equal(h.sender.enqueue('123456'), 'accepted');
  assert.equal(budget.snapshot(), 6);
  assert.equal(h.sender.enqueue('12345'), 'overflow');
  assert.equal(budget.snapshot(), 6);
  h.socket.finish(0);
  h.socket.finish(1);
  assert.equal(budget.snapshot(), 0);

  assert.equal(h.sender.enqueue('1234'), 'accepted');
  assert.equal(budget.snapshot(), 4);
  h.sender.dispose();
  assert.equal(budget.snapshot(), 0);
});

test('分片重组为一条完整文本消息：非 ASCII 字符跨片、末片 FIN', () => {
  const h = makeHarness({ fragmentBytes: 4 });
  // '中文' = 6 字节；4 字节分片会把第二字切成「首字节 + 余下两字节」。
  assert.equal(h.sender.enqueue('中文'), 'accepted');
  const messages = reassemble(h.socket);
  assert.deepEqual(messages, [{ text: '中文', frameCount: 2 }]);
  const first = h.socket.frames[0]!;
  const second = h.socket.frames[1]!;
  assert.equal(first.fin, false, '首片不能 FIN');
  assert.equal(second.fin, true, '末片必须 FIN');
  assert.deepEqual([...first.data], [...Buffer.from('中文', 'utf8').subarray(0, 4)], '按字节切分，不按字符');
});

test('同方向 FIFO：前一条消息的全部分片先于后一条，绝不交错', () => {
  const h = makeHarness({ fragmentBytes: 4 });
  assert.equal(h.sender.enqueue('AAAAAAAA'), 'accepted');
  assert.equal(h.sender.enqueue('BBBBBBBB'), 'accepted');
  assert.deepEqual(reassemble(h.socket), [
    { text: 'AAAAAAAA', frameCount: 2 },
    { text: 'BBBBBBBB', frameCount: 2 },
  ]);
  assert.equal(h.socket.frames[0]!.fin, false);
  assert.equal(h.socket.frames[1]!.fin, true);
});

test('每次只提交一片：本地写入回调返回前不提交下一片', () => {
  const h = makeHarness({ fragmentBytes: 4 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted');
  assert.equal(h.socket.frames.length, 1, '只提交了第一片并等待回调');
  assert.equal(h.sender.snapshot().awaitingFlush, true);

  h.socket.finish(0);
  assert.equal(h.socket.frames.length, 2, '回调后才提交第二片');
  h.socket.finish(1);
  assert.equal(h.sender.snapshot().acceptedBytes, 0);
  assert.deepEqual(reassemble(h.socket), [{ text: 'abcdefgh', frameCount: 2 }]);
});

test('fragmentBytes=0 单帧模式：整条一帧 FIN，且不等待排水', () => {
  const h = makeHarness({ fragmentBytes: 0 }, false);
  h.socket.bufferedAmount = 10_000; // 远超高水位：单帧模式不做排水等待
  assert.equal(h.sender.enqueue('hello世界'), 'accepted');
  assert.equal(h.socket.frames.length, 1);
  assert.equal(h.socket.frames[0]!.fin, true);
  assert.equal(h.socket.frames[0]!.binary, false);
  assert.equal(h.socket.frames[0]!.data.toString('utf8'), 'hello世界');
});

test('分片模式高水位：超 HIGH 时停止加片，降到 LOW 后继续', () => {
  const h = makeHarness({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted');
  assert.equal(h.socket.frames.length, 1);

  h.socket.bufferedAmount = 100; // 第一片回调时水位超 HIGH
  h.socket.finish(0);
  assert.equal(h.socket.frames.length, 1, '超 HIGH 不得继续提交');
  assert.equal(h.sender.snapshot().draining, true);

  h.socket.bufferedAmount = 1; // 降到 LOW 以下
  h.timers.advance(10);
  assert.equal(h.socket.frames.length, 2, '排水到 LOW 后继续提交');
  h.socket.finish(1);
  assert.deepEqual(reassemble(h.socket), [{ text: 'abcdefgh', frameCount: 2 }]);
});

test('排水实测 bufferedAmount 下降计 onProgress；未下降不伪造进度也不判 stall', () => {
  const h = makeHarness({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted'); // 第 1 片正常提交
  // 第 1 片成功回调本身计一次进度；此刻水位超 HIGH，随后进入排水等待。
  h.socket.bufferedAmount = 100;
  h.socket.finish(0);
  assert.equal(h.events.progress, 1, '成功分片回调计一次进度');
  assert.equal(h.sender.snapshot().draining, true);

  h.timers.advance(10); // 水位保持 100，未下降
  assert.equal(h.events.progress, 1, '水位未下降不得伪造进度');
  assert.equal(h.events.failures.length, 0, '停滞判定属于心跳，Sender 不得据此判 stall');
  assert.equal(h.sender.snapshot().draining, true);

  h.socket.bufferedAmount = 50; // 实测下降
  h.timers.advance(10);
  assert.equal(h.events.progress, 2, 'bufferedAmount 实测下降计一次进度');
  assert.equal(h.sender.snapshot().draining, true, '仍高于 LOW，继续等待');

  h.socket.bufferedAmount = 2; // 再降并落到 LOW
  h.timers.advance(10);
  assert.equal(h.events.progress, 3, '落到 LOW 前的那次下降同样计进度');
  assert.equal(h.socket.frames.length, 2, '降到 LOW 后恢复提交下一片');
});

test('三种预算与一次计费：单条/接受总量/队列各自拒绝，计费只在接受时一次', () => {
  const h = makeHarness({ fragmentBytes: 4, maxMessageBytes: 1_000, acceptBudgetBytes: 1_020 }, false);
  assert.equal(h.sender.enqueue('x'.repeat(1_001)), 'oversized');
  assert.deepEqual(h.events.rejects[0], { kind: 'message-bytes', messageBytes: 1_001 });

  // 第一条 600 字节进入在途；第二条 600 字节使接受总量 1,200 > 1,020。
  assert.equal(h.sender.enqueue('a'.repeat(600)), 'accepted');
  assert.equal(h.sender.snapshot().acceptedBytes, 600);
  const outcome: MuxAcceptOutcome = h.sender.enqueue('b'.repeat(600));
  assert.equal(outcome, 'overflow');
  assert.deepEqual(h.events.rejects[1], { kind: 'accepted-bytes', messageBytes: 600 });
  assert.equal(h.sender.snapshot().acceptedBytes, 600, '被拒绝的消息不计费');
});

test('业务消息按完整字节只计费一次，直到末片成功回调才一次性扣减', () => {
  const h = makeHarness({ fragmentBytes: 4 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted');
  assert.equal(h.sender.snapshot().acceptedBytes, 8, '入队即按完整字节计费');
  h.socket.finish(0);
  assert.equal(h.sender.snapshot().acceptedBytes, 8, '中间片不扣减');
  assert.equal(h.sender.snapshot().fragmentOffset, 4);
  h.socket.finish(1);
  assert.equal(h.sender.snapshot().acceptedBytes, 0, '末片回调才一次扣减');
});

test('生产突发：8192 条等待槽可容纳 5000 条小消息且仍保留接受字节上限', () => {
  const h = makeHarness({ fragmentBytes: 4, acceptBudgetBytes: 2_000_000, maxQueueMessages: 8192, maxQueueBytes: 2_000_000 }, false);
  h.sender.enqueue('in-flight');
  for (let i = 0; i < 5000; i += 1) assert.equal(h.sender.enqueue('x'.repeat(300)), 'accepted', `message ${i}`);
  assert.equal(h.sender.snapshot().queuedMessages, 5000);
  assert.equal(h.sender.snapshot().queuedBytes, 1_500_000);
});

test('队列条数/字节上限：超限拒绝为 queue-full，并区分拒绝类别', () => {
  const byCount = makeHarness({ fragmentBytes: 4, maxQueueMessages: 1 }, false);
  assert.equal(byCount.sender.enqueue('aaaa'), 'accepted'); // 进入在途，不占队列
  assert.equal(byCount.sender.enqueue('bbbb'), 'accepted'); // 队列深度 1
  assert.equal(byCount.sender.enqueue('cccc'), 'queue-full');
  assert.deepEqual(byCount.events.rejects[0], { kind: 'queue-count', messageBytes: 4 });

  const byBytes = makeHarness({ fragmentBytes: 4, maxQueueBytes: 4 }, false);
  assert.equal(byBytes.sender.enqueue('aaaa'), 'accepted'); // 在途，不占队列字节
  assert.equal(byBytes.sender.enqueue('bbbb'), 'accepted'); // 队列 4 字节
  assert.equal(byBytes.sender.enqueue('cccc'), 'queue-full');
  assert.deepEqual(byBytes.events.rejects[0], { kind: 'queue-bytes', messageBytes: 4 });
});

test('cancel 只删除未开始消息并退回计费；已开始的同 tag 消息必须发完 FIN', () => {
  const h = makeHarness({ fragmentBytes: 4 }, false);
  assert.equal(h.sender.enqueue('AAAAAAAA', { tag: 'a' }), 'accepted'); // 进入在途
  assert.equal(h.sender.enqueue('BBBB', { tag: 'b' }), 'accepted');
  assert.equal(h.sender.enqueue('CCCC', { tag: 'c' }), 'accepted');
  assert.equal(h.sender.snapshot().acceptedBytes, 16);

  const removed = h.sender.cancel('b');
  assert.deepEqual(removed, { removedMessages: 1, removedBytes: 4, started: false });
  assert.equal(h.sender.snapshot().queuedMessages, 1);
  assert.equal(h.sender.snapshot().acceptedBytes, 12, '退回被删消息的计费');

  const started = h.sender.cancel('a');
  assert.deepEqual(started, { removedMessages: 0, removedBytes: 0, started: true }, '在途消息不可取消');

  // 发完 a 的两片；随后 c（4 字节，单片）；b 已删除，不出现。
  h.socket.finish(0);
  h.socket.finish(1);
  h.socket.finish(2);
  assert.deepEqual(reassemble(h.socket), [
    { text: 'AAAAAAAA', frameCount: 2 },
    { text: 'CCCC', frameCount: 1 },
  ]);
});

test('dispose 停止接收、清理排水计时器；迟到回调 no-op 且不重复扣账', () => {
  const h = makeHarness({ fragmentBytes: 4 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted');
  assert.equal(h.socket.frames.length, 1);
  const progressBefore = h.events.progress;
  const failureCountBefore = h.events.failures.length;

  h.sender.dispose();
  assert.equal(h.sender.enqueue('xyz'), 'closed');
  assert.equal(h.sender.snapshot().disposed, true);
  assert.equal(h.sender.snapshot().acceptedBytes, 0);

  h.socket.finish(0); // 迟到回调
  assert.equal(h.socket.frames.length, 1, 'dispose 后不得继续写入');
  assert.equal(h.events.progress, progressBefore, '迟到回调不算进度');
  assert.equal(h.events.failures.length, failureCountBefore, 'dispose 不是 failure');

  h.sender.dispose(); // 幂等
  assert.equal(h.sender.snapshot().disposed, true);
});

test('dispose 取消排水轮询：排水中的迟到 timer 不写任何东西', () => {
  const h = makeHarness({ fragmentBytes: 4, highWaterBytes: 8, lowWaterBytes: 2 }, false);
  assert.equal(h.sender.enqueue('abcdefgh'), 'accepted');
  h.socket.bufferedAmount = 100;
  h.socket.finish(0);
  assert.equal(h.sender.snapshot().draining, true);

  h.sender.dispose();
  h.socket.bufferedAmount = 0;
  h.timers.advance(100);
  assert.equal(h.socket.frames.length, 1, 'dispose 后排水回调不得继续提交分片');
});

test('busy/idle/progress 回调：按边沿与成功分片计数，供心跳直接消费', () => {
  const h = makeHarness({ fragmentBytes: 4 });
  assert.equal(h.sender.enqueue('AAAAAAAA'), 'accepted'); // 2 片
  assert.deepEqual({ busy: h.events.busy, idle: h.events.idle, progress: h.events.progress }, { busy: 1, idle: 1, progress: 2 });
  assert.equal(h.sender.enqueue('BBBBBBBB'), 'accepted'); // 2 片
  assert.deepEqual({ busy: h.events.busy, idle: h.events.idle, progress: h.events.progress }, { busy: 2, idle: 2, progress: 4 });
  assert.equal(h.sender.snapshot().busy, false);
});

test('本地写入失败进入 carrier 失败路径：sync 抛错 / 回调 error / socket 非 OPEN', () => {
  const syncThrow = makeHarness({ fragmentBytes: 4 }, false);
  syncThrow.socket.send = () => { throw new Error('socket closing'); };
  syncThrow.sender.enqueue('abcdefgh');
  assert.equal(syncThrow.events.failures.length, 1);
  assert.equal(syncThrow.sender.snapshot().disposed, true);

  const callbackError = makeHarness({ fragmentBytes: 4 }, false);
  callbackError.sender.enqueue('abcdefgh');
  callbackError.socket.finish(0, new Error('write failed'));
  assert.equal(callbackError.events.failures.length, 1);
  assert.equal(callbackError.sender.snapshot().disposed, true);

  const notOpen = makeHarness({ fragmentBytes: 4 }, false);
  notOpen.socket.readyState = 0;
  notOpen.sender.enqueue('abcdefgh');
  assert.equal(notOpen.events.failures.length, 1);
  assert.equal(notOpen.socket.frames.length, 0, '非 OPEN 不写出');
});

test('接受生产规模常量：100 MiB 单条 / 102 MiB 接受预算在容量内正常工作', () => {
  const h = makeHarness({
    fragmentBytes: 0,
    maxMessageBytes: 100 * 1024 * 1024,
    acceptBudgetBytes: 102 * 1024 * 1024,
  });
  assert.equal(h.sender.enqueue('x'.repeat(2 * 1024 * 1024)), 'accepted');
  assert.equal(h.socket.frames.length, 1);
  assert.equal(h.sender.snapshot().acceptedBytes, 0, '单帧发送后计费归零');
});
