// Remote mux 心跳/写停滞状态机单测。使用注入的单调时钟与受控调度面，确定性验证：
// 每方向至多一条未决 nonce probe、queued/flushed/pong 三阶段、匹配 nonce 才确认、
// 独立的 queued 写入期限与 Pong deadline、写停滞只依据可解释本地进度、busy/idle 重新起算，
// 以及 dispose 推进 generation 后所有迟到回调 no-op。模块不采样 bufferedAmount，也不依赖 ws。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MuxHeartbeat,
  type MuxHeartbeatCloseSource,
  type MuxHeartbeatSnapshot,
  type MuxHeartbeatSocket,
} from '../src/remote-mux-heartbeat.js';

const OPEN = 1;
const PING_INTERVAL = 2_000;
const PONG_TIMEOUT = 30_000;
// 与 PONG_TIMEOUT 取不同值：queued 写入期限与 Pong deadline 必须能按触发条件区分。
const WRITE_STALL = 6_000;

/** 记录每次 Ping（含其本地写入回调）的 stub socket；readyState 可改。 */
class StubSocket implements MuxHeartbeatSocket {
  readyState = OPEN;
  readonly pings: Array<{ payload: Buffer; done: (error?: Error) => void }> = [];
  ping(payload: Buffer, done: (error?: Error) => void): void {
    this.pings.push({ payload, done });
  }
}

/** 受控调度面：按 due 顺序触发，`now` 与模块共享同一个单调时间轴。 */
class FakeTimers {
  private current = 0;
  private seq = 0;
  private readonly timers = new Map<number, { due: number; order: number; fn: () => void }>();

  readonly now = (): number => this.current;
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

type Harness = {
  heartbeat: MuxHeartbeat;
  socket: StubSocket;
  timers: FakeTimers;
  closes: MuxHeartbeatCloseSource[];
  state: () => MuxHeartbeatSnapshot;
};

function makeHarness(overrides: Partial<{ readyState: number }> = {}): Harness {
  const socket = new StubSocket();
  if (overrides.readyState !== undefined) socket.readyState = overrides.readyState;
  const timers = new FakeTimers();
  const closes: MuxHeartbeatCloseSource[] = [];
  let nonceSeq = 0;
  const heartbeat = new MuxHeartbeat(socket, {
    pingIntervalMs: PING_INTERVAL,
    pongTimeoutMs: PONG_TIMEOUT,
    writeStallMs: WRITE_STALL,
    onClose: (source) => closes.push(source),
    now: timers.now,
    schedule: timers.schedule,
    createNonce: () => Buffer.alloc(12, ++nonceSeq),
  });
  return { heartbeat, socket, timers, closes, state: () => heartbeat.snapshot() };
}

const lastPing = (socket: StubSocket) => {
  const ping = socket.pings.at(-1);
  assert.ok(ping, '必须已经发出 Ping');
  return ping;
};

test('每方向至多一条未决 probe：有未决 probe 时 tick 不重复发起', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  h.heartbeat.tick();
  h.heartbeat.tick();
  assert.equal(h.socket.pings.length, 1, '未决 probe 期间不得再发 Ping');
  assert.equal(h.state().state, 'queued');

  // 确认后释放，下一次 tick 才允许新探测。
  h.heartbeat.notePong(lastPing(h.socket).payload);
  h.heartbeat.tick();
  assert.equal(h.socket.pings.length, 2, 'probe 清除后允许新探测');
});

test('queued/flushed/pong 三阶段可区分，且时间戳来自注入的单调时钟', () => {
  const h = makeHarness();
  h.timers.advance(500);
  h.heartbeat.tick();
  assert.deepEqual(
    [h.state().state, h.state().queuedAt, h.state().flushedAt, h.state().lastPongAt],
    ['queued', 500, null, null],
    'tick 只登记 queued，绝不把本地写入当对端收到',
  );

  h.timers.advance(120);
  lastPing(h.socket).done();
  assert.deepEqual(
    [h.state().state, h.state().queuedAt, h.state().flushedAt],
    ['flushed', 500, 620],
    '本地写入完成只推进到 flushed',
  );

  h.timers.advance(80);
  h.heartbeat.notePong(lastPing(h.socket).payload);
  assert.deepEqual(
    [h.state().state, h.state().lastPongAt],
    ['idle', 700],
    '匹配 Pong 后回到 idle 并记录匹配时刻',
  );
});

test('只有逐字节匹配的 Pong 才确认；无关/重复/迟到 Pong 不清除当前 probe', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  lastPing(h.socket).done();
  const nonce = lastPing(h.socket).payload;

  h.heartbeat.notePong(Buffer.from('wrong-nonce'));
  h.heartbeat.notePong(Buffer.alloc(12, 0xff));
  assert.equal(h.state().state, 'flushed', '不匹配的 Pong 不得清除 probe');

  h.heartbeat.notePong(nonce);
  assert.equal(h.state().state, 'idle', '匹配 Pong 确认并清除 probe');

  // 重复到达的同一 Pong 在 probe 已清除后成为 no-op。
  h.heartbeat.notePong(nonce);
  assert.equal(h.state().lastPongAt, 0);
});

test('匹配 Pong 早于本地发送回调：迟到 flush 回调不得重新启动 Pong deadline', () => {
  const h = makeHarness();
  h.heartbeat.tick(); // queued：尚未本地提交，本不应有 deadline
  const ping = lastPing(h.socket);

  // Pong 先到且逐字节匹配：立即确认并清除 probe，此时 flush 回调尚未触发。
  h.heartbeat.notePong(ping.payload);
  assert.equal(h.state().state, 'idle');

  // 迟到的本地写入成功回调：probe 身份不再匹配，必须成为 no-op，绝不能补挂 Pong deadline。
  ping.done();
  assert.equal(h.state().state, 'idle', '迟到 flush 不得重建 probe 阶段');
  h.timers.advance(PONG_TIMEOUT * 2);
  assert.deepEqual(h.closes, [], '迟到 flush 不得启动 Pong deadline');
});

test('匹配 Pong 后已启动新探测：旧 probe 的迟到 flush 回调不影响当前 probe', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  const first = lastPing(h.socket);
  h.heartbeat.notePong(first.payload); // 确认并清除 probe#1
  h.heartbeat.tick(); // 登记 probe#2
  const second = lastPing(h.socket);
  assert.notEqual(second.payload.compare(first.payload), 0, '每次探测使用新的 nonce');

  first.done(); // probe#1 的迟到回调：身份不匹配 → 不得推进 probe#2
  assert.deepEqual(
    [h.state().state, h.state().flushedAt],
    ['queued', null],
    '旧 probe 回调不得推进当前 probe，也不得挂 deadline',
  );

  second.done(); // 当前 probe 正常本地提交后才起算 deadline
  assert.equal(h.state().state, 'flushed');
  h.timers.advance(PONG_TIMEOUT);
  assert.deepEqual(h.closes, ['ping-timeout']);
});

test('Pong deadline 独立于 tick：flushed 后即使不再 tick 也会到期关闭', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  lastPing(h.socket).done();

  h.timers.advance(PONG_TIMEOUT - 1);
  assert.deepEqual(h.closes, [], '未到时限不得关闭');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['ping-timeout'], 'Pong deadline 到期即关闭，不依赖周期 tick');
  assert.equal(h.state().state, 'idle', '关闭后 probe 与定时器一并清理');
});

test('queued Ping 写回调不触发：writeStallMs 到期按 write-stall 关闭，不启动 Pong deadline', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  assert.equal(h.state().state, 'queued');

  h.timers.advance(WRITE_STALL - 1);
  assert.deepEqual(h.closes, [], 'queued 写入期限未到不得关闭');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall'], '写回调不触发必须按写停滞关闭，而非 ping-timeout');
  assert.equal(h.state().state, 'idle', '关闭后 probe 与所有计时器一并清理');
});

test('queued 写入期限独立于 busy 写停滞：markIdle 不清除它', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  h.heartbeat.markIdle(); // 未 busy：清理的是 busy 写停滞，不得牵连 queued 写入期限
  assert.equal(h.state().stallArmed, false, 'stallArmed 只反映 busy 写停滞，与 queued 写入期限无关');
  h.timers.advance(WRITE_STALL);
  assert.deepEqual(h.closes, ['write-stall'], 'queued 写入期限必须独立存续并到期');
});

test('flush 成功交接：queued 写入期限取消，改由 Pong deadline 判定', () => {
  const h = makeHarness();
  h.heartbeat.tick(); // t=0：queued 写入期限 due = WRITE_STALL
  h.timers.advance(WRITE_STALL - 1);
  lastPing(h.socket).done(); // t=WRITE_STALL-1 flush：Pong deadline due = flush + PONG_TIMEOUT
  assert.equal(h.state().state, 'flushed');

  h.timers.advance(1); // t=WRITE_STALL：若 queued 写入期限未取消，会在此误报 write-stall
  assert.deepEqual(h.closes, [], 'flush 后 queued 写入期限必须取消');
  h.timers.advance(PONG_TIMEOUT - 2);
  assert.deepEqual(h.closes, [], '未到 Pong deadline 不得关闭');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['ping-timeout'], 'flush 后只由 Pong deadline 判定');
});

test('业务写入进度顺延 queued 写入期限（未 flush、未 busy）', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  h.timers.advance(WRITE_STALL - 1);
  h.heartbeat.noteWriteProgress(); // socket 正在排水：queued 写入期限从当前时刻重新起算
  h.timers.advance(WRITE_STALL - 1);
  assert.deepEqual(h.closes, [], '可解释的业务进度必须顺延 queued 写入期限');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall'], '顺延后仍会到期关闭');
});

test('业务写入进度不顺延已启动的 Pong deadline', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  lastPing(h.socket).done(); // flushed：Pong deadline 从此刻起算
  h.timers.advance(PONG_TIMEOUT - 1);
  h.heartbeat.noteWriteProgress(); // 业务进度是对端独立时限之外的事件，不得顺延 Pong deadline
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['ping-timeout'], 'Pong deadline 不因业务进度顺延');
});

test('匹配 Pong 早于 flush：取消 queued 写入期限，迟到 flush 不得重启任何期限', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  const ping = lastPing(h.socket);
  h.heartbeat.notePong(ping.payload); // 早于 flush
  assert.equal(h.state().state, 'idle');
  ping.done(); // 迟到 flush
  h.timers.advance(WRITE_STALL * 2);
  assert.deepEqual(h.closes, [], 'queued 写入期限已随匹配 Pong 取消');
  h.timers.advance(PONG_TIMEOUT * 2);
  assert.deepEqual(h.closes, [], '迟到 flush 不得重启 Pong deadline');
});

test('Ping 发送同步失败与回调 error 都按 send-failed 关闭，且不启动 Pong deadline', () => {
  const syncFail = makeHarness();
  syncFail.socket.ping = () => { throw new Error('socket closing'); };
  syncFail.heartbeat.tick();
  assert.deepEqual(syncFail.closes, ['ping-send-failed']);
  assert.equal(syncFail.state().state, 'idle');

  const asyncFail = makeHarness();
  asyncFail.heartbeat.tick();
  lastPing(asyncFail.socket).done(new Error('write error'));
  assert.deepEqual(asyncFail.closes, ['ping-send-failed'], 'error 回调不是进度，按 send failure 关闭');
  asyncFail.timers.advance(PONG_TIMEOUT * 2);
  assert.deepEqual(asyncFail.closes, ['ping-send-failed'], '失败后不得再产生第二个关闭来源');
});

test('flush 回调 error：按 ping-send-failed 关闭并取消 queued 写入期限', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  h.timers.advance(WRITE_STALL - 1);
  lastPing(h.socket).done(new Error('write error'));
  assert.deepEqual(h.closes, ['ping-send-failed']);
  h.timers.advance(WRITE_STALL * 2 + PONG_TIMEOUT * 2);
  assert.deepEqual(h.closes, ['ping-send-failed'], '关闭后不得残留 queued 写入期限再关一次');
});

test('写停滞：busy 且本地无进度时按 WRITE_STALL_MS 关闭', () => {
  const h = makeHarness();
  h.heartbeat.markBusy();
  assert.equal(h.state().stallArmed, true);
  h.timers.advance(WRITE_STALL - 1);
  assert.deepEqual(h.closes, []);
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall']);
});

test('写停滞：可解释的本地进度重置期限；error 回调不算进度', () => {
  const h = makeHarness();
  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL - 1);
  h.heartbeat.noteWriteProgress();
  h.timers.advance(WRITE_STALL - 1);
  assert.deepEqual(h.closes, [], '成功本地写入进展必须重置写停滞期限');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall']);

  // error 回调不是进度：只 busy、不报告进度，直接从 busy 时刻到期。
  const errorOnly = makeHarness();
  errorOnly.heartbeat.markBusy();
  errorOnly.timers.advance(WRITE_STALL);
  assert.deepEqual(errorOnly.closes, ['write-stall'], 'error 不算进展，仍应到期');
});

test('busy->idle 清理期限，恢复 busy 后重新起算，不因旧计数立即误关', () => {
  const h = makeHarness();
  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL - 1);
  h.heartbeat.markIdle();
  assert.equal(h.state().stallArmed, false, 'idle 必须清理写停滞期限');
  h.timers.advance(WRITE_STALL * 10);
  assert.deepEqual(h.closes, [], 'idle 期间不得按写停滞关闭');

  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL - 1);
  assert.deepEqual(h.closes, [], '恢复 busy 必须从零重新起算');
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall']);
});

test('busy 期间重复 markBusy 不重置写停滞期限（只有 noteWriteProgress 能重置）', () => {
  const h = makeHarness();
  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL - 1);
  h.heartbeat.markBusy(); // 已在 busy：边沿触发语义下为 no-op，不得重新起算
  h.timers.advance(1);
  assert.deepEqual(h.closes, ['write-stall'], 'markBusy 只在 idle->busy 边沿起算');
});

test('markIdle 幂等：未 busy 或重复调用均无副作用', () => {
  const h = makeHarness();
  h.heartbeat.markIdle();
  h.heartbeat.markIdle();
  assert.equal(h.state().stallArmed, false);
  h.timers.advance(WRITE_STALL * 2);
  assert.deepEqual(h.closes, []);
  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL);
  assert.deepEqual(h.closes, ['write-stall']);
});

test('idle 时 noteWriteProgress 不启动写停滞期限', () => {
  const h = makeHarness();
  h.heartbeat.noteWriteProgress();
  assert.equal(h.state().stallArmed, false);
  h.timers.advance(WRITE_STALL * 2);
  assert.deepEqual(h.closes, []);
});

test('dispose 幂等、推进 generation，关闭后迟到回调与定时器全部 no-op', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  const ping = lastPing(h.socket);
  const generationBefore = h.state().generation;
  h.heartbeat.dispose();
  h.heartbeat.dispose();
  assert.equal(h.state().generation, generationBefore + 1, 'dispose 只推进一次 generation');
  assert.equal(h.state().state, 'idle');

  // 关闭后：迟到的 flush 回调、迟到的匹配 Pong、以及原先安排的定时器都不再产生行为。
  ping.done();
  h.heartbeat.notePong(ping.payload);
  h.heartbeat.markBusy();
  h.timers.advance(WRITE_STALL * 2);
  assert.deepEqual(h.closes, [], 'dispose 后不得触发任何 onClose');
  assert.equal(h.state().state, 'idle');
  assert.equal(h.state().stallArmed, false);
});

test('dispose 取消 queued 写入期限：迟到定时器回调 no-op', () => {
  const h = makeHarness();
  h.heartbeat.tick();
  h.timers.advance(WRITE_STALL - 1);
  h.heartbeat.dispose();
  h.timers.advance(WRITE_STALL * 2);
  assert.deepEqual(h.closes, [], 'dispose 后 queued 写入期限不得再触发关闭');
});

test('teardown 先于 onClose：调用方在 onClose 内可读取到已收敛的 snapshot', () => {
  const socket = new StubSocket();
  const timers = new FakeTimers();
  const closes: MuxHeartbeatCloseSource[] = [];
  const snapshotsAtClose: MuxHeartbeatSnapshot[] = [];
  const heartbeat = new MuxHeartbeat(socket, {
    pingIntervalMs: PING_INTERVAL,
    pongTimeoutMs: PONG_TIMEOUT,
    writeStallMs: WRITE_STALL,
    now: timers.now,
    schedule: timers.schedule,
    createNonce: () => Buffer.alloc(12, 1),
    onClose: (source) => {
      closes.push(source);
      snapshotsAtClose.push(heartbeat.snapshot()); // 回调内读取：不得抛错，且应是关闭后的状态
    },
  });
  const generationBefore = heartbeat.snapshot().generation;

  heartbeat.markBusy();
  timers.advance(WRITE_STALL);

  assert.deepEqual(closes, ['write-stall']);
  assert.equal(snapshotsAtClose.length, 1, 'onClose 恰好被调用一次');
  assert.deepEqual(
    [snapshotsAtClose[0].state, snapshotsAtClose[0].stallArmed, snapshotsAtClose[0].generation],
    ['idle', false, generationBefore + 1],
    'onClose 可见状态机已收敛且 generation 已推进的快照',
  );
});

test('onTick 同步 dispose：tick 必须复检 disposed，不得再登记 probe、发 Ping 或安排期限', () => {
  const socket = new StubSocket();
  const timers = new FakeTimers();
  const closes: MuxHeartbeatCloseSource[] = [];
  const heartbeat = new MuxHeartbeat(socket, {
    pingIntervalMs: PING_INTERVAL,
    pongTimeoutMs: PONG_TIMEOUT,
    writeStallMs: WRITE_STALL,
    now: timers.now,
    schedule: timers.schedule,
    createNonce: () => Buffer.alloc(12, 1),
    onClose: (source) => closes.push(source),
    // 附件回调在 tick 内同步关闭 carrier：teardown 清空 probe，但 socket.readyState 仍为 OPEN。
    onTick: () => heartbeat.dispose(),
  });

  heartbeat.tick();

  assert.equal(socket.pings.length, 0, 'onTick 内 dispose 后本 tick 不得再发 Ping');
  assert.equal(heartbeat.snapshot().state, 'idle', '不得登记新 probe');
  assert.equal(heartbeat.snapshot().stallArmed, false, '不得安排写停滞期限');
  // 若 beginProbe 仍执行，其 queued 写入期限会在此推进后触发关闭；复检后应无任何关闭。
  timers.advance(WRITE_STALL * 2);
  assert.deepEqual(closes, [], 'dispose 后不得因任何迟到期限触发 onClose');
  assert.equal(socket.pings.length, 0);
});

test('onClose 每实例至多一次：首个确定的关闭来源胜出', () => {
  const h = makeHarness();
  h.heartbeat.markBusy();
  h.heartbeat.tick();
  h.timers.advance(WRITE_STALL);
  // 写停滞先到期；随后 Pong deadline/再 tick 均不得追加关闭。
  h.timers.advance(PONG_TIMEOUT);
  h.heartbeat.tick();
  assert.deepEqual(h.closes, ['write-stall']);
});

test('socket 非 OPEN 时 tick 不发起探测', () => {
  const h = makeHarness({ readyState: 0 });
  h.heartbeat.tick();
  assert.equal(h.socket.pings.length, 0);
  h.socket.readyState = OPEN;
  h.heartbeat.tick();
  assert.equal(h.socket.pings.length, 1);
});

test('start() 按 pingIntervalMs 周期探测，匹配 Pong 后继续下一轮', () => {
  const h = makeHarness();
  h.heartbeat.start();
  h.heartbeat.start(); // 幂等：不得叠加两个周期
  h.timers.advance(PING_INTERVAL);
  assert.equal(h.socket.pings.length, 1);

  lastPing(h.socket).done();
  h.heartbeat.notePong(lastPing(h.socket).payload);
  h.timers.advance(PING_INTERVAL);
  assert.equal(h.socket.pings.length, 2, '确认后下一周期继续探测');

  h.heartbeat.dispose();
  h.timers.advance(PING_INTERVAL * 3);
  assert.equal(h.socket.pings.length, 2, 'dispose 后周期探测停止');
});
