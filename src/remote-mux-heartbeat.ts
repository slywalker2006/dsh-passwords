/**
 * Remote mux 单方向心跳与写停滞状态机。
 *
 * `/api/remote.mux` carrier 由浏览器腿和上游腿两条独立方向组成，每条腿各持有一个本类
 * 实例。它只做四件事，且都不依赖 `ws`：
 *
 *  1. 保活探测：每方向至多一条未决 Ping probe `{ nonce, queuedAt, flushedAt, deadline }`。
 *     `tick()` 只在没有未决 probe 时登记新 probe，且**先登记状态再调用 `socket.ping()`**，
 *     使匹配 Pong 与迟到回调都能按 probe 对象身份判定，避免“回调早于状态”的竞态。
 *  2. Pong 期限：只有在 Ping 本地写入完成（flushed）后才启动该 probe 独立的 Pong
 *     deadline。到期仍未收到逐字节匹配的 Pong 即判该腿失活；无关、迟到、重复的 Pong
 *     都不清除当前 probe。Pong 期限不依赖下一次 tick 才检查。
 *  3. queued 写入期限：probe 登记后即用 `writeStallMs` 起算独立期限，覆盖“Ping 本地写入
 *     回调始终不触发、又未进入 busy 写停滞”的盲区；flush 成功即交接给该 probe 的 Pong
 *     deadline，匹配 Pong / error / dispose 都会取消它。它是与 busy 写停滞**独立**的触发
 *     条件：由 beginProbe 起算而非 idle→busy 边沿，markIdle 不清除它。可解释的业务写入
 *     进度顺延该期限，但不顺延 Pong deadline。
 *  4. 写停滞：只依据调用方给出的**可解释本地进度回调**（分片整帧成功写回调，或实测
 *     `bufferedAmount` 下降）重置期限。本模块从不采样 `bufferedAmount`，也不把“水位不
 *     下降”当作停顿的唯一判据；error 回调不是进度。idle 时清理期限，下次 busy 重新起算。
 *
 * 所有时长走注入的单调时钟与调度面。`dispose()` 幂等并推进 generation，关闭之后任何
 * 迟到回调都成为 no-op。生产 socket 与测试 stub 都按最小面 `MuxHeartbeatSocket` 传入；
 * `ws` 连接的适配只有一行：`{ readyState: ws.readyState, ping: (p, done) => ws.ping(p, true, done) }`。
 */
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

/** WebSocket.OPEN；本模块不依赖 ws，故本地保留常量（与 proxy.ts 的 MUX_SOCKET_OPEN 同源）。 */
const MUX_SOCKET_OPEN = 1;

/** 单方向探测/写停滞判定的关闭来源，供调用方以 allowlist 记录诊断。 */
export type MuxHeartbeatCloseSource = 'ping-timeout' | 'ping-send-failed' | 'write-stall';

/** 单调时钟（毫秒）；默认 `performance.now()`，调用方不得用 `Date.now()`。 */
export type MonotonicClock = () => number;

/** 调度面：安排一次回调并返回取消函数。默认基于 `setTimeout`/`clearTimeout` 并 unref。 */
export type MuxTimerSchedule = (callback: () => void, delayMs: number) => () => void;

/** 单方向 socket 的最小面：只需发送心跳 Ping。 */
export type MuxHeartbeatSocket = {
  readonly readyState: number;
  /** 发送 Ping；`payload` 为 probe nonce，`done` 在本地写入完成后回调（error 表示发送失败）。 */
  ping(payload: Buffer, done: (error?: Error) => void): void;
};

/**
 * 构造所需的时长与回调。三个时长均为必填配置契约：模块按原值使用，不做范围校验、
 * 不做默认兜底，非法取值由调用方在 config 层保证。
 */
export interface MuxHeartbeatOptions {
  /** 保活探测间隔；仅在 `start()` 拥有周期时使用，`tick()` 本身不看它。 */
  readonly pingIntervalMs: number;
  /** Ping 本地提交后等待 nonce 匹配 Pong 的时限。 */
  readonly pongTimeoutMs: number;
  /** busy 写停滞与「probe 已登记但本地写入回调尚未触发」的 queued 写入期限共用的时限。 */
  readonly writeStallMs: number;
  /** 探测超时/发送失败/写停滞时通知调用方关闭该 carrier（每实例至多一次）。 */
  readonly onClose: (source: MuxHeartbeatCloseSource) => void;
  readonly now?: MonotonicClock;
  readonly schedule?: MuxTimerSchedule;
  /** nonce 生成器；默认 12 字节随机，测试可确定性注入。 */
  readonly createNonce?: () => Buffer;
  /** 每次 tick 的附加回调（例如收敛延迟会话流）；不参与 deadline 判定。 */
  readonly onTick?: () => void;
}

/** 未决 probe 已推进到的阶段：idle 无 probe，queued 已登记，flushed 本地写入已完成。 */
export type MuxHeartbeatState = 'idle' | 'queued' | 'flushed';

/** 供测试与关闭诊断读取的只读快照。 */
export type MuxHeartbeatSnapshot = {
  readonly state: MuxHeartbeatState;
  readonly generation: number;
  readonly queuedAt: number | null;
  readonly flushedAt: number | null;
  /** 最近一次 nonce 匹配 Pong 的单调时刻；尚无匹配时为 null。 */
  readonly lastPongAt: number | null;
  readonly stallArmed: boolean;
};

/** 一条未决 Ping probe；回调一律以对象身份 + generation 校验，替代任何计数窗口。 */
type Probe = {
  readonly generation: number;
  readonly nonce: Buffer;
  readonly queuedAt: number;
  flushedAt: number | null;
  cancelDeadline: (() => void) | null;
};

const defaultSchedule: MuxTimerSchedule = (callback, delayMs) => {
  const timer = setTimeout(callback, delayMs);
  timer.unref();
  return () => clearTimeout(timer);
};

export class MuxHeartbeat {
  private readonly socket: MuxHeartbeatSocket;
  private readonly pingIntervalMs: number;
  private readonly pongTimeoutMs: number;
  private readonly writeStallMs: number;
  private readonly onClose: (source: MuxHeartbeatCloseSource) => void;
  private readonly now: MonotonicClock;
  private readonly schedule: MuxTimerSchedule;
  private readonly createNonce: () => Buffer;
  private readonly onTick: () => void;

  private generation = 0;
  private disposed = false;
  private probe: Probe | null = null;
  private lastPongAt: number | null = null;
  private cancelInterval: (() => void) | null = null;
  private stallCancel: (() => void) | null = null;
  private probeWriteCancel: (() => void) | null = null;
  private busy = false;

  constructor(socket: MuxHeartbeatSocket, options: MuxHeartbeatOptions) {
    this.socket = socket;
    this.pingIntervalMs = options.pingIntervalMs;
    this.pongTimeoutMs = options.pongTimeoutMs;
    this.writeStallMs = options.writeStallMs;
    this.onClose = options.onClose;
    this.now = options.now ?? (() => performance.now());
    this.schedule = options.schedule ?? defaultSchedule;
    this.createNonce = options.createNonce ?? (() => randomBytes(12));
    this.onTick = options.onTick ?? (() => {});
  }

  /** 启动周期探测。幂等；每个周期只调用 `tick()`，deadline 由各自的定时器负责。 */
  start(): void {
    if (this.disposed || this.cancelInterval !== null) return;
    this.armInterval();
  }

  /**
   * 单次心跳 tick：执行附加回调，并在没有未决 probe 且 socket 可写时登记一个新探测。
   * 有未决 probe 时绝不重复发起（每方向至多一条）。
   *
   * `onTick()` 可能同步 `dispose()`（例如收敛延迟会话流时直接关闭 carrier），因此回调返回后
   * 必须重新检查 `disposed`：teardown 会把 probe 置空但不会改 socket.readyState，若不复检，
   * 已关闭的实例仍会在此登记 probe、安排期限并发出一条 Ping。
   */
  tick(): void {
    if (this.disposed) return;
    this.onTick();
    if (this.disposed) return;
    if (this.probe !== null) return;
    if (this.socket.readyState !== MUX_SOCKET_OPEN) return;
    this.beginProbe();
  }

  /**
   * `socket` 的 'pong' 事件入口。只有 payload 与当前 probe nonce 逐字节相同的 Pong 才
   * 确认并清除 probe；无关、迟到、重复 Pong 一律忽略，不清除当前 probe。匹配 Pong 若
   * 早于本地发送回调到达，同样立即确认；随后到达的回调会因 probe 已清除而成为 no-op。
   */
  notePong(payload: Buffer): void {
    if (this.disposed) return;
    const probe = this.probe;
    if (probe === null) return;
    if (!payload.equals(probe.nonce)) return;
    if (probe.cancelDeadline !== null) probe.cancelDeadline();
    this.cancelProbeWriteDeadline();
    this.probe = null;
    this.lastPongAt = this.now();
  }

  /**
   * 进入 busy（存在已接受但尚未完成本地写入的数据）：从当前时刻起算写停滞期限。
   * 边沿触发——已在 busy 时重复调用为 no-op，不会重置期限；新的写入进度请用
   * `noteWriteProgress()` 上报，避免“不停排队即可无限推迟关闭”。
   */
  markBusy(): void {
    if (this.disposed || this.busy) return;
    this.busy = true;
    this.armStall();
  }

  /**
   * 回到 idle（无待写数据且本地缓冲归零）：清理写停滞期限，下次 busy 从零重新起算。
   * 幂等；未 busy 时调用无副作用。
   */
  markIdle(): void {
    if (this.disposed) return;
    this.busy = false;
    if (this.stallCancel !== null) {
      this.stallCancel();
      this.stallCancel = null;
    }
  }

  /**
   * 报告一次可解释的本地写入进度：成功写回调，或调用方实测到的 `bufferedAmount` 下降。
   * busy 时重置写停滞期限；存在尚未 flush 的 probe 时同时顺延其 queued 写入期限——socket
   * 正在排水，排在前面的数据之后只是还没轮到 Ping 写出。但已启动的 Pong deadline 是对端
   * 响应的独立时限，**绝不**被进度顺延。调用方不得用“水位没有下降”代替真正的进度事件，也
   * 不得在 error 回调里调用本方法——error 不是进度，应按各自 send failure 路径处理。
   */
  noteWriteProgress(): void {
    if (this.disposed) return;
    const probe = this.probe;
    if (probe !== null && probe.flushedAt === null) this.armProbeWriteDeadline(probe);
    if (this.busy) this.armStall();
  }

  /** 关闭或 carrier 回收：停止所有计时、推进 generation，使迟到回调成为 no-op。幂等。 */
  dispose(): void {
    this.teardown();
  }

  /** 只读快照，供测试断言与结构化关闭日志使用。 */
  snapshot(): MuxHeartbeatSnapshot {
    const probe = this.probe;
    return {
      state: probe === null ? 'idle' : probe.flushedAt === null ? 'queued' : 'flushed',
      generation: this.generation,
      queuedAt: probe?.queuedAt ?? null,
      flushedAt: probe?.flushedAt ?? null,
      lastPongAt: this.lastPongAt,
      stallArmed: this.stallCancel !== null,
    };
  }

  private armInterval(): void {
    this.cancelInterval = this.schedule(() => {
      this.cancelInterval = null;
      this.tick();
      if (!this.disposed) this.armInterval();
    }, this.pingIntervalMs);
  }

  private beginProbe(): void {
    const probe: Probe = {
      generation: this.generation,
      nonce: this.createNonce(),
      queuedAt: this.now(),
      flushedAt: null,
      cancelDeadline: null,
    };
    // 先登记再发 Ping：匹配 Pong 或迟到回调都按 probe 身份判定，避免回调先于状态。
    this.probe = probe;
    // queued 写入期限与 busy 写停滞是两个独立触发条件：本期限自 beginProbe 起算，
    // 即使调用方从未进入 busy 也有看护；flush 成功后交给 Pong deadline。
    this.armProbeWriteDeadline(probe);
    try {
      this.socket.ping(probe.nonce, (error) => this.onPingFlushed(probe, error));
    } catch {
      this.fail('ping-send-failed');
    }
  }

  private onPingFlushed(probe: Probe, error?: Error): void {
    // 身份校验同时覆盖“匹配 Pong 先于本地发送回调”：此时 probe 已被置空，迟到回调在此直接
    // 返回，绝不会为该 probe 补挂一条 Pong deadline（即不会重新启动期限）。
    if (this.disposed || this.probe !== probe || probe.generation !== this.generation) return;
    if (error !== undefined) {
      // Ping 本地写入失败：立即按 send failure 关闭，不当作进度，也不启动 Pong deadline。
      this.fail('ping-send-failed');
      return;
    }
    probe.flushedAt = this.now();
    // flush 成功即交接：取消 queued 写入期限，改由该 probe 的 Pong deadline 计时，两者不重叠。
    this.cancelProbeWriteDeadline();
    probe.cancelDeadline = this.schedule(() => this.onPongTimeout(probe), this.pongTimeoutMs);
  }

  private onPongTimeout(probe: Probe): void {
    if (this.disposed || this.probe !== probe || probe.generation !== this.generation) return;
    this.fail('ping-timeout');
  }

  private armStall(): void {
    if (this.stallCancel !== null) this.stallCancel();
    this.stallCancel = this.schedule(() => this.onStallTimeout(), this.writeStallMs);
  }

  private onStallTimeout(): void {
    if (this.disposed || !this.busy) return;
    this.fail('write-stall');
  }

  private armProbeWriteDeadline(probe: Probe): void {
    if (this.probeWriteCancel !== null) this.probeWriteCancel();
    this.probeWriteCancel = this.schedule(() => this.onProbeWriteTimeout(probe), this.writeStallMs);
  }

  private cancelProbeWriteDeadline(): void {
    if (this.probeWriteCancel !== null) {
      this.probeWriteCancel();
      this.probeWriteCancel = null;
    }
  }

  private onProbeWriteTimeout(probe: Probe): void {
    // 身份 + generation 校验：flush / 匹配 Pong 都会取消本期限；迟到回调在此成为 no-op。
    if (this.disposed || this.probe !== probe || probe.generation !== this.generation) return;
    this.fail('write-stall');
  }

  private fail(source: MuxHeartbeatCloseSource): void {
    if (this.disposed) return;
    // 先 teardown 再通知：状态在此收敛并推进 generation，使 onClose 内读取的 snapshot()
    // 反映关闭后的确定状态，同时让随后任何迟到回调成为 no-op（顺序不可颠倒）。
    this.teardown();
    this.onClose(source);
  }

  private teardown(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    this.busy = false;
    if (this.cancelInterval !== null) {
      this.cancelInterval();
      this.cancelInterval = null;
    }
    if (this.stallCancel !== null) {
      this.stallCancel();
      this.stallCancel = null;
    }
    const probe = this.probe;
    this.probe = null;
    if (probe !== null && probe.cancelDeadline !== null) probe.cancelDeadline();
    this.cancelProbeWriteDeadline();
  }
}
