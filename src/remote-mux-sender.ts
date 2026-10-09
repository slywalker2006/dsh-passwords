/**
 * Remote mux 单方向串行分片发送器（第一阶段：可测试核心）。
 *
 * `/api/remote.mux` 每条腿各持有一个本类实例。它只做一件事：**把一条业务文本消息
 * 还原成一条 WebSocket 文本消息**，同时把用户态写入积压压在可配置的高/低水位之内。
 * 它不知道也不构造任何协议级 JSON：分片只切 UTF-8 字节，接收端重组后仍是同一条文本消息。
 *
 * 关键契约：
 *  1. 一条业务文本消息 = 一条 WebSocket 文本消息。整条消息一次 `Buffer.from(text, 'utf8')`
 *     编码，按字节切分；首片 `fin:false`，末片 `fin:true`，中间片由 `ws` 生成 continuation
 *     opcode。UTF-8 字符可跨片，接收端仍还原为完整文本。`fragmentBytes=0` 时整条单帧
 *     `fin:true` 发送，不等待排水。
 *  2. 同方向同一 socket 上**最多一条未完成消息**。消息严格 FIFO；分片绝不交错。
 *  3. 每次只提交一片，**等这一片的本地写入回调**才提交下一片。回调带 error 视为本地写入
 *     失败，进入 carrier 失败路径，绝不静默丢弃。
 *  4. 三种独立预算分别记账：单条消息 `maxMessageBytes`（100 MiB）、已接受但未完成写入的
 *     完整消息总量 `acceptBudgetBytes`（102 MiB）、等待发送的队列深度 `maxQueueMessages` /
 *     `maxQueueBytes`。**一条业务消息按完整 UTF-8 字节数只在被接受时计费一次**，直到末片
 *     成功回调后才一次性扣减——绝不按片计费。
 *  5. `cancel(tag)` 只删除**尚未开始发送**的同 tag 队列项并退回其计费；正在分片的消息不受
 *     影响，必须发到 FIN。返回的 `started` 告知调用方该 tag 是否有已开始的消息，以便把该流的
 *     cancel 排在当前 FIN 之后。
 *  6. `dispose()` 幂等：停止接收、清理排水计时器与在途等待、推进 generation，此后任何迟到
 *     回调都是 no-op，不会继续写入也不会重复扣账。
 *
 * 心跳协作：`onBusy`/`onIdle` 在「存在已接受未写完数据」的边沿触发（幂等，不重复触发），
 * `onProgress` 在每次**成功的分片本地写入回调**、以及排水轮询**实测 `bufferedAmount` 下降**
 * 时触发——这三者正是 `MuxHeartbeat` 判定写停滞所需的输入。`onProgress` 只在确有进展时触发：
 *「水位未下降」不构成 stall 判据，本模块从不据此判定或关闭。`onFailure` 在 carrier 级发送失败
 * 时触发一次，调用方据此关闭两腿。
 *
 * 所有数值均为必填配置契约：模块按原值使用，不做范围校验、不做默认兜底，非法取值由 config
 * 层保证。timer 走注入的调度面，生产与测试分别使用真实/受控实现。
 */
import type { MuxTimerSchedule } from './remote-mux-heartbeat.js';

/** WebSocket.OPEN；本模块不依赖 ws，故本地保留常量（与 proxy.ts 的 MUX_SOCKET_OPEN 同源）。 */
const MUX_SOCKET_OPEN = 1;

/** 分片发送选项：文本帧（`binary:false`）＋ 是否为消息末片（`fin`）。 */
export type MuxFragmentSendOptions = {
  readonly binary: false;
  readonly fin: boolean;
};

/** Sender 所需的最小 socket 面（生产为 ws 连接，测试为 stub）。 */
export type MuxFragmentSocket = {
  readonly readyState: number;
  readonly bufferedAmount: number;
  /**
   * 写出一个文本分片。`onFlush` 在该片的**本地写入完成**后回调：成功即一次可解释的本地
   * 写入进度；带 error 表示本地写入失败，不是进度，进入 carrier 失败路径。
   */
  send(data: Buffer, options: MuxFragmentSendOptions, onFlush?: (error?: Error) => void): void;
};

/** `enqueue` 的接受结果；`accepted` 只表示已接受排队，不表示已送达。 */
export type MuxAcceptOutcome = 'accepted' | 'oversized' | 'overflow' | 'queue-full' | 'closed';

/** 用于网关关闭诊断的精确拒绝类别；不包含消息正文或标签。 */
export type MuxRejectKind = 'message-bytes' | 'accepted-bytes' | 'queue-count' | 'queue-bytes';

/** 进程级 Remote mux 接受字节预算；多个 carrier 共享，避免每条连接独立上界叠加成不可控 RSS。 */
export class MuxSenderBudget {
  private reservedBytes = 0;

  constructor(readonly maxBytes: number) {}

  tryReserve(bytes: number): boolean {
    if (this.reservedBytes + bytes > this.maxBytes) return false;
    this.reservedBytes += bytes;
    return true;
  }

  release(bytes: number): void {
    this.reservedBytes -= bytes;
    if (this.reservedBytes < 0) this.reservedBytes = 0;
  }

  snapshot(): number {
    return this.reservedBytes;
  }
}

/**
 * 构造所需的容量、水位与回调。数值均为必填配置契约，模块按原值使用、不做默认兜底。
 */
export interface MuxSenderOptions {
  /** 分片字节数；`0` 表示单帧模式（不切分、不等待排水）。 */
  readonly fragmentBytes: number;
  /** 提交下一片前若 `bufferedAmount` 超过此值，则等待排水（仅分片模式）。 */
  readonly highWaterBytes: number;
  /** 排水等待的下限：`bufferedAmount` 降到不超过此值后继续提交。 */
  readonly lowWaterBytes: number;
  /** 单条消息的最大 UTF-8 字节数；超过则拒绝为 `oversized`。 */
  readonly maxMessageBytes: number;
  /** 已接受但未完成本地写入的完整消息总量上限；超过则拒绝为 `overflow`。 */
  readonly acceptBudgetBytes: number;
  /** 等待发送的队列条目上限；超过则拒绝为 `queue-full`。 */
  readonly maxQueueMessages: number;
  /** 等待发送的队列字节上限；超过则拒绝为 `queue-full`。 */
  readonly maxQueueBytes: number;
  /** 排水轮询间隔（毫秒）；仅分片模式使用。 */
  readonly drainPollIntervalMs: number;
  /** idle→busy 边沿：存在已接受未写完数据时触发一次（幂等）。 */
  readonly onBusy?: () => void;
  /** busy→idle 边沿：已接受数据全部写完、队列清空时触发一次（幂等）。 */
  readonly onIdle?: () => void;
  /** 成功的分片本地写入回调，或排水轮询实测到 `bufferedAmount` 下降时触发（可解释的本地写入进度，非 error 回调）。 */
  readonly onProgress?: () => void;
  /** carrier 级发送失败（sync 抛错 / 回调 error / socket 非 OPEN）时触发一次。 */
  readonly onFailure?: (error?: Error) => void;
  /** 记录最近一次容量拒绝；只提供类别和消息字节数，不提供正文。 */
  readonly onReject?: (kind: MuxRejectKind, messageBytes: number) => void;
  /** 可选进程级接受预算；消息从接受到完成写入期间持有预留。 */
  readonly sharedBudget?: MuxSenderBudget;
  /** 调度面；默认基于 `setTimeout`/`clearTimeout` 并 unref。 */
  readonly schedule?: MuxTimerSchedule;
}

/** `enqueue` 的可选元数据。`tag` 为不透明标签，仅用于 `cancel` 定位，不参与协议解析。 */
export interface MuxEnqueueOptions {
  readonly tag?: string;
}

/** `cancel` 的结果：删除的未开始消息与字节数，以及该 tag 是否已有消息开始发送。 */
export interface MuxCancelResult {
  readonly removedMessages: number;
  readonly removedBytes: number;
  /** 该 tag 有消息正在分片：它必须发到 FIN，调用方应把该流 cancel 排在其后。 */
  readonly started: boolean;
}

/** 供测试与诊断读取的只读快照。 */
export interface MuxSenderSnapshot {
  readonly disposed: boolean;
  readonly busy: boolean;
  readonly queuedMessages: number;
  readonly queuedBytes: number;
  /** 已接受但尚未完成本地写入的完整消息字节总数（含在途消息）。 */
  readonly acceptedBytes: number;
  readonly inFlight: boolean;
  readonly fragmentOffset: number;
  readonly awaitingFlush: boolean;
  readonly draining: boolean;
  readonly bufferedAmount: number;
  readonly generation: number;
}

/** 一条已接受的消息；`generation` 用于回调的身份校验，避免迟到回调影响新状态。 */
type MuxItem = {
  readonly generation: number;
  readonly tag: string | null;
  readonly bytes: Buffer;
};

const defaultSchedule: MuxTimerSchedule = (callback, delayMs) => {
  const timer = setTimeout(callback, delayMs);
  timer.unref();
  return () => clearTimeout(timer);
};

export class MuxSender {
  private readonly socket: MuxFragmentSocket;
  private readonly fragmentBytes: number;
  private readonly highWaterBytes: number;
  private readonly lowWaterBytes: number;
  private readonly maxMessageBytes: number;
  private readonly acceptBudgetBytes: number;
  private readonly maxQueueMessages: number;
  private readonly maxQueueBytes: number;
  private readonly drainPollIntervalMs: number;
  private readonly onBusy: () => void;
  private readonly onIdle: () => void;
  private readonly onProgress: () => void;
  private readonly onFailure: (error?: Error) => void;
  private readonly onReject: (kind: MuxRejectKind, messageBytes: number) => void;
  private readonly sharedBudget: MuxSenderBudget | null;
  private readonly schedule: MuxTimerSchedule;

  private generation = 0;
  private disposed = false;
  private busy = false;

  private queue: MuxItem[] = [];
  private queueBytes = 0;
  private acceptedBytes = 0;

  private current: MuxItem | null = null;
  private fragmentOffset = 0;
  private awaitingFlush = false;
  private drainCancel: (() => void) | null = null;
  /** 排水轮询上一次观测到的 `bufferedAmount`；仅用于识别「实测下降」这一进展信号。 */
  private drainLastBuffered: number | null = null;

  constructor(socket: MuxFragmentSocket, options: MuxSenderOptions) {
    this.socket = socket;
    this.fragmentBytes = options.fragmentBytes;
    this.highWaterBytes = options.highWaterBytes;
    this.lowWaterBytes = options.lowWaterBytes;
    this.maxMessageBytes = options.maxMessageBytes;
    this.acceptBudgetBytes = options.acceptBudgetBytes;
    this.maxQueueMessages = options.maxQueueMessages;
    this.maxQueueBytes = options.maxQueueBytes;
    this.drainPollIntervalMs = options.drainPollIntervalMs;
    this.onBusy = options.onBusy ?? (() => {});
    this.onIdle = options.onIdle ?? (() => {});
    this.onProgress = options.onProgress ?? (() => {});
    this.onFailure = options.onFailure ?? (() => {});
    this.onReject = options.onReject ?? (() => {});
    this.sharedBudget = options.sharedBudget ?? null;
    this.schedule = options.schedule ?? defaultSchedule;
  }

  /**
   * 接受一条业务文本消息并排队发送。同步完成容量校验与一次计费，不表示已送达。
   * 被接受的消息按完整 UTF-8 字节数计入 `acceptedMessageBytes`，直到末片成功回调后一次扣减。
   */
  enqueue(text: string, options: MuxEnqueueOptions = {}): MuxAcceptOutcome {
    if (this.disposed) return 'closed';
    const size = Buffer.byteLength(text, 'utf8');
    if (size > this.maxMessageBytes) {
      this.onReject('message-bytes', size);
      return 'oversized';
    }
    if (this.acceptedBytes + size > this.acceptBudgetBytes) {
      this.onReject('accepted-bytes', size);
      return 'overflow';
    }
    // 队列条数/字节只约束**等待**的消息：能立即开始发送的消息不占等待队列，不受队列上限。
    if (this.current !== null) {
      if (this.queue.length + 1 > this.maxQueueMessages) {
        this.onReject('queue-count', size);
        return 'queue-full';
      }
      if (this.queueBytes + size > this.maxQueueBytes) {
        this.onReject('queue-bytes', size);
        return 'queue-full';
      }
    }

    if (this.sharedBudget !== null && !this.sharedBudget.tryReserve(size)) {
      this.onReject('accepted-bytes', size);
      return 'overflow';
    }
    // 只有通过全部护栏后才保留消息副本；拒绝路径不会先分配完整 Buffer。
    let bytes: Buffer;
    try {
      bytes = Buffer.from(text, 'utf8');
    } catch (error) {
      this.sharedBudget?.release(size);
      throw error;
    }
    const item: MuxItem = { generation: this.generation, tag: options.tag ?? null, bytes };
    this.queue.push(item);
    this.queueBytes += size;
    this.acceptedBytes += size;
    this.refreshBusy();
    this.pump();
    return 'accepted';
  }

  /**
   * 删除该 tag 所有**尚未开始发送**的队列项并退回计费。正在分片的消息不受影响；返回的
   * `started` 告知调用方该 tag 是否已有消息开始发送（必须发到 FIN 后再发 cancel）。
   */
  cancel(tag: string): MuxCancelResult {
    if (this.disposed) return { removedMessages: 0, removedBytes: 0, started: false };
    const kept: MuxItem[] = [];
    let removedMessages = 0;
    let removedBytes = 0;
    for (const item of this.queue) {
      if (item.tag === tag) {
        removedMessages += 1;
        removedBytes += item.bytes.byteLength;
      } else {
        kept.push(item);
      }
    }
    this.queue = kept;
    this.queueBytes -= removedBytes;
    this.acceptedBytes -= removedBytes;
    this.sharedBudget?.release(removedBytes);
    this.refreshBusy();
    return {
      removedMessages,
      removedBytes,
      started: this.current !== null && this.current.tag === tag,
    };
  }

  /** 停止接收、清理排水计时器与在途等待、推进 generation。幂等；此后迟到回调全部 no-op。 */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.generation += 1;
    this.sharedBudget?.release(this.acceptedBytes);
    if (this.drainCancel !== null) {
      this.drainCancel();
      this.drainCancel = null;
    }
    this.queue = [];
    this.queueBytes = 0;
    this.acceptedBytes = 0;
    this.current = null;
    this.fragmentOffset = 0;
    this.awaitingFlush = false;
    this.drainLastBuffered = null;
    this.busy = false;
  }

  /** 只读快照，供测试断言与结构化关闭日志使用。 */
  snapshot(): MuxSenderSnapshot {
    return {
      disposed: this.disposed,
      busy: this.busy,
      queuedMessages: this.queue.length,
      queuedBytes: this.queueBytes,
      acceptedBytes: this.acceptedBytes,
      inFlight: this.current !== null,
      fragmentOffset: this.fragmentOffset,
      awaitingFlush: this.awaitingFlush,
      draining: this.drainCancel !== null,
      bufferedAmount: this.socket.bufferedAmount,
      generation: this.generation,
    };
  }

  /** 推进发送：取队首为在途消息（若尚无），或提交当前消息的下一片。 */
  private pump(): void {
    if (this.disposed) return;
    if (this.awaitingFlush || this.drainCancel !== null) return;
    if (this.current === null) {
      const next = this.queue.shift();
      if (next === undefined) return;
      this.queueBytes -= next.bytes.byteLength;
      this.current = next;
      this.fragmentOffset = 0;
    }
    this.submitFragment();
  }

  /** 计算并提交当前消息的下一个分片；单帧模式提交整条消息。 */
  private submitFragment(): void {
    const message = this.current;
    if (message === null) return;
    const total = message.bytes.byteLength;
    if (this.fragmentBytes <= 0) {
      this.commit(message, message.bytes, true);
      return;
    }
    const offset = this.fragmentOffset;
    const end = Math.min(offset + this.fragmentBytes, total);
    this.commit(message, message.bytes.subarray(offset, end), end >= total);
  }

  /** 提交一片：先过水位闸门，再写出并等待这一片的本地写入回调。 */
  private commit(message: MuxItem, chunk: Buffer, isLast: boolean): void {
    // 单帧模式不做排水等待（fragmentBytes=0 只关闭分片与排水）。
    if (this.fragmentBytes > 0) {
      const buffered = this.socket.bufferedAmount;
      if (buffered > this.highWaterBytes) {
        // 记下进入排水时的水位，排水轮询据此识别「实测下降」这一可解释的本地写入进展。
        this.drainLastBuffered = buffered;
        this.awaitDrain();
        return;
      }
    }
    if (this.socket.readyState !== MUX_SOCKET_OPEN) {
      this.fail();
      return;
    }
    this.awaitingFlush = true;
    try {
      this.socket.send(chunk, { binary: false, fin: isLast }, (error) => this.onFlush(message, chunk, isLast, error));
    } catch (error) {
      this.awaitingFlush = false;
      this.fail(error instanceof Error ? error : undefined);
    }
  }

  /** 一片的本地写入完成回调：校验身份后推进进度或进入 carrier 失败路径。 */
  private onFlush(message: MuxItem, chunk: Buffer, isLast: boolean, error?: Error): void {
    if (this.disposed || this.current !== message || message.generation !== this.generation) return;
    this.awaitingFlush = false;
    if (error != null) {
      this.fail(error);
      return;
    }
    this.onProgress();
    if (isLast) {
      this.current = null;
      this.fragmentOffset = 0;
      this.acceptedBytes -= message.bytes.byteLength;
      this.sharedBudget?.release(message.bytes.byteLength);
      this.refreshBusy();
    } else {
      this.fragmentOffset += chunk.byteLength;
    }
    this.pump();
  }

  /**
   * 水位超 HIGH：每 `drainPollIntervalMs` 轮询到 `bufferedAmount <= LOW` 后继续。
   *
   * 每次轮询比较观测到的 `bufferedAmount`：**实测下降**代表本地写入确有进展，据此上报一次
   * `onProgress` 以重置心跳的写停滞期限。未下降时不伪造进度，也绝不在此判定 stall——停滞超时
   * 由心跳独立的 write-stall deadline 负责，本模块只提供真实进展信号。
   */
  private awaitDrain(): void {
    this.drainCancel = this.schedule(() => {
      this.drainCancel = null;
      if (this.disposed) return;
      if (this.socket.readyState !== MUX_SOCKET_OPEN) {
        this.fail();
        return;
      }
      const buffered = this.socket.bufferedAmount;
      if (this.drainLastBuffered !== null && buffered < this.drainLastBuffered) this.onProgress();
      this.drainLastBuffered = buffered;
      if (buffered <= this.lowWaterBytes) {
        this.drainLastBuffered = null;
        this.pump();
        return;
      }
      this.awaitDrain();
    }, this.drainPollIntervalMs);
  }

  /** busy/idle 边沿：`acceptedBytes` 是否大于零即「存在已接受未写完数据」。 */
  private refreshBusy(): void {
    const active = this.acceptedBytes > 0;
    if (active && !this.busy) {
      this.busy = true;
      this.onBusy();
    } else if (!active && this.busy) {
      this.busy = false;
      this.onIdle();
    }
  }

  /** carrier 级失败：先收敛状态（使迟到回调 no-op），再通知调用方一次。 */
  private fail(error?: Error): void {
    if (this.disposed) return;
    this.dispose();
    this.onFailure(error);
  }
}
