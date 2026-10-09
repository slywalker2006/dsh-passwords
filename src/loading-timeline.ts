/**
 * 加载时间线观测（《dsh-mux-heartbeat-review-and-loading-plan》第 139–150 节）。
 *
 * 这是一个**纯观测**模块：它只把固定的 stage 常量与数值/布尔字段写进记录，任何运行期
 * 字符串（响应正文、Cookie、JWT、`Authorization`、完整 URL/query）在类型层面就无法进入
 * 记录；`mark()` 入口再对 stage 做一次运行期白名单校验，即便调用方用类型断言塞进任意
 * 字符串，也只会被丢弃。它不改变任何业务协议：默认关闭时所有入口都是零记录、零输出。
 *
 * 需要区分的阶段：
 *   · 上游快照准备               `mux.upstream.snapshot.prepare`
 *   · baseline 等待              `baseline.wait`
 *   · 首个完整 item              `mux.session.follow.firstItem`
 *   · 终端首输出                 `mux.terminal.follow.firstOutput`
 *   · 网关同步处理分段           `gateway.{history,page}.{parse,filter,stringify}`
 *   · 输入/输出字节、记录数       数值字段 `bytesIn` / `bytesOut` / `records` / `count`
 *   · 事件循环延迟               `gateway.eventLoop.delay`
 *   · HTTP 整段缓冲 / mux 共享连接  `http.{history,page}.*` / `mux.history.inFlightAtTerminalOutput`
 *
 * 默认关闭：`LoadingTimeline` 未显式传入 `enabled` 时跟随环境变量 `DSH_LOADING_TIMELINE`
 * （动态读取：测试可在运行期开启共享实例以验证生产埋点）。关闭时：
 *   · `mark()` / `elapsed()` 直接返回；
 *   · `begin()` 返回哨兵 0，调用方无需分支；
 *   · `spanSync()` / `spanAsync()` 直接执行被观测函数，不加计时、不观测。
 */
import { monitorEventLoopDelay, performance } from 'node:perf_hooks';

/** 固定的 stage 常量：记录里只可能出现这些名字，绝不含任何运行期字符串。 */
export const LOADING_TIMELINE_STAGES = [
  'mux.carrier.open',
  'mux.upstream.snapshot.prepare',
  'mux.session.follow.firstItem',
  'mux.terminal.follow.firstOutput',
  'mux.history.inFlightAtTerminalOutput',
  'baseline.wait',
  'http.history.firstByte',
  'http.history.complete',
  'http.page.firstByte',
  'http.page.complete',
  'gateway.history.parse',
  'gateway.history.filter',
  'gateway.history.stringify',
  'gateway.page.parse',
  'gateway.page.filter',
  'gateway.page.stringify',
  'gateway.eventLoop.delay',
] as const;
export type LoadingTimelineStage = (typeof LOADING_TIMELINE_STAGES)[number];

const STAGE_SET: ReadonlySet<string> = new Set(LOADING_TIMELINE_STAGES);

/** 允许进入记录的数值字段（发生时取整到 0.01）。 */
export const LOADING_TIMELINE_NUMERIC_FIELDS = [
  'elapsedMs',
  'bytesIn',
  'bytesOut',
  'records',
  'count',
  'eventLoopDelayMs',
  'eventLoopDelayMaxMs',
] as const;
/** 允许进入记录的布尔字段。 */
export const LOADING_TIMELINE_BOOLEAN_FIELDS = ['ok', 'historyInFlight'] as const;

export type LoadingTimelineNumericField = (typeof LOADING_TIMELINE_NUMERIC_FIELDS)[number];
export type LoadingTimelineBooleanField = (typeof LOADING_TIMELINE_BOOLEAN_FIELDS)[number];

/** 调用方只能提交白名单字段；未知字段（url/cookie/body 等）在运行时被忽略。 */
export type LoadingTimelineFields = Partial<
  Record<LoadingTimelineNumericField | LoadingTimelineBooleanField, number | boolean>
>;

/** 记录形状：stage 常量 + 数值/布尔，没有任何自由文本。 */
export type LoadingTimelineRecord = Readonly<Record<string, string | number | boolean>>;

/** `spanSync` / `spanAsync` 观测函数返回值时可附带的、纯数值/布尔的结论。 */
export interface LoadingTimelineSample {
  readonly ok?: boolean;
  readonly bytesIn?: number;
  readonly bytesOut?: number;
  readonly records?: number;
  readonly count?: number;
}

/** 数值归一化：有限数保留两位小数；NaN/Infinity/非数值一律丢弃。 */
function normalizeNumeric(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) return undefined;
  return Math.round(value * 100) / 100;
}

export class LoadingTimeline {
  readonly #enabledOption: boolean | undefined;
  readonly #records: Array<Record<string, string | number | boolean>> = [];

  constructor(options: { enabled?: boolean } = {}) {
    this.#enabledOption = options.enabled;
  }

  /** 显式开关优先；否则动态跟随 `DSH_LOADING_TIMELINE === '1'`。 */
  get enabled(): boolean {
    return this.#enabledOption ?? process.env.DSH_LOADING_TIMELINE === '1';
  }

  /** 计时起点；关闭时返回哨兵 0，调用方无需分支。 */
  begin(): number {
    return this.enabled ? performance.now() : 0;
  }

  /** 记录一条仅有白名单字段的记录；关闭时零开销。 */
  mark(stage: LoadingTimelineStage, fields: LoadingTimelineFields = {}): void {
    if (!this.enabled) return;
    this.#push(stage, fields);
  }

  /** 记录自 `begin()` 起、到本次调用为止的耗时；关闭或起点为 0 时不做任何事。 */
  elapsed(stage: LoadingTimelineStage, start: number, fields: LoadingTimelineFields = {}): void {
    if (start === 0 || !this.enabled) return;
    this.#push(stage, { ...fields, elapsedMs: performance.now() - start });
  }

  /**
   * 观测一次同步处理：始终执行并返回 `fn()`（关闭时直接执行、不加计时），
   * 开启时记录耗时，并可经 `sample` 附带纯数值结论。`fn` 抛错时原样向上传播
   * （记录 `ok:false`），绝不吞掉或改写业务异常。
   */
  spanSync<T>(
    stage: LoadingTimelineStage,
    fn: () => T,
    sample?: (value: T) => LoadingTimelineSample,
  ): T {
    if (!this.enabled) return fn();
    const start = performance.now();
    try {
      const value = fn();
      this.#push(stage, { ...sample?.(value), elapsedMs: performance.now() - start });
      return value;
    } catch (error) {
      this.#push(stage, { ok: false, elapsedMs: performance.now() - start });
      throw error;
    }
  }

  /** 同 `spanSync`，用于有界等待等异步处理；关闭时不额外包一层 Promise。 */
  spanAsync<T>(
    stage: LoadingTimelineStage,
    fn: () => Promise<T>,
    sample?: (value: T) => LoadingTimelineSample,
  ): Promise<T> {
    if (!this.enabled) return fn();
    const start = performance.now();
    return fn().then(
      (value) => {
        this.#push(stage, { ...sample?.(value), elapsedMs: performance.now() - start });
        return value;
      },
      (error: unknown) => {
        this.#push(stage, { ok: false, elapsedMs: performance.now() - start });
        throw error;
      },
    );
  }

  records(): readonly LoadingTimelineRecord[] {
    return this.#records.map((record) => ({ ...record }));
  }

  summaryJson(): string {
    return JSON.stringify(this.#records);
  }

  /** 清空已采集记录（仅供同名工具本身在多次观测之间复位，不影响生产语义）。 */
  reset(): void {
    this.#records.length = 0;
  }

  /** 低噪声：仅当显式设置 `DSH_LOADING_TIMELINE=1` 时输出一行 JSON 摘要，供人工采集。 */
  emit(): void {
    if (!this.enabled || process.env.DSH_LOADING_TIMELINE !== '1') return;
    process.stdout.write(`${this.summaryJson()}\n`);
  }

  #push(stage: LoadingTimelineStage, fields: LoadingTimelineFields): void {
    // 运行期 stage 白名单：即便调用方用类型断言塞入任意字符串，也绝不进入记录。
    if (!STAGE_SET.has(stage)) return;
    const record: Record<string, string | number | boolean> = { stage };
    for (const key of LOADING_TIMELINE_NUMERIC_FIELDS) {
      const value = normalizeNumeric(fields[key]);
      if (value !== undefined) record[key] = value;
    }
    for (const key of LOADING_TIMELINE_BOOLEAN_FIELDS) {
      const value = fields[key];
      if (typeof value === 'boolean') record[key] = value;
    }
    this.#records.push(record);
  }
}

/** 进程级共享实例：生产埋点与测试都写入它；默认关闭，动态跟随环境变量。 */
export const loadingTimeline = new LoadingTimeline();

/**
 * 事件循环延迟采样器。用 `perf_hooks.monitorEventLoopDelay()` 采集事件循环
 * 阻塞直方图，`sample()` 时取均值/峰值（毫秒）记一条记录并复位窗口。
 *
 * 惰性启用：`sample()` 在时间线开启且尚未启用直方图时按需启用。直方图的内部定时器
 * 是 unref 的，不会阻止进程退出（已在实现时实测）。
 */
export class EventLoopDelaySampler {
  readonly #timeline: LoadingTimeline;
  #histogram: ReturnType<typeof monitorEventLoopDelay> | null = null;

  constructor(timeline: LoadingTimeline) {
    this.#timeline = timeline;
  }

  /** 采样一次事件循环延迟（毫秒）；时间线关闭时为无操作。 */
  sample(stage: LoadingTimelineStage): void {
    if (!this.#timeline.enabled) return;
    if (this.#histogram === null) {
      const histogram = monitorEventLoopDelay({ resolution: 20 });
      histogram.enable();
      this.#histogram = histogram;
    }
    const histogram = this.#histogram;
    // 首次采样窗口尚未填充时均值不可用（count 0），跳过以避免记下退化的 NaN 样本。
    if (histogram.count === 0) return;
    this.#timeline.mark(stage, {
      eventLoopDelayMs: histogram.mean / 1e6,
      eventLoopDelayMaxMs: histogram.max / 1e6,
      count: histogram.count,
    });
    histogram.reset();
  }

  /** 停止采样并释放直方图；幂等。 */
  stop(): void {
    this.#histogram?.disable();
    this.#histogram = null;
  }
}

/** 共享事件循环采样器，供生产埋点按需采样。 */
export const eventLoopDelaySampler = new EventLoopDelaySampler(loadingTimeline);
