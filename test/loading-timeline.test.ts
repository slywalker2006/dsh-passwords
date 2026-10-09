// 加载时间线观测模块（src/loading-timeline.ts）的纯单元测试。
//
// 覆盖：默认关闭、动态环境开关、结构白名单（未知/字符串字段一律丢弃、stage 运行期校验）、
// 数值归一化、begin/elapsed、spanSync/spanAsync（含异常传播）、事件循环延迟采样，
// 以及“需要区分”的阶段常量齐备。全部用合成值，不触发任何网络或业务路径。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  LOADING_TIMELINE_STAGES,
  LoadingTimeline,
  EventLoopDelaySampler,
} from '../src/loading-timeline.js';

const delay = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

/** 记录里的键只允许出现在白名单里。 */
const ALLOWED_KEYS = new Set<string>([
  'stage', 'elapsedMs', 'bytesIn', 'bytesOut', 'records', 'count',
  'eventLoopDelayMs', 'eventLoopDelayMaxMs', 'ok', 'historyInFlight',
]);

test('默认关闭：未显式开启且环境未设置时不记录', () => {
  const saved = process.env.DSH_LOADING_TIMELINE;
  delete process.env.DSH_LOADING_TIMELINE;
  try {
    const auto = new LoadingTimeline();
    assert.equal(auto.enabled, false);
    auto.mark('http.history.complete', { elapsedMs: 1, bytesIn: 10, bytesOut: 20, records: 3, ok: true });
    auto.elapsed('gateway.history.parse', auto.begin(), { bytesIn: 1 });
    assert.deepEqual(auto.records(), []);
    assert.equal(auto.summaryJson(), '[]');

    const off = new LoadingTimeline({ enabled: false });
    off.mark('gateway.eventLoop.delay', { eventLoopDelayMs: 5 });
    assert.deepEqual(off.records(), []);
  } finally {
    if (saved === undefined) delete process.env.DSH_LOADING_TIMELINE; else process.env.DSH_LOADING_TIMELINE = saved;
  }
});

test('动态环境开关：跟随 DSH_LOADING_TIMELINE 运行期变化', () => {
  const saved = process.env.DSH_LOADING_TIMELINE;
  const auto = new LoadingTimeline();
  try {
    delete process.env.DSH_LOADING_TIMELINE;
    assert.equal(auto.enabled, false);
    auto.mark('mux.carrier.open', { ok: true });
    assert.deepEqual(auto.records(), []);

    process.env.DSH_LOADING_TIMELINE = '1';
    assert.equal(auto.enabled, true);
    auto.mark('mux.carrier.open', { ok: true });
    assert.equal(auto.records().length, 1);

    // 显式开关优先于环境变量：即便环境为 1，显式关闭实例仍不记录。
    const explicitOff = new LoadingTimeline({ enabled: false });
    assert.equal(explicitOff.enabled, false);
  } finally {
    auto.reset();
    if (saved === undefined) delete process.env.DSH_LOADING_TIMELINE; else process.env.DSH_LOADING_TIMELINE = saved;
  }
});

test('结构白名单：未知字段与字符串一律丢弃，记录只含数值/布尔', () => {
  const tl = new LoadingTimeline({ enabled: true });
  const secret = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig';
  tl.mark('http.history.complete', {
    elapsedMs: 5, bytesIn: 10, bytesOut: 20, records: 3, ok: true, count: 7,
    // 以下均不在白名单内（含运行期字符串），必须被丢弃：
    url: `/api/session.history?token=${secret}`,
    cookie: `dsh_gateway_token=${secret}`,
    body: 'HISTORY-BODY-MARKER',
    authorization: secret,
    stage: 'attacker-controlled-stage',
  } as unknown as Parameters<LoadingTimeline['mark']>[1]);

  assert.deepEqual(tl.records(), [
    { stage: 'http.history.complete', elapsedMs: 5, bytesIn: 10, bytesOut: 20, records: 3, count: 7, ok: true },
  ]);
  const out = tl.summaryJson();
  for (const forbidden of [secret, 'dsh_gateway_token', 'HISTORY-BODY-MARKER', '/api/session.history', 'http://', '?']) {
    assert.equal(out.includes(forbidden), false, `观测记录不得包含敏感内容：${forbidden}`);
  }
  for (const record of tl.records()) {
    for (const key of Object.keys(record)) {
      assert.ok(ALLOWED_KEYS.has(key), `记录出现白名单外的键：${key}`);
    }
  }
});

test('stage 运行期白名单：类型断言塞入的未知 stage 也会被丢弃', () => {
  const tl = new LoadingTimeline({ enabled: true });
  tl.mark('evil/stage?token=leak' as unknown as Parameters<LoadingTimeline['mark']>[0], { elapsedMs: 1 });
  assert.deepEqual(tl.records(), []);
});

test('数值归一化：NaN/Infinity/非数值丢弃，有限数保留两位小数', () => {
  const tl = new LoadingTimeline({ enabled: true });
  tl.mark('http.page.complete', {
    elapsedMs: 2.346,
    bytesIn: Number.NaN,
    bytesOut: Number.POSITIVE_INFINITY,
    records: -3,
    count: 2.999,
    ok: 'yes' as unknown as boolean,
  });
  assert.deepEqual(tl.records(), [{ stage: 'http.page.complete', elapsedMs: 2.35, records: -3, count: 3 }]);
});

test('begin/elapsed 记录耗时；关闭时 begin 返回哨兵 0', () => {
  const off = new LoadingTimeline({ enabled: false });
  assert.equal(off.begin(), 0);
  off.elapsed('gateway.history.parse', 0, { bytesIn: 1 });
  assert.deepEqual(off.records(), []);

  const tl = new LoadingTimeline({ enabled: true });
  const start = tl.begin();
  assert.ok(start > 0);
  tl.elapsed('gateway.history.parse', start, { bytesIn: 128 });
  const [record] = tl.records();
  assert.equal(record?.stage, 'gateway.history.parse');
  assert.equal(record?.bytesIn, 128);
  assert.equal(typeof record?.elapsedMs, 'number');
  assert.ok((record?.elapsedMs as number) >= 0);
});

test('spanSync 记录耗时与采样字段，并在异常时记录 ok:false 后原样抛出', () => {
  const tl = new LoadingTimeline({ enabled: true });
  const value = tl.spanSync('gateway.history.stringify',
    () => 42,
    () => ({ bytesOut: 64, records: 3 }));
  assert.equal(value, 42);
  const [ok] = tl.records();
  assert.equal(ok?.stage, 'gateway.history.stringify');
  assert.equal(ok?.bytesOut, 64);
  assert.equal(ok?.records, 3);

  const boom = new Error('boom');
  assert.throws(() => tl.spanSync('gateway.history.parse', () => { throw boom; }), /boom/);
  assert.deepEqual(tl.records().at(-1), { stage: 'gateway.history.parse', ok: false, elapsedMs: tl.records().at(-1)!.elapsedMs });
});

test('spanAsync 记录耗时与结论，异常原样传播；关闭时透传不包裹', async () => {
  const tl = new LoadingTimeline({ enabled: true });
  const ready = await tl.spanAsync('baseline.wait', async () => { await delay(5); return true; }, (value) => ({ ok: value }));
  assert.equal(ready, true);
  const [record] = tl.records();
  assert.equal(record?.stage, 'baseline.wait');
  assert.equal(record?.ok, true);
  assert.ok((record?.elapsedMs as number) >= 0);

  await assert.rejects(
    tl.spanAsync('baseline.wait', async () => { await delay(1); throw new Error('nope'); }),
    /nope/,
  );
  assert.equal(tl.records().at(-1)?.ok, false);

  // 关闭时：spanAsync 直接返回原 Promise，不额外包裹。
  const off = new LoadingTimeline({ enabled: false });
  const passthrough = Promise.resolve('x');
  assert.equal(off.spanAsync('baseline.wait', () => passthrough), passthrough);
});

test('事件循环延迟采样：开启时产出有限数值，关闭时无记录，stop 幂等', async () => {
  const tl = new LoadingTimeline({ enabled: true });
  const sampler = new EventLoopDelaySampler(tl);
  sampler.sample('gateway.eventLoop.delay'); // 惰性启用直方图；首个窗口尚未填充，不记录
  assert.deepEqual(tl.records(), []);
  await delay(120); // 等直方图采样一个窗口（resolution 20ms）
  sampler.sample('gateway.eventLoop.delay');
  const record = tl.records().find((entry) => entry.stage === 'gateway.eventLoop.delay');
  assert.ok(record, '应记录一条事件循环延迟样本');
  assert.equal(typeof record.eventLoopDelayMs, 'number');
  assert.ok(Number.isFinite(record.eventLoopDelayMs as number));
  assert.equal(typeof record.eventLoopDelayMaxMs, 'number');
  assert.ok(Number.isFinite(record.eventLoopDelayMaxMs as number));
  sampler.stop();
  sampler.stop();

  const off = new LoadingTimeline({ enabled: false });
  new EventLoopDelaySampler(off).sample('gateway.eventLoop.delay');
  assert.deepEqual(off.records(), []);
});

test('阶段常量齐备：覆盖需要区分的所有观测点', () => {
  const required = [
    'mux.upstream.snapshot.prepare',
    'baseline.wait',
    'mux.session.follow.firstItem',
    'mux.terminal.follow.firstOutput',
    'gateway.history.parse',
    'gateway.history.filter',
    'gateway.history.stringify',
    'gateway.page.parse',
    'gateway.page.filter',
    'gateway.page.stringify',
    'gateway.eventLoop.delay',
  ];
  for (const stage of required) {
    assert.ok((LOADING_TIMELINE_STAGES as readonly string[]).includes(stage), `缺少阶段常量：${stage}`);
  }
  assert.equal(new Set(LOADING_TIMELINE_STAGES).size, LOADING_TIMELINE_STAGES.length, '阶段常量不得重复');
});
