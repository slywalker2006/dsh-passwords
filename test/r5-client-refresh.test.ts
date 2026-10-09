// 复审 R5：workspace/preset 请求永久 pending 会锁死整张卡片的刷新流程。
//
// 旧实现把 workspace + agent-presets 放进 refresh 主链的 Promise.all：
// 只要其中一个永不 settle，链尾的 .finally 就永不执行，refreshingRef 永久为
// true —— 30s 定时刷新与操作后手动刷新全部被排队吞掉，整张卡片停止更新。
//
// 新实现让可选请求独立于主链（各自 AbortController + 有限超时）：
//   - pending 的可选请求不再阻塞后续刷新（maintains error state / dirty draft）；
//   - 新一轮刷新会取消上一轮仍在飞行中的可选请求，避免旧响应覆盖新数据；
//   - 超时后主动中止并转入错误态，而不是无限等待。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test, type TestContext } from 'node:test';
import { createElement } from 'react';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';

import { DshPasswordsCard } from '../src/client/card.tsx';

const OPTIONAL_REQUEST_TIMEOUT_MS = 5000;
const WORKSPACE_REQUEST_TIMEOUT_MS = 120_000;
const REQUIRED_REFRESH_TIMEOUT_MS = 10000;

type CardProps = { t: (key: string, params?: Record<string, unknown>) => string };

const admin = { id: 1, username: 'test-admin', role: 'admin' as const };

const subuser = {
  id: 2,
  username: 'subuser',
  role: 'user' as const,
  permissions: {
    allowedFolders: [],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    allowSsh: false,
    allowedAgentPresets: [],
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
    allowedSessionIds: [],
  },
  usage: null,
};

const workspacesPayload = {
  workspaces: [{
    path: '/work/visible',
    title: 'Visible workspace',
    sessions: [{ id: 'session-visible', title: 'Visible session' }],
  }],
};

const updateStatus = {
  env: 'npm-prefix', currentVersion: '0.0.0', latestVersion: null,
  updateAvailable: false, phase: 'idle', downloadPercent: null,
  downloadMode: null, downloadedBytes: 0, totalBytes: null,
  pendingVersion: null, installConfirmationRequired: false,
  lastNotificationAt: null, idleRemainingMs: null, autoUpdateEnabled: false,
  autoInstallSupported: true, checking: false, manualCommand: '',
  lastCheckedAt: null, lastError: null, applyCooldownRemainingMs: 0,
};

/** 永不 settle 的响应：模拟上游彻底卡死。 */
const never = () => new Promise<Response>(() => undefined);

function abortError() {
  return new DOMException('The operation was aborted.', 'AbortError');
}

/**
 * 让 mock fetch 尊重 AbortSignal：真实 fetch 在 signal abort 时会 reject，
 * 这里复刻该行为，才能验证“取消 / 有限超时”确实使请求有界结束。
 */
function withAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (signal === undefined) return promise;
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value); },
      (error) => { signal.removeEventListener('abort', onAbort); reject(error); },
    );
  });
}

type Override = (signal: AbortSignal | undefined) => Response | Promise<Response>;

async function mountCard(
  t: TestContext,
  overrides: Record<string, Override> = {},
  payloadOverrides: Record<string, unknown> = {},
) {
  const intervals = new Map<number, { callback: () => void; delay: number }>();
  let nextTimer = 0;
  let renderer: ReactTestRenderer | undefined;
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      setInterval(callback: () => void, delay: number) {
        intervals.set(++nextTimer, { callback, delay });
        return nextTimer;
      },
      clearInterval(id: number) { intervals.delete(id); },
    },
  });
  t.after(async () => {
    try {
      await act(async () => { renderer?.unmount(); });
    } finally {
      if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow);
      else Reflect.deleteProperty(globalThis, 'window');
    }
    assert.equal(intervals.size, 0, '卡片必须清理自己的定时器');
  });
  t.mock.method(console, 'error', () => {});

  const payloads: Record<string, unknown> = {
    '/api/dsh-passwords/state': { me: admin, users: [] },
    '/gateway/api/overview': { me: admin, users: [subuser] },
    '/api/session/modelCatalog': {
      type: 'server-response', rpcId: 'rpc-model-catalog',
      result: {
        ok: true,
        value: { default: { provider: 'openai', model: 'gpt-5' }, routableProviders: ['openai'], groups: [], failures: [] },
      },
    },
    '/api/dsh-passwords/workspaces': workspacesPayload,
    '/api/dsh-passwords/patch/status': {
      status: { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'patched' },
    },
    '/api/dsh-passwords/update/status': { status: updateStatus },
    '/api/dsh-passwords/agent-presets': { presets: [] },
    ...payloadOverrides,
  };

  const requests: Array<{ input: string; init?: RequestInit; signal: AbortSignal | undefined }> = [];
  t.mock.method(globalThis, 'fetch', (input: string, init?: RequestInit) => {
    const signal = init?.signal ?? undefined;
    requests.push({ input, init, signal });
    if (signal?.aborted) return Promise.reject(abortError());
    const override = overrides[input];
    if (override) return withAbort(Promise.resolve().then(() => override(signal)), signal);
    assert.ok(input in payloads, `Unexpected request: ${input}`);
    return withAbort(Promise.resolve(Response.json(payloads[input])), signal);
  });

  const translate: CardProps['t'] = (key) => key;
  await act(async () => {
    renderer = create(createElement(DshPasswordsCard, { t: translate } satisfies CardProps));
  });
  return {
    renderer: renderer!,
    text: () => JSON.stringify(renderer!.toJSON()),
    requests,
    stateCalls: () => requests.filter((request) => request.input === '/api/dsh-passwords/state').length,
    async refresh() {
      const timer = [...intervals.values()].find(({ delay }) => delay === 30_000);
      assert.ok(timer, '卡片必须保留 30s 刷新定时器');
      await act(async () => { timer.callback(); });
    },
    async tickIntervals(delay: number) {
      const timers = [...intervals.values()].filter((timer) => timer.delay === delay);
      await act(async () => { for (const timer of timers) timer.callback(); });
    },
  };
}

test('R5: 挂起的 workspace/preset 请求不阻塞后续刷新', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': never,
    '/api/dsh-passwords/agent-presets': never,
  });
  assert.match(card.text(), /permsWorkspacesLoading/, '工作区挂起时必须显示加载态');

  const before = card.stateCalls();
  await card.refresh();
  assert.equal(card.stateCalls(), before + 1, '挂起请求不得把 refreshingRef 永久锁住');
  assert.match(card.text(), /test-admin/, '刷新主链必须继续更新身份信息');
});

test('R5: 新一轮刷新保留 workspace 请求但取消轻量 preset 请求', async (t) => {
  let resolveWorkspace: (() => void) | undefined;
  const workspacePending = () => new Promise<Response>((resolve) => {
    resolveWorkspace = () => resolve(Response.json(workspacesPayload));
  });
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': workspacePending,
    '/api/dsh-passwords/agent-presets': never,
  });
  const inFlight = (path: string) => card.requests.filter((request) => request.input === path).at(-1);
  const firstWorkspace = inFlight('/api/dsh-passwords/workspaces');
  const firstPreset = inFlight('/api/dsh-passwords/agent-presets');
  assert.ok(firstWorkspace?.signal && firstPreset?.signal, '可选请求必须携带可取消的 signal');
  assert.equal(firstWorkspace.signal.aborted, false, '首轮工作区请求此时不应被取消');
  assert.equal(firstPreset.signal.aborted, false, '首轮预设请求此时不应被取消');

  await card.refresh();
  assert.equal(firstWorkspace.signal.aborted, false, '冷枚举工作区请求不得被周期刷新取消');
  assert.equal(firstPreset.signal.aborted, true, '轻量预设请求仍应被新一轮刷新取消');
  resolveWorkspace?.();
  await act(async () => { await Promise.resolve(); });
});

test('R5: 可选请求挂起时刷新仍保留未保存的会话草稿', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/agent-presets': never,
  }, {
    '/api/dsh-passwords/workspaces': workspacesPayload,
  });
  const sessionInput = () => card.renderer.root
    .findAllByProps({ className: 'dshpw-session-check' })
    .find((node) => node.findAllByType('input').length === 1)!
    .findByType('input');
  assert.ok(sessionInput(), '会话授权开关必须可见');

  await act(async () => { sessionInput().props.onChange({ target: { checked: true } }); });
  const before = card.stateCalls();
  await card.refresh();

  assert.equal(card.stateCalls(), before + 1, '预设挂起不得阻塞刷新');
  assert.equal(sessionInput().props.checked, true, '刷新不得覆盖未保存的会话编辑');
});

test('R5: 可选请求超时后转入错误态而不是无限 pending', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': never,
  });
  assert.match(card.text(), /permsWorkspacesLoading/);

  t.mock.timers.tick(WORKSPACE_REQUEST_TIMEOUT_MS);
  await act(async () => {
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  });

  assert.match(card.text(), /permsWorkspacesTimeout/, '超时必须转入有界的错误态');
  assert.doesNotMatch(card.text(), /permsWorkspacesLoading/, '超时后不得停留在加载态');
});

test('R5: 必需链墙钟超时释放 refreshingRef 并转入错误态', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const card = await mountCard(t, { '/api/dsh-passwords/state': never });
  assert.equal(card.stateCalls(), 1, '挂起时首轮 state 请求已发出');

  t.mock.timers.tick(REQUIRED_REFRESH_TIMEOUT_MS);
  await act(async () => {
    for (let i = 0; i < 20; i += 1) await Promise.resolve();
  });
  assert.match(card.text(), /permsRefreshTimeout/, '必需链超时必须转入错误态');

  const before = card.stateCalls();
  await card.refresh();
  assert.equal(card.stateCalls(), before + 1, '超时后刷新守卫必须已释放，下一轮能重新发起请求');
});

test('R5: 卸载取消所有仍在飞行的刷新请求', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': never,
    '/api/dsh-passwords/agent-presets': never,
    '/api/session/modelCatalog': never,
  });
  const inFlight = (path: string) => card.requests.filter((request) => request.input === path).at(-1);
  const workspace = inFlight('/api/dsh-passwords/workspaces');
  const preset = inFlight('/api/dsh-passwords/agent-presets');
  const catalog = inFlight('/api/session/modelCatalog');
  assert.ok(workspace?.signal && preset?.signal && catalog?.signal, '可选请求必须携带可取消的 signal');

  await act(async () => { card.renderer.unmount(); });
  assert.equal(workspace.signal.aborted, true, '卸载必须取消工作区请求');
  assert.equal(preset.signal.aborted, true, '卸载必须取消预设请求');
  assert.equal(catalog.signal.aborted, true, '卸载必须取消模型目录请求');
});


test('R5: 挂起的 patch/status 与 update/status 请求携带 signal 并在卸载时取消', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/patch/status': never,
    '/api/dsh-passwords/update/status': never,
  });
  const inFlight = (path: string) => card.requests.filter((request) => request.input === path).at(-1);
  const patch = inFlight('/api/dsh-passwords/patch/status');
  const update = inFlight('/api/dsh-passwords/update/status');
  assert.ok(patch?.signal && update?.signal, 'patch/update 状态请求必须携带可取消的 signal');

  await act(async () => { card.renderer.unmount(); });
  assert.equal(patch.signal.aborted, true, '卸载必须取消 patch/status 请求');
  assert.equal(update.signal.aborted, true, '卸载必须取消 update/status 请求');
});

test('R5: 下载中轮询单飞，挂起的响应不重叠堆积', async (t) => {
  const downloading = { ...updateStatus, phase: 'downloading' as const };
  let statusCalls = 0;
  const card = await mountCard(t, {
    // 首次（refresh 的独立拉取）返回 downloading 以激活轮询；之后全部挂起。
    '/api/dsh-passwords/update/status': () => {
      statusCalls += 1;
      return statusCalls === 1 ? Response.json({ status: downloading }) : never();
    },
  });
  const requestCount = () => card.requests.filter((request) => request.input === '/api/dsh-passwords/update/status').length;
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  const afterStart = requestCount();
  assert.ok(afterStart >= 2, 'downloading 状态必须启动单飞轮询并发出首轮请求');

  for (let i = 0; i < 5; i += 1) await card.tickIntervals(700);
  assert.equal(requestCount(), afterStart, '上一轮未返回时不得叠加新的轮询请求');
  assert.equal(statusCalls, afterStart, '轮询请求数必须与 tick 次数无关');
});

test('R5: overview 非超时失败进入可见错误而不是静默留空', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/overview': () => { throw new Error('overview exploded'); },
  });
  assert.match(card.text(), /overview exploded/, 'overview 失败必须显示可见错误');
});

// react-test-renderer 18.3.1 的构建不包含 StrictMode effect 双调用，且本仓库无 DOM
// 测试环境，effect 重跑（StrictMode / HMR）无法在运行时触发。按仓库既有惯例
// （见 client-picker-delete / client-chat-fab）用源码契约守住复位顺序。
test('R5: 源码契约——主刷新 effect 重跑时必须复位 disposedRef', () => {
  const source = readFileSync(new URL('../src/client/card.tsx', import.meta.url), 'utf8');
  const reset = source.indexOf('disposedRef.current = false;');
  assert.ok(reset >= 0, '主 effect 必须复位 disposedRef，否则重跑后 refresh 永久短路');
  assert.equal((source.match(/disposedRef\.current = false;/g) ?? []).length, 1, '复位点应唯一');
  const refreshCall = source.indexOf('refresh();', reset);
  const disposedTrue = source.indexOf('disposedRef.current = true;', reset);
  assert.ok(refreshCall > reset, '复位必须发生在本轮 refresh 之前');
  assert.ok(disposedTrue > refreshCall, 'cleanup 置 true 必须晚于复位');
});
