import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createAssignableInventoryLoader,
  isPermanentGatewayExitCode,
  listAssignableResources,
  listAssignableWorkspaces,
  prewarmAssignableInventory,
} from '../src/plugin.js';

test('gateway permanent exit codes do not accept signal strings', () => {
  assert.equal(isPermanentGatewayExitCode(1), true);
  assert.equal(isPermanentGatewayExitCode(37), true);
  assert.equal(isPermanentGatewayExitCode(0), false);
  assert.equal(isPermanentGatewayExitCode('1'), false);
});

type Workspace = {
  path: string;
  title: string;
  sessionIds: readonly string[];
  status(): Promise<'ok' | 'missing-dir'>;
};

function registry(workspace: Workspace, archivedSessionIds: readonly string[] = []) {
  return {
    list: () => [workspace],
    archivedSessionIds,
  };
}

function workspace(sessionIds: readonly string[]): Workspace {
  return {
    path: '/workspaces/project',
    title: 'Project',
    sessionIds,
    status: async () => 'ok',
  };
}

test('Issue #25: live blank sessions remain assignable when registered by DSH', async () => {
  const result = await listAssignableWorkspaces(
    registry(workspace(['blank-live'])),
    { get: (id: string) => id === 'blank-live' ? { deriveMessages: () => [] } : undefined },
    { get: () => ({ title: 'New session' }) },
    undefined,
  );

  assert.deepEqual(result[0]?.sessions, [{ id: 'blank-live', title: 'New session' }]);
});

test('Issue #25: titled persisted blank sessions remain assignable', async () => {
  const result = await listAssignableWorkspaces(
    registry(workspace(['blank-persisted'])),
    { get: () => undefined },
    undefined,
    {
      readSurface: async () => ({ events: [] }),
      readTitle: async () => ({ title: 'Persisted new session' }),
    },
  );

  assert.deepEqual(result[0]?.sessions, [{ id: 'blank-persisted', title: 'Persisted new session' }]);
});

test('untitled persisted initialization slots are hidden from the assignment inventory', async () => {
  const result = await listAssignableWorkspaces(
    registry(workspace(['session-empty', 'session-message'])),
    { get: () => undefined },
    undefined,
    {
      readSurface: async (id: string) => ({ events: id === 'session-empty' ? [] : [{ type: 'user/message' }] }),
      readTitle: async () => undefined,
      listEvents: async (id: string) => id === 'session-empty'
        ? [{ type: 'session' }, { type: 'permission/preset' }, { type: 'sandbox/mode' }, { type: 'approval/policy' }, { type: 'subagent/model-selection-policy' }]
        : [{ type: 'user/message' }],
    },
  );

  assert.deepEqual(result[0]?.sessions, [{ id: 'session-message', title: 'session-message' }]);
});

test('untitled sessions with unknown raw events or empty raw logs are retained', async () => {
  const result = await listAssignableWorkspaces(
    registry(workspace(['unknown', 'no-events'])),
    { get: () => undefined },
    undefined,
    {
      readSurface: async () => ({ events: [] }),
      readTitle: async () => undefined,
      listEvents: async (id: string) => id === 'unknown' ? [{ type: 'turn/start' }] : [],
    },
  );

  assert.deepEqual(result[0]?.sessions, [
    { id: 'unknown', title: 'unknown' },
    { id: 'no-events', title: 'no-events' },
  ]);
});

test('assignable resources use one post-enumeration archive snapshot', async () => {
  let archived: readonly string[] = [];
  const result = await listAssignableResources({
    list: () => [{
      path: '/workspaces/project',
      title: 'Project',
      sessionIds: ['s1', 's2'],
      status: async () => { archived = ['s1']; return 'ok'; },
    }],
    get archivedSessionIds() { return archived; },
  });
  assert.deepEqual(result.assignableSessions, ['s2']);
  assert.deepEqual(result.retainedSessions, ['s1']);
  assert.deepEqual(result.assignableSessions.filter((id) => result.retainedSessions.includes(id)), []);
});

test('Issue #25: archived sessions are never assignable, including blank sessions', async () => {
  const result = await listAssignableWorkspaces(
    registry(workspace(['blank-archived']), ['blank-archived']),
    { get: () => ({}) },
    { get: () => ({ title: 'Archived' }) },
    undefined,
  );

  assert.deepEqual(result[0]?.sessions, []);
});

test('Issue #25: a definitely missing persisted session is omitted', async () => {
  const missing = Object.assign(new Error('session not found'), { code: 'SESSION_QUERY_SESSION_NOT_FOUND' });
  const result = await listAssignableWorkspaces(
    registry(workspace(['missing'])),
    { get: () => undefined },
    undefined,
    { readSurface: async () => { throw missing; } },
  );

  assert.deepEqual(result[0]?.sessions, []);
});

test('Issue #25: non-missing session storage failures are propagated', async () => {
  const failure = new Error('database unavailable');
  await assert.rejects(
    listAssignableWorkspaces(
      registry(workspace(['unavailable'])),
      { get: () => undefined },
      undefined,
      { readSurface: async () => { throw failure; } },
    ),
    failure,
  );
});

test('Issue #39: batched titles preserve order and skip surface reads for titled sessions', async () => {
  let observedIds: readonly string[] = [];
  const surfaceCalls: string[] = [];
  const result = await listAssignableWorkspaces(
    registry(workspace(['titled', 'untitled'])),
    { get: () => undefined },
    undefined,
    {
      readTitleSnapshots: async (ids) => {
        observedIds = ids;
        return ids.map((sessionId) => ({
          sessionId,
          status: 'fulfilled',
          value: { title: { title: sessionId === 'titled' ? 'Title' : '' } },
        }));
      },
      readTitle: async () => { throw new Error('batch result should be used'); },
      readSurface: async (id) => { surfaceCalls.push(id); return { events: [{ type: 'user/message' }] }; },
      listEvents: async () => [{ type: 'user/message' }],
    },
  );

  assert.deepEqual(observedIds, ['titled', 'untitled']);
  assert.deepEqual(surfaceCalls, ['untitled']);
  assert.deepEqual(result[0]?.sessions, [
    { id: 'titled', title: 'Title' },
    { id: 'untitled', title: 'untitled' },
  ]);
});

test('Issue #39: batch misses fall back per id and definite missing sessions remain omitted', async () => {
  const missing = Object.assign(new Error('session not found'), { code: 'SESSION_QUERY_SESSION_NOT_FOUND' });
  const readTitleCalls: string[] = [];
  const surfaceCalls: string[] = [];
  const result = await listAssignableWorkspaces(
    registry(workspace(['batch-hit', 'batch-miss', 'deleted'])),
    { get: () => undefined },
    undefined,
    {
      readTitleSnapshots: async () => [{
        sessionId: 'batch-hit', status: 'fulfilled', value: { title: { title: 'Batch title' } },
      }],
      readTitle: async (id) => {
        readTitleCalls.push(id);
        if (id === 'deleted') throw missing;
        return { title: 'Fallback title' };
      },
      readSurface: async (id) => { surfaceCalls.push(id); return { events: [{ type: 'user/message' }] }; },
      listEvents: async () => [{ type: 'user/message' }],
    },
  );

  assert.deepEqual(readTitleCalls, ['batch-miss', 'deleted']);
  assert.deepEqual(surfaceCalls, [], 'a fallback title avoids the surface read');
  assert.deepEqual(result[0]?.sessions, [
    { id: 'batch-hit', title: 'Batch title' },
    { id: 'batch-miss', title: 'Fallback title' },
  ]);
});

test('Issue #39: missing sessions in legacy title fallback are omitted; other title errors propagate', async () => {
  const missing = Object.assign(new Error('session not found'), { code: 'SESSION_QUERY_SESSION_NOT_FOUND' });
  const result = await listAssignableWorkspaces(
    registry(workspace(['missing', 'present'])),
    { get: () => undefined },
    undefined,
    {
      readTitle: async (id) => { if (id === 'missing') throw missing; return { title: 'Present' }; },
      readSurface: async (id) => {
        if (id === 'missing') throw missing;
        return { events: [{ type: 'user/message', id }] };
      },
    },
  );
  assert.deepEqual(result[0]?.sessions, [{ id: 'present', title: 'Present' }]);

  const failure = new Error('storage unavailable');
  await assert.rejects(
    listAssignableWorkspaces(
      registry(workspace(['broken'])), { get: () => undefined }, undefined,
      { readTitle: async () => { throw failure; }, readSurface: async () => ({ events: [] }) },
    ),
    failure,
  );
});

test('Issue #39: rejected batch results propagate non-missing errors', async () => {
  const failure = new Error('snapshot storage unavailable');
  await assert.rejects(
    listAssignableWorkspaces(
      registry(workspace(['broken'])), { get: () => undefined }, undefined,
      {
        readTitleSnapshots: async () => [{ sessionId: 'broken', status: 'rejected', reason: failure }],
        readSurface: async () => ({ events: [] }),
      },
    ),
    failure,
  );
});

test('Issue #39: non-array batch title results fall back to per-id reads', async () => {
  const readTitleCalls: string[] = [];
  const surfaceCalls: string[] = [];
  const result = await listAssignableWorkspaces(
    registry(workspace(['a', 'b'])),
    { get: () => undefined },
    undefined,
    {
      // 运行期故意返回非数组：消费端必须用 Array.isArray 守卫并回退逐条。
      readTitleSnapshots: (async () => ({ broken: true })) as never,
      readTitle: async (id) => { readTitleCalls.push(id); return { title: `T-${id}` }; },
      readSurface: async (id) => { surfaceCalls.push(id); return { events: [{ type: 'user/message' }] }; },
    },
  );

  assert.deepEqual(readTitleCalls, ['a', 'b'], '非数组批次回退到逐条 readTitle');
  assert.deepEqual(surfaceCalls, [], '逐条拿到标题后不再读 surface');
  assert.deepEqual(result[0]?.sessions, [
    { id: 'a', title: 'T-a' },
    { id: 'b', title: 'T-b' },
  ]);
});

test('Issue #39: prewarm retries until the lazily exposed registry is ready', async () => {
  let registryReads = 0;
  const live = registry(workspace(['session']));
  const refreshed: unknown[] = [];
  const errors: unknown[] = [];
  const cancel = prewarmAssignableInventory(
    () => { registryReads += 1; return registryReads >= 3 ? live : undefined; },
    async (reg) => { refreshed.push(reg); },
    { attempts: 5, delayMs: 0, wait: async () => {}, onError: (error) => { errors.push(error); } },
  );
  await new Promise((resolve) => setImmediate(resolve));
  cancel();

  assert.equal(registryReads, 3, '未就绪时按界重试，就绪后停止');
  assert.deepEqual(refreshed, [live], 'registry 就绪后恰好预热一次');
  assert.deepEqual(errors, [], '成功预热不产生错误');
});

test('Issue #39: prewarm is bounded and reports when the registry never appears', async () => {
  let registryReads = 0;
  let refreshCalls = 0;
  const errors: unknown[] = [];
  const cancel = prewarmAssignableInventory(
    () => { registryReads += 1; return undefined; },
    async () => { refreshCalls += 1; },
    { attempts: 3, delayMs: 0, wait: async () => {}, onError: (error) => { errors.push(error); } },
  );
  await new Promise((resolve) => setImmediate(resolve));
  cancel();

  assert.equal(registryReads, 3, '有限次尝试后停止轮询');
  assert.equal(refreshCalls, 0, 'registry 缺失时不触发枚举');
  assert.equal(errors.length, 1, '耗尽重试必须可观测');
  const failure = errors[0];
  assert.ok(failure instanceof Error);
  assert.match(failure.message, /workspace registry unavailable/);
});

test('Issue #39: prewarm cancellation stops polling and stays silent', async () => {
  let registryReads = 0;
  let release: (() => void) | undefined;
  const errors: unknown[] = [];
  const cancel = prewarmAssignableInventory(
    () => { registryReads += 1; return undefined; },
    async () => { throw new Error('refresh must not run after cancel'); },
    {
      attempts: 5,
      delayMs: 0,
      wait: () => new Promise<void>((resolve) => { release = resolve; }),
      onError: (error) => { errors.push(error); },
    },
  );
  cancel();
  release?.();
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(registryReads, 1, '取消后不再轮询');
  assert.deepEqual(errors, [], '取消不是错误，也不报告耗尽');
});

test('Issue #39: inventory TTL is opt-in, scoped per loader, and coalesces concurrent misses', async () => {
  let now = 10_000;
  const originalNow = Date.now;
  Date.now = () => now;
  let reads = 0;
  let noCacheReads = 0;
  const reg = registry(workspace(['cached']));
  let resolveTitle: ((value: { title: string }) => void) | undefined;
  let markTitleStarted: (() => void) | undefined;
  const titleStarted = new Promise<void>((resolve) => { markTitleStarted = resolve; });
  const query = {
    readTitle: async () => {
      reads += 1;
      markTitleStarted?.();
      return await new Promise<{ title: string }>((resolve) => { resolveTitle = resolve; });
    },
    readSurface: async () => ({ events: [{ type: 'user/message' }] }),
  };
  try {
    const noCache = createAssignableInventoryLoader(0);
    const plainQuery = {
      readTitle: async () => { noCacheReads += 1; return { title: 'cached' }; },
      readSurface: query.readSurface,
    };
    await noCache(reg, { get: () => undefined }, undefined, plainQuery);
    await noCache(reg, { get: () => undefined }, undefined, plainQuery);
    assert.equal(noCacheReads, 2, 'TTL 0 recomputes for every request');
    assert.equal(reads, 0);

    const loader = createAssignableInventoryLoader(100);
    const first = loader(reg, { get: () => undefined }, undefined, query);
    const second = loader(reg, { get: () => undefined }, undefined, query);
    await titleStarted;
    assert.equal(reads, 1, 'concurrent cold requests share one enumeration');
    resolveTitle?.({ title: 'cached title' });
    await Promise.all([first, second]);
    await loader(reg, { get: () => undefined }, undefined, query);
    assert.equal(reads, 1, 'warm requests use the instance cache');

    const otherInstance = createAssignableInventoryLoader(100);
    let otherReads = 0;
    await otherInstance(reg, { get: () => undefined }, undefined, {
      readTitle: async () => { otherReads += 1; return { title: 'other' }; },
      readSurface: query.readSurface,
    });
    assert.equal(otherReads, 1, 'separate plugin instances do not share cached data');

    now += 101;
    const expired = loader(reg, { get: () => undefined }, undefined, {
      readTitle: async () => { reads += 1; return { title: 'expired' }; },
      readSurface: query.readSurface,
    });
    await expired;
    assert.equal(reads, 2, 'expired entries are recomputed');

    // 过期请求先返回旧快照，后台刷新完成后下一次读取才观察新值。
    let resolveRefresh: ((value: { title: string }) => void) | undefined;
    const stale = createAssignableInventoryLoader(100);
    await stale(reg, { get: () => undefined }, undefined, {
      readTitle: async () => ({ title: 'initial' }),
      readSurface: query.readSurface,
    });
    now += 101;
    const staleRead = await stale(reg, { get: () => undefined }, undefined, {
      readTitle: async () => await new Promise<{ title: string }>((resolve) => { resolveRefresh = resolve; }),
      readSurface: query.readSurface,
    });
    assert.equal(staleRead[0]?.sessions[0]?.title, 'initial', '过期时先返回 stale 快照');
    resolveRefresh?.({ title: 'refreshed' });
    await new Promise((resolve) => setImmediate(resolve));
    const refreshed = await stale(reg, { get: () => undefined }, undefined, {
      readTitle: async () => ({ title: 'unexpected' }),
      readSurface: query.readSurface,
    });
    assert.equal(refreshed[0]?.sessions[0]?.title, 'refreshed', '后台刷新结果进入缓存');
  } finally {
    Date.now = originalNow;
  }
});

test('Issue #39: TTL=0 coalesces concurrent misses but never caches across time', async () => {
  const reg = registry(workspace(['cached']));
  let reads = 0;
  let resolveTitle: ((value: { title: string }) => void) | undefined;
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => { markStarted = resolve; });
  let secondRoundReads = 0;

  const loader = createAssignableInventoryLoader(0);
  const first = loader(reg, { get: () => undefined }, undefined, {
    readTitle: async () => {
      reads += 1;
      markStarted?.();
      return await new Promise<{ title: string }>((resolve) => { resolveTitle = resolve; });
    },
    readSurface: async () => ({ events: [{ type: 'user/message' }] }),
  });
  const second = loader(reg, { get: () => undefined }, undefined, {
    readTitle: async () => {
      reads += 1;
      markStarted?.();
      return await new Promise<{ title: string }>((resolve) => { resolveTitle = resolve; });
    },
    readSurface: async () => ({ events: [{ type: 'user/message' }] }),
  });
  await started;
  assert.equal(reads, 1, 'concurrent cold requests share one enumeration even when TTL=0');
  resolveTitle?.({ title: 'fresh' });
  await Promise.all([first, second]);

  // No time-based cache at TTL=0: a request arriving after resolution recomputes.
  await loader(reg, { get: () => undefined }, undefined, {
    readTitle: async () => { secondRoundReads += 1; return { title: 'again' }; },
    readSurface: async () => ({ events: [{ type: 'user/message' }] }),
  });
  assert.equal(secondRoundReads, 1, 'a later request recomputes when TTL=0');
});
