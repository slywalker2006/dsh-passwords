// 复审 R3：权限保存的权威校验此前会冷读完整会话日志（批量标题 + 无标题 session 的
// surface），而展示缓存是 TTL 作用域的另一套 loader，因此「展示缓存不能改善保存速度」。
//
// 契约修正：保存路径（internal/assignable-resources）改用实时 registry/archive 的
// 结构化权威枚举 listAssignableResources()——不读任何会话日志、不经过展示缓存；展示
// 路径（/workspaces 下拉）保留标题/初始化空槽过滤与 SWR 缓存。这里用行为测试与源码
// 契约测试固定两者边界，并证明保存路径的实时性（缓存后归档不被放行）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  createAssignableInventoryLoader,
  listAssignableResources,
  listAssignableWorkspaces,
} from '../src/plugin.js';

type Workspace = {
  path: string;
  title: string;
  sessionIds: readonly string[];
  status(): Promise<'ok' | 'missing-dir'>;
};

function workspace(path: string, sessionIds: readonly string[], status: 'ok' | 'missing-dir' = 'ok'): Workspace {
  return { path, title: path, sessionIds, status: async () => status };
}

function registry(workspaces: Workspace[], archivedSessionIds: readonly string[] = []) {
  return { list: () => workspaces, archivedSessionIds };
}

const INITIAL_EVENTS = [
  { type: 'session' },
  { type: 'permission/preset' },
  { type: 'sandbox/mode' },
  { type: 'approval/policy' },
  { type: 'subagent/model-selection-policy' },
];

test('R3：保存路径的权威集合来自实时 registry/archive，不读会话日志标题', async () => {
  const reg = registry(
    [
      workspace('/ws/ok', ['live', 'persisted-init-only']),
      workspace('/ws/missing', ['gone'], 'missing-dir'),
    ],
    ['archived'],
  );

  const resources = await listAssignableResources(reg);

  assert.deepEqual(resources.folders, ['/ws/ok'], 'missing-dir 工作区不可分配');
  // 无标题的持久化槽位仍在可分配集合——证明这里没有为“隐藏空槽”去读标题/日志。
  assert.deepEqual(resources.assignableSessions, ['live', 'persisted-init-only']);
  assert.deepEqual(resources.retainedSessions, ['archived']);
  assert.ok(!resources.assignableSessions.includes('archived'), '归档会话不可新增分配');
  assert.ok(!resources.assignableSessions.includes('gone'), 'missing-dir 工作区的会话不可分配');
});

test('R3：展示清单为隐藏空槽读日志，保存路径对同一 registry 零日志读取', async () => {
  const reg = registry([workspace('/ws/ok', ['blank-init-only'])]);
  const reads = { title: 0, surface: 0 };
  const query = {
    readTitle: async () => { reads.title += 1; return { title: '' }; },
    readSurface: async () => { reads.surface += 1; return { events: [] as Array<{ type: string }> }; },
    listEvents: async () => INITIAL_EVENTS,
  };

  const display = await listAssignableWorkspaces(reg, { get: () => undefined }, undefined, query);
  assert.deepEqual(display[0]?.sessions, [], '展示清单隐藏初始化专用空槽');
  assert.ok(reads.title + reads.surface > 0, '展示路径确实读取了会话日志');

  const before = { ...reads };
  const resources = await listAssignableResources(reg);
  assert.deepEqual(resources.assignableSessions, ['blank-init-only'], '保存路径按实时 registry 判定可分配');
  assert.deepEqual(reads, before, '保存路径不新增任何会话日志读取');
});

test('R3：缓存后归档的会话不被保存路径放行，但保留在 retained 中', async () => {
  const reg: { list: () => Workspace[]; archivedSessionIds: readonly string[] } = {
    list: () => [workspace('/ws/ok', ['s1'])],
    archivedSessionIds: [],
  };
  const query = {
    readTitle: async () => ({ title: 'Titled' }),
    readSurface: async () => ({ events: [{ type: 'user/message' }] }),
  };
  const loader = createAssignableInventoryLoader(60_000);

  const warm = await loader(reg, { get: () => undefined }, undefined, query);
  assert.deepEqual(warm[0]?.sessions.map((session) => session.id), ['s1']);

  reg.archivedSessionIds = ['s1'];
  const staleDisplay = await loader(reg, { get: () => undefined }, undefined, query);
  assert.deepEqual(staleDisplay[0]?.sessions.map((session) => session.id), ['s1'], '展示缓存在 TTL 窗口内仍含已归档会话');

  const authority = await listAssignableResources(reg);
  assert.deepEqual(authority.assignableSessions, [], '保存路径按实时 archive 排除已归档会话');
  assert.deepEqual(authority.retainedSessions, ['s1'], '已归档会话保留，既有授权不被全面撤销');
});

const pluginSource = readFileSync(path.join(import.meta.dirname, '..', 'src', 'plugin.ts'), 'utf8');

test('R3：internal/assignable-resources 直接使用 registry 权威枚举，不再走展示缓存或会话查询', () => {
  const start = pluginSource.indexOf("'/api/dsh-passwords/internal/assignable-resources'");
  const end = pluginSource.indexOf("'/api/dsh-passwords/internal/sandbox'", start);
  assert.ok(start >= 0 && end > start, '必须能定位内部资源路由');
  const handler = pluginSource.slice(start, end);

  assert.ok(handler.includes('listAssignableResources(registry)'), '必须直接调用 registry 权威枚举');
  for (const forbidden of [
    "ctx.get('sessionQuery')",
    "ctx.get('sessionTitle')",
    "ctx.get('sessions')",
    'loadAssignableInventory(',
    'loadFreshAssignableInventory',
  ]) {
    assert.ok(!handler.includes(forbidden), `内部保存权威路径不得依赖 ${forbidden}`);
  }
  assert.ok(!pluginSource.includes('loadFreshAssignableInventory'), '不再保留全量冷读的 fresh loader 实例');
});
