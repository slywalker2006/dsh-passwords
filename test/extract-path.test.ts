// "未分组/新会话" 修复回归测试
// 覆盖三类根因修复：
//  1) extractPathFromBody / extractWorkspaceId 递归跳过 args 伪包裹
//     （dsh 只消费顶层 payload.cwd/workspaceId，args 是客户端不用的假字段；
//      若把 args.cwd 当白名单依据 → fail-open 越权到默认工作区 /opt）
//  2) WORKSPACE_ENDPOINT_RE 只匹配 create、不再拦 fork
//     （fork 继承源会话 cwd，归属已由 SESSION_SCOPED_RE/needsOwnershipCheck 校验）
//  3) collectIdPathPairs 同时收集 obj.workspaceId 与 obj.id
//     （dsh 工作区对象实际是 {workspaceId,path,...}，没有顶层 id；漏收集
//      workspaceId 会让 session.create 带 workspaceId 时缓存搜不到 → fail-closed 403 功能缺失）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  collectIdPathPairs,
  extractWorkspaceId,
  extractPathFromBody,
  WORKSPACE_ENDPOINT_RE,
  isWorkspaceCreate,
  isWorkspaceDirectoryCreate,
  isWorkspaceDeleteOrRename,
  extractWorkspaceRenamePaths,
  normalizePath,
  parseWebSocketAllowlist,
  webSocketAccessForPath,
  isAdminOnlySidebarEndpoint,
} from '../src/permissions.js';

// ── 1) args 伪包裹跳过 ─────────────────────────────────────────────

test('WebSocket 白名单只支持精确路径和显式子路径', () => {
  assert.deepEqual(parseWebSocketAllowlist('/sidebar/ws/terminal, /sidebar/ws/terminal, /plugin/ws/*', 'TEST'), [
    '/sidebar/ws/terminal',
    '/plugin/ws/*',
  ]);
  assert.equal(webSocketAccessForPath('/plugin/ws/run', ['/plugin/ws/*'], [], 'admin', false), 'authenticated');
  assert.equal(webSocketAccessForPath('/plugin/ws', ['/plugin/ws/*'], [], 'admin', false), 'deny');
  assert.equal(webSocketAccessForPath('/plugin/ws/run', ['/plugin/ws/*'], [], 'user', false), 'deny');
  assert.equal(webSocketAccessForPath('/plugin/ws/run', ['/plugin/ws/*'], ['/plugin/ws/*'], 'user', false), 'authenticated');
  assert.equal(webSocketAccessForPath('/plugin/ws/run', ['/plugin/ws/*'], [], 'admin', false), 'authenticated');
  assert.equal(webSocketAccessForPath('/api/events.mux', [], [], 'user', true), 'authenticated');
  assert.equal(webSocketAccessForPath('/unknown', [], [], 'admin', false), 'deny');
  for (const value of ['/gateway/x', '/api/dsh-passwords/internal/x', '/*', '/x/../y', '/x%2fy', '/x?y=1']) {
    assert.throws(() => parseWebSocketAllowlist(value, 'TEST'));
  }
});

test('better-sidebar 宿主侧路由只允许主用户', () => {
  assert.equal(isAdminOnlySidebarEndpoint('/sidebar/api/fs.tree'), true);
  assert.equal(isAdminOnlySidebarEndpoint('/sidebar/upload'), true);
  assert.equal(isAdminOnlySidebarEndpoint('/sidebar/ws/terminal'), true);
  assert.equal(isAdminOnlySidebarEndpoint('/sidebar'), true);
  assert.equal(isAdminOnlySidebarEndpoint('/api/events.mux'), false);
  assert.equal(isAdminOnlySidebarEndpoint('/api/dsh-passwords/state'), false);
});

test('R-A：extractPathFromBody 跳过 args 伪包裹（防 fail-open 越权）', () => {
  // dsh 信封：payload 顶层 cwd 是真参数；args 下的 cwd 是 dsh 不消费的伪字段
  const wire = { type: 'client-request', rpcId: 1, method: 'session.create', payload: { cwd: '/root/11' } };
  assert.equal(extractPathFromBody(wire), '/root/11', 'payload 顶层 cwd 命中');

  // 攻击形态：只有 args.cwd（被 dsh 忽略，会用默认工作区 /opt）
  // 网关应视为无合法路径字段 → 返回 null（fail-closed 403）
  const evil = { type: 'client-request', rpcId: 1, method: 'session.create', payload: { args: { cwd: '/root/11' } } };
  assert.equal(extractPathFromBody(evil), null, 'args.cwd 必须被跳过');

  // 混合：payload.cwd 在、args.cwd 也在 → 取真参数
  const mixed = { ...evil, payload: { cwd: '/root/22', args: { cwd: '/root/11' } } };
  assert.equal(extractPathFromBody(mixed), '/root/22', '真参数优先，忽略 args.cwd');
});

test('R-A：extractWorkspaceId 跳过 args 伪包裹', () => {
  const wire = { type: 'client-request', rpcId: 1, method: 'session.create', payload: { workspaceId: 'ws-1' } };
  assert.equal(extractWorkspaceId(wire), 'ws-1', 'payload 顶层 workspaceId 命中');

  const evil = { type: 'client-request', rpcId: 1, method: 'session.create', payload: { args: { workspaceId: 'ws-3' } } };
  assert.equal(extractWorkspaceId(evil), null, 'args.workspaceId 必须被跳过');

  // 顶层 workspaceId 与 args 嵌套并存 → 取真参数
  const mixed = { ...evil, payload: { workspaceId: 'ws-2', args: { workspaceId: 'ws-3' } } };
  assert.equal(extractWorkspaceId(mixed), 'ws-2', '真参数优先');
});

// ── 2) WORKSPACE_ENDPOINT_RE 只拦 create ───────────────────────────

test('R-A：WORKSPACE_ENDPOINT_RE 只匹配 create 不匹配 fork', () => {
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session.create'), true, '斜杠风格 create');
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session/create'), true, '点号风格 create');
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session.fork'), false, 'fork 不做文件夹白名单');
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session/create2'), false, 'create2 不是 create');
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session.list'), false, 'list 不在此列');
  assert.equal(WORKSPACE_ENDPOINT_RE.test('/api/session.history'), false, 'history 不在此列');
});

test('工作区路径归一化和重命名字段提取保持一致', () => {
  assert.equal(normalizePath('/srv/a/../project'), '/srv/project');
  assert.deepEqual(extractWorkspaceRenamePaths({ payload: { oldPath: '/srv/a/../project', newPath: '/srv/project-renamed' } }), {
    oldPath: '/srv/a/../project',
    newPath: '/srv/project-renamed',
  });
  assert.equal(extractWorkspaceRenamePaths({ payload: { path: '/srv/project' } }), null);
});

test('工作区管理权限只开放创建、删除和重命名', () => {
  assert.equal(isWorkspaceCreate('/api/workspace.create'), true);
  assert.equal(isWorkspaceCreate('/api/workspace.add'), true);
  assert.equal(isWorkspaceCreate('/api/workspace.delete'), false);
  assert.equal(isWorkspaceDirectoryCreate('/api/host.createDirectory'), true);
  assert.equal(isWorkspaceDirectoryCreate('/api/host/createDirectory'), true);
  assert.equal(isWorkspaceDirectoryCreate('/api/directoryPicker/createDirectory'), true, 'alpha.3 directory picker');
  assert.equal(isWorkspaceDirectoryCreate('/api/directoryPicker.createDirectory'), true, 'legacy-compatible directory picker');
  assert.equal(isWorkspaceDirectoryCreate('/api/host.listDirectory'), false);
  assert.equal(isWorkspaceDirectoryCreate('/api/workspace.create'), false);
  assert.equal(isWorkspaceDeleteOrRename('/api/workspace.delete'), true);
  assert.equal(isWorkspaceDeleteOrRename('/api/workspace.rename'), true);
  assert.equal(isWorkspaceDeleteOrRename('/api/workspace.move'), false);
  assert.equal(isWorkspaceDeleteOrRename('/api/workspace.import'), false);
});

// ── 3) collectIdPathPairs 收集 workspaceId 与 id ───────────────────

test('R-A：collectIdPathPairs 收集 obj.workspaceId 与 obj.id', () => {
  const items = {
    items: [
      { workspaceId: 'ws-a', path: '/root/11', title: 'A', sessionIds: [] },
      { id: 'ws-b', path: '/root/22', title: 'B' },
      { title: 'C' }, // 无 id/workspaceId → 跳过
    ],
  };
  const m = collectIdPathPairs(items);
  assert.equal(m.get('ws-a'), '/root/11', 'workspaceId 形式收集');
  assert.equal(m.get('ws-b'), '/root/22', 'id 形式收集（兼容旧字段）');
  assert.equal(m.size, 2, '无 id 的对象不产生映射');
});
