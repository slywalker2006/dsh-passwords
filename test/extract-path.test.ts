// "未分组/新会话" 修复回归测试
// 覆盖三类根因修复：
//  1) alpha.2 ClientConnection 的真实业务参数只存在于 payload.args（部分 Session
//     endpoint 再使用 args.request）。已识别信封不得回退扫描外层诱导字段；否则网关
//     可能校验 A 路径而 DSH 实际执行 B 路径，形成 fail-open 越权。
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
  extractDirectoryCreatePath,
  extractWorkspaceCreatePath,
  WORKSPACE_ENDPOINT_RE,
  isWorkspaceCreate,
  isWorkspaceDirectoryCreate,
  isWorkspaceDeleteOrRename,
  extractWorkspaceRenamePaths,
  normalizePath,
  parseEndpointAllowlist,
  endpointAllowed,
} from '../src/permissions.js';

// ── 1) ClientConnection 参数边界 ───────────────────────────────────

test('端点登记表：只支持精确路径与尾部 /* 通配', () => {
  assert.deepEqual(parseEndpointAllowlist('/api/plugin/ws/terminal, /api/plugin/ws/terminal, /api/plugin/ws/*', 'TEST'), [
    '/api/plugin/ws/terminal',
    '/api/plugin/ws/*',
  ]);
  for (const value of ['/gateway/x', '/api/dsh-passwords/internal/x', '/*', '/x/../y', '/x%2fy', '/x?y=1']) {
    assert.throws(() => parseEndpointAllowlist(value, 'TEST'));
  }
});

test('endpointAllowed：精确路径与尾部通配的匹配口径一致（通配只放行直接子路径）', () => {
  const rules = ['/api/plugin/ws/terminal', '/api/plugin/ws/*'];
  assert.equal(endpointAllowed('/api/plugin/ws/terminal', rules), true, '精确路径命中');
  assert.equal(endpointAllowed('/api/plugin/ws/terminal/extra', rules), false, '精确路径不匹配更深路径');
  assert.equal(endpointAllowed('/api/plugin/ws/term', rules), true, '通配命中直接子路径');
  assert.equal(endpointAllowed('/api/plugin/ws/a/b', rules), false, '通配不匹配更深路径');
  assert.equal(endpointAllowed('/api/plugin/ws', rules), false, '通配不匹配基路径本身');
  assert.equal(endpointAllowed('/api/plugin/ws/', rules), false, '空子段不算直接子路径');
  assert.equal(endpointAllowed('/api/plugin/wsx/terminal', rules), false, '前缀相似但不共享路径分段不算命中');
  assert.equal(endpointAllowed('/api/other', rules), false, '未登记路径不命中');
  assert.equal(endpointAllowed('/api/plugin/ws/terminal', []), false, '空规则集 fail-closed');
});

test('R-A：extractPathFromBody 只采信 alpha.2 的 payload.args（防外层 decoy 越权）', () => {
  // session/create 的真实参数位于 args.request。
  const wire = {
    type: 'client-request', rpcId: 'wire-path', method: 'session/create',
    payload: { args: { request: { cwd: '/root/11' } } },
  };
  assert.equal(extractPathFromBody(wire), '/root/11', 'args.request.cwd 必须被识别为真实路径');

  // directoryPicker/list 的 path 直接位于 args；信封外同名字段会被 DSH strip，
  // 因而绝不能参与网关的授权判定。
  const direct = {
    type: 'client-request', rpcId: 'direct-path', method: 'directoryPicker/list',
    payload: { args: { path: '/root/22' } }, path: '/outside-decoy',
  };
  assert.equal(extractPathFromBody(direct), '/root/22', 'args.path 必须优先于外层诱导字段');

  const decoy = {
    type: 'client-request', rpcId: 'decoy-path', method: 'directoryPicker/list',
    payload: { args: {} }, path: '/root/11', cwd: '/root/11',
  };
  assert.equal(extractPathFromBody(decoy), null, 'args 无路径时不得回退到信封外层字段');
});

test('R-A：创建端点只采信上游实际执行的 path 字段', () => {
  const directory = {
    type: 'client-request', rpcId: 'create-directory', method: 'directoryPicker/createDirectory',
    payload: { args: { cwd: '/allowed', path: '/outside', name: 'x' } },
  };
  assert.equal(extractDirectoryCreatePath(directory), '/outside');

  const workspace = {
    type: 'client-request', rpcId: 'create-workspace', method: 'workspace/create',
    payload: { args: { request: { cwd: '/allowed', path: '/outside' } } },
  };
  assert.equal(extractWorkspaceCreatePath(workspace), '/outside');
  assert.equal(extractDirectoryCreatePath({
    type: 'client-request', rpcId: 'missing-path', method: 'directoryPicker/createDirectory',
    payload: { args: { cwd: '/allowed', name: 'x' } },
  }), null);
});

test('R-A：extractWorkspaceId 只采信 alpha.2 的 payload.args', () => {
  const wire = {
    type: 'client-request', rpcId: 'wire-workspace', method: 'session/create',
    payload: { args: { request: { workspaceId: 'ws-1' } } },
  };
  assert.equal(extractWorkspaceId(wire), 'ws-1', 'args.request.workspaceId 必须被识别');

  const decoy = {
    type: 'client-request', rpcId: 'decoy-workspace', method: 'session/create',
    payload: { args: {} }, workspaceId: 'ws-allowed',
  };
  assert.equal(extractWorkspaceId(decoy), null, 'args 无 workspaceId 时不得回退到信封外层字段');
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
