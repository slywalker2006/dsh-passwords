// 权限模块安全关键纯函数的回归测试（之前零覆盖）：
// 沙盒降级 / 审批强制拒绝 / 会话归属过滤 / 权限路径过滤 / preset 解析。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  permissionPresetFromCommand,
  presetFromSettingsMutate,
  forceRejectApproval,
  clampSessionHistorySandbox,
  filterByPathField,
  filterOwnedSessionIds,
  filterSessionSearchItems,
  sandboxPresetRank,
  parseSessionAddress,
  isUploadRequest,
  parseEndpointAllowlist,
  parseEndpointRule,
  endpointAllowed,
  isOfficialRootPath,
  isOfficialApiRoute,
  isLegacyOfficialApiRoute,
  isOfficialFileReadRequest,
  fileReadTargetFromQuery,
  isOfficialSessionQueryRoute,
  sessionQueryTarget,
  OFFICIAL_API_NAMESPACES,
  SUBUSER_BLOCKED_API_NAMESPACES,
  SUBUSER_BLOCKED_API_ENDPOINTS,
  isSubuserBlockedApiPath,
  isSubuserBlockedRemoteEndpoint,
  classifySubuserPath,
  dynamicPluginStreamAllowed,
  isWorkspaceWrite,
  SESSION_SCOPED_RE,
  WORKSPACE_FILES_SESSION_METHODS,
  workspaceFilesMethodOf,
  isWorkspaceFilesSessionScopedRequest,
  parseWorkspaceFilesCall,
  workspaceFilesTargetAllowed,
  collectAuthorizedSessionIds,
  pathWithin,
  workspaceRegistrationAllowed,
  directoryEntryVisible,
} from '../src/permissions.js';

test('alpha.1：原始 session 上传路径纳入上传权限门卫', () => {
  assert.equal(isUploadRequest('POST', '/api/session/uploadFileBinary'), true);
  assert.equal(isUploadRequest('POST', '/api/fileUploads/upload'), true);
  assert.equal(isUploadRequest('GET', '/api/session/uploadFileBinary'), false);
  assert.equal(isUploadRequest('POST', '/api/third-party-uploads'), false, '第三方上传端点不再内置在官方门卫里');
});

// ── 端点登记表：可选传输前缀、匹配与子用户分类器 ──────────────────

test('parseEndpointAllowlist：接受可选能力/传输前缀并规范化大小写', () => {
  assert.deepEqual(parseEndpointAllowlist('WS:/api/a,Http:/api/b,Owner:/api/c,/api/d', 'TEST'), [
    'ws:/api/a',
    'http:/api/b',
    'owner:/api/c',
    '/api/d',
  ]);
});

test('parseEndpointRule：能力与传输前缀可任意组合/顺序', () => {
  assert.deepEqual(parseEndpointRule('owner:ws:/x'), { capability: 'owner-only', transport: 'ws', path: '/x' });
  assert.deepEqual(parseEndpointRule('ws:owner:/x'), { capability: 'owner-only', transport: 'ws', path: '/x' });
  assert.deepEqual(parseEndpointRule('http:/x'), { capability: 'ssh', transport: 'http', path: '/x' });
  assert.deepEqual(parseEndpointRule('/x'), { capability: 'ssh', transport: 'any', path: '/x' });
});

test('parseEndpointAllowlist：前缀后缺路径 / 非斜杠开头 / 非法字符 / 网关前缀均启动即失败', () => {
  assert.throws(() => parseEndpointAllowlist('ws:', 'TEST'), /missing a path/);
  assert.throws(() => parseEndpointAllowlist('owner:', 'TEST'), /missing a path/);
  assert.throws(() => parseEndpointAllowlist('ws:api/a', 'TEST'), /must start with \//);
  assert.throws(() => parseEndpointAllowlist('/api/a?x=1', 'TEST'), /query, encoding/);
  assert.throws(() => parseEndpointAllowlist('/gateway/login', 'TEST'), /gateway paths cannot be registered/);
  assert.throws(() => parseEndpointAllowlist('http:/api/dsh-passwords/internal/x', 'TEST'), /internal gateway paths/);
});

test('endpointAllowed：按传输与能力过滤（不传 capability 时两类规则都算命中）', () => {
  const rules = parseEndpointAllowlist('ws:/api/ws-only,http:/api/http-only,/api/both,owner:/api/owner', 'TEST');
  assert.equal(endpointAllowed('/api/both', rules), true);
  assert.equal(endpointAllowed('/api/both', rules, { transport: 'http' }), true);
  assert.equal(endpointAllowed('/api/both', rules, { transport: 'ws' }), true);
  assert.equal(endpointAllowed('/api/ws-only', rules, { transport: 'ws' }), true);
  assert.equal(endpointAllowed('/api/ws-only', rules, { transport: 'http' }), false);
  assert.equal(endpointAllowed('/api/http-only', rules, { transport: 'http' }), true);
  assert.equal(endpointAllowed('/api/http-only', rules, { transport: 'ws' }), false);
  assert.equal(endpointAllowed('/api/other', rules), false);
  assert.equal(endpointAllowed('/api/owner', rules), true, '不传 capability：两类规则都命中（SSRF 校验口径）');
  assert.equal(endpointAllowed('/api/owner', rules, { capability: 'ssh' }), false);
  assert.equal(endpointAllowed('/api/owner', rules, { capability: 'owner-only' }), true);
});

test('classifySubuserPath：传输过滤 + owner: 优先于 ssh + 官方/第三方划分', () => {
  const endpointRules = parseEndpointAllowlist(
    'ws:/api/plugin/terminal,http:/api/plugin/exec,/api/plugin/hosts,owner:/api/plugin/hosts',
    'TEST',
  );

  // 传输过滤
  assert.equal(classifySubuserPath('/api/plugin/terminal', { endpointRules, transport: 'ws' }), 'ssh');
  assert.equal(classifySubuserPath('/api/plugin/terminal', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/plugin/exec', { endpointRules, transport: 'http' }), 'ssh');
  assert.equal(classifySubuserPath('/api/plugin/exec', { endpointRules, transport: 'ws' }), 'third-party');

  // owner: 优先（同一路径同时以 ssh 与 owner: 登记）
  assert.equal(classifySubuserPath('/api/plugin/hosts', { endpointRules, transport: 'http' }), 'owner-only');
  assert.equal(classifySubuserPath('/api/plugin/hosts', { endpointRules, transport: 'ws' }), 'owner-only');

  // 官方面（/api 命名空间 + 官方根级路径）
  assert.equal(classifySubuserPath('/api/session/history', { endpointRules, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/workspace.list', { endpointRules, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/permissionPresets/catalog', { endpointRules, transport: 'http' }), 'official', 'alpha.1 官方权限预设目录');
  assert.equal(classifySubuserPath('/api/terminal/shells', { endpointRules, transport: 'http' }), 'third-party', 'terminal 命名空间故意不开放给子用户（远程 shell = 沙箱逃逸）');
  assert.equal(classifySubuserPath('/', { endpointRules, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/assets/app.js', { endpointRules, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/plugins/pkg/client.js', { endpointRules, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/dsh-passwords/state', { endpointRules, transport: 'http' }), 'platform');

  // 普通 DSH 扩展不需要逐插件登记；未知普通 API/根级路由直接通行。
  assert.equal(classifySubuserPath('/api/plugin-other/x', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/live-stats', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/third-party-panel/status', { endpointRules, transport: 'http' }), 'third-party');
});

test('classifySubuserPath：运行时清单通用适配 namespace 与根级路由', () => {
  const dynamicManifest = { generation: 'test', namespaces: new Set(['myPlugin']), streamEndpoints: new Set(['myPlugin/watch']), exactPaths: new Set<string>(), pathPrefixes: new Set<string>() };
  assert.equal(classifySubuserPath('/api/myPlugin/run', { endpointRules: [], transport: 'http', dynamicManifest }), 'official');
  assert.equal(classifySubuserPath('/api/unknown/run', { endpointRules: [], transport: 'http', dynamicManifest }), 'third-party');
  assert.equal(dynamicPluginStreamAllowed('myPlugin/watch', dynamicManifest), true);
  assert.equal(dynamicPluginStreamAllowed('myPlugin/unknown', dynamicManifest), false);
  const rootManifest = { generation: 'root', namespaces: new Set<string>(), streamEndpoints: new Set<string>(), exactPaths: new Set(['/extension/status']), pathPrefixes: new Set(['/extension/events']) };
  assert.equal(classifySubuserPath('/extension/status', { endpointRules: [], transport: 'http', dynamicManifest: rootManifest }), 'official');
  assert.equal(classifySubuserPath('/extension/events/live', { endpointRules: [], transport: 'http', dynamicManifest: rootManifest }), 'official');
  assert.equal(classifySubuserPath('/extension/unknown', { endpointRules: [], transport: 'http', dynamicManifest: rootManifest }), 'third-party');
});

test('classifySubuserPath：尾部 /* 只放行直接子路径（不放行基路径与更深层）', () => {
  const endpointRules = parseEndpointAllowlist('/api/plugin/*', 'TEST');
  assert.equal(classifySubuserPath('/api/plugin/one', { endpointRules, transport: 'http' }), 'ssh');
  assert.equal(classifySubuserPath('/api/plugin', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/plugin/one/two', { endpointRules, transport: 'http' }), 'third-party');
});

test('isOfficialRootPath：官方根级白名单（SPA 壳 / 静态 / 插件 bundle），其余根路径 fail-closed', () => {
  for (const allowed of [
    '/', '/index.html', '/favicon.ico', '/assets/app.js', '/plugins', '/plugins/pkg/client.js', '/logo.svg',
    '/open-in-app/apps', '/open-in-app/icon/vscode', '/open-in-app/open',
  ]) {
    assert.equal(isOfficialRootPath(allowed), true, `${allowed} 属官方根级`);
  }
  for (const denied of ['/third-party-panel/read', '/modlens', '/sidebar/ws/terminal', '/api/x', '/html', '/open-in-app/unknown']) {
    assert.equal(isOfficialRootPath(denied), false, `${denied} 不属官方根级`);
  }
});

test('alpha.2 命名空间门禁：officeToPdf/pluginManager 保持硬拒绝，Agent Teams可按动态清单适配', () => {
  const endpointRules = parseEndpointAllowlist('', 'TEST');

  // alpha.2 官方包 @deepseek-ai/dsh-office-to-pdf 注册 namespace: 'officeToPdf'，
  // 方法为 generation / render。但 render(workspaceFileScope, path, …) 接受绝对或
  // 工作区相对路径，scope 由请求头派生、作用域隔离依赖 workspaceFiles 实现
  // （只读审计：可能放行作用域外路径）。现有文档（含 compatibility-matrix.md）
  // 没有允许子用户使用该命名空间的既有政策；在专用授权守卫与真实 E2E 证明作用域
  // 隔离前，不归官方自动放行，两条通道与两种 API 形状一律 fail-closed。
  assert.equal(OFFICIAL_API_NAMESPACES.has('officeToPdf'), false);
  assert.equal(SUBUSER_BLOCKED_API_NAMESPACES.has('officeToPdf'), true);
  assert.equal(classifySubuserPath('/api/officeToPdf', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/officeToPdf/generation', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/officeToPdf/render', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/officeToPdf.render', { endpointRules, transport: 'http' }), 'third-party', '旧式 namespace.method 形状同口径');
  assert.equal(classifySubuserPath('/api/officeToPdf.generation', { endpointRules, transport: 'ws' }), 'third-party', '两条通道一致');

  // pluginManager = host 侧 pnpm 安装/卸载/运行第三方包（特权/RCE 面）：绝不进 official allowlist
  assert.equal(OFFICIAL_API_NAMESPACES.has('pluginManager'), false);
  assert.equal(classifySubuserPath('/api/pluginManager', { endpointRules, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/pluginManager/install', { endpointRules, transport: 'http' }), 'third-party');

  // agentTeams 不再硬编码拒绝；未出现在运行时 manifest 时仍默认拒绝。
  assert.equal(OFFICIAL_API_NAMESPACES.has('agentTeams'), false);
  assert.equal(classifySubuserPath('/api/agentTeams/spawn', { endpointRules, transport: 'http' }), 'third-party');
  const dynamic = { generation: 'agent-team', namespaces: new Set(['agentTeams']), streamEndpoints: new Set<string>(), exactPaths: new Set<string>(), pathPrefixes: new Set<string>() };
  assert.equal(classifySubuserPath('/api/agentTeams/spawn', { endpointRules, transport: 'http', dynamicManifest: dynamic }), 'official');
});

test('通用 SSH 登记规则不能改变 pluginManager / officeToPdf / terminal / dynamicCordisRunner 的分类，Agent Teams按动态清单适配', () => {
  // 宽泛规则（运维常见写法）不得把特权/未验证命名空间带进来
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const blockedPaths = [
    '/api/pluginManager',
    '/api/pluginManager/change',
    '/api/pluginManager/runPnpm',
    '/api/pluginManager.change',
    '/api/pluginManager.runPnpm',

    '/api/officeToPdf',
    '/api/officeToPdf/generation',
    '/api/officeToPdf/render',
    '/api/officeToPdf.generation',
    '/api/officeToPdf.render',
    '/api/terminal',
    '/api/terminal/list',
    '/api/terminal/create',
    '/api/terminal/write',
    '/api/terminal/follow',
    '/api/terminal/shells',
    '/api/terminal.environment',
    '/api/terminal.create',
  ];
  for (const path of blockedPaths) {
    assert.equal(classifySubuserPath(path, { endpointRules: generic, transport: 'http' }), 'third-party', `http ${path}`);
    assert.equal(classifySubuserPath(path, { endpointRules: generic, transport: 'ws' }), 'third-party', `ws ${path}`);
  }
  // Agent Teams 是动态已安装插件面；没有 manifest 时仍未知，维持 fail-closed。
  assert.equal(classifySubuserPath('/api/agentTeams/spawn', { endpointRules: generic, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: generic, transport: 'http' }), 'third-party');

  // 精确登记（含尾部 /* 通配）同样拿不到 ssh 分类：登记表不是硬拒绝的旁路；
  // terminal 的 allowSsh 放行由 gateway 的显式官方 terminal 分支完成。
  const scoped = parseEndpointAllowlist(
    '/api/pluginManager/*,/api/pluginManager.change,ws:/api/agentTeams/*,http:/api/agentTeams.spawn,/api/officeToPdf/*,/api/officeToPdf.render,/api/terminal/*,ws:/api/terminal/*,/api/dynamicCordisRunner/*,ws:/api/dynamicCordisRunner/*',
    'TEST',
  );
  assert.equal(classifySubuserPath('/api/pluginManager/change', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/pluginManager/change', { endpointRules: scoped, transport: 'ws' }), 'third-party');
  assert.equal(classifySubuserPath('/api/pluginManager.change', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: scoped, transport: 'ws' }), 'third-party');
  assert.equal(classifySubuserPath('/api/agentTeams/spawn', { endpointRules: scoped, transport: 'ws' }), 'ssh');
  assert.equal(classifySubuserPath('/api/officeToPdf/render', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/officeToPdf/render', { endpointRules: scoped, transport: 'ws' }), 'third-party');
  assert.equal(classifySubuserPath('/api/officeToPdf.render', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal/create', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal/create', { endpointRules: scoped, transport: 'ws' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal/write', { endpointRules: scoped, transport: 'ws' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal/list', { endpointRules: scoped, transport: 'http' }), 'third-party', '登记规则场景下 terminal/list 仍归 third-party（空成功伪装依赖此分类）');

  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: scoped, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: scoped, transport: 'ws' }), 'third-party');

  // owner: 登记的既有语义保留：子用户仍 403（owner-only），且不会被误判成 ssh
  const ownerOnly = parseEndpointAllowlist(
    'owner:/api/pluginManager/change,owner:/api/agentTeams.spawn,owner:/api/officeToPdf/render',
    'TEST',
  );
  assert.equal(classifySubuserPath('/api/pluginManager/change', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only');
  assert.equal(classifySubuserPath('/api/agentTeams.spawn', { endpointRules: ownerOnly, transport: 'ws' }), 'owner-only');
  assert.equal(classifySubuserPath('/api/officeToPdf/render', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only', '显式 owner: 登记仍先于硬拒绝（主用户语义不受影响）');

  // 前缀相近但不相同的命名空间不受硬拒绝影响（防误伤）
  assert.equal(classifySubuserPath('/api/pluginManagerBackup', { endpointRules: generic, transport: 'http' }), 'ssh');
  assert.equal(classifySubuserPath('/api/officeToPdfBackup', { endpointRules: generic, transport: 'http' }), 'ssh');

  // Agent Teams 随已安装扩展适配，宿主代码执行与 terminal 仍走专门边界。
  assert.deepEqual([...SUBUSER_BLOCKED_API_NAMESPACES].sort(), ['dynamicCordisRunner', 'officeToPdf', 'pluginManager', 'pluginRegistryProbe', 'productAnalytics', 'speech', 'terminal']);
});

test('宿主遥测、registry 探针和可选语音命名空间不落入普通插件透传面', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  for (const [namespace, method] of [['productAnalytics', 'report'], ['pluginRegistryProbe', 'fastest'], ['speech', 'configure']]) {
    for (const transport of ['http', 'ws'] as const) {
      for (const path of [`/api/${namespace}/${method}`, `/api/${namespace}.${method}`]) {
        assert.equal(isSubuserBlockedApiPath(path), true, path);
        assert.equal(classifySubuserPath(path, { endpointRules: none, transport }), 'third-party', path);
      }
    }
    assert.equal(isSubuserBlockedRemoteEndpoint(`${namespace}/${method}`), true);
  }
  assert.equal(isSubuserBlockedRemoteEndpoint('speech/follow'), true);
  assert.equal(isSubuserBlockedApiPath('/api/productAnalyticsBackup/report'), false);
});

test('子用户宿主写/出站探测端点 fail-closed：settings 写方法与 llm/discoverModels', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const exact = parseEndpointAllowlist('/api/settings/*,/api/llm/*,http:/api/settings/*', 'TEST');
  const hostWrites = ['settings/mutate', 'settings/update', 'settings/replace', 'llm/discoverModels'];
  // 动态清单声称已加载这些流也不能放行（宿主写面优先于运行时清单）。
  const dynamicManifest = {
    generation: 'host-write-guard',
    namespaces: new Set(['settings', 'llm']),
    streamEndpoints: new Set(hostWrites),
    exactPaths: new Set<string>(),
    pathPrefixes: new Set<string>(),
  };
  for (const endpoint of hostWrites) {
    assert.equal(isSubuserBlockedRemoteEndpoint(endpoint), true, endpoint);
    assert.equal(dynamicPluginStreamAllowed(endpoint, dynamicManifest), false, endpoint);
    for (const path of [`/api/${endpoint}`, `/api/${endpoint.replace('/', '.')}`]) {
      assert.equal(isSubuserBlockedApiPath(path), true, path);
      for (const transport of ['http', 'ws'] as const) {
        for (const rules of [none, generic, exact]) {
          assert.equal(classifySubuserPath(path, { endpointRules: rules, transport }), 'third-party', path);
        }
      }
    }
  }
  // 只读对照面保持可用：设置描述与已注册提供方枚举不是写/出站探测。
  for (const endpoint of ['settings/describe', 'llm/listProviders', 'llm/listConfigurableProviders']) {
    assert.equal(isSubuserBlockedRemoteEndpoint(endpoint), false, endpoint);
    assert.equal(isSubuserBlockedApiPath(`/api/${endpoint}`), false, endpoint);
  }
  // 边界只按官方端点收紧：第三方插件自己的同名/相近方法不被本边界误伤。
  for (const endpoint of ['thirdPartyPlugin/mutate', 'thirdPartyPlugin/update', 'settings/mutateExtra', 'llm/listProvidersV2']) {
    assert.equal(isSubuserBlockedRemoteEndpoint(endpoint), false, endpoint);
    assert.equal(isSubuserBlockedApiPath(`/api/${endpoint}`), false, endpoint);
  }
});

test('terminal 命名空间保持硬拒绝分类：allowSsh 放行由 gateway 显式处理（alpha.2 安全边界）', () => {
  // 仍然不进官方清单：terminal 是宿主侧远程 shell，对子用户开放 = 沙箱逃逸。
  assert.equal(OFFICIAL_API_NAMESPACES.has('terminal'), false);
  assert.equal(SUBUSER_BLOCKED_API_NAMESPACES.has('terminal'), true);

  // 空登记表：terminal 一律 third-party（两条通道、两种 API 形状同口径）；
  // gateway 只有在 allowSsh=true 时才对官方已知 terminal 端点透传。
  const none = parseEndpointAllowlist('', 'TEST');
  assert.equal(classifySubuserPath('/api/terminal/shells', { endpointRules: none, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal/list', { endpointRules: none, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/terminal.list', { endpointRules: none, transport: 'http' }), 'third-party');

  // 根因回归：
  //   generic   = 通用宽泛登记（运维常见写法）
  //   registered= 问题报告的精确写法 /api/terminal/* + ws:/api/terminal/*，
  //               此前会把 create/write/follow 分类为 ssh 并借 allow_ssh 放行
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const registered = parseEndpointAllowlist('/api/terminal/*,ws:/api/terminal/*', 'TEST');
  const terminalPaths = [
    '/api/terminal',
    '/api/terminal/list',
    '/api/terminal/create',
    '/api/terminal/write',
    '/api/terminal/follow',
    '/api/terminal/shells',
    '/api/terminal/environment',
    '/api/terminal/resize',
    '/api/terminal/rename',
    '/api/terminal/close',
    '/api/terminal/retain',
    '/api/terminal.list',
    '/api/terminal.create',
  ];
  for (const rules of [generic, registered]) {
    for (const path of terminalPaths) {
      assert.equal(classifySubuserPath(path, { endpointRules: rules, transport: 'http' }), 'third-party', `http ${path}`);
      assert.equal(classifySubuserPath(path, { endpointRules: rules, transport: 'ws' }), 'third-party', `ws ${path}`);
    }
  }

  // terminal/list 空成功伪装依赖 third-party 分支：登记场景下分类必须仍是 third-party
  assert.equal(classifySubuserPath('/api/terminal/list', { endpointRules: registered, transport: 'http' }), 'third-party');

  // owner: 登记的既有语义保留：显式 owner 仍先于硬拒绝（主用户语义不受影响）
  const ownerOnly = parseEndpointAllowlist('owner:/api/terminal/create', 'TEST');
  assert.equal(classifySubuserPath('/api/terminal/create', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only');

  // 前缀相近但不同的命名空间不受硬拒绝影响（防误伤）
  assert.equal(classifySubuserPath('/api/terminalBackup', { endpointRules: generic, transport: 'http' }), 'ssh');
  assert.equal(classifySubuserPath('/api/terminals.list', { endpointRules: generic, transport: 'http' }), 'ssh');
});

test('terminal：alpha.2 客户端会调用 list/environment/shells/close，网关按 allowSsh 切换桩与透传', () => {
  // terminal 不是“客户端不调用”：终端面板与顶栏会先探环境/list、再 create。
  // 分类层保持 third-party，真正的开关语义由 gateway 的 allowSsh 分支实现；关闭时
  // list/environment/shells/close 使用无能力桩，开启时已知 terminal RPC 才透传。
  const none = parseEndpointAllowlist('', 'TEST');
  const registered = parseEndpointAllowlist('/api/terminal/*,ws:/api/terminal/*', 'TEST');
  for (const method of ['list', 'environment', 'shells', 'close', 'create', 'write', 'follow', 'resize', 'rename', 'retain']) {
    for (const rules of [none, registered]) {
      assert.equal(classifySubuserPath(`/api/terminal/${method}`, { endpointRules: rules, transport: 'http' }), 'third-party', `http ${method}`);
      assert.equal(classifySubuserPath(`/api/terminal.${method}`, { endpointRules: rules, transport: 'ws' }), 'third-party', `ws ${method}`);
    }
  }
  assert.equal(OFFICIAL_API_NAMESPACES.has('terminal'), false);
});

// ── alpha.2 官方命名空间清理：清单固定 / 精确路由 / 遗留兼容 / 硬拒单端点 ──

test('OFFICIAL_API_NAMESPACES：alpha.1 实测清单精确固定（新增必须显式改测试与兼容性矩阵）', () => {
  assert.deepEqual([...OFFICIAL_API_NAMESPACES].sort(), [
    '$events',
    'account',
    'agentPresets',
    'commands',
    'credentials',
    'directoryPicker',
    'dynamicCordisRunner',
    'fileReferences',
    'fileUploads',
    'goals',
    'job',
    'llm',
    'messageFeedback',
    'permissionPresets',
    'pluginInventory',
    'remote.mux',
    'schedule',
    'session',
    'sessionFeedback',
    'sessionReferenceResolver',
    'settings',
    'skills',
    'subagents',
    'userQuestions',
    'workspace',
    'workspaceFiles',
  ]);
  // 本地名字空间式成员、非 RPC 的通用词、旧线遗留名、硬拒命名空间均不得混入
  for (const absent of ['dsh-composer', 'file', 'git', 'host', 'present', 'respond', 'events', 'terminal', 'pluginManager', 'pluginRegistryProbe', 'productAnalytics', 'speech', 'agentTeams', 'officeToPdf']) {
    assert.equal(OFFICIAL_API_NAMESPACES.has(absent), false, absent);
  }
});

test('dsh-composer 不是 host RPC：不再被当作 official（含全部子路径与点号形状）', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  for (const path of ['/api/dsh-composer', '/api/dsh-composer/anything', '/api/dsh-composer.anything']) {
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'third-party', path);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'ws' }), 'third-party', path);
  }
  // 登记表仍是唯一放行通道：主用户显式登记后子用户可用（ssh），owner: 语义不变
  const registered = parseEndpointAllowlist('/api/dsh-composer/*', 'TEST');
  assert.equal(classifySubuserPath('/api/dsh-composer/x', { endpointRules: registered, transport: 'http' }), 'ssh');
});

test('alpha.2 官方精确路由：changes / present / file 只按精确路径放行，同名第三方 namespace 不跟走', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  for (const path of ['/api/changes.summary', '/api/changes.diff', '/api/changes.open', '/api/present.host', '/api/present.open', '/api/file']) {
    assert.equal(isOfficialApiRoute(path), true, `${path} 属官方精确路由`);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'official', path);
  }
  // 不整命名空间放行：第三方同名 namespace 仍 fail-closed
  for (const path of [
    '/api/changes', '/api/changes.evil', '/api/changes/evil',
    '/api/present', '/api/present.evil', '/api/present/evil',
    '/api/file.evil', '/api/file/evil',
  ]) {
    assert.equal(isOfficialApiRoute(path), false, `${path} 不是官方精确路由`);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'third-party', path);
  }
  // 官方非 RPC 通道与会话日志导出仍按命名空间放行
  const officialChannels = ['/api/remote.mux', '/api/$events', '/api/$events/result', '/api/session.export'];
  for (const path of officialChannels) {
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'official', path);
  }
});

test('遗留兼容：respond / events / host 目录 / git 取数据只按精确端点保留，同名第三方 namespace 不跟走', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const legacyAllowed = [
    '/api/respond',
    '/api/events.host',
    '/api/events.mux',
    '/api/host.createDirectory',
    '/api/host/createDirectory',
    '/api/host.listDirectory',
    '/api/git.clone',
    '/api/git.pull',
    '/api/git.fetch',
    '/api/git/status',
  ];
  for (const path of legacyAllowed) {
    assert.equal(isLegacyOfficialApiRoute(path), true, `${path} 属旧线保留端点`);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'official', path);
  }

  // 同名命名空间的其它端点不再是 official：第三方插件不能借名获得官方待遇
  const notLegacy = [
    '/api/git', '/api/git.push', '/api/git/repoInfo', '/api/git.evil',
    '/api/host', '/api/host.evil', '/api/host/other', '/api/host.list',
    '/api/respond.evil', '/api/respond/other',
    '/api/events', '/api/events.other', '/api/events/other',
  ];
  for (const path of notLegacy) {
    assert.equal(isLegacyOfficialApiRoute(path), false, `${path} 不是旧线保留端点`);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'third-party', path);
  }

  // events 只保留点号形状：斜杠形状会让事件流绕过网关过滤，必须继续 third-party
  assert.equal(classifySubuserPath('/api/events/host', { endpointRules: none, transport: 'http' }), 'third-party');
  assert.equal(classifySubuserPath('/api/events/mux', { endpointRules: none, transport: 'http' }), 'third-party');

  // 未列入精确端点的遗留方法可由主用户显式登记（登记是唯一放行通道）
  const generic = parseEndpointAllowlist('/api/*', 'TEST');
  assert.equal(classifySubuserPath('/api/git.push', { endpointRules: generic, transport: 'http' }), 'ssh');
});

test('session/initializeDefaultModel：宿主全局模型初始化对子用户硬拒绝', () => {
  assert.equal(SUBUSER_BLOCKED_API_ENDPOINTS.has('session/initializeDefaultModel'), true);
  assert.equal(isSubuserBlockedApiPath('/api/session/initializeDefaultModel'), true);
  assert.equal(isSubuserBlockedApiPath('/api/session.initializeDefaultModel'), true);
});

test('directoryPicker/pick：宿主原生选择器对子用户硬拒绝，list/createDirectory 保留官方', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const exact = parseEndpointAllowlist('/api/directoryPicker/*,/api/directoryPicker.pick', 'TEST');

  assert.equal(SUBUSER_BLOCKED_API_NAMESPACES.has('directoryPicker'), false, '命名空间整体仍属官方');
  assert.equal(SUBUSER_BLOCKED_API_ENDPOINTS.has('directoryPicker/pick'), true);

  // 空表/通用/精确登记三种情形都会被硬拒绝先拦下（含点号形状与两条通道）
  for (const rules of [none, generic, exact]) {
    for (const path of ['/api/directoryPicker/pick', '/api/directoryPicker.pick']) {
      assert.equal(isSubuserBlockedApiPath(path), true, path);
      assert.equal(classifySubuserPath(path, { endpointRules: rules, transport: 'http' }), 'third-party', path);
      assert.equal(classifySubuserPath(path, { endpointRules: rules, transport: 'ws' }), 'third-party', path);
    }
  }

  // 同命名空间的浏览/创建不受影响（网关另有子树白名单、创建记账与响应过滤）
  assert.equal(classifySubuserPath('/api/directoryPicker/list', { endpointRules: none, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/directoryPicker/createDirectory', { endpointRules: none, transport: 'http' }), 'official');
  assert.equal(isSubuserBlockedApiPath('/api/directoryPicker/list'), false);

  // 前缀相近命名空间不误伤
  assert.equal(isSubuserBlockedApiPath('/api/directoryPickerBackup/pick'), false);
  assert.equal(classifySubuserPath('/api/directoryPickerBackup', { endpointRules: generic, transport: 'http' }), 'ssh');

  // owner: 登记的既有语义保留：显式 owner 仍先于硬拒绝
  const ownerOnly = parseEndpointAllowlist('owner:/api/directoryPicker/pick', 'TEST');
  assert.equal(classifySubuserPath('/api/directoryPicker/pick', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only');
});

test('0.1.7：硬拒绝端点集合精确固定（宿主级能力 + 无法校验归属的桌面动作）', () => {
  assert.deepEqual([...SUBUSER_BLOCKED_API_ENDPOINTS].sort(), [
    'account/cancelSignIn',

    'account/signOut',
    'account/startSignIn',
    'credentials/set',
    'credentials/unset',
    'directoryPicker/pick',
    'llm/discoverModels',
    'session/canOpenWorkspacePath',
    'session/initializeDefaultModel',
    'session/openWorkspacePath',
    'session/workspacePathApplications',
    'settings/mutate',
    'settings/openSettingsDocument',
    'settings/replace',
    'settings/update',
  ]);
});

test('0.1.7 硬拒新端点：精确方法先于登记表，且不按前缀/命名空间扩散', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const exact = parseEndpointAllowlist('/api/credentials/*,/api/settings/*,/api/session/*,/api/dynamicCordisRunner/*,/api/llm/*', 'TEST');
  const blocked = [
    'credentials/set', 'credentials/unset', 'settings/openSettingsDocument',
    'settings/mutate', 'settings/update', 'settings/replace',
    'llm/discoverModels',
    'session/openWorkspacePath', 'session/canOpenWorkspacePath', 'session/workspacePathApplications',

  ];
  for (const endpoint of blocked) {
    const slash = `/api/${endpoint}`;
    const dot = `/api/${endpoint.replace('/', '.')}`;
    assert.equal(isSubuserBlockedApiPath(slash), true, slash);
    assert.equal(isSubuserBlockedApiPath(dot), true, dot);
    for (const rules of [none, generic, exact]) {
      assert.equal(classifySubuserPath(slash, { endpointRules: rules, transport: 'http' }), 'third-party', slash);
      assert.equal(classifySubuserPath(dot, { endpointRules: rules, transport: 'ws' }), 'third-party', dot);
    }
  }
  // 精确匹配：普通命名空间的前缀相近方法不被顺带硬拒
  for (const path of [
    '/api/credentials/setExtra', '/api/credentials.settings',
    '/api/settings/openSettingsDocumentExtra',
    '/api/settings/mutateExtra', '/api/settings.updateSettings', '/api/settings/replacer',
    '/api/settings2/mutate', '/api/llm/discoverModelsExtra', '/api/llmX/discoverModels',
    '/api/llm.discoverModelsBackup',
    '/api/session/openWorkspacePathExtra', '/api/session/canOpenWorkspacePathX',
    '/api/credentialsX/set', '/api/settings2/openSettingsDocument',
  ]) {
    assert.equal(isSubuserBlockedApiPath(path), false, path);
  }
  // 普通官方命名空间的其它方法仍可按既有规则进入 official；动态 Cordis 是整体硬拒，
  // 所有已知、未知、未来方法及命名空间根路径都必须 fail-closed。
  for (const path of ['/api/credentials/rotate', '/api/settings/describe', '/api/settings.describe', '/api/llm/listProviders', '/api/llm.listConfigurableProviders', '/api/session/history']) {
    assert.equal(isSubuserBlockedApiPath(path), false, path);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'official', path);
  }
  for (const path of [
    '/api/dynamicCordisRunner', '/api/dynamicCordisRunner/',
    '/api/dynamicCordisRunner/getClientCode', '/api/dynamicCordisRunner/runHostHalf',
    '/api/dynamicCordisRunner/unknownMethod', '/api/dynamicCordisRunner/v1/futureMethod',
    '/api/dynamicCordisRunner.getClientCode', '/api/dynamicCordisRunner.runHostHalf',
  ]) {
    assert.equal(isSubuserBlockedApiPath(path), true, path);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'third-party', path);
    assert.equal(classifySubuserPath(path, { endpointRules: generic, transport: 'ws' }), 'third-party', path);
    assert.equal(SESSION_SCOPED_RE.test(path), false, path);
  }
  // owner: 登记的既有语义保留：显式 owner 仍先于硬拒，网关随后统一 403
  const ownerOnly = parseEndpointAllowlist('owner:/api/credentials/set,owner:/api/dynamicCordisRunner/runHostHalf', 'TEST');
  assert.equal(classifySubuserPath('/api/credentials/set', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only');
  assert.equal(classifySubuserPath('/api/dynamicCordisRunner/runHostHalf', { endpointRules: ownerOnly, transport: 'http' }), 'owner-only');
});

// ── 0.1.7-alpha.1：工作区写谓词与第三方命名空间口径 ───────────────

test('isWorkspaceWrite：workspace/initializeDefault 纳入 fail-closed 工作区写', () => {
  assert.equal(isWorkspaceWrite('/api/workspace/initializeDefault'), true);
  assert.equal(isWorkspaceWrite('/api/workspace.initializeDefault'), true);
  assert.equal(isWorkspaceWrite('/api/workspace/initializeDefaultExtra'), false, '前缀相近不误伤');
  assert.equal(isWorkspaceWrite('/api/session/initializeDefault'), false, '不可跨命名空间误命中');
  // 原有写动词口径不变
  for (const method of ['add', 'create', 'remove', 'delete', 'rename', 'update', 'import', 'move', 'insertBefore', 'insertSessionBefore', 'materialize', 'adopt']) {
    assert.equal(isWorkspaceWrite(`/api/workspace/${method}`), true, method);
  }
  // 会话导航状态写（pin/unpin/unarchive/archiveSession）不是工作区写：
  // 它们由 SESSION_SCOPED_RE 逐会话校验，若进本谓词会变成对子用户整类 403
  for (const method of ['archiveSession', 'pinSession', 'unpinSession', 'unarchiveSession']) {
    assert.equal(isWorkspaceWrite(`/api/workspace/${method}`), false, method);
  }
});

test('0.1.7 alpha.2 官方 job/account 面：写入和未登记第三方仍 fail-closed', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');
  const managerOnly = parseEndpointAllowlist('/api/pluginManager,ws:/api/pluginManager', 'TEST');
  assert.equal(OFFICIAL_API_NAMESPACES.has('job'), true);
  assert.equal(OFFICIAL_API_NAMESPACES.has('account'), true);
  assert.equal(OFFICIAL_API_NAMESPACES.has('pluginManager'), false);
  assert.equal(classifySubuserPath('/api/job/unknown', { endpointRules: none, transport: 'http' }), 'official', 'job wire 保持上游兼容');
  assert.equal(classifySubuserPath('/api/account/unknown', { endpointRules: none, transport: 'http' }), 'third-party', 'account 未知 unary 方法对子用户拒绝');
  assert.equal(classifySubuserPath('/api/account', { endpointRules: none, transport: 'http' }), 'third-party', 'account namespace root 不应绕过只读方法白名单');
  for (const path of ['/api/pluginManager/install', '/api/pluginManager.install']) {
    assert.equal(SESSION_SCOPED_RE.test(path), false, `${path} 不得被纳入归属校验面`);
    assert.equal(classifySubuserPath(path, { endpointRules: none, transport: 'http' }), 'third-party', `${path} 未登记时必须拒绝`);
  }
  // pluginManager 在硬拒集合里：即使是主用户显式登记（http/ws）也照样拦下
  assert.equal(isSubuserBlockedApiPath('/api/pluginManager/install'), true);
  assert.equal(isSubuserBlockedApiPath('/api/pluginManager.install'), true);
  for (const transport of ['http', 'ws'] as const) {
    assert.equal(classifySubuserPath('/api/pluginManager/install', { endpointRules: managerOnly, transport }), 'third-party', transport);
  }
  // account 登录写操作硬拒；profile/balance 保持产品选定的宿主只读视图。
  for (const method of ['startSignIn', 'cancelSignIn', 'signOut']) {
    assert.equal(isSubuserBlockedApiPath(`/api/account/${method}`), true, method);
  }
  assert.equal(isSubuserBlockedApiPath('/api/account/getProfile'), false);
  assert.equal(isSubuserBlockedApiPath('/api/account/getBalance'), false);
  assert.equal(isSubuserBlockedApiPath('/api/account/getState'), false);
  assert.equal(isSubuserBlockedApiPath('/api/account/unknown'), true);
  assert.equal(isSubuserBlockedApiPath('/api/account'), true);
  assert.equal(classifySubuserPath('/api/account/getState', { endpointRules: generic, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/job/list', { endpointRules: generic, transport: 'http' }), 'official');
});

// ── workspaceFiles / present / changes：会话作用域与文件边界 ────────

/** alpha.2 ClientConnection 信封（真实 wire：POST /api/<namespace>/<method>） */
const wsEnvelope = (method: string, args: Record<string, unknown>): unknown => ({
  type: 'client-request',
  rpcId: 'rpc-1',
  method,
  payload: { args },
});

test('workspaceFiles：七个会话方法纳入 SESSION_SCOPED_RE（点号/斜杠同口径）', () => {
  for (const method of WORKSPACE_FILES_SESSION_METHODS) {
    assert.equal(SESSION_SCOPED_RE.test(`/api/workspaceFiles/${method}`), true, method);
    assert.equal(SESSION_SCOPED_RE.test(`/api/workspaceFiles.${method}`), true, method);
    assert.equal(isWorkspaceFilesSessionScopedRequest(`/api/workspaceFiles/${method}`), true, method);
    assert.equal(workspaceFilesMethodOf(`/api/workspaceFiles.${method}`), method);
  }
  // 未知/未来的方法不纳入（也不误伤前缀相近的命名空间）
  assert.equal(workspaceFilesMethodOf('/api/workspaceFiles/write'), null);
  assert.equal(SESSION_SCOPED_RE.test('/api/workspaceFiles/write'), false);
  assert.equal(isWorkspaceFilesSessionScopedRequest('/api/workspaceFiles'), false);
  assert.equal(SESSION_SCOPED_RE.test('/api/workspaceFiles'), false);
  assert.equal(workspaceFilesMethodOf('/api/workspaceFilesBackup/read'), null);
  // 目标目录判定需要会话根作参照，逐会话关闭语义仍由网关的归属校验落地
  assert.equal(SESSION_SCOPED_RE.test('/api/workspaceFiles/read'), true);
});

test('0.1.7：sessionFeedback/record 与 goals/get 纳入会话作用域（点号/斜杠同口径）', () => {
  for (const endpoint of ['sessionFeedback/record', 'goals/get']) {
    assert.equal(SESSION_SCOPED_RE.test(`/api/${endpoint}`), true, endpoint);
    assert.equal(SESSION_SCOPED_RE.test(`/api/${endpoint.replace('/', '.')}`), true, `${endpoint} 点号形状`);
  }
  // 前缀相近的方法不被顺带纳入
  assert.equal(SESSION_SCOPED_RE.test('/api/sessionFeedback/records'), false);
  assert.equal(SESSION_SCOPED_RE.test('/api/goals/getExtra'), false);
  assert.equal(SESSION_SCOPED_RE.test('/api/goals/gett'), false);
  // 它们是归属校验而不是硬拒：两条收紧路径互不替代
  assert.equal(isSubuserBlockedApiPath('/api/sessionFeedback/record'), false);
  assert.equal(isSubuserBlockedApiPath('/api/goals/get'), false);
});

test('0.1.7-rc.2：schedule 官方化，list/history/update/delete 走会话归属，catalog 官方放行并由网关过滤', () => {
  const none = parseEndpointAllowlist('', 'TEST');
  const generic = parseEndpointAllowlist('/api/*,ws:/api/*,http:/api/*', 'TEST');

  // 命名空间整体进入官方清单：登记表为空时也不再是 third-party
  assert.equal(OFFICIAL_API_NAMESPACES.has('schedule'), true);
  assert.equal(isSubuserBlockedApiPath('/api/schedule/list'), false);
  assert.equal(classifySubuserPath('/api/schedule/list', { endpointRules: none, transport: 'http' }), 'official');

  // 四个带 request.sessionId 的方法逐会话归属校验（点号/斜杠同口径）
  for (const method of ['list', 'history', 'update', 'delete']) {
    assert.equal(SESSION_SCOPED_RE.test(`/api/schedule/${method}`), true, method);
    assert.equal(SESSION_SCOPED_RE.test(`/api/schedule.${method}`), true, `${method} 点号形状`);
  }
  // 前缀相近的方法/命名空间不被顺带纳入
  for (const path of ['/api/schedule/listExtra', '/api/schedule/listAll', '/api/schedule', '/api/scheduleList/list', '/api/schedules/list']) {
    assert.equal(SESSION_SCOPED_RE.test(path), false, path);
  }

  // catalog 无会话身份：不进归属校验面，但对子用户不再硬拒——官方分类放行，
  // 授权边界改由 gateway 解析响应后按条目 sessionId 过滤（见 gateway-proxy 的
  // SCHEDULE_CATALOG_RE）。此处只断言分类面：空登记表下两种形状与两条通道均为
  // official；宽泛的 /api/* 规则会以 ssh 命中点号形状（登记表既有语义，与本次改动
  // 无关），但不再落入 third-party 硬拒；响应过滤与分类无关、始终执行。
  assert.equal(SESSION_SCOPED_RE.test('/api/schedule/catalog'), false);
  assert.equal(SESSION_SCOPED_RE.test('/api/schedule.catalog'), false);
  assert.equal(isSubuserBlockedApiPath('/api/schedule/catalog'), false);
  assert.equal(isSubuserBlockedApiPath('/api/schedule.catalog'), false);
  assert.equal(classifySubuserPath('/api/schedule/catalog', { endpointRules: none, transport: 'http' }), 'official');
  assert.equal(classifySubuserPath('/api/schedule.catalog', { endpointRules: none, transport: 'ws' }), 'official');
  assert.equal(classifySubuserPath('/api/schedule/catalog', { endpointRules: generic, transport: 'http' }), 'official');
  assert.equal(
    classifySubuserPath('/api/schedule.catalog', { endpointRules: generic, transport: 'http' }),
    'ssh',
    '宽泛 /api/* 登记把点号形状归为已登记 ssh（非 official），但已不再是 third-party 硬拒',
  );
  // 逐方法精确相等：依赖归属校验的其它方法不受影响，前缀相近不误伤
  // （catalogExtra 仍是 schedule 官方命名空间下的未知方法，不为 catalog 过滤器命中）
  assert.equal(isSubuserBlockedApiPath('/api/schedule/list'), false);
  assert.equal(isSubuserBlockedApiPath('/api/schedule/catalogExtra'), false);
});

test('present.open / changes.open 按 POST 会话作用域纳入（query 会话身份由网关回落采集）', () => {
  assert.equal(SESSION_SCOPED_RE.test('/api/present.open'), true);
  assert.equal(SESSION_SCOPED_RE.test('/api/changes.open'), true);
  // 同批路由里只有 GET 的成员盖不到：归属校验只跑写方法，GET 侧必须靠专用谓词
  assert.equal(SESSION_SCOPED_RE.test('/api/changes.summary'), false);
  assert.equal(SESSION_SCOPED_RE.test('/api/changes.diff'), false);
  assert.equal(isOfficialSessionQueryRoute('/api/changes.summary'), true);
  assert.equal(isOfficialSessionQueryRoute('/api/changes.diff'), true);
  assert.equal(isOfficialSessionQueryRoute('/api/present.open'), true);
  assert.equal(isOfficialSessionQueryRoute('/api/present.host'), false, 'present.host 不带会话身份');
  assert.equal(isOfficialSessionQueryRoute('/api/present/other'), false);
});

test('/api/file：官方 GET/HEAD 读取路由 + 严格绝对路径解析（fail-closed）', () => {
  assert.equal(isOfficialFileReadRequest('GET', '/api/file'), true);
  assert.equal(isOfficialFileReadRequest('HEAD', '/api/file'), true);
  assert.equal(isOfficialFileReadRequest('POST', '/api/file'), false);
  assert.equal(isOfficialFileReadRequest('GET', '/api/file/x'), false);
  assert.equal(isOfficialFileReadRequest('GET', '/api/fileUploads/upload'), false, '前缀相近不误伤');

  assert.equal(fileReadTargetFromQuery(new URLSearchParams('path=/etc/hosts')), '/etc/hosts');
  assert.equal(fileReadTargetFromQuery(new URLSearchParams({ path: '/w/../etc/passwd' })), '/etc/passwd', '点段先归一化');
  assert.equal(fileReadTargetFromQuery({ path: '/etc/hosts' }), '/etc/hosts', '普通对象容器同样受理');
  assert.equal(fileReadTargetFromQuery(new URLSearchParams('path=relative/x')), null, '相对路径无法判定 → null');
  assert.equal(fileReadTargetFromQuery(new URLSearchParams('other=/etc/hosts')), null);
  assert.equal(fileReadTargetFromQuery(new URLSearchParams('path=')), null);
  assert.equal(fileReadTargetFromQuery(new URLSearchParams('path=%00/etc/x')), null, 'NUL 注入 → null');
  assert.equal(fileReadTargetFromQuery(null), null);
  assert.equal(fileReadTargetFromQuery('path=/etc/hosts'), null, '未识别的容器形状 → null');
});

test('sessionQueryTarget：严格取会话身份与坐标（fail-closed）', () => {
  assert.deepEqual(sessionQueryTarget(new URLSearchParams('sessionId=s1&seq=2&index=0')), { sessionId: 's1', seq: 2, index: 0 });
  assert.deepEqual(sessionQueryTarget({ sessionId: 's1', seq: '3' }), { sessionId: 's1', seq: 3, index: null });
  assert.deepEqual(sessionQueryTarget(new URLSearchParams('sessionId=s1')), { sessionId: 's1', seq: null, index: null });
  assert.equal(sessionQueryTarget(new URLSearchParams('seq=1&index=0')), null, '缺会话身份 → null');
  assert.equal(sessionQueryTarget(new URLSearchParams('sessionId=')), null);
  assert.equal(sessionQueryTarget(new URLSearchParams({ sessionId: 'x'.repeat(201) })), null, '超长会话身份 → null');
  assert.deepEqual(
    sessionQueryTarget(new URLSearchParams('sessionId=s1&seq=-1&index=abc')),
    { sessionId: 's1', seq: null, index: null },
    '非法坐标记为 null，不编造 0',
  );
  assert.equal(sessionQueryTarget(null), null);
});

test('SESSION_SCOPED_RE 匹配 userQuestions/answer 的点号与斜杠写法', () => {
  assert.equal(SESSION_SCOPED_RE.test('/api/userQuestions/answer'), true);
  assert.equal(SESSION_SCOPED_RE.test('/api/userQuestions.answer'), true);
  assert.equal(SESSION_SCOPED_RE.test('/api/userQuestions/attachWait'), false);
});

test('collectAuthorizedSessionIds 从 userQuestions/answer 提取 agentId', () => {
  const frame = {
    type: 'client-request',
    method: 'userQuestions/answer',
    payload: { args: { agentId: 's1', callId: 'c', answer: {} } },
  };
  assert.deepEqual(collectAuthorizedSessionIds(frame), new Set(['s1']));
  // 缺 agentId 时不收集任何会话身份（空集合），调用方据此 fail-closed 拒绝
  assert.deepEqual(
    collectAuthorizedSessionIds({ ...frame, payload: { args: { callId: 'c' } } }),
    new Set(),
  );
});

test('collectAuthorizedSessionIds：workspaceFileScopeId 必须作为会话身份参与归属校验', () => {
  const ids = collectAuthorizedSessionIds(wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1', path: '/w/a.txt' }));
  assert.deepEqual([...(ids ?? [])], ['s1']);
  // 非字符串值 → 整体 fail-closed（返回 null，调用方必须拒绝）
  assert.equal(collectAuthorizedSessionIds(wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 7, path: '/w/a.txt' })), null);
  // 与其他会话身份字段并列收集：任一未授权都会让调用方 403
  const both = collectAuthorizedSessionIds(wsEnvelope('session/prompt', { workspaceFileScopeId: 's1', sessionId: 's2' }));
  assert.deepEqual([...(both ?? [])].sort(), ['s1', 's2']);
  assert.equal(collectAuthorizedSessionIds({ sessionId: 'legacy' })?.has('legacy'), true, '非信封旧协议形状照旧受理');
});

test('parseWorkspaceFilesCall：严格解出会话身份与读取目标（fail-closed）', () => {
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1', path: '/w/a.txt' })),
    { method: 'read', scopeId: 's1', targetPath: '/w/a.txt', absolute: true },
  );
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/list', wsEnvelope('workspaceFiles/list', { workspaceFileScopeId: 's1', path: 'src' })),
    { method: 'list', scopeId: 's1', targetPath: 'src', absolute: false },
  );
  // changes：0.1.7 已是带 path 的 stream，但本模块恒不产出 targetPath（fail-closed，
  // 网关对子用户整类拒绝该流），path 不作为放行依据。
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles.changes', wsEnvelope('workspaceFiles/changes', { workspaceFileScopeId: 's1' })),
    { method: 'changes', scopeId: 's1', targetPath: null, absolute: false },
    'changes 不产出 targetPath',
  );
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles.changes', wsEnvelope('workspaceFiles/changes', { workspaceFileScopeId: 's1', path: '/w/a.txt' })),
    { method: 'changes', scopeId: 's1', targetPath: null, absolute: false },
    '0.1.7 带 path 的 changes 也不把它当授权输入',
  );
  // readRelated：按宿主语义（resolve(dirname(path), relativePath)）解析真实目标
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
      workspaceFileScopeId: 's1', path: '/w/sub/a.md', relativePath: '../../etc/passwd',
    })),
    { method: 'readRelated', scopeId: 's1', targetPath: '/etc/passwd', absolute: true },
    '逃逸目标必须显式暴露给调用方判定',
  );
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
      workspaceFileScopeId: 's1', path: '/w/a.md', relativePath: 'sibling.txt',
    })),
    { method: 'readRelated', scopeId: 's1', targetPath: '/w/sibling.txt', absolute: true },
  );
  assert.equal(
    parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
      workspaceFileScopeId: 's1', path: '/w/a.md', relativePath: '/etc/hosts',
    })),
    null,
    '绝对 relativePath 不符合 alpha.2 readRelated 形状，必须直接拒绝',
  );

  // 形状不符一律 null：调用方必须拒绝，不能回落到默认值
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', { sessionId: 's1', path: '/w/a.txt' }), null, '无 ClientConnection 信封');
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { path: '/w/a.txt' })), null, '缺会话身份');
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: '', path: '/w/a.txt' })), null);
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1' })), null, '缺路径');
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1', path: '' })), null);
  assert.equal(parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1', path: 7 })), null);
  assert.equal(
    parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', { workspaceFileScopeId: 's1', path: '/w/a.md' })),
    null,
    '缺 relativePath',
  );
  assert.equal(parseWorkspaceFilesCall('/api/terminal/list', wsEnvelope('terminal/list', { workspaceFileScopeId: 's1' })), null, '非 workspaceFiles 路径');
});

test('readBytes：0.1.7 options 形状 fail-closed，baseFile 一律拒绝', () => {
  const readBytes = (args: Record<string, unknown>): unknown =>
    parseWorkspaceFilesCall('/api/workspaceFiles/readBytes', wsEnvelope('workspaceFiles/readBytes', args));
  const scope = { workspaceFileScopeId: 's1', path: '/w/a.bin' };
  const parsed = { method: 'readBytes', scopeId: 's1', targetPath: '/w/a.bin', absolute: true };

  // 0.1.7 合法形状：options 是 plain object，只带 range（未读全部/默认窗口/显式窗口）
  assert.deepEqual(readBytes({ ...scope, options: {} }), parsed);
  assert.deepEqual(readBytes({ ...scope, options: { range: {} } }), parsed);
  assert.deepEqual(readBytes({ ...scope, options: { range: { offset: 0, length: 4096 } } }), parsed);
  // 相对 path 仍按会话根解析（绝对/相对判定不受 options 影响）
  assert.deepEqual(
    readBytes({ workspaceFileScopeId: 's1', path: 'media/a.bin', options: { range: { length: 16 } } }),
    { method: 'readBytes', scopeId: 's1', targetPath: 'media/a.bin', absolute: false },
  );
  // 0.1.6 旧的两参数 readBytes（那代 wire 没有 options）不因本次收紧而回归
  assert.deepEqual(readBytes(scope), parsed);

  // baseFile 会改变 path 的解析基准 → 无论值是什么一律拒绝
  assert.equal(readBytes({ ...scope, options: { baseFile: '/etc/passwd' } }), null, '绝对 baseFile');
  assert.equal(readBytes({ ...scope, options: { baseFile: 'sibling.txt' } }), null, '相对 baseFile');
  assert.equal(readBytes({ ...scope, options: { baseFile: null } }), null, '不可解析的 baseFile 也拒绝');
  assert.equal(readBytes({ ...scope, options: { range: { offset: 0 }, baseFile: '/etc' } }), null, 'range+baseFile 组合');
  assert.equal(
    readBytes({ workspaceFileScopeId: 's1', path: 'a.bin', options: { baseFile: '/w/other.bin' } }),
    null,
    '工作区内的 path 也不能借 baseFile 换解析基准',
  );

  // options 存在时必须是 plain object；未知键/非法 range 同样拒绝
  assert.equal(readBytes({ ...scope, options: null }), null);
  assert.equal(readBytes({ ...scope, options: 'range' }), null);
  assert.equal(readBytes({ ...scope, options: [] }), null);
  assert.equal(readBytes({ ...scope, options: { length: 10 } }), null, '未知键（read 的 limit/length 不属于 readBytes options）');
  assert.equal(readBytes({ ...scope, options: { range: { limit: 10 } } }), null, "readBytes 的窗口字段是 length，不是 read 的 limit");
  assert.equal(readBytes({ ...scope, options: { range: 5 } }), null);
  assert.equal(readBytes({ ...scope, options: { range: null } }), null);
  assert.equal(readBytes({ ...scope, options: { range: { offset: -1 } } }), null, '负偏移');
  assert.equal(readBytes({ ...scope, options: { range: { offset: 1.5 } } }), null, '非整数偏移');
  assert.equal(readBytes({ ...scope, options: { range: { length: '4096' } } }), null);

  // 不误伤其余方法：0.1.6/0.1.7 的 read / readRelated 都没有 options 参数
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/read', wsEnvelope('workspaceFiles/read', { workspaceFileScopeId: 's1', path: '/w/a.txt' })),
    { method: 'read', scopeId: 's1', targetPath: '/w/a.txt', absolute: true },
  );
  assert.deepEqual(
    parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
      workspaceFileScopeId: 's1', path: '/w/a.md', relativePath: 'b.md',
    })),
    { method: 'readRelated', scopeId: 's1', targetPath: '/w/b.md', absolute: true },
    'readRelated 不受 readBytes options 收紧影响',
  );
});

test('workspaceFilesTargetAllowed：读取目标的目录白名单边界（含相对与逃逸路径）', () => {
  const folders = ['/root/11'];
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/11/a.txt', absolute: true }, '/root/11', folders), true);
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/etc/passwd', absolute: true }, '/root/11', folders), false, '工作区外绝对路径拒绝');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/12/a.txt', absolute: true }, '/root/11', folders), false);
  assert.equal(workspaceFilesTargetAllowed({ targetPath: 'src/a.ts', absolute: false }, '/root/11', folders), true, '相对路径按会话根解析');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '../12/a.ts', absolute: false }, '/root/11', folders), false, '相对逃逸解析后不在会话根内');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/12/a.ts', absolute: true }, '/root/11', ['/root']), false, '白名单更宽也必须在会话根内');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/11/a.txt', absolute: true }, null, folders), false, '不知会话根 → fail-closed');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: 'src/a.ts', absolute: false }, '', folders), false);
  assert.equal(workspaceFilesTargetAllowed({ targetPath: null, absolute: false }, '/root/11', folders), false, 'changes 无路径可判定 → 不得默认放行');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/11/a.txt', absolute: true }, '/root/11', []), true, '空白名单 = 不限目录');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/11/a.txt', absolute: true }, '/root/11', ['__deny__']), false, '禁止所有哨兵');
  assert.equal(workspaceFilesTargetAllowed({ targetPath: '/root/11', absolute: true }, '/root/11', folders), true, '会话根本身');

  // 与 parseWorkspaceFilesCall 串联：readRelated 的逃逸目标被白名单拦下
  const escape = parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
    workspaceFileScopeId: 's1', path: '/root/11/sub/a.md', relativePath: '../../etc/passwd',
  }));
  assert.notEqual(escape, null);
  assert.equal(workspaceFilesTargetAllowed(escape!, '/root/11', folders), false);
  const inside = parseWorkspaceFilesCall('/api/workspaceFiles/readRelated', wsEnvelope('workspaceFiles/readRelated', {
    workspaceFileScopeId: 's1', path: '/root/11/sub/a.md', relativePath: 'b.md',
  }));
  assert.equal(workspaceFilesTargetAllowed(inside!, '/root/11', folders), true);
  // changes 整条链路：身份可解，但目标不可判定 → 拒绝
  const changes = parseWorkspaceFilesCall('/api/workspaceFiles/changes', wsEnvelope('workspaceFiles/changes', { workspaceFileScopeId: 's1' }));
  assert.equal(workspaceFilesTargetAllowed(changes!, '/root/11', folders), false);
});

// ── RC.1 SessionAddress（普通会话与子代理地址） ─────────────────

test('parseSessionAddress：保留普通会话与完整 subagent 地址', () => {
  assert.deepEqual(parseSessionAddress({ kind: 'session', sessionId: 'parent-visible' }), {
    kind: 'session',
    sessionId: 'parent-visible',
  });
  assert.deepEqual(parseSessionAddress({
    kind: 'subagent',
    parentSessionId: 'parent-visible',
    childSessionId: 'child-visible',
    mode: 'continuable',
  }), {
    kind: 'subagent',
    parentSessionId: 'parent-visible',
    childSessionId: 'child-visible',
    mode: 'continuable',
  });
  const oneShot = parseSessionAddress({
    kind: 'subagent',
    parentSessionId: 'parent-visible',
    childSessionId: 'child-one-shot',
    mode: 'one-shot',
  });
  assert.equal(oneShot?.kind, 'subagent');
  assert.equal(oneShot?.mode, 'one-shot');
  // 0.1.7-alpha.1 新增 mode='unknown'：仍只靠 parentSessionId 授权，不被整类拒绝
  assert.deepEqual(parseSessionAddress({
    kind: 'subagent',
    parentSessionId: 'parent-visible',
    childSessionId: 'child-unknown',
    mode: 'unknown',
  }), {
    kind: 'subagent',
    parentSessionId: 'parent-visible',
    childSessionId: 'child-unknown',
    mode: 'unknown',
  });
  assert.deepEqual(
    [...(collectAuthorizedSessionIds({
      address: { kind: 'subagent', parentSessionId: 'p', childSessionId: 'c', mode: 'unknown' },
    }) ?? [])],
    ['p'],
    'unknown 不改变授权口径：仍取 parent',
  );
});

test('parseSessionAddress：拒绝不完整或伪造的子代理地址', () => {
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: 'p', childSessionId: 'c' }), null);
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: 'p', childSessionId: 'c', mode: 'invalid' }), null);
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: 'p', childSessionId: 'c', mode: 'UNKNOWN' }), null, 'mode 大小写敏感');
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: '', childSessionId: 'c', mode: 'unknown' }), null);
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: 'p', childSessionId: 'x'.repeat(201), mode: 'unknown' }), null);
  assert.equal(parseSessionAddress({ kind: 'subagent', parentSessionId: 'p', childSessionId: 'c', mode: 'unknown ' }), null);
  assert.equal(parseSessionAddress({ kind: 'session', sessionId: '' }), null);
  assert.equal(parseSessionAddress({ kind: 'session', sessionId: 'x'.repeat(201) }), null);
  // 数组/自定义原型/继承字段不得冒充地址
  assert.equal(parseSessionAddress(Object.assign(Object.create({ kind: 'session' }), { sessionId: 's1' })), null);
});

// ── permissionPresetFromCommand（/permission 命令解析） ─────────

test('permissionPresetFromCommand：解析 preset 参数', () => {
  assert.equal(permissionPresetFromCommand('/permission workspace-write'), 'workspace-write');
  assert.equal(permissionPresetFromCommand('/permission read-only'), 'read-only');
  assert.equal(permissionPresetFromCommand('/permission danger-full-access'), 'danger-full-access');
});

test('permissionPresetFromCommand：非本命令/无参数返回 null', () => {
  assert.equal(permissionPresetFromCommand('/permission'), null);
  assert.equal(permissionPresetFromCommand('/help'), null);
  assert.equal(permissionPresetFromCommand('/permission '), null);
  assert.equal(permissionPresetFromCommand('permission workspace-write'), null);
});

// ── presetFromSettingsMutate（settings.mutate 找 defaultPreset） ─

test('presetFromSettingsMutate：path 数组含 defaultPreset 时返回 value', () => {
  const body = {
    ops: [{ path: ['permission', 'defaultPreset'], value: 'read-only' }],
  };
  assert.equal(presetFromSettingsMutate(body), 'read-only');
  assert.equal(presetFromSettingsMutate({ ops: [{ path: ['other'], value: 'x' }] }), null);
  assert.equal(presetFromSettingsMutate(null), null);
});

test('presetFromSettingsMutate：args 伪包裹里的值也会命中（fail-closed 方向）', () => {
  const body = { args: { path: ['permission', 'defaultPreset'], value: 'danger-full-access' } };
  // 与 extractPathFromBody/extractWorkspaceId 不同，这里不跳过 args——
  // 注意：这是故意的 fail-closed（沙盒检测里命中 args 高权限会 403 拦截，
  // dsh 忽略 args 走默认 preset 时也只是多拦不误放），与路径白名单相反方向，安全。
  assert.equal(presetFromSettingsMutate(body), 'danger-full-access');
});

// ── forceRejectApproval（受限子用户 AI 提权审批强制拒绝） ──────

test('forceRejectApproval：outcome 非 rejected 时改为 rejected', () => {
  const obj = { approvalId: 'ap1', outcome: 'approved' };
  assert.equal(forceRejectApproval(obj), true);
  assert.equal(obj.outcome, 'rejected');
});

test('forceRejectApproval：嵌套 result.value 信封也能命中', () => {
  const obj = { result: { value: { approvalId: 'ap2', outcome: 'accepted' } } };
  assert.equal(forceRejectApproval(obj), true);
  assert.equal(obj.result.value.outcome, 'rejected');
});

test('forceRejectApproval：已是 rejected / ask_user_question(answer) 不改', () => {
  const obj = { approvalId: 'ap3', outcome: 'rejected' };
  assert.equal(forceRejectApproval(obj), false);
  assert.equal(obj.outcome, 'rejected');
  const q = { answer: 'yes' }; // ask_user_question 的响应用 answer，不受影响
  assert.equal(forceRejectApproval(q), false);
});

// ── clampSessionHistorySandbox（沙盒降级） ─────────────────────

/** 构造 one-line 对象（不引 dsh 深层类型，结构足够即可） */
const mk = (o: Record<string, unknown>) => o;

test('clampSessionHistorySandbox：preset/mode/currentValue 超过授权级别时降级', () => {
  const target = mk({
    events: [
      { event: { type: 'permission/preset', data: { preset: 'danger-full-access' } } },
      { event: { type: 'sandbox/mode', data: { mode: 'workspace-write' } } },
    ],
    projections: { values: { permissions: { currentValue: 'danger-full-access' } } },
  });
  const changed = clampSessionHistorySandbox(target, 'read-only');
  assert.equal(changed, true);
  assert.equal(((target as any).events[0].event as any).data.preset, 'read-only');
  assert.equal(((target as any).events[1].event as any).data.mode, 'read-only');
  assert.equal(((target as any).projections.values.permissions as any).currentValue, 'read-only');
});

test('clampSessionHistorySandbox：同级别/更低级别不改', () => {
  const target = mk({
    events: [{ event: { type: 'sandbox/mode', data: { mode: 'read-only' } } }],
    projections: { values: { permissions: { currentValue: 'read-only' } } },
  });
  assert.equal(clampSessionHistorySandbox(target, 'workspace-write'), false);
  assert.equal(((target as any).events[0].event as any).data.mode, 'read-only');
});

test('clampSessionHistorySandbox：allowedMode=null 时不动（主用户不限）', () => {
  const target = mk({ events: [{ event: { type: 'sandbox/mode', data: { mode: 'danger-full-access' } } }] });
  assert.equal(clampSessionHistorySandbox(target, null), false);
});

// ── filterByPathField（白名单路径过滤） ────────────────────────

test('filterByPathField：白名单外的带 path 对象被丢弃，其余保留', () => {
  const input = {
    items: [
      { path: '/root/11', id: 'a' },
      { path: '/root/21', id: 'b' },
      { title: '无 path 字段' },
    ],
  };
  const out = filterByPathField(input, ['/root/21'], 'path') as typeof input;
  assert.equal(out.items.length, 2);
  assert.equal((out.items[0] as any).id, 'b');
  assert.equal((out.items[1] as any).title, '无 path 字段');
});

test('filterByPathField：空白名单 = 全部允许；__deny__ 哨兵 = 全部拒绝', () => {
  const input = { items: [{ path: '/x' }] };
  assert.equal((filterByPathField(input, [], 'path') as any).items.length, 1);
  assert.equal((filterByPathField(input, ['__deny__'], 'path') as any).items.length, 0);
});

// ── filterOwnedSessionIds（会话归属过滤） ───────────────────────

test('filterOwnedSessionIds：只保留 keep() 通过的 sessionId', () => {
  const input = { items: [{ path: '/w', sessionIds: ['s1', 's2', 's3'] }] };
  filterOwnedSessionIds(input, (id) => id === 's2');
  assert.deepEqual((input.items[0] as any).sessionIds, ['s2']);
});

test('filterOwnedSessionIds：sessionIds 含非字符串时清除非法值（fail-closed）', () => {
  const input = { items: [{ sessionIds: ['s1', 2] }] };
  filterOwnedSessionIds(input, () => true);
  assert.deepEqual((input.items[0] as any).sessionIds, ['s1']);
});

// ── filterSessionSearchItems（rc.1 session/search 授权过滤） ────

test('filterSessionSearchItems：只保留授权会话并保留摘要字段', () => {
  const visible = { sessionId: 's-visible', snippet: 'allowed', score: 0.9 };
  const hidden = { sessionId: 's-hidden', snippet: 'secret' };
  const out = filterSessionSearchItems([visible, hidden], (id) => id === 's-visible');
  assert.deepEqual(out, [visible]);
  assert.notEqual(out?.[0], visible, '过滤结果应创建新对象，避免把上游对象交给后续调用方');
});

test('filterSessionSearchItems：非法或缺少 sessionId 的项直接丢弃', () => {
  const out = filterSessionSearchItems([
    null,
    1,
    'not-an-object',
    [],
    {},
    { sessionId: '' },
    { sessionId: 42, snippet: 'invalid id' },
    { sessionId: 's-visible', snippet: 'allowed' },
  ], () => true);
  assert.deepEqual(out, [{ sessionId: 's-visible', snippet: 'allowed' }]);
});

test('filterSessionSearchItems：非数组结果返回 null，触发上层 fail-closed', () => {
  assert.equal(filterSessionSearchItems(null, () => true), null);
  assert.equal(filterSessionSearchItems({ items: [] }, () => true), null);
});

// ── sandboxPresetRank（级别映射） ──────────────────────────────

test('sandboxPresetRank：未知值按最宽松 2 处理（防越权切换）', () => {
  assert.equal(sandboxPresetRank('read-only'), 0);
  assert.equal(sandboxPresetRank('workspace-write'), 1);
  assert.equal(sandboxPresetRank('danger-full-access'), 2);
  assert.equal(sandboxPresetRank('bogus'), 2);
});

// ── D1 工作流：工作区登记白名单与目录浏览可见性 ──────────────────

test('pathWithin：相等/子路径/点段/根与空白语义', () => {
  assert.equal(pathWithin('/root/33', '/root/33'), true, '相等');
  assert.equal(pathWithin('/root/33/sub', '/root/33'), true, '子路径');
  assert.equal(pathWithin('/root/33/../34', '/root/33'), false, '点段解析后不再在内');
  assert.equal(pathWithin('/root/33', '/root/34'), false);
  assert.equal(pathWithin('/anything', '/'), true, '根 = 全盘');
  assert.equal(pathWithin('/anything', ''), false, '空根无效');
  assert.equal(pathWithin('/anything', '.'), false, '当前目录根无效');
});

test('workspaceRegistrationAllowed：只接受精确分配/自己子树/刚创建目录', () => {
  const assigned = ['/root/33'];
  const owned = ['/root/33/mine'];
  const pending = ['/root/33/fresh'];
  assert.equal(workspaceRegistrationAllowed('/root/33', assigned, owned, pending), true, '精确分配');
  assert.equal(workspaceRegistrationAllowed('/root/33/mine/sub', assigned, owned, pending), true, '自己的工作区子树');
  assert.equal(workspaceRegistrationAllowed('/root/33/fresh', assigned, owned, pending), true, '刚创建目录');
  assert.equal(workspaceRegistrationAllowed('/root/33/preexisting', assigned, owned, pending), false, '预存在未分配');
  assert.equal(workspaceRegistrationAllowed('/root/33/../34', assigned, owned, pending), false, '点段逃逸');
  assert.equal(workspaceRegistrationAllowed('/', assigned, owned, pending), false, '根目录拒绝');
  assert.equal(workspaceRegistrationAllowed('/root/33', ['__deny__'], owned, pending), false, '哨兵不作为分配项');
  assert.equal(workspaceRegistrationAllowed('/root/33/fresh', [], [], []), false, '无任何凭据时拒绝');
});

test('directoryEntryVisible：祖先导航只保留通往授权根的条目', () => {
  const roots = ['/workspaces/visible'];
  assert.equal(directoryEntryVisible('/workspaces/visible', roots), true, '授权根本身');
  assert.equal(directoryEntryVisible('/workspaces/visible/sub', roots), true, '授权根内');
  assert.equal(directoryEntryVisible('/workspaces', roots), true, '祖先（通往授权根）');
  assert.equal(directoryEntryVisible('/', roots), true, '根祖先');
  assert.equal(directoryEntryVisible('/workspaces/other', roots), false, '无关兄弟目录');
  assert.equal(directoryEntryVisible('/root/33', roots), false, '无关子树');
});
