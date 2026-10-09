// 补丁机制回归测试：覆盖支持的 DSH bundle 布局、0.2.1-alpha.1/alpha.2 产物与回滚契约
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { applyRemotePatch, patchStatus, rollbackPatch } from '../src/patch.js';

/** 构建一个模拟 dsh 根目录（含两个必选补丁目标文件 + 可选 workspace 文件），返回 root 与清理函数 */
function makeDshRoot(
  settingsContent: string,
  workspaceContent?: string,
  connectionContent?: string,
): { root: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-patch-'));
  const settingsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(path.join(settingsDir, 'client.js'), settingsContent);
  if (workspaceContent !== undefined) {
    const wsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-workspace', 'lib');
    mkdirSync(wsDir, { recursive: true });
    writeFileSync(path.join(wsDir, 'client.js'), workspaceContent);
  }
  if (connectionContent !== undefined) {
    const connectionDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib');
    mkdirSync(connectionDir, { recursive: true });
    writeFileSync(path.join(connectionDir, 'index.js'), connectionContent);
  }
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function makeDshRootWithBindAll(
  startupContent: string,
  webServerContent: string,
): { root: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-patch-bindall-'));
  const settingsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(path.join(settingsDir, 'client.js'), RC7_SETTINGS_PATCHED);
  const startupDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-web-app', 'lib');
  mkdirSync(startupDir, { recursive: true });
  writeFileSync(path.join(startupDir, 'startup.js'), startupContent);
  const webServerDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-host-webserver', 'lib');
  mkdirSync(webServerDir, { recursive: true });
  writeFileSync(path.join(webServerDir, 'index.js'), webServerContent);
  return { root, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

const BIND_ALL_STARTUP_FILE = ['node_modules', '@deepseek-ai', 'dsh-web-app', 'lib', 'startup.js'];
const BIND_ALL_WEBSERVER_FILE = ['node_modules', '@deepseek-ai', 'dsh-host-webserver', 'lib', 'index.js'];

const REAL_STARTUP_PATH = path.join(process.cwd(), ...BIND_ALL_STARTUP_FILE);
const REAL_WEBSERVER_PATH = path.join(process.cwd(), ...BIND_ALL_WEBSERVER_FILE);

// 有限生命周期真实监听探针：用 mock root 内已打补丁的真实 WebServer 绑 0.0.0.0:0，
// 打印实际端口后主动退出（OS 关闭监听，不留 server）。cwd = mock root，使其相对 import
// 命中补丁副本，裸依赖沿目录向上解析到项目 node_modules。
const WS_BIND_ALL_PROBE = [
  "import { Context } from '@deepseek-ai/cordis';",
  "const mod = await import('./node_modules/@deepseek-ai/dsh-host-webserver/lib/index.js');",
  "mod.WebServer.Config({ host: '0.0.0.0', port: 0 });",
  'const ctx = new Context();',
  "ctx.plugin(mod.WebServer, { host: '0.0.0.0', port: 0 });",
  'await new Promise((resolve) => setTimeout(resolve, 700));',
  'const port = ctx.webServer && ctx.webServer.port;',
  "console.log('BINDALL_LISTEN_PORT=' + port);",
  'process.exit(0);',
  '',
].join('\n');

/** 在指定 MCP_DSH_PATCH_ALLOW_BIND_ALL 取值下运行并恢复原值 */
function withBindAllEnv<T>(value: string | undefined, run: () => T): T {
  const prev = process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL;
  if (value === undefined) delete process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL;
  else process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL = value;
  try {
    return run();
  } finally {
    if (prev === undefined) delete process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL;
    else process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL = prev;
  }
}

// alpha.1 拒绑闸：options.host 字面比较 + 双引号报错文案（旧锚点）
const ALPHA1_STARTUP_BIND_GUARD = [
  'function apply(ctx) {',
  '  const program = webCommand();',
  '  program.action(() => {',
  '    const options = program.opts();',
  '    if (options.host === "0.0.0.0") program.error("error: --host 0.0.0.0 is intentionally not supported yet for safety: it would expose remote code execution to the network; use 127.0.0.1 instead");',
  '    ctx.provide("webStartup", options);',
  '  });',
  '}',
  'export { apply };',
  '',
].join('\n');

// alpha.2 拒绑闸：isWildcardHost 判定 + 模板串报错文案（与 node_modules 实际产物一致）
const ALPHA2_STARTUP_BIND_GUARD = [
  'function apply(ctx) {',
  '  const program = webCommand();',
  '  program.action(() => {',
  '    const options = program.opts();',
  '    if (options.host !== void 0 && isWildcardHost(options.host)) program.error(`error: --host ${options.host} is an unspecified (wildcard) address, which is not supported: binding every interface would expose remote code execution to the network; bind one concrete IPv4 or IPv6 address instead`);',
  '    ctx.provide("webStartup", options);',
  '  });',
  '}',
  'export { apply };',
  '',
].join('\n');

// alpha.2 webserver 配置闸：WebServer.Config.host 校验中的通配拒绝（与 node_modules 实际产物一致）
const WS_BIND_GUARD_UNPATCHED = [
  'const WebServer = class extends Service {',
  '  static Config = z.object({',
  '    host: z.transform(z.string(), (value) => {',
  '      const parsed = parseIpLiteral(value);',
  '      if (parsed === void 0) throw notLiteralError(value);',
  '      if (isWildcardAddress(parsed)) throw new Error(`webserver: host ${JSON.stringify(value)} is an unspecified (wildcard) address, which is not supported: binding every interface would expose remote code execution to the network; bind one concrete IPv4 or IPv6 address of a local interface instead`);',
  '      return value;',
  '    }).required(),',
  '    port: z.natural().max(65535).required(),',
  '  });',
  '};',
  'export { WebServer };',
  '',
].join('\n');

const RC7_SETTINGS_UNPATCHED =
  'const mode = connection.isLoopback ? "host" : "memory";\nexport default mode;\n';
const RC7_SETTINGS_PATCHED = 'const mode = "host";\nexport default mode;';
const ALPHA3_SETTINGS_UNPATCHED = 'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";\n';
const ALPHA3_SETTINGS_PATCHED = 'const persistence = "host";\n';
const ALPHA_CONNECTION_UNPATCHED = [
  'class BrowserAuth {',
  '  authenticatedUrl(baseUrl) { return baseUrl; }',
  '  authorizeIndex(req, res) { return true; }',
  '}',
  'class HostConnectionService {',
  '  authenticatedUrl(baseUrl) { return this.browserAuth.authenticatedUrl(baseUrl); }',
  '}',
].join('\n');
const ALPHA_CONNECTION_PATCHED_MARK = 'dshpw-authenticated-cookie';
const ALPHA_CONNECTION_PATCH_HARDEN_MARK = 'dshpw-authenticated-cookie-loopback-v2';

const ALPHA_CONNECTION_OLD_PATCHED = [
  'class BrowserAuth {',
  '  authenticatedUrl(baseUrl) { return baseUrl; }',
  '  /** dshpw-authenticated-cookie: trusted Host-side authority-bound Cookie mint. */',
  '  authenticatedCookie(baseUrl) {',
  '    const url = new URL(baseUrl);',
  '    const authority = url.host;',
  '    const issuedAt = Date.now();',
  '    const expiresAt = issuedAt + this.maxAgeMilliseconds;',
  '    const value = encodeCookie({ version: COOKIE_PAYLOAD_VERSION, authority, issuedAt, expiresAt }, this.secret);',
  "    return cookieName(authority) + '=' + value;",
  '  }',
  '  authorizeIndex(req, res) { return true; }',
  '}',
  'class HostConnectionService {',
  '  authenticatedUrl(baseUrl) { return this.browserAuth.authenticatedUrl(baseUrl); }',
  '  /** dshpw-authenticated-cookie: expose only the derived Cookie pair to trusted Host plugins. */',
  '  authenticatedCookie(baseUrl) { return this.browserAuth.authenticatedCookie(baseUrl); }',
  '}',
].join('\n');

function makeDshRootWithProfileSettings(
  dshSettingsContent: string,
  profileSettingsContent: string,
): { root: string; profile: string; cleanup: () => void } {
  const root = mkdtempSync(path.join(tmpdir(), 'dshpw-duplicate-patch-'));
  const profile = path.join(root, 'profile');
  const dshSettingsDir = path.join(root, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
  const profileSettingsDir = path.join(profile, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
  mkdirSync(dshSettingsDir, { recursive: true });
  mkdirSync(profileSettingsDir, { recursive: true });
  writeFileSync(path.join(root, 'dsh', 'package.json'), JSON.stringify({ version: '0.2.1-alpha.1' }));
  writeFileSync(path.join(profile, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'package.json'), JSON.stringify({ version: '0.2.1-alpha.1' }));
  writeFileSync(path.join(dshSettingsDir, 'client.js'), dshSettingsContent);
  writeFileSync(path.join(profileSettingsDir, 'client.js'), profileSettingsContent);
  return { root: path.join(root, 'dsh'), profile, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}


/** 与真实 dsh-client-ui-workspace client.js 相同的 click-outside 粘滞搜索块（制表符缩进） */
const WORKSPACE_STICKY = [
  '\t\t\t(0, react.useEffect)(() => {',
  '\t\t\t\tif (!wide || !searchExpanded) return;',
  '\t\t\t\tconst onClick = (event) => {',
  '\t\t\t\t\tif (!(event.target instanceof Node) || searchRoot.current?.contains(event.target) === true) return;',
  '\t\t\t\t\tsearchInput.current?.blur();',
  '\t\t\t\t\tif (normalizedQuery !== "") return;',
  '\t\t\t\t\tsetSearchExpanded(false);',
  '\t\t\t\t};',
  '\t\t\t\tdocument.addEventListener("click", onClick);',
  '\t\t\t\treturn () => {',
  '\t\t\t\t\tdocument.removeEventListener("click", onClick);',
  '\t\t\t\t};',
  '\t\t\t}, [',
  '\t\t\t\tnormalizedQuery,',
  '\t\t\t\twide,',
  '\t\t\t\tsearchExpanded',
  '\t\t\t]);',
  '\t\t\t(0, react_jsx_runtime.jsx)("input", {',
  '\t\t\t\t\tref: searchInput,',
  '\t\t\t\t\tclassName: WorkspaceBrowser_module_css_default.searchInput,',
  '\t\t\t\t\ttype: "text",',
  '\t\t\t\t\tplaceholder: t("search.placeholder"),',
  '\t\t\t\t}),',
  '',
].join('\n');



test('补丁：DSH 根与 web profile 存在重复 settings 副本时全部修复并纳入状态', () => {
  const duplicate = makeDshRootWithProfileSettings(RC7_SETTINGS_UNPATCHED, ALPHA3_SETTINGS_UNPATCHED);
  try {
    assert.equal(patchStatus(duplicate.root, duplicate.profile).settingsHostMode, false);
    assert.equal(applyRemotePatch(duplicate.root, duplicate.profile), 'applied');
    assert.equal(patchStatus(duplicate.root, duplicate.profile).settingsHostMode, true);
    assert.equal(
      readFileSync(path.join(duplicate.root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8'),
      RC7_SETTINGS_PATCHED + '\n',
    );
    assert.equal(
      readFileSync(path.join(duplicate.profile, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8'),
      ALPHA3_SETTINGS_PATCHED,
    );
  } finally {
    duplicate.cleanup();
  }
});
test('补丁：当前支持范围内 settings 未打 host 模式时会被打进', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_UNPATCHED);
  try {
    const result = applyRemotePatch(root);
    assert.equal(result, 'applied', 'settings 未打时应应用并返回 applied');
    const s = readFileSync(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8');
    assert.ok(s.includes('"host"') && !s.includes('connection.isLoopback'), 'client.js 已强制 host 模式');
  } finally {
    cleanup();
  }
});

test('补丁：alpha.3 settings 使用 remote.$host.isLoopback 时强制 host persistence', () => {
  const { root, cleanup } = makeDshRoot(ALPHA3_SETTINGS_UNPATCHED);
  try {
    assert.equal(patchStatus(root).settingsHostMode, false);
    assert.equal(applyRemotePatch(root), 'applied');
    const settings = readFileSync(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8');
    assert.equal(settings, ALPHA3_SETTINGS_PATCHED);
    assert.equal(patchStatus(root).settingsHostMode, true);
  } finally {
    cleanup();
  }
});

test('补丁：当前 0.2.1-alpha.1 npm artifacts 应应用 settings 与 Cookie bridge 并保持语法有效', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_PATCHED);
  try {
    const settingsSource = path.join(process.cwd(), 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js');
    const settingsTarget = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js');
    mkdirSync(path.dirname(settingsTarget), { recursive: true });
    const source = readFileSync(settingsSource, 'utf8');
    // 0.2.1-alpha.1 当前包仍可能携带 remote.$host.isLoopback；若未来包已换回 host，
    // 仍明确构造一个可被当前补丁识别的未打版本，而不是依赖无效的 no-op replace。
    const unpatchedSettings = source.includes('ctx.remote.$host.isLoopback ? "host" : "memory"')
      ? source
      : source.replace('const persistence = "host";', 'const persistence = ctx.remote.$host.isLoopback ? "host" : "memory";');
    writeFileSync(settingsTarget, unpatchedSettings);
    const connectionTarget = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib', 'index.js');
    mkdirSync(path.dirname(connectionTarget), { recursive: true });
    writeFileSync(connectionTarget, ALPHA_CONNECTION_UNPATCHED);
    // npm ci installs the official unmodified 0.2.1-alpha.1 artifacts. Both the
    // browser-side host persistence and the private Host Cookie bridge must
    // be patched before the public gateway is allowed to start.
    assert.equal(patchStatus(root).settingsHostMode, false);
    assert.equal(patchStatus(root).connectionCookieBridge, 'unsupported');
    assert.equal(applyRemotePatch(root), 'applied');
    assert.equal(patchStatus(root).settingsHostMode, true);
    assert.equal(patchStatus(root).connectionCookieBridge, 'patched');
    const settings = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js');
    const connection = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib', 'index.js');
    assert.ok(readFileSync(settings, 'utf8').includes('const persistence = "host"'));
    assert.ok(readFileSync(connection, 'utf8').includes(ALPHA_CONNECTION_PATCH_HARDEN_MARK));
    assert.equal(spawnSync(process.execPath, ['--check', settings]).status, 0);
    assert.equal(spawnSync(process.execPath, ['--check', connection]).status, 0);
  } finally {
    cleanup();
  }
});

test('补丁：工作区搜索粘滞态 → 无结果时点击别处自动收起清空（消除“无匹配会话”滞留）', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_PATCHED, WORKSPACE_STICKY);
  try {
    const before = patchStatus(root);
    assert.equal(before.workspaceSearch, false, '初始未打 workspace 子补丁');

    const result = applyRemotePatch(root);
    assert.equal(result, 'applied', 'settings 已满足时 workspace 子补丁应实际应用');

    const ws = readFileSync(
      path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-workspace', 'lib', 'client.js'),
      'utf8',
    );
    assert.ok(!ws.includes('if (normalizedQuery !== "") return;'), '旧粘滞行为（query 非空直接 return）已移除');
    assert.ok(ws.includes('remoteSearch.status !== "loading"'), '已注入无结果自动收起逻辑');
    assert.ok(ws.includes('remoteSearch,'), 'click-outside effect 依赖数组已补 remoteSearch（防闭包过期）');
    // v2 搜索框自动填充加固：search 类型 + 折叠态只读 + 密码管理器忽略标记。
    assert.ok(ws.includes('autoComplete: "search"'), '搜索框已改为 search autocomplete');
    assert.ok(ws.includes('dshpw-session-search'), '搜索框已注入中性 name，摘掉用户名框资格');
    assert.ok(ws.includes('data-dshpw-autofill-harden'), '搜索框已注入 v2 自动填充加固标记');

    const after = patchStatus(root);
    assert.equal(after.workspaceSearch, true, '状态检测为已打');

    // 幂等：再跑一次必须 unchanged
    const again = applyRemotePatch(root);
    assert.equal(again, 'unchanged', '幂等：二次应用不再改动');
  } finally {
    cleanup();
  }
});

test('补丁：alpha.1 connection 增加受信任 Host Cookie 兑换入口且保持幂等', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_PATCHED, undefined, ALPHA_CONNECTION_UNPATCHED);
  try {
    assert.equal(applyRemotePatch(root), 'applied');
    const file = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib', 'index.js');
    const first = readFileSync(file, 'utf8');
    assert.ok(first.includes(ALPHA_CONNECTION_PATCHED_MARK));
    assert.ok(first.includes('authenticatedCookie('));
    assert.ok(first.includes('new URL(baseUrl)'));
    assert.equal(applyRemotePatch(root), 'unchanged');
    assert.equal(readFileSync(file, 'utf8'), first);
  } finally {
    cleanup();
  }
});

test('补丁：旧版 alpha Cookie bridge 自动升级为 loopback-v2 且保持原始 Host bridge', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_PATCHED, undefined, ALPHA_CONNECTION_OLD_PATCHED);
  try {
    assert.equal(applyRemotePatch(root), 'applied');
    const file = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-connection', 'lib', 'index.js');
    const patched = readFileSync(file, 'utf8');
    assert.ok(patched.includes(ALPHA_CONNECTION_PATCH_HARDEN_MARK));
    assert.ok(patched.includes('requires a loopback authority'));
    assert.ok(patched.includes('requires HTTP(S)'));
    assert.ok(patched.includes('authenticatedCookie(baseUrl) { return this.browserAuth.authenticatedCookie(baseUrl); }'));
    assert.equal(applyRemotePatch(root), 'unchanged');
  } finally {
    cleanup();
  }
});

test('补丁状态：connection Cookie bridge 明确区分 patched、native、unsupported 和 missing', () => {
  const patched = makeDshRoot(RC7_SETTINGS_PATCHED, undefined, ALPHA_CONNECTION_UNPATCHED);
  const native = makeDshRoot(RC7_SETTINGS_PATCHED, undefined, 'class BrowserAuth { authenticatedCookie(baseUrl) { return baseUrl; } }');
  const unsupported = makeDshRoot(RC7_SETTINGS_PATCHED, undefined, 'class BrowserAuth { authenticatedUrl(baseUrl) { return baseUrl; } }');
  const missing = makeDshRoot(RC7_SETTINGS_PATCHED);
  try {
    assert.equal(applyRemotePatch(patched.root), 'applied');
    assert.equal(patchStatus(patched.root).connectionCookieBridge, 'patched');
    assert.equal(patchStatus(native.root).connectionCookieBridge, 'native');
    assert.equal(patchStatus(unsupported.root).connectionCookieBridge, 'unsupported');
    assert.equal(patchStatus(missing.root).connectionCookieBridge, 'missing');
  } finally {
    patched.cleanup();
    native.cleanup();
    unsupported.cleanup();
    missing.cleanup();
  }
});

test('补丁：安全回滚仅恢复当前哈希仍匹配的目标', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_UNPATCHED);
  try {
    assert.equal(applyRemotePatch(root), 'applied');
    assert.equal(rollbackPatch(root), 'rolled-back');
    const settings = readFileSync(path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib', 'client.js'), 'utf8');
    assert.equal(settings, RC7_SETTINGS_UNPATCHED);
  } finally {
    cleanup();
  }
});

test('补丁：workspace 目标文件缺失时不失败（可选子补丁不影响 host-mode）', () => {
  // 不传 workspaceContent → 文件不存在；settings 未打 → applied 仅由 settings 驱动
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_UNPATCHED);
  try {
    const result = applyRemotePatch(root);
    assert.notEqual(result, 'missing', 'workspace 文件缺失不应报 missing');
    assert.equal(result, 'applied', 'settings 子补丁仍正常应用');

    const st = patchStatus(root);
    assert.equal(st.workspaceSearch, false, '缺失按未打处理');
    assert.equal(st.settingsHostMode, true, 'settings host 模式已打');
  } finally {
    cleanup();
  }
});

test('补丁状态：alpha.2 两闸未打时 bindAll 不得假绿，注入后同时放行并幂等', () => {
  const { root, cleanup } = makeDshRootWithBindAll(ALPHA2_STARTUP_BIND_GUARD, WS_BIND_GUARD_UNPATCHED);
  const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
  const webServerFile = path.join(root, ...BIND_ALL_WEBSERVER_FILE);
  try {
    withBindAllEnv('1', () => {
      assert.equal(patchStatus(root).bindAll, false, '两闸未打必须 fail-closed 报 false');
      assert.equal(applyRemotePatch(root), 'applied');
      assert.equal(patchStatus(root).bindAll, true);
    });
    const startup = readFileSync(startupFile, 'utf8');
    assert.ok(startup.includes('dshpw-bindall'), '启动闸已注入标记');
    assert.ok(startup.includes('isWildcardHost(options.host)'), '保留 alpha.2 启动闸原通配条件');
    assert.ok(!startup.includes('is an unspecified (wildcard) address'), '启动闸拒绝式调用已移除');
    const webServer = readFileSync(webServerFile, 'utf8');
    assert.ok(webServer.includes('dshpw-bindall'), 'webserver 闸已注入标记');
    assert.ok(webServer.includes('isWildcardAddress(parsed)'), '保留 webserver 原通配条件');
    assert.ok(!webServer.includes('throw new Error(`webserver: host'), 'webserver 拒绝式 throw 已移除');
    assert.equal(spawnSync(process.execPath, ['--check', startupFile]).status, 0);
    assert.equal(spawnSync(process.execPath, ['--check', webServerFile]).status, 0);
    assert.equal(withBindAllEnv('1', () => applyRemotePatch(root)), 'unchanged', '幂等');
  } finally {
    cleanup();
  }
});

test('补丁：alpha.1 启动闸与 alpha.2 webserver 闸同轮放行（验证锚点集合，无版本分支）', () => {
  const { root, cleanup } = makeDshRootWithBindAll(ALPHA1_STARTUP_BIND_GUARD, WS_BIND_GUARD_UNPATCHED);
  const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
  try {
    withBindAllEnv('1', () => {
      assert.equal(patchStatus(root).bindAll, false);
      assert.equal(applyRemotePatch(root), 'applied');
      assert.equal(patchStatus(root).bindAll, true);
    });
    const patched = readFileSync(startupFile, 'utf8');
    assert.ok(patched.includes('options.host === "0.0.0.0"'), '保留 alpha.1 原条件');
    assert.ok(!patched.includes('intentionally not supported'), '拒绝式报错已移除');
    assert.equal(spawnSync(process.execPath, ['--check', startupFile]).status, 0);
  } finally {
    cleanup();
  }
});

test('补丁：bind-all 未开启时不改动两个目标文件（默认不弱化）', () => {
  const { root, cleanup } = makeDshRootWithBindAll(ALPHA2_STARTUP_BIND_GUARD, WS_BIND_GUARD_UNPATCHED);
  const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
  const webServerFile = path.join(root, ...BIND_ALL_WEBSERVER_FILE);
  try {
    withBindAllEnv(undefined, () => {
      assert.equal(applyRemotePatch(root), 'unchanged');
      assert.equal(patchStatus(root).bindAll, true, '未开启时沿用既有“不参与计算”语义');
    });
    assert.equal(readFileSync(startupFile, 'utf8'), ALPHA2_STARTUP_BIND_GUARD);
    assert.equal(readFileSync(webServerFile, 'utf8'), WS_BIND_GUARD_UNPATCHED);
  } finally {
    cleanup();
  }
});

test('补丁：bind-all 关闭时自愈恢复两闸（哈希匹配）', () => {
  const { root, cleanup } = makeDshRootWithBindAll(ALPHA2_STARTUP_BIND_GUARD, WS_BIND_GUARD_UNPATCHED);
  const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
  const webServerFile = path.join(root, ...BIND_ALL_WEBSERVER_FILE);
  try {
    withBindAllEnv('1', () => {
      assert.equal(applyRemotePatch(root), 'applied');
    });
    assert.notEqual(readFileSync(startupFile, 'utf8'), ALPHA2_STARTUP_BIND_GUARD);
    assert.notEqual(readFileSync(webServerFile, 'utf8'), WS_BIND_GUARD_UNPATCHED);
    withBindAllEnv(undefined, () => {
      assert.equal(applyRemotePatch(root), 'applied', '关闭开关时恢复两闸');
    });
    assert.equal(readFileSync(startupFile, 'utf8'), ALPHA2_STARTUP_BIND_GUARD);
    assert.equal(readFileSync(webServerFile, 'utf8'), WS_BIND_GUARD_UNPATCHED);
  } finally {
    cleanup();
  }
});

test('补丁：bind-all 后回滚按哈希恢复两个原始文件', () => {
  const { root, cleanup } = makeDshRootWithBindAll(ALPHA2_STARTUP_BIND_GUARD, WS_BIND_GUARD_UNPATCHED);
  const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
  const webServerFile = path.join(root, ...BIND_ALL_WEBSERVER_FILE);
  try {
    withBindAllEnv('1', () => {
      assert.equal(applyRemotePatch(root), 'applied');
    });
    assert.equal(rollbackPatch(root), 'rolled-back');
    assert.equal(readFileSync(startupFile, 'utf8'), ALPHA2_STARTUP_BIND_GUARD);
    assert.equal(readFileSync(webServerFile, 'utf8'), WS_BIND_GUARD_UNPATCHED);
  } finally {
    cleanup();
  }
});

test(
  '补丁：真实 alpha.2 dsh-web-app startup.js 可被识别并注入',
  { skip: !existsSync(REAL_STARTUP_PATH) },
  () => {
    const realStartup = readFileSync(REAL_STARTUP_PATH, 'utf8');
    assert.ok(realStartup.includes('isWildcardHost(options.host)'), '安装产物仍是 alpha.2 启动闸形态');
    const { root, cleanup } = makeDshRootWithBindAll(realStartup, WS_BIND_GUARD_UNPATCHED);
    const startupFile = path.join(root, ...BIND_ALL_STARTUP_FILE);
    try {
      withBindAllEnv('1', () => {
        assert.equal(patchStatus(root).bindAll, false);
        assert.equal(applyRemotePatch(root), 'applied');
        assert.equal(patchStatus(root).bindAll, true);
      });
      assert.equal(spawnSync(process.execPath, ['--check', startupFile]).status, 0);
    } finally {
      cleanup();
    }
  },
);

test(
  '补丁：真实 alpha.2 dsh-host-webserver —— 未打拒绝通配，注入后配置放行且能真实监听 0.0.0.0 后退出',
  { skip: !existsSync(REAL_WEBSERVER_PATH) },
  async () => {
    // 未打的真实产物：配置校验即拒绝通配（第二道闸的真实行为）
    const realModule = await import(pathToFileURL(REAL_WEBSERVER_PATH).href);
    assert.throws(
      () => realModule.WebServer.Config({ host: '0.0.0.0', port: 0 }),
      /wildcard/,
      '未打 webserver 必须拒绝 0.0.0.0',
    );

    // 项目本地 mock root：真实 index.js 的裸依赖（cordis/schemastery/…）沿目录向上解析到项目 node_modules
    const root = mkdtempSync(path.join(process.cwd(), '.dshpw-verify-'));
    try {
      const settingsDir = path.join(root, 'node_modules', '@deepseek-ai', 'dsh-client-ui-settings', 'lib');
      mkdirSync(settingsDir, { recursive: true });
      writeFileSync(path.join(settingsDir, 'client.js'), RC7_SETTINGS_PATCHED);
      mkdirSync(path.join(root, ...BIND_ALL_STARTUP_FILE.slice(0, -1)), { recursive: true });
      copyFileSync(REAL_STARTUP_PATH, path.join(root, ...BIND_ALL_STARTUP_FILE));
      mkdirSync(path.join(root, ...BIND_ALL_WEBSERVER_FILE.slice(0, -1)), { recursive: true });
      copyFileSync(REAL_WEBSERVER_PATH, path.join(root, ...BIND_ALL_WEBSERVER_FILE));

      withBindAllEnv('1', () => {
        assert.equal(patchStatus(root).bindAll, false, '两闸未打必须 fail-closed');
        assert.equal(applyRemotePatch(root), 'applied');
        assert.equal(patchStatus(root).bindAll, true);
      });

      const webServerFile = path.join(root, ...BIND_ALL_WEBSERVER_FILE);
      assert.ok(readFileSync(webServerFile, 'utf8').includes('dshpw-bindall'));
      // 打后真实副本：配置接受通配
      const patchedModule = await import(pathToFileURL(webServerFile).href);
      assert.equal(patchedModule.WebServer.Config({ host: '0.0.0.0', port: 0 }).host, '0.0.0.0');

      // 真实监听：有限生命周期子进程，绑 0.0.0.0 后打印端口并退出（OS 关闭监听，不留 server）
      const probe = spawnSync(process.execPath, ['--input-type=module', '-e', WS_BIND_ALL_PROBE], {
        cwd: root,
        encoding: 'utf8',
        timeout: 20000,
      });
      assert.equal(probe.status, 0, `真实监听探针应正常退出：${String(probe.stderr)}`);
      const match = /BINDALL_LISTEN_PORT=(\d+)/.exec(probe.stdout);
      assert.ok(match !== null, `探针应打印真实监听端口：${probe.stdout}`);
      assert.ok(Number(match[1]) > 0, '应为有效的非 0 监听端口');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
