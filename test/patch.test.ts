// 补丁机制回归测试：覆盖 DSH 0.1.2 RC.1 的当前补丁与回滚契约
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
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

test('补丁：当前 rc.1 npm artifacts 应应用 settings 与 Cookie bridge 并保持语法有效', () => {
  const { root, cleanup } = makeDshRoot(RC7_SETTINGS_PATCHED);
  try {
    const packages = [
      ['dsh-client-ui-settings', 'client.js'],
      ['dsh-client-connection', 'index.js'],
    ] as const;
    for (const [packageName, fileName] of packages) {
      const target = path.join(root, 'node_modules', '@deepseek-ai', packageName, 'lib', fileName);
      const source = path.join(process.cwd(), 'node_modules', '@deepseek-ai', packageName, 'lib', fileName);
      mkdirSync(path.dirname(target), { recursive: true });
      copyFileSync(source, target);
    }
    // npm ci installs the official unmodified RC.1 artifacts. Both the
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
