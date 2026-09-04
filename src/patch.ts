// 远程设置补丁：强制启用。
//
// 背景：dsh 把 settings 等特权面设计成 loopback-only——
//   1. 客户端（dsh-client-ui-settings/lib/client.js）：
//      connection.isLoopback ? "host" : "memory" → 远程浏览器走 memory 模式，
//      设置表单不可用
//   2. 主机侧（dsh-host-apiproxy/lib/index.js）：
//      WEB_SETTINGS_NAMESPACES 硬编码白名单，第三方插件命名空间不在其中
// 网关把 Host/Origin 改写为 127.0.0.1:3080，主机侧栅栏对经网关的流量放行，
// 所以只需把客户端持久化强制为 host 模式 + 把插件命名空间加进白名单。
//
// 信任边界：只有通过密码门登录的浏览器能写设置（直连 3080 的局域网浏览器
// 仍会被主机侧栅栏拒绝）。无论本地直连还是远程，强制打此补丁影响都不大，
// 因此不提供开关：网关每次启动自动应用（幂等），dsh 升级覆盖文件后重启
// 网关自动重打，或在设置页点"重载补丁"。
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const BAK_SUFFIX = '.bak-dshpw';
const BAK_META_SUFFIX = '.sha256-dshpw';

function contentHash(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function backupMetaPath(target: string): string {
  return target + BAK_META_SUFFIX;
}

/**
 * 保存当前 dsh bundle 的原始版本，并写入内容哈希。
 * 固定 .bak 文件名会跨 dsh 升级残留；每次明确识别到全新未打补丁源码时
 * 都刷新备份，避免 rollbackPatch 把旧 rc.7 文件恢复到 rc.8。
 */
interface BackupMeta {
  originalSha256: string;
  patchedSha256: string;
}

function saveOriginalBackup(target: string, content: string, patchedContent: string): void {
  writeFileSync(target + BAK_SUFFIX, content);
  const meta: BackupMeta = {
    originalSha256: contentHash(content),
    patchedSha256: contentHash(patchedContent),
  };
  writeFileSync(backupMetaPath(target), `${JSON.stringify(meta)}\n`);
}

function readBackupMeta(target: string): BackupMeta | null {
  const backup = target + BAK_SUFFIX;
  const meta = backupMetaPath(target);
  if (!existsSync(backup) || !existsSync(meta)) return null;
  try {
    const value = JSON.parse(readFileSync(meta, 'utf8')) as Partial<BackupMeta>;
    if (
      typeof value.originalSha256 !== 'string' ||
      typeof value.patchedSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/.test(value.originalSha256) ||
      !/^[a-f0-9]{64}$/.test(value.patchedSha256)
    ) {
      return null;
    }
    const content = readFileSync(backup);
    return contentHash(content) === value.originalSha256 ? value as BackupMeta : null;
  } catch {
    return null;
  }
}

function ensureOriginalBackup(target: string, content: string, patchedContent: string): void {
  const existing = readBackupMeta(target);
  const originalSha256 = contentHash(content);
  const patchedSha256 = contentHash(patchedContent);
  if (existing?.originalSha256 === originalSha256 && existing.patchedSha256 === patchedSha256) return;
  if (existing?.originalSha256 === originalSha256) {
    writeFileSync(backupMetaPath(target), `${JSON.stringify({ originalSha256, patchedSha256 })}\n`);
    return;
  }
  // 补丁算法升级时，当前文件可能正好是上一版记录的 patched 内容（例如
  // rc.8 Issue #8 的旧实现只替换首个三元，新实现接着补全余下位置）。此时
  // 仍应保留已有的真正原始 bundle；把当前内容当新“原始文件”会让 rollback
  // 只能恢复半补丁，无法恢复 dsh 原文件。
  if (existing?.patchedSha256 === originalSha256) {
    writeFileSync(
      backupMetaPath(target),
      `${JSON.stringify({ originalSha256: existing.originalSha256, patchedSha256 })}\n`,
    );
    return;
  }
  saveOriginalBackup(target, content, patchedContent);
}

function currentMatchesPatchedBackup(target: string): boolean {
  const meta = readBackupMeta(target);
  if (!meta || !existsSync(target)) return false;
  try {
    return contentHash(readFileSync(target)) === meta.patchedSha256;
  } catch {
    return false;
  }
}

/**
 * 将旧版本留下的无元数据备份安全迁移到哈希格式。
 * 只有“旧备份经当前补丁算法转换后精确等于当前文件”才允许迁移；
 * rc.7 备份与 rc.8 当前 bundle 不一致时不会被误认，也不会覆盖任何文件。
 */
function migrateLegacyBackup(
  target: string,
  currentContent: string,
  patch: (original: string) => string | null,
): void {
  if (readBackupMeta(target) !== null || !existsSync(target + BAK_SUFFIX)) return;
  try {
    const original = readFileSync(target + BAK_SUFFIX, 'utf8');
    const patched = patch(original);
    if (patched !== null && patched !== original && patched === currentContent) {
      saveOriginalBackup(target, original, currentContent);
    }
  } catch {
    // 迁移是兼容性加固，失败时保留旧备份但不把它当作可回滚备份。
  }
}

/**
 * 查找 dsh 运行时实际会解析到的 bundle 文件。
 *
 * 常规全局安装把依赖嵌套在 `dsh/node_modules`；`npm install --prefix` 则可能把
 * 它们提升到 prefix 的 `node_modules`。补丁必须跟随 Node 从 dsh 包目录逐级向上
 * 查找 node_modules 的规则，不能假设依赖永远嵌套在 dsh 包内（Issue #8 Docker）。
 */
function findDshBundleFile(dshRoot: string, packageName: string, relativePath: string): string | null {
  let dir = dshRoot;
  for (;;) {
    const candidate = path.join(dir, 'node_modules', packageName, relativePath);
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // dsh 0.1.2-alpha.1 在源码构建时保留 pnpm workspace 布局：包名仍沿用
  // dsh 的公开 package name，但不会复制到 dshRoot/node_modules 下的发布包目录。
  // 只加入已确认的源码目录映射，不做模糊递归搜索，避免补丁打到错误同名文件。
  const workspacePath: Record<string, string> = {
    [SETTINGS_PACKAGE]: path.join('packages', 'client', 'ui-settings'),
    [WORKSPACE_PACKAGE]: path.join('packages', 'client', 'ui-workspace'),
    [STARTUP_PACKAGE]: path.join('packages', 'bundle', 'web-app'),
    [CONNECTION_PACKAGE]: path.join('packages', 'client', 'connection'),
  };
  const workspacePackage = workspacePath[packageName];
  if (workspacePackage !== undefined) {
    const candidate = path.join(dshRoot, workspacePackage, relativePath);
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

const SETTINGS_PACKAGE = '@deepseek-ai/dsh-client-ui-settings';
const SETTINGS_FILE = path.join('lib', 'client.js');
const WHITELIST_PACKAGE = '@deepseek-ai/dsh-host-apiproxy';
const WHITELIST_FILE = path.join('lib', 'index.js');
const WORKSPACE_PACKAGE = '@deepseek-ai/dsh-client-ui-workspace';
const WORKSPACE_FILE = path.join('lib', 'client.js');
const STARTUP_PACKAGE = '@deepseek-ai/dsh-web-app';
const STARTUP_FILE = path.join('lib', 'startup.js');
const CONNECTION_PACKAGE = '@deepseek-ai/dsh-client-connection';
const CONNECTION_FILE = path.join('lib', 'index.js');
const AUTH_COOKIE_PATCH_MARK = 'dshpw-authenticated-cookie';
const AUTH_COOKIE_PATCH_HARDEN_MARK = 'dshpw-authenticated-cookie-loopback-v2';
// dsh 上游安全闸：拒绑 0.0.0.0（防把可执行 RPC 暴露到网络）。分容器拓扑中网关容器
// 要跨容器访问 dsh web，但 dsh 只允许回环——本子补丁默认关闭（MCP_DSH_PATCH_ALLOW_BIND_ALL=1
// 开启），开启后允许 dsh 绑所有网卡，使另一容器的网关能访问到 dsh web。
const BIND_ALL_MARK = 'dshpw-bindall';
const BIND_ALL_FROM =
  'if (options.host === "0.0.0.0") program.error("error: --host 0.0.0.0 is intentionally not supported yet for safety: it would expose remote code execution to the network; use 127.0.0.1 instead");';
const BIND_ALL_TO =
  `/* ${BIND_ALL_MARK} */ if (options.host === "0.0.0.0") console.warn("[dshpw] --host 0.0.0.0 enabled for gateway reachability");`;
// 结构化闸签名：不依赖完整报错文案——上游改措辞仍能识别「拒绑闸还在」，
// 真正移除拒绑（原生支持 0.0.0.0）才不匹配。用于 fail-closed 状态判定。
const BIND_ALL_GUARD_RE = /program\.error\(\s*['"][^'"]*0\.0\.0\.0[^'"]*['"]/;;

/**
 * Add the alpha.1 Host-only Cookie minting bridge. The official browser auth
 * flow remains unchanged: browsers still receive a Cookie only after the
 * one-time query-token exchange. This extra method is callable only by the
 * in-process Host plugin and returns a Cookie pair, never a token or Set-Cookie
 * header. The replacement is deliberately marker-based and idempotent so an
 * upstream bundle can be repatched after npm updates.
 */
function authenticatedCookieMethodSource(): string {
  return [
    `\t/** ${AUTH_COOKIE_PATCH_MARK} / ${AUTH_COOKIE_PATCH_HARDEN_MARK}: trusted Host-side authority-bound Cookie mint. */`,
    '\tauthenticatedCookie(baseUrl) {',
    '\t\tconst url = new URL(baseUrl);',
    '\t\tif (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("client-connection: authenticatedCookie requires HTTP(S)");',
    '\t\tif (url.username !== "" || url.password !== "") throw new Error("client-connection: authenticatedCookie rejects URL credentials");',
    '\t\tconst parts = url.hostname.split(".");',
    '\t\tconst loopback = url.hostname === "localhost" || url.hostname === "[::1]" || (parts.length === 4 && parts[0] === "127" && parts.every((part) => /^\\d{1,3}$/.test(part) && Number(part) <= 255));',
    '\t\tif (!loopback) throw new Error("client-connection: authenticatedCookie requires a loopback authority");',
    '\t\tconst authority = url.host;',
    '\t\tconst issuedAt = Date.now();',
    '\t\tconst expiresAt = issuedAt + this.maxAgeMilliseconds;',
    '\t\tconst value = encodeCookie({ version: COOKIE_PAYLOAD_VERSION, authority, issuedAt, expiresAt }, this.secret);',
    "\t\treturn cookieName(authority) + '=' + value;",
    '\t}',
  ].join('\n');
}

function patchConnectionAuthCookie(content: string): string | null {
  if (content.includes(AUTH_COOKIE_PATCH_HARDEN_MARK)) return null;
  const browserMethod = /(\n\s*authenticatedUrl\(baseUrl\)\s*\{[\s\S]*?\})\n(?=\s*\/\*|\s*authorizeIndex\()/;
  const browserMatch = browserMethod.exec(content);
  if (browserMatch === null) return null;

  // Upgrade a previously injected alpha bridge in place. The old marker is
  // intentionally accepted only as a migration signal; the new method adds
  // the authority/protocol/loopback boundary before minting any Cookie.
  if (content.includes(AUTH_COOKIE_PATCH_MARK)) {
    const oldBrowserCookie = /\n\s*\/\*\* dshpw-authenticated-cookie: trusted Host-side authority-bound Cookie mint\. \*\/\n\s*authenticatedCookie\(baseUrl\) \{[\s\S]*?\n\s*\}\n(?=\s*\/\*|\s*authorizeIndex\()/;
    const oldMatch = oldBrowserCookie.exec(content);
    if (oldMatch === null) return null;
    const migrated = content.replace(oldBrowserCookie, `\n${authenticatedCookieMethodSource()}\n`);
    return migrated === content ? null : migrated;
  }

  const browserInsertion = [
    browserMatch[0].trimEnd(),
    authenticatedCookieMethodSource(),
    '',
  ].join('\n');
  let next = content.replace(browserMethod, `\n${browserInsertion}`);
  const hostMethod = /(\n\s*authenticatedUrl\(baseUrl\)\s*\{\s*return this\.browserAuth\.authenticatedUrl\(baseUrl\);\s*\})\n/;
  const hostMatch = hostMethod.exec(next);
  if (hostMatch === null) return null;
  const hostInsertion = [
    hostMatch[0].trimEnd(),
    `\t/** ${AUTH_COOKIE_PATCH_MARK}: expose only the derived Cookie pair to trusted Host plugins. */`,
    '\tauthenticatedCookie(baseUrl) { return this.browserAuth.authenticatedCookie(baseUrl); }',
    '',
  ].join('\n');
  next = next.replace(hostMethod, `\n${hostInsertion}`);
  return next === content ? null : next;
}

/** 分容器拓扑开关：MCP_DSH_PATCH_ALLOW_BIND_ALL=1/true/yes 时允许 dsh web 绑 0.0.0.0 */
function bindAllEnabled(): boolean {
  const raw = (process.env.MCP_DSH_PATCH_ALLOW_BIND_ALL ?? '').trim().toLowerCase();
  return ['1', 'true', 'yes'].includes(raw);
}

const SETTINGS_FROM = 'connection.isLoopback ? "host" : "memory"';
// DSH 0.1.2 alpha/rc releases moved the loopback fact from the old connection
// service to the Remote Host facts. Keep this as a distinct anchor: absence of
// the legacy string alone must never be treated as a successful remote patch.
const SETTINGS_ALPHA_FROM = 'ctx.remote.$host.isLoopback ? "host" : "memory"';
const SETTINGS_TO = '"host"';

// dsh 上游行为：搜索 query 非空时点击侧栏外只 blur 不收起——无结果时
// 「无匹配会话」死状态会永久滞留侧栏（打开设置/卡片等任何点击都无法消除，
// 只能手动按 Esc/X）。子补丁：无结果（ready/error 且 0 条）时点击别处自动清空并收起。
// rc.7/rc.8 都保留同一行为契约，但 rc.8 的 bundle 压缩了换行并给 effect
// 依赖增加 searchOnExpand。按语义片段匹配，不能依赖具体格式，否则补丁会静默跳过。
const SEARCH_STICKY_RE =
  /(searchInput\.current\?\.\s*blur\(\);\s*)if\s*\(normalizedQuery\s*!==\s*""\)\s*return;\s*(setSearchExpanded\(false\);)/;
const SEARCH_STICKY_TO =
  '$1if (normalizedQuery === "") { $2 } else if (remoteSearch.status !== "loading" && remoteSearch.items.length === 0) { setQuery(""); $2 }';
// 上面新增了 remoteSearch 读取：click-outside effect 的依赖数组必须补上，否则闭包里的
// remoteSearch 是注册时的旧值（结果到达后不重新注册）→ 永远看到 loading，补丁失效。
// 只匹配同时含 normalizedQuery/wide/searchExpanded 的该 effect 依赖数组，兼容 rc.8
// 新增的 searchOnExpand 和不同的换行/缩进。
const SEARCH_DEPS_RE =
  /(\},\s*\[\s*)(normalizedQuery\s*,\s*wide\s*,\s*searchExpanded)/;
const SEARCH_DEPS_TO = '$1remoteSearch, $2';
const SEARCH_DEPS_PATCHED_RE =
  /\},\s*\[\s*remoteSearch\s*,\s*normalizedQuery\s*,\s*wide\s*,\s*searchExpanded/;

function hasSettingsNamespace(content: string, namespace: string): boolean {
  const escaped = namespace.replace(/[.*+?^${}()|[\[\]\\]/g, '\\$&');
  return new RegExp(`["']${escaped}["']`).test(content);
}

// dsh 上游行为：搜索输入框无 autocomplete/name 属性——浏览器密码管理器在页面出现
// 密码框时会用启发式找用户名框（DOM 里密码框之前最近的文本框），侧栏搜索框会被
// 选中并填入已存用户名（实测被填 "admin" → 触发搜索 → 无匹配会话，见 PROCESS.md
// 步骤 32）。子补丁：给搜索框加 autocomplete="off" + 中性 name，摘掉用户名框资格。
const SEARCH_AUTOFILL_MARK = 'dshpw-session-search';
const SEARCH_AUTOFILL_HARDEN_MARK = 'data-dshpw-autofill-harden';
const SEARCH_AUTOFILL_RE =
  /(className:\s*WorkspaceBrowser_module_css_default\.searchInput,\s*type:\s*"text",)/;
// v2：autocomplete=off 会被部分密码管理器忽略；search + 折叠态 readOnly + 厂商忽略
// 标记组合更稳。readOnly 只在搜索框折叠时生效，用户主动展开后仍可正常输入。
const SEARCH_AUTOFILL_TO =
  '$1\n\t\t\t\t\t\t\tautoComplete: "search",\n\t\t\t\t\t\t\tname: "dshpw-session-search",\n\t\t\t\t\t\t\treadOnly: !searchExpanded,\n\t\t\t\t\t\t\t\'data-dshpw-autofill-harden\': "v2",\n\t\t\t\t\t\t\t\'data-lpignore\': "true",\n\t\t\t\t\t\t\t\'data-1p-ignore\': "true",\n\t\t\t\t\t\t\t\'data-bwignore\': "true",';
const SEARCH_AUTOFILL_V2_RE =
  /(autoComplete:\s*)"off"(,\s*name:\s*[\"']dshpw-session-search[\"'],)/;
const SEARCH_AUTOFILL_V2_TO =
  '$1"search"$2\n\t\t\t\t\t\t\treadOnly: !searchExpanded,\n\t\t\t\t\t\t\t\'data-dshpw-autofill-harden\': "v2",\n\t\t\t\t\t\t\t\'data-lpignore\': "true",\n\t\t\t\t\t\t\t\'data-1p-ignore\': "true",\n\t\t\t\t\t\t\t\'data-bwignore\': "true",';

/**
 * 命名空间白名单补丁是否适用当前 dsh。
 * dsh 0.1.0-rc.7+ 移除了主机侧硬编码 WEB_SETTINGS_NAMESPACES 白名单
 * （改用 settings.describe() 动态枚举命名空间），此时无对象可打 →
 * 视为原生支持，无需（也无法）再插 "dsh-passwords"。
 * 旧版 dsh（<=rc.6）仍需要追加白名单，走插入分支；
 * 当前 rc.8 属 rc.7+ 行为，原生支持，走不到该分支。
 */
function whitelistPatchApplicable(content: string): boolean {
  return /WEB_SETTINGS_NAMESPACES\s*=/.test(content);
}

/** 找到 dsh 安装根目录（@deepseek-ai/dsh），找不到返回 null */
export function findDshRoot(explicit: string): string | null {
  if (explicit) return existsSync(explicit) ? explicit : null;
  try {
    const globalRoot = spawnSync('npm', ['root', '-g'], { encoding: 'utf8' }).stdout.trim();
    const candidate = path.join(globalRoot, '@deepseek-ai', 'dsh');
    if (existsSync(candidate)) return candidate;
  } catch {
    // npm 不可用时走兜底路径
  }
  // 本地依赖：从 cwd 向上找 node_modules/@deepseek-ai/dsh
  // （覆盖 npm i 到项目本地而非全局的场景，如 Windows/开发机/手动部署）
  let dir = process.cwd();
  for (;;) {
    const candidate = path.join(dir, 'node_modules', '@deepseek-ai', 'dsh');
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  for (const candidate of [
    '/usr/local/lib/node_modules/@deepseek-ai/dsh',
    '/usr/lib/node_modules/@deepseek-ai/dsh',
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/** 补丁当前状态（用于 status 展示） */
export function patchStatus(
  dshRoot: string,
): {
  settingsHostMode: boolean;
  whitelist: boolean;
  workspaceSearch: boolean;
  bindAll: boolean;
  connectionCookieBridge: 'patched' | 'native' | 'missing' | 'unsupported';
} {
  const settingsFile = findDshBundleFile(dshRoot, SETTINGS_PACKAGE, SETTINGS_FILE);
  const wlFile = findDshBundleFile(dshRoot, WHITELIST_PACKAGE, WHITELIST_FILE);
  const wsFile = findDshBundleFile(dshRoot, WORKSPACE_PACKAGE, WORKSPACE_FILE);
  let settingsHostMode = false;
  let whitelist = false;
  let workspaceSearch = false;
  let connectionCookieBridge: 'patched' | 'native' | 'missing' | 'unsupported' = 'missing';
  try {
    if (settingsFile === null) throw new Error('settings bundle not found');
    const s = readFileSync(settingsFile, 'utf8');
    settingsHostMode =
      !s.includes(SETTINGS_FROM) &&
      !s.includes(SETTINGS_ALPHA_FROM) &&
      s.includes(SETTINGS_TO);
  } catch { /* 文件缺失按未打处理 */ }
  try {
    // rc.7+ / alpha 的 @Remote gateway 已移除旧 ApiProxy 白名单；旧包缺失
    // 本身就是原生动态注册机制，不应阻断其他独立补丁。
    if (wlFile === null) {
      whitelist = true;
    } else {
      const w = readFileSync(wlFile, 'utf8');
      whitelist = !whitelistPatchApplicable(w) || hasSettingsNamespace(w, 'dsh-passwords');
    }
  } catch { /* 同上 */ }
  try {
    if (wsFile === null) throw new Error('workspace bundle not found');
    const ws = readFileSync(wsFile, 'utf8');
    // 打过 = 不再含旧行为串 + 含子补丁标记（文件缺失按未打处理）
    // 括号显式分组：自动填充「已打 v2 标记」与「不适用（RE 无匹配）」必须
    // 先于粘滞态子补丁成立——否则 (A&&B&&C)||D 在 D 恒真时会把
    // 未打粘滞态的文件误报为已打。
    workspaceSearch =
      !ws.includes('if (normalizedQuery !== "") return;') &&
      ws.includes('remoteSearch.status !== "loading"') &&
      SEARCH_DEPS_PATCHED_RE.test(ws) &&
      // 搜索框自动填充加固：v2 标记存在才算完成；旧 v1（仅 off+name）会自动升级
      (ws.includes(SEARCH_AUTOFILL_HARDEN_MARK) || !SEARCH_AUTOFILL_RE.test(ws));
  } catch { /* 同上 */ }
  const connectionFile = findDshBundleFile(dshRoot, CONNECTION_PACKAGE, CONNECTION_FILE);
  if (connectionFile !== null) {
    try {
      const connection = readFileSync(connectionFile, 'utf8');
      if (connection.includes(AUTH_COOKIE_PATCH_HARDEN_MARK)) {
        connectionCookieBridge = 'patched';
      } else if (connection.includes('authenticatedCookie(baseUrl)')) {
        connectionCookieBridge = 'native';
      } else if (connection.includes('authenticatedUrl(baseUrl)')) {
        connectionCookieBridge = 'unsupported';
      }
    } catch {
      connectionCookieBridge = 'missing';
    }
  }
  let bindAll = true;
  try {
    if (bindAllEnabled()) {
      const stFile = findDshBundleFile(dshRoot, STARTUP_PACKAGE, STARTUP_FILE);
      // fail-closed：已打（标记存在）或上游原生移除拒绑闸才算满足；精确串
      // 失配 + 无标记（上游改了报错文案）必须报未打，否则 Docker 校验会
      // 静默放行实际未打补丁的容器。
      const st = stFile === null ? null : readFileSync(stFile, 'utf8');
      bindAll = st !== null && (st.includes(BIND_ALL_MARK) || !BIND_ALL_GUARD_RE.test(st));
    }
  } catch {
    bindAll = false;
  }
  return { settingsHostMode, whitelist, workspaceSearch, bindAll, connectionCookieBridge };
}

/** 应用补丁（幂等）：返回 'applied'（本次有改动）或 'unchanged' 或 'missing'（目标文件不在） */
export function applyRemotePatch(dshRoot: string): 'applied' | 'unchanged' | 'missing' {
  const settingsFile = findDshBundleFile(dshRoot, SETTINGS_PACKAGE, SETTINGS_FILE);
  const wlFile = findDshBundleFile(dshRoot, WHITELIST_PACKAGE, WHITELIST_FILE);
  const connectionFile = findDshBundleFile(dshRoot, CONNECTION_PACKAGE, CONNECTION_FILE);
  if (settingsFile === null) return 'missing';
  let changed = false;

  // 旧 ApiProxy 白名单目标在 alpha 已删除；其缺失表示采用 @Remote 动态注册，
  // 不能阻断 settings/workspace/startup 等独立目标。只有目标存在时才尝试旧补丁。
  let w = '';
  let whitelistPatched: string | null = null;
  if (wlFile !== null) {
    w = readFileSync(wlFile, 'utf8');
    migrateLegacyBackup(wlFile, w, (original) => {
      if (!whitelistPatchApplicable(original) || hasSettingsNamespace(original, 'dsh-passwords')) return null;
      const re = /const WEB_SETTINGS_NAMESPACES = \[([\s\S]*?)\];/;
      const match = re.exec(original);
      if (!match) return null;
      const inserted = match[1].replace(/(\s*[\'\"][^\'\"]+[\'\"])/, `$1,\n\t"dsh-passwords"`);
      return original.replace(re, `const WEB_SETTINGS_NAMESPACES = [${inserted}];`);
    });
    if (whitelistPatchApplicable(w) && !hasSettingsNamespace(w, 'dsh-passwords')) {
      const re = /const WEB_SETTINGS_NAMESPACES = \[([\s\S]*?)\];/;
      const match = re.exec(w);
      if (!match) return 'missing';
      const currentBlock = match[1];
      const existing = [...currentBlock.matchAll(/[\'\"]([^\'\"]+)[\'\"]/g)].map((m) => m[1]);
      if (!existing.includes('dsh-passwords')) {
        const inserted = currentBlock.replace(/(\s*[\'\"][^\'\"]+[\'\"])/, `$1,\n\t"dsh-passwords"`);
        whitelistPatched = w.replace(re, `const WEB_SETTINGS_NAMESPACES = [${inserted}];`);
      }
    }
  }

  // alpha.1 connection：为 dsh-passwords 的同进程 Host 插件提供受信任的
  // authority-bound Cookie 派生入口。首次启动后会在磁盘上完成补丁；后续
  // dsh 重启加载已打补丁的 HostConnectionService，插件即可无网络地刷新 Cookie。
  if (connectionFile !== null) {
    const c = readFileSync(connectionFile, 'utf8');
    migrateLegacyBackup(connectionFile, c, patchConnectionAuthCookie);
    const patched = patchConnectionAuthCookie(c);
    if (patched !== null) {
      ensureOriginalBackup(connectionFile, c, patched);
      writeFileSync(connectionFile, patched);
      changed = true;
    }
  }

  // 1) 客户端 settings 强制 host 模式
  // rc.8 起文件中有两处该三元（SettingsScopeController + SettingsDescribeMirror）：
  // String.replace(string, string) 只替换第一处，首轮补丁会让 DescribeMirror 漏打，
  // 远程浏览器设置页报 "settings are unavailable in this browser"（Issue #8）。
  // split/join 全量替换，一轮打完。
  const s = readFileSync(settingsFile, 'utf8');
  migrateLegacyBackup(settingsFile, s, (original) => {
    const patched = original
      .split(SETTINGS_FROM).join(SETTINGS_TO)
      .split(SETTINGS_ALPHA_FROM).join(SETTINGS_TO);
    return patched === original ? null : patched;
  });
  if (s.includes(SETTINGS_FROM) || s.includes(SETTINGS_ALPHA_FROM)) {
    const patched = s
      .split(SETTINGS_FROM).join(SETTINGS_TO)
      .split(SETTINGS_ALPHA_FROM).join(SETTINGS_TO);
    ensureOriginalBackup(settingsFile, s, patched);
    writeFileSync(settingsFile, patched);
    changed = true;
  }

  // 2) 白名单补齐（仅 rc.6 及以下适用）。rc.7+（含当前 rc.8）已移除该机制，预检结果为 null。
  if (whitelistPatched !== null && wlFile !== null) {
    ensureOriginalBackup(wlFile, w, whitelistPatched);
    writeFileSync(wlFile, whitelistPatched);
    changed = true;
  }

  // 3) 工作区侧栏搜索两个子补丁（可选：目标文件不存在则跳过，不影响 1/2）
  //    ① 无结果搜索点击别处自动收起并清空（消除「无匹配会话」死状态滞留）
  //    ② 搜索框 autocomplete="off" + 中性 name（阻断密码管理器把搜索框当用户名框自动填充）
  const wsFile = findDshBundleFile(dshRoot, WORKSPACE_PACKAGE, WORKSPACE_FILE);
  if (wsFile !== null) {
    const ws = readFileSync(wsFile, 'utf8');
    migrateLegacyBackup(wsFile, ws, (original) => {
      let next = original;
      if (SEARCH_STICKY_RE.test(next) && SEARCH_DEPS_RE.test(next)) {
        next = next.replace(SEARCH_STICKY_RE, SEARCH_STICKY_TO).replace(SEARCH_DEPS_RE, SEARCH_DEPS_TO);
      }
      if (!next.includes(SEARCH_AUTOFILL_HARDEN_MARK)) {
        if (SEARCH_AUTOFILL_RE.test(next) && !next.includes(SEARCH_AUTOFILL_MARK)) {
          next = next.replace(SEARCH_AUTOFILL_RE, SEARCH_AUTOFILL_TO);
        } else if (SEARCH_AUTOFILL_V2_RE.test(next)) {
          next = next.replace(SEARCH_AUTOFILL_V2_RE, SEARCH_AUTOFILL_V2_TO);
        } else if (next.includes(SEARCH_AUTOFILL_MARK)) {
          const nameRe = /(name:\s*[\"']dshpw-session-search[\"'],)/;
          if (nameRe.test(next)) {
            next = next.replace(nameRe, '$1\n\t\t\t\t\t\t\treadOnly: !searchExpanded,\n\t\t\t\t\t\t\t\'data-dshpw-autofill-harden\': "v2",\n\t\t\t\t\t\t\t\'data-lpignore\': "true",\n\t\t\t\t\t\t\t\'data-1p-ignore\': "true",\n\t\t\t\t\t\t\t\'data-bwignore\': "true",');
          }
        }
      }
      return next === original ? null : next;
    });
    let wsNext = ws;
    let wsChanged = false;
    if (SEARCH_STICKY_RE.test(wsNext) && SEARCH_DEPS_RE.test(wsNext)) {
      wsNext = wsNext.replace(SEARCH_STICKY_RE, SEARCH_STICKY_TO).replace(SEARCH_DEPS_RE, SEARCH_DEPS_TO);
      wsChanged = true;
    }
    if (!wsNext.includes(SEARCH_AUTOFILL_HARDEN_MARK)) {
      if (SEARCH_AUTOFILL_RE.test(wsNext) && !wsNext.includes(SEARCH_AUTOFILL_MARK)) {
        wsNext = wsNext.replace(SEARCH_AUTOFILL_RE, SEARCH_AUTOFILL_TO);
        wsChanged = true;
      } else if (SEARCH_AUTOFILL_V2_RE.test(wsNext)) {
        // 已应用 v1：只升级属性，不重复插入 name/搜索字段
        wsNext = wsNext.replace(SEARCH_AUTOFILL_V2_RE, SEARCH_AUTOFILL_V2_TO);
        wsChanged = true;
      } else if (wsNext.includes(SEARCH_AUTOFILL_MARK)) {
        // 容错：dsh bundle 格式变化但保留 v1 name，补齐 v2 属性
        const nameRe = /(name:\s*[\"']dshpw-session-search[\"'],)/;
        if (nameRe.test(wsNext)) {
          wsNext = wsNext.replace(
            nameRe,
            '$1\n\t\t\t\t\t\t\treadOnly: !searchExpanded,\n\t\t\t\t\t\t\t\'data-dshpw-autofill-harden\': "v2",\n\t\t\t\t\t\t\t\'data-lpignore\': "true",\n\t\t\t\t\t\t\t\'data-1p-ignore\': "true",\n\t\t\t\t\t\t\t\'data-bwignore\': "true",',
          );
          wsChanged = true;
        }
      }
    }
    if (wsChanged) {
      ensureOriginalBackup(wsFile, ws, wsNext);
      writeFileSync(wsFile, wsNext);
      changed = true;
    }
  }

  // 4) 允许 dsh web 绑 0.0.0.0（默认关闭：MCP_DSH_PATCH_ALLOW_BIND_ALL=1 才打；
  //    分容器拓扑需要网关容器跨容器访问 dsh web）。目标文件缺失则跳过，不影响 1-3。
  //    开关关闭时反向自愈：恢复曾打过的 startup.js（见下）。
  if (bindAllEnabled()) {
    const stFile = findDshBundleFile(dshRoot, STARTUP_PACKAGE, STARTUP_FILE);
    if (stFile !== null) {
      const st = readFileSync(stFile, 'utf8');
      migrateLegacyBackup(stFile, st, (original) =>
        original.includes(BIND_ALL_FROM) ? original.replace(BIND_ALL_FROM, BIND_ALL_TO) : null,
      );
      if (st.includes(BIND_ALL_FROM)) {
        const patched = st.replace(BIND_ALL_FROM, BIND_ALL_TO);
        ensureOriginalBackup(stFile, st, patched);
        writeFileSync(stFile, patched);
        changed = true;
      }
    }
  } else {
    // 开关关闭时自愈：曾开启过的部署（共享卷/复用状态卷）会残留已移除闸的
    // startup.js，静默保留等于关闭开关后安全闸仍未恢复。仅在当前内容与备份
    // 元数据完全吻合时恢复（与 rollbackPatch 同口径，防跨版本污染）。
    const stFile = findDshBundleFile(dshRoot, STARTUP_PACKAGE, STARTUP_FILE);
    if (stFile !== null && currentMatchesPatchedBackup(stFile)) {
      writeFileSync(stFile, readFileSync(stFile + BAK_SUFFIX));
      changed = true;
    }
  }

  return changed ? 'applied' : 'unchanged';
}

/**
 * 回滚补丁：从 .bak-dshpw 备份恢复目标文件。
 * 备份不存在（从未打过补丁）时返回 'no-backup'。
 */
export function rollbackPatch(dshRoot: string): 'rolled-back' | 'no-backup' | 'missing' | 'modified' {
  const settingsFile = findDshBundleFile(dshRoot, SETTINGS_PACKAGE, SETTINGS_FILE);
  const wlFile = findDshBundleFile(dshRoot, WHITELIST_PACKAGE, WHITELIST_FILE);
  if (settingsFile === null) return 'missing';
  const wsFile = findDshBundleFile(dshRoot, WORKSPACE_PACKAGE, WORKSPACE_FILE);
  const stFile = findDshBundleFile(dshRoot, STARTUP_PACKAGE, STARTUP_FILE);
  const connectionFile = findDshBundleFile(dshRoot, CONNECTION_PACKAGE, CONNECTION_FILE);
  const targets = [settingsFile, wlFile, wsFile, stFile, connectionFile].filter((target): target is string => target !== null);

  // Preflight every target before writing any file. A partial rollback would leave
  // DSH in an undocumented mixed state when another tool has changed one bundle.
  const backedUp = targets.filter((target) => readBackupMeta(target) !== null);
  if (backedUp.some((target) => !currentMatchesPatchedBackup(target))) return 'modified';
  if (backedUp.length === 0) return 'no-backup';

  for (const target of backedUp) {
    writeFileSync(target, readFileSync(target + BAK_SUFFIX));
    unlinkSync(target + BAK_SUFFIX);
    unlinkSync(backupMetaPath(target));
  }
  return 'rolled-back';
}

/** 延迟重启 dsh 网页服务（补丁生效需要 dsh 重新加载模块）；仅适用于常驻进程
 *  用 spawnSync 参数数组（不拼 shell），杜绝命令注入；服务名仍做字符白名单
 *  双保险（systemctl 只接受合法 unit 名）。 */
export function restartDshWebChecked(service: string, delayMs = 2500): Promise<{ ok: boolean; message: string }> {
  return new Promise((resolve) => {
    if (!service) {
      resolve({ ok: false, message: '未配置 dsh-web 服务名' });
      return;
    }
    if (!/^[A-Za-z0-9_.@-]+$/.test(service)) {
      resolve({ ok: false, message: '重启服务名非法' });
      return;
    }
    const timer = setTimeout(() => {
      try {
        const result = spawnSync('systemctl', ['restart', service], { stdio: 'ignore' });
        if (result.status !== 0 || result.error) {
          resolve({ ok: false, message: result.error instanceof Error ? result.error.message : `systemctl exit ${String(result.status)}` });
          return;
        }
        resolve({ ok: true, message: '' });
      } catch (error) {
        resolve({ ok: false, message: error instanceof Error ? error.message : String(error) });
      }
    }, delayMs);
    timer.unref();
  });
}

export function restartDshWeb(service: string, delayMs = 2500): void {
  void restartDshWebChecked(service, delayMs).then((result) => {
    if (!result.ok) console.error(`[dsh-passwords] 重启 ${service} 失败（补丁将在下次 dsh 重启后生效）: ${result.message}`);
  });
}
