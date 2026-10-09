// 子用户权限模型 + 网关侧强制执行的纯函数（无 DB/框架依赖，便于复用与测试）。
//
// 权限（主用户在设置卡片里为每个子用户配置）：
//   - allowedFolders         允许打开的工作区/项目文件夹（绝对路径；空数组 = 全部允许，
//                            __deny__ 哨兵 = 禁止所有）
//   - hourlyTokenLimit       每小时 token 上限（null = 不限）
//   - dailyMinutesLimit      每日使用时长上限，分钟（从当天首次使用起算；null = 不限）
//   - allowUpload            是否使用大请求体/大文件上传档位（false = 64 MiB，true = 300 MiB）
//   - allowGitDownload       是否允许 git 下载（clone/pull 等）
//   - allowWorkspaceCreate   是否允许创建/删除/重命名工作区（创建总开关；能读才能创建）
//   - allowSsh               是否允许使用主用户配置的 SSH 端点与官方 terminal
//   - allowedSessionIds      显式会话授权（未初始化前自动种子化可见会话；保存后新会话不再自动加入）
//   - disabledSessions       已授权工作区内逐会话关闭的会话 ID（兼容旧行为）
//   - sandboxMode            沙盒级别（read-only / workspace-write / danger-full-access）
//   - banned                 是否封禁（封禁后经密码门的请求全部 403）
//
// 统一目录授权：allowedFolders 是**唯一**的读取/创建范围（父目录与目标路径都以词法 +
// canonical 两个口径同时命中 folderAllowed，并拒绝文件系统根/敏感基）。旧列
// workspace_creation_roots 已退役：不再作为独立创建根参与任何活跃授权判定，也不存在
// 主目录（home）或 pending 绕过创建白名单的例外；旧 API 提交该字段由 admin 端点显式 400。
//
// 说明：folder / upload / git 的网关层拦截是"尽力而为"（基于 dsh 的 HTTP API
// 路径与请求体字段）。主用户账号不受任何限制。
import path from 'node:path';

/**
 * 规范化路径：反斜杠转正斜杠、解析 . / .. 点段、去尾部斜杠、
 * Windows 盘符统一小写（大小写不敏感比较）。
 * F-21：必须解析点段——/root/11/../21 在文件系统层等于 /root/21，
 * 若只做字符串前缀匹配，白名单会被 .. 点段直接绕过（实锤：受限子用户
 * 可写/删白名单外文件、建会话到 /etc）。posix.normalize 与 dsh 的
 * 路径解析口径一致（dsh 运行于 Linux 且自身也用 URL/路径归一化）。
 */
export function normalizePath(p: string): string {
  let n = p.replace(/\\/g, '/');
  n = path.posix.normalize(n);
  if (n.length >= 2 && n[1] === ':') n = n[0].toLowerCase() + n.slice(1);
  return n;
}

/** 平台实际认可的完全限定路径；Windows 不接受隐含当前盘符的 /foo 或 \\foo。 */
export function isFullyQualifiedPath(candidate: string): boolean {
  return process.platform === 'win32'
    ? /^[A-Za-z]:[\\/]/.test(candidate)
    : candidate.startsWith('/');
}

/** 该输入是否带有绝对/盘符语义；Windows 下还拒绝 drive-relative 的 C:foo。 */
export function isAbsoluteLikePath(candidate: string): boolean {
  return process.platform === 'win32'
    ? candidate.startsWith('/') || /^[A-Za-z]:/.test(candidate)
    : candidate.startsWith('/');
}

/** 词法或 canonical 路径是否为 POSIX 根或 Windows 盘符根。 */
export function isFilesystemRootPath(candidate: string): boolean {
  const normalized = normalizePath(candidate);
  return normalized === '/' || /^[a-z]:\/$/i.test(normalized);
}

/**
 * 端点登记规则的前缀（都可选、顺序不限、大小写不敏感）：
 *   - `owner:`           仅主用户可用（子用户两条通道一律 403），优先于 ssh 判定；
 *   - `ws:` / `http:`    限定传输通道；不写 = HTTP 与 WebSocket 都放行。
 * 例：`owner:http:/api/plugin/hosts`、`ws:/api/plugin/terminal`、`/api/plugin/*`。
 */
export type EndpointTransport = 'any' | 'http' | 'ws';
/** 规则的能力归属：ssh = 子用户凭 allowSsh 开关使用；owner-only = 仅主用户。 */
export type EndpointCapability = 'ssh' | 'owner-only';

export interface ParsedEndpointRule {
  capability: EndpointCapability;
  transport: EndpointTransport;
  path: string;
}

/**
 * 拆出规则的能力与传输前缀，返回三者。前缀可任意组合/顺序
 * （`owner:ws:` 与 `ws:owner:` 等价）；路径部分原样返回，由调用方校验。
 */
export function parseEndpointRule(rule: string): ParsedEndpointRule {
  let rest = rule;
  let capability: EndpointCapability = 'ssh';
  let transport: EndpointTransport = 'any';
  for (;;) {
    if (capability === 'ssh' && /^owner:/i.test(rest)) {
      capability = 'owner-only';
      rest = rest.slice('owner:'.length);
      continue;
    }
    if (transport === 'any' && /^ws:/i.test(rest)) {
      transport = 'ws';
      rest = rest.slice('ws:'.length);
      continue;
    }
    if (transport === 'any' && /^http:/i.test(rest)) {
      transport = 'http';
      rest = rest.slice('http:'.length);
      continue;
    }
    break;
  }
  return { capability, transport, path: rest };
}

/** 单条规则的路径匹配（已剥离前缀；`/*` 只匹配直接子路径）。 */
function endpointPathMatches(pathname: string, rulePath: string): boolean {
  if (!rulePath.endsWith('/*')) return rulePath === pathname;
  const base = rulePath.slice(0, -2);
  if (!pathname.startsWith(`${base}/`)) return false;
  const child = pathname.slice(base.length + 1);
  return child !== '' && !child.includes('/');
}

/**
 * 解析逗号分隔的端点登记表（HTTP / WebSocket、主用户 / 子用户共用一张表）。
 *
 * 规则语法：`[owner:][ws:|http:]路径`（前缀都可省略、顺序任意）。路径为精确
 * 匹配，或尾部 `/*` 只匹配其直接子路径。登记表是权限边界：格式非法的输入直接
 * 报错（启动阶段 fail-closed），而不是被静默放宽或忽略。表内存放什么完全由主
 * 用户决定——代码不含任何插件专属路径。
 */
export function parseEndpointAllowlist(raw: string | undefined, envName: string): string[] {
  if (raw === undefined || raw.trim() === '') return [];
  const rules = new Set<string>();
  for (const item of raw.split(',')) {
    const entry = item.trim();
    if (entry === '') continue;
    if (entry.length > 256) throw new Error(`${envName}: rule is longer than 256 characters`);
    const parsed = parseEndpointRule(entry);
    const rule = parsed.path;
    if (rule === '') throw new Error(`${envName}: rule is missing a path: ${entry}`);
    if (!rule.startsWith('/')) {
      throw new Error(`${envName}: rule must start with / (optionally after owner:/ws:/http: prefixes): ${entry}`);
    }
    if (/[? #%\\\u0000-\u001f\u007f]/.test(rule)) {
      throw new Error(`${envName}: rule contains query, encoding, backslash, or control characters: ${entry}`);
    }
    const wildcard = rule.endsWith('/*');
    if (rule.includes('*') && !wildcard) {
      throw new Error(`${envName}: only a trailing /* wildcard is supported: ${entry}`);
    }
    const pathPart = wildcard ? rule.slice(0, -2) : rule;
    if (pathPart === '' || pathPart === '/') throw new Error(`${envName}: root and /* are not allowed`);
    if (pathPart === '/gateway' || pathPart.startsWith('/gateway/')) {
      throw new Error(`${envName}: gateway paths cannot be registered: ${entry}`);
    }
    if (pathPart === '/api/dsh-passwords/internal' || pathPart.startsWith('/api/dsh-passwords/internal/')) {
      throw new Error(`${envName}: internal gateway paths cannot be registered: ${entry}`);
    }
    const segments = pathPart.split('/').slice(1);
    if (segments.some((segment) => segment === '.' || segment === '..' || segment === '')) {
      throw new Error(`${envName}: rule contains an empty or dot path segment: ${entry}`);
    }
    const capabilityPrefix = parsed.capability === 'owner-only' ? 'owner:' : '';
    const transportPrefix = parsed.transport === 'any' ? '' : `${parsed.transport}:`;
    rules.add(`${capabilityPrefix}${transportPrefix}${rule}`);
    if (rules.size > 64) throw new Error(`${envName}: at most 64 rules are supported`);
  }
  return [...rules];
}

/**
 * 路径是否命中登记规则。`/*` 只授予其直接子路径，不放行基路径与更深层路径；
 * 调用方需先剥离 query。可选按能力（owner-only / ssh）与传输通道过滤：
 * 不传 capability 时两种能力的规则都算命中（SSRF 校验等场景）。
 */
const parsedEndpointRuleCache = new Map<string, ParsedEndpointRule>();

function cachedEndpointRule(rule: string): ParsedEndpointRule {
  const cached = parsedEndpointRuleCache.get(rule);
  if (cached !== undefined) return cached;
  const parsed = parseEndpointRule(rule);
  if (parsedEndpointRuleCache.size >= 512) {
    const oldest = parsedEndpointRuleCache.keys().next().value;
    if (typeof oldest === 'string') parsedEndpointRuleCache.delete(oldest);
  }
  parsedEndpointRuleCache.set(rule, parsed);
  return parsed;
}

export function endpointAllowed(
  pathname: string,
  rules: readonly string[],
  options: { transport?: 'http' | 'ws'; capability?: EndpointCapability } = {},
): boolean {
  for (const rule of rules) {
    const parsed = cachedEndpointRule(rule);
    if (options.capability !== undefined && parsed.capability !== options.capability) continue;
    if (options.transport !== undefined && parsed.transport !== 'any' && parsed.transport !== options.transport) continue;
    if (endpointPathMatches(pathname, parsed.path)) return true;
  }
  return false;
}

/**
 * 官方 dsh API 的命名空间（RPC endpoint 的第一段）。
 *
 * 判定口径：官方 dsh 把全部 RPC 挂在共享的 /api 前缀通道上，端点形如
 * `/api/<namespace>/<method>`（旧版本也可能是 `/api/<namespace>.<method>`），
 * 而第三方插件的通道同样是 `/api/<插件名>/...`——两者路径形状相同，只能靠
 * 命名空间区分。
 *
 * 本清单来源：DSH 0.1.7 官方包实测（0.1.7-alpha.1 落地）——@deepseek-ai/dsh-api-remotes
 * 的客户端 Remote 面 `namespace: "..."` 注册，与各 owner 包 `lib/typert.host.js` 的
 * `invocation.namespace` 逐项交叉核对（0.1.5-rc.2 / 0.1.6-alpha.2 实测清单是其子集）。
 * 方向取舍（0.1.7 起收紧）：清单写宽会把第三方路径自动当成 official 直接交给
 * 子用户（绕过主用户的登记决策），因此只登记有实测依据的命名空间；**本地名字
 * 空间式成员不进清单**——例如 `dsh-composer` 是 dsh-client-ui-conversation 里
 * 浏览器端 contenteditable 编辑器的实例名（`Editor({ namespace })`），不是 host
 * RPC 命名空间，列进来会让一切叫 `/api/dsh-composer/...` 的第三方路由无条件获得
 * 官方待遇。非 RPC 的官方路由按精确路径判定（见 OFFICIAL_API_ROUTE_RE），旧的
 * 遗留命名空间只保留已确认的精确端点（见 LEGACY_OFFICIAL_API_ROUTE_RE）。
 * ⚠ `terminal` 命名空间（dsh-api-terminal-controller：list/environment/shells/
 * close/create/write/follow/resize/rename/retain）故意不在清单内：它是服务器端
 * 远程 shell，不能因官方命名空间或宽泛 SSH 登记而自动放行。0.1.7 客户端**确实**
 * 会调用 list/environment/shells/close（终端面板与顶栏「重试恢复终端」先探环境、再列出
 * 已有终端、必要时 create），这些请求由 gateway 的显式 SSH 权限分支处理：allowSsh
 * 关闭时返回无能力 UX 桩，开启时才透传官方 terminal；create/write/follow 等宿主
 * shell 能力同样只在该开关开启后可用。主用户不受影响（管理员不经分类）。
 * 0.1.7 起仍由 SUBUSER_BLOCKED_API_NAMESPACES 硬拒绝通用分类：否则 `/api/terminal/*`
 * 一旦被通用或精确 SSH 规则登记，terminal 就会绕过「官方 terminal 与第三方 SSH
 * 共用一个权限开关」的显式网关语义。terminal/list 的关闭态空成功伪装由 gateway
 * 特殊分支提供，不改变这里的 fail-closed 分类。
 * ⚠ `officeToPdf`（@deepseek-ai/dsh-office-to-pdf，0.1.7 官方）同样不进清单：
 * `render(workspaceFileScope, path, …)` 接受绝对/工作区相对路径，scope 由请求头
 * 派生（sessionId + workspaceRoot），作用域隔离依赖 workspaceFiles 实现（0.1.7
 * 只读审计：可能放行作用域外路径），网关侧尚无该命名空间的会话/文件夹守卫，
 * 真实 E2E 也未证明隔离；在此之前子用户 fail-closed（见
 * SUBUSER_BLOCKED_API_NAMESPACES）。主用户不经分类，不受影响。
 * `pluginManager` 仍不在清单内，并由 SUBUSER_BLOCKED_API_NAMESPACES 硬拒绝；
 * Agent Teams 作为已安装扩展可由动态 manifest 自动适配。
 *
 * 官方面 = 本集合（命名空间）∪ OFFICIAL_API_ROUTE_RE（官方精确路由）∪
 * LEGACY_OFFICIAL_API_ROUTE_RE（旧线保留端点），且必须先通过硬拒绝检查
 * （classifySubuserPath 的判定顺序）。
 * 变更时必须同步 test / 兼容性矩阵。
 */
export const OFFICIAL_API_NAMESPACES: ReadonlySet<string> = new Set([
  // ── 0.1.7 host 侧 RPC 命名空间（dsh-api-remotes 实测，逐个 owner 包核对）──
  'agentPresets',
  'commands',
  'credentials',
  'directoryPicker',
  'dynamicCordisRunner',
  'fileReferences',
  'fileUploads',
  'goals',
  'llm',
  'job',
  'account',
  'messageFeedback',
  'permissionPresets',
  'pluginInventory',
  'schedule', // 0.1.7-rc.2 dsh-schedule；catalog 由网关按条目 sessionId 过滤（见 proxy）
  'session',
  'sessionFeedback',
  'sessionReferenceResolver',
  'settings',
  'skills',
  'subagents',
  'workspace',
  'userQuestions',
  'workspaceFiles',
  // ── 非 RPC 的官方通道 ──
  '$events', // dsh-api-gateway：remote mux 上的逻辑事件流端点（/api/$events*）
  'remote.mux', // dsh-api-gateway：流多路复用 WebSocket
]);

/**
 * `/api/<namespace>[/...]`（或旧式 `/api/<namespace>.<method>`）的命名空间；
 * 非 `/api/` 路径返回 null。取第一段再按 `.` 取头部，两种形状口径一致。
 */
function apiNamespaceOf(pathname: string): { segment: string; head: string } | null {
  if (!pathname.startsWith('/api/')) return null;
  const rest = pathname.slice('/api/'.length);
  const segment = rest.split('/')[0] ?? '';
  const head = segment.split('.')[0] ?? '';
  return { segment, head };
}

/**
 * `/api/<namespace>[.<method>][/<method>…]` 的命名空间与方法拆解；非 /api/、
 * 无方法段或形状不合法返回 null。点号与斜杠两种官方写法同口径
 * （`/api/session.history` 与 `/api/session/history` 都是 session/history）。
 */
function apiEndpointOf(pathname: string): { namespace: string; method: string | null } | null {
  const namespace = apiNamespaceOf(pathname);
  if (namespace === null) return null;
  const dotMethod =
    namespace.segment.length > namespace.head.length + 1
      ? namespace.segment.slice(namespace.head.length + 1)
      : '';
  const segments = pathname.slice('/api/'.length).split('/');
  const slashMethod = segments.length > 1 && segments[1] !== '' ? segments[1] : '';
  const method = dotMethod !== '' ? dotMethod : slashMethod !== '' ? slashMethod : null;
  return { namespace: namespace.head, method };
}

/**
 * 官方**精确路由**（不是命名空间）：官方包用 connection.fetch.register 直接注册
 * 的单条 HTTP 路由，没有更深层路径。按精确路径判定而不是给这些通用词（file /
 * changes / present）开命名空间：第三方插件注册同名 namespace 时不会自动获得
 * 官方待遇（对子用户仍 fail-closed，需主用户登记）。
 *
 * 依据（0.1.7 官方注册点实测）：
 *   - GET/HEAD /api/file                    dsh-api-session-controller：有界文件读取，
 *                                           路径来自 query 且为**任意绝对路径**（无会话作用域）
 *   - GET  /api/changes.summary|diff
 *     POST /api/changes.open                dsh-client-ui-deliverables：变更摘要/对比/宿主打开
 *   - GET  /api/present.host
 *     POST /api/present.open                dsh-client-ui-deliverables：桌面可用性/打开已声明文件
 * （会话日志导出 /api/session.export 由 `session` 命名空间覆盖；remote mux 与
 * $events 见命名空间清单。）
 */
const OFFICIAL_API_ROUTE_RE = /^\/api\/(?:file|changes\.(?:summary|diff|open)|present\.(?:host|open))$/;

/**
 * 旧线（0.1.2 / 0.1.3 / 0.1.5）保留的官方精确路由：网关仍要回连这些 DSH 行，
 * 但它们注册的命名空间在 0.1.7 已不存在或已改名，逐条列出实际端点与现状：
 *   - /api/respond                审批响应（0.1.7 已并入 session/respond）
 *   - /api/events.host|events.mux 旧事件通道（0.1.7 改为 /api/remote.mux）
 *   - /api/host.createDirectory|listDirectory  旧目录选择器 RPC（0.1.7 改为 directoryPicker）
 *   - /api/git.<动词>             dsh 内置 git 工具的 RPC（取数据/只读检视类动词）
 * 兼容只落在这些**精确端点**上，不做整命名空间放行：第三方插件注册同名
 * namespace（例如自己的 /api/git/xyz、/api/host/xyz）不会被当成官方，对子用户
 * 仍是 third-party（未登记即拒绝）；主用户不经分类，不受影响。
 * ⚠ events 只保留点号形状：斜杠形状 /api/events/host 不是 DSH 注册过的路由，
 * 放行会让该路径绕过网关的 host 事件流过滤（信息泄露），因此保持 third-party。
 * ⚠ git 只列取数据/只读动词；写类动词（push/commit/reset…）不在兼容列表，需要时
 * 由主用户按 ssh 规则显式登记（fail-closed）。
 */
const LEGACY_OFFICIAL_API_ROUTE_RE =
  /^\/api\/(?:respond|events\.(?:host|mux)|host[.\/](?:createDirectory|listDirectory)|git[.\/](?:clone|pull|fetch|status|diff|log|show|branch|checkout|lsFiles|ls-files|revParse|rev-parse|remote|tag|tags|blame))$/;

/** 路径是否命中官方精确路由（/api/file、/api/changes.*、/api/present.*）。 */
export function isOfficialApiRoute(pathname: string): boolean {
  return OFFICIAL_API_ROUTE_RE.test(pathname);
}

/** 路径是否命中旧线保留的官方精确路由（respond / events / host 目录 / git 取数据）。 */
export function isLegacyOfficialApiRoute(pathname: string): boolean {
  return LEGACY_OFFICIAL_API_ROUTE_RE.test(pathname);
}

/**
 * 子用户硬拒绝的 API 命名空间：先于端点登记表判定，任何登记规则都无法覆盖。
 *
 * `pluginManager`（dsh-plugin-manager）的 change/runPnpm 可在 profile 内安装、
 * 卸载、运行第三方包——等于把特权/RCE 面交给子用户；`officeToPdf`
 * （dsh-office-to-pdf，0.1.7）的 `render`
 * 接受绝对/工作区相对路径，且底层 workspaceFiles 可能放行作用域外路径（只读
 * 审计尚未证明其隔离边界）。
 * `dynamicCordisRunner` 涉及动态包定义、host half 生命周期和宿主代码执行，
 * 仍然硬拒。
 * `terminal`（dsh-api-terminal-controller）的 create/write/follow 等
 * 是宿主侧远程 shell，不能由官方命名空间或第三方登记表自动开放。命中 `/api/*`
 * 这类宽泛规则（或精确规则）时仍归入 third-party，随后由 gateway 的统一 allowSsh
 * 分支决定是否允许：关闭时 terminal/list/environment/shells/close 回固定的本地
 * UX 桩、其余方法 403；开启时仅官方 terminal 的已知 HTTP/mux 端点原样透传。
 * 未知 terminal 方法仍 fail-closed。terminal 仍不进 OFFICIAL_API_NAMESPACES；
 * 主用户不经分类，官方 terminal 对主用户由网关原样透传。
 *
 * officeToPdf 在作用域隔离经过验证前 fail-closed。productAnalytics、
 * pluginRegistryProbe 和可选的 speech 是宿主级能力，不属于普通扩展透传面。
 */
export const SUBUSER_BLOCKED_API_NAMESPACES: ReadonlySet<string> = new Set([
  'pluginManager',
  'pluginRegistryProbe',
  'dynamicCordisRunner',
  'officeToPdf',
  'productAnalytics',
  'speech',
  'terminal',
]);

/**
 * 子用户硬拒绝的**单个 RPC 端点**（`<namespace>/<method>`）：命名空间整体仍属
 * 官方时用本集合收紧个别方法。与命名空间集合一样先于端点登记表判定，任何登记
 * 规则都无法覆盖（owner: 登记除外，其语义优先）。匹配为**逐方法精确相等**，
 * 不按命名空间前缀扩散：同命名空间的其它方法（含未知方法）不受影响。
 *
 * `dynamicCordisRunner` 已按命名空间整体硬拒绝，未在下方方法集合重复登记。
 *
 * `directoryPicker/pick`（dsh-api-workspace-controller）：直接打开**宿主操作系统
 * 原生目录选择器**，返回的绝对路径不受子用户目录白名单约束，且网关侧没有任何
 * 可校验的输入（无 path、无 sessionId）；它属于宿主操作员能力，子用户 fail-closed。
 * 同命名空间的 list / createDirectory 仍可用：网关对它们有子树白名单校验、创建
 * 记账与响应过滤（见 isDirectoryListRequest / isWorkspaceDirectoryCreate）。
 *
 * 0.1.7 收紧项（全部属于宿主级能力，或网关无法取得可校验归属的请求）：
 *   - `credentials/set` / `credentials/unset`（credentials Remote）：写入/删除宿主
 *     凭据（provider 密钥等）。wire 里只有凭据内容、没有会话身份，网关没有任何
 *     可校验的归属输入；子用户能写凭据就等于能替换宿主身份与上游密钥，fail-closed。
 *   - `settings/openSettingsDocument`（settings Remote）：无路径参数，直接在宿主上
 *     用原生编辑器打开提供方配置文件（在任何沙盒之外）。同命名空间的 `describe`
 *     为只读且已脱敏（redactSecrets），仍按官方路径走网关校验；写方法见下一条。
 *   - `settings/mutate` / `settings/update` / `settings/replace`（settings Remote）：
 *     三者都经同一条 `write(ns, mode, …)` 落盘**宿主全局 settings**（settings.yaml
 *     的任意命名空间，含 llm/权限/插件等宿主级配置）。产品默认面要求子用户只能使用
 *     主用户分配的工作区、使用权与新建会话，不能修改宿主全局 settings；这些写请求的
 *     namespace 与 payload 也没有会话身份，网关无法把写入收敛到某个已授权会话的沙盒，
 *     因此整体 fail-closed（比逐字段 clamp 更严格，且不依赖上游字段形状）。
 *   - `llm/discoverModels`（dsh-llm）：`discoverModels(settingsNs, request)` 由调用方
 *     提供 endpoint/baseURL 与一次性凭据，触发**宿主进程对任意目标发起出站探测**
 *     （模型发现），属于宿主级出站/SSRF 面而非子用户工作区能力；wire 里没有会话
 *     身份，网关无法校验目标归属，fail-closed。同命名空间的 listProviders /
 *     listConfigurableProviders 只是已注册提供方的只读枚举，保持官方面可用。
 *   - `session/openWorkspacePath` / `session/canOpenWorkspacePath` /
 *     `session/workspacePathApplications`（dsh-api-session-controller）：宿主桌面
 *     文件管理器导航、原生能力探测与关联应用枚举。三者 wire 里都**没有会话身份**
 *     （分别只带 `request.path` 或无参），网关无法把动作绑定到某个已授权会话，也
 *     无法用会话 cwd 白名单约束目标路径（`canOpenWorkspacePath` 更是全局能力探测）。
 *     它们不再靠 SESSION_SCOPED_RE 的归属校验（本类请求取不到身份，判定无意义），
 *     统一 fail-closed。
 *   - `dynamicCordisRunner`（dsh-cordis-host-runner）：整个命名空间涉及动态包定义、
 *     host half 生命周期、宿主代码执行、运行状态枚举与插件控制。其请求面无法由
 *     网关可靠收敛到子用户的沙盒/工作区权限，因此 0.1.7 起对子用户整体硬拒绝；
 *     未知或未来新增方法也必须保持 fail-closed。
 *   - `schedule/catalog`（dsh-schedule，0.1.7-rc.2）：无参（`() => …`），返回宿主
 *     全局的活跃/非活跃提醒及其**原始 Session id**。wire 里没有任何会话身份，本集合
 *     曾据此硬拒绝；现行做法改为**官方放行 + 网关逐条响应过滤**：gateway 解析
 *     `result.value` 数组，按每个条目的 `sessionId` 调
 *     `authorizedSubuserSessionRoot`，sessionId 缺失/非法/未授权一律丢弃，因此子用户
 *     只能看到自己已授权会话的提醒（与 workspace.list 的 archivedSessionIds 同一
 *     判定口径）。响应不可解析时 fail-closed（502），绝不回放未过滤的全局清单。
 *     同命名空间的 list / history / update / delete 都带 `request.sessionId`，走
 *     SESSION_SCOPED_RE 的逐会话归属校验。
 */
export const SUBUSER_BLOCKED_API_ENDPOINTS: ReadonlySet<string> = new Set([
  'directoryPicker/pick',
  'account/startSignIn',
  'account/cancelSignIn',
  'account/signOut',
  'credentials/set',
  'credentials/unset',
  'llm/discoverModels',
  'settings/mutate',
  'settings/openSettingsDocument',
  'settings/replace',
  'settings/update',
  'session/openWorkspacePath',
  'session/canOpenWorkspacePath',
  'session/initializeDefaultModel',
  'session/workspacePathApplications',
]);

export const SUBUSER_ALLOWED_ACCOUNT_ENDPOINTS: ReadonlySet<string> = new Set([
  'account/getState',
  'account/getProfile',
  'account/getBalance',
]);

/**
 * 该路径是否命中子用户硬拒绝的命名空间或单个端点
 * （`/api/x`、`/api/x.y`、`/api/x/…` 同口径）。
 */
export function isSubuserBlockedApiPath(pathname: string): boolean {
  // Root-level routes of sensitive host capabilities need the same boundary as
  // their /api counterparts, even when the runtime manifest lists a WS route.
  if (pathname.startsWith('/') && !pathname.startsWith('/api/')) {
    const root = pathname.slice(1).split('/')[0] ?? '';
    if (SUBUSER_BLOCKED_API_NAMESPACES.has(root)) return true;
  }
  const namespace = apiNamespaceOf(pathname);
  if (
    namespace !== null &&
    (SUBUSER_BLOCKED_API_NAMESPACES.has(namespace.segment) ||
      SUBUSER_BLOCKED_API_NAMESPACES.has(namespace.head))
  ) {
    // Block the namespace root as well as every method/deeper path. This avoids a
    // root-path parse miss becoming an official or registered subuser route.
    return true;
  }
  const endpoint = apiEndpointOf(pathname);
  if (endpoint === null) return false;
  if (endpoint.namespace === 'account') {
    return endpoint.method === null || !SUBUSER_ALLOWED_ACCOUNT_ENDPOINTS.has(`account/${endpoint.method}`);
  }
  return endpoint.method !== null && SUBUSER_BLOCKED_API_ENDPOINTS.has(`${endpoint.namespace}/${endpoint.method}`);
}

/**
 * 该路径是否属于官方 dsh API 面。
 *
 * 取第一段（按 `/` 拆分）再按 `.` 取头部，因此 `/api/session/history`、
 * `/api/session.export` 与 `/api/session` 都归入 session 命名空间；非 RPC 的官方
 * 路由按精确路径判定（file / changes.* / present.*），旧线保留端点（respond /
 * events.host|mux / host.createDirectory|listDirectory / git 取数据动词）也只按
 * 精确端点命中——同名第三方 namespace 不会因此无条件变成 official。
 */
export function isOfficialApiPath(pathname: string): boolean {
  if (isOfficialApiRoute(pathname) || isLegacyOfficialApiRoute(pathname)) return true;
  const namespace = apiNamespaceOf(pathname);
  if (namespace === null) return false;
  return OFFICIAL_API_NAMESPACES.has(namespace.segment) || OFFICIAL_API_NAMESPACES.has(namespace.head);
}

/**
 * 根级静态文件扩展名（dist 回退服务直接提供的资源文件）。
 */
const OFFICIAL_ROOT_STATIC_EXT_RE =
  /\.(?:css|js|mjs|cjs|map|ico|png|jpe?g|gif|webp|avif|svg|woff2?|ttf|otf|eot|txt|webmanifest)$/i;

/** DSH 0.1.7 host-open-in-app 的三个官方根级路由。 */
const OFFICIAL_OPEN_IN_APP_ICON_RE = /^\/open-in-app\/icon\/[A-Za-z0-9_-]+$/;

/**
 * 官方站点根级路径（非 /api）：SPA 壳与静态资源、插件客户端 bundle、事件流。
 *
 * 依据（官方 0.1.7 实测）：除 `/plugins` 和静态回退资源外，宿主还注册
 * 了 `dsh-host-open-in-app` 的应用目录、图标与启动路由。其余非 /api 路径一律
 * 视为第三方：未登记对子用户拒绝（fail-closed）。
 */
export function isOfficialRootPath(pathname: string): boolean {
  if (pathname === '/' || pathname === '/index.html' || pathname === '/favicon.ico') return true;
  if (pathname === '/open-in-app/apps' || pathname === '/open-in-app/open' || OFFICIAL_OPEN_IN_APP_ICON_RE.test(pathname)) return true;
  if (pathname.startsWith('/assets/')) return true;
  if (pathname === '/plugins' || pathname.startsWith('/plugins/')) return true;
  return OFFICIAL_ROOT_STATIC_EXT_RE.test(pathname);
}

/**
 * 子用户请求的端点分类（网关唯一的路由分类入口，不含任何插件专属路径）：
 *
 *   platform    —— 网关自身插件路由（/api/dsh-passwords/*），由其自身守卫鉴权
 *   owner-only  —— 登记表中 owner: 规则：子用户两条通道一律拒绝
 *   ssh         —— 登记表中其余规则：子用户需勾选 allow_ssh（两把钥匙）
 *   official    —— 官方 dsh 面 + 宿主运行时已注册的普通插件面
 *   third-party —— 其余未登记插件路径：普通 HTTP 直通，WS 须命中清单
 *
 * 判定顺序 owner-only → blocked → ssh → platform → official → third-party：
 * 显式 owner: 登记优先；SUBUSER_BLOCKED_API_NAMESPACES / SUBUSER_BLOCKED_API_ENDPOINTS
 * 先于 ssh 登记（宽泛规则也不能放行）；transport 决定带传输前缀的规则是否命中
 * （owner: 规则不区分通道）。
 */
export type SubuserPathClass = 'platform' | 'owner-only' | 'ssh' | 'official' | 'third-party';

/**
 * 宿主运行时发现的已注册 Remote/HTTP API 面。它只扩展已加载插件的可观测面，
 * 不猜测未知路径，也不放开硬拒绝的敏感 namespace；动态插件面不复用 allow_ssh。
 */
export interface DynamicPluginManifest {
  namespaces: ReadonlySet<string>;
  streamEndpoints: ReadonlySet<string>;
  exactPaths: ReadonlySet<string>;
  pathPrefixes: ReadonlySet<string>;
  generation: string;
}

export function classifySubuserPath(
  pathname: string,
  options: { endpointRules: readonly string[]; transport: 'http' | 'ws'; dynamicManifest?: DynamicPluginManifest },
): SubuserPathClass {
  if (endpointAllowed(pathname, options.endpointRules, { capability: 'owner-only' })) return 'owner-only';
  if (isSubuserBlockedApiPath(pathname)) return 'third-party';
  if (endpointAllowed(pathname, options.endpointRules, { capability: 'ssh', transport: options.transport })) return 'ssh';
  if (pathname === '/api/dsh-passwords' || pathname.startsWith('/api/dsh-passwords/')) return 'platform';
  if (pathname.startsWith('/api/')) {
    if (isOfficialApiPath(pathname)) return 'official';
    if (dynamicPluginApiPath(pathname, options.dynamicManifest)) return 'official';
    // 普通扩展仍保留 third-party 分类标签；网关授权层不再因此拒绝，
    // 仅用于与显式 SSH/owner 规则和硬拒边界区分。
    return 'third-party';
  }
  if (isOfficialRootPath(pathname)) return 'official';
  if (dynamicPluginRootPath(pathname, options.dynamicManifest)) return 'official';
  // 根级普通插件同样由网关授权层直通；保留 third-party 标签用于
  // 区分显式 SSH/owner 端点，敏感 endpoint 已在前面的硬拒边界处理。
  return 'third-party';
}

/** 动态插件 API/path 判定：只依赖宿主运行时清单，不包含任何插件专属协议。 */
export function dynamicPluginApiPath(pathname: string, manifest: DynamicPluginManifest | undefined): boolean {
  if (manifest === undefined) return false;
  const endpoint = apiEndpointOf(pathname);
  if (endpoint !== null && manifest.namespaces.has(endpoint.namespace)) return true;
  return dynamicPluginPathMatch(pathname, manifest);
}

/** 动态插件根级路由判定；清单路径匹配不扩展到网关内部面。 */
export function dynamicPluginRootPath(pathname: string, manifest: DynamicPluginManifest | undefined): boolean {
  if (manifest === undefined || pathname.startsWith('/api/') || pathname.startsWith('/gateway/')) return false;
  return dynamicPluginPathMatch(pathname, manifest);
}

function dynamicPluginPathMatch(pathname: string, manifest: DynamicPluginManifest): boolean {
  if (manifest.exactPaths.has(pathname)) return true;
  for (const prefix of manifest.pathPrefixes) {
    const base = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    if (pathname === base || pathname.startsWith(`${base}/`)) return true;
  }
  return false;
}

/** 动态 Remote 流只在宿主已注册且未命中子用户硬拒边界的面上放行。 */
export function dynamicPluginStreamAllowed(endpoint: string, manifest: DynamicPluginManifest | undefined): boolean {
  if (manifest === undefined || !manifest.streamEndpoints.has(endpoint)) return false;
  return !isSubuserBlockedRemoteEndpoint(endpoint);
}

/** Remote endpoint 与 HTTP API 共用同一组子用户硬拒边界。 */
export function isSubuserBlockedRemoteEndpoint(endpoint: string): boolean {
  const namespace = endpoint.split('/')[0] ?? '';
  return SUBUSER_BLOCKED_API_NAMESPACES.has(namespace) ||
    (namespace === 'account' && endpoint !== 'account/watch') ||
    SUBUSER_BLOCKED_API_ENDPOINTS.has(endpoint);
}

// ── 官方文件通道（/api/file、present/changes 会话 query 路由）的严格边界判定 ──
// 这些官方路由把“读/打开哪个文件”放在 query 里，而不是 RPC 的会话作用域内，
// 因此网关无法用端点登记或 SESSION_SCOPED_RE 单独完成判定。以下纯函数只做一件事：
// 从 unknown 输入里**严格**取出应有的边界信息；任何形状不符一律返回 null
// （fail-closed，调用方必须按未授权处理，不得回落到默认值）。

/**
 * 官方 /api/file 读取路由（0.1.7 只注册 GET/HEAD）：有界文件读取。
 * ⚠ 路径参数是**任意绝对路径**、没有会话作用域（不随会话工作区隔离），
 * 因此受限子用户必须额外做目录白名单判定（见 fileReadTargetFromQuery）。
 */
export function isOfficialFileReadRequest(method: string, pathname: string): boolean {
  return (method === 'GET' || method === 'HEAD') && pathname === '/api/file';
}

/** 从 unknown 查询容器（URLSearchParams / 普通对象）里取一个非空字符串参数。 */
function queryParam(query: unknown, name: string): string | null {
  if (query instanceof URLSearchParams) {
    const value = query.get(name);
    return value !== null && value !== '' ? value : null;
  }
  if (query === null || typeof query !== 'object' || Array.isArray(query)) return null;
  const value = (query as Record<string, unknown>)[name];
  return typeof value === 'string' && value !== '' ? value : null;
}

/** 从 unknown 查询容器里取一个非负整数字符数（缺失/非法一律 null）。 */
function queryInteger(query: unknown, name: string): number | null {
  const raw = queryParam(query, name);
  if (raw === null || !/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

/** 该路径是否绝对（POSIX 根 或 Windows 盘符）；归一化后再判定。 */
function isAbsoluteLike(candidate: string): boolean {
  return isAbsoluteLikePath(candidate);
}

/**
 * /api/file 的目标路径（严格、fail-closed）：只接受 query 里的 `path`，
 * 且必须是绝对路径、不含 NUL；其余（容器形状未知、参数缺失/为空、相对路径、
 * 控制字符）返回 null。DSH 自身只接受合法绝对路径（否则 400），所以这里的
 * null 不会误伤合法请求，只会让网关对“拿不到可校验路径”的输入拒绝。
 */
export function fileReadTargetFromQuery(query: unknown): string | null {
  const raw = queryParam(query, 'path');
  if (raw === null || raw.includes('\u0000')) return null;
  const normalized = normalizePath(raw);
  return isAbsoluteLike(normalized) ? normalized : null;
}

/** changes.summary|diff|open 与 present.open：会话身份位于 query 的官方路由。 */
const OFFICIAL_SESSION_QUERY_ROUTE_RE = /^\/api\/(?:changes\.(?:summary|diff|open)|present\.open)$/;

/**
 * 该路径是否为“会话身份在 query 里”的官方路由（changes.summary|diff|open、
 * present.open）。这些路由没有 RPC 信封，SESSION_SCOPED_RE 也拿不到 sessionId，
 * 网关必须用 sessionQueryTarget 自行取会话身份再判归属。
 * present.host 不带会话身份（只返回宿主桌面元数据），故不在此列。
 */
export function isOfficialSessionQueryRoute(pathname: string): boolean {
  return OFFICIAL_SESSION_QUERY_ROUTE_RE.test(pathname);
}

export interface SessionQueryTarget {
  sessionId: string;
  /** seq 坐标（缺失/非数字为 null）；调用方需要时应自行 fail-closed。 */
  seq: number | null;
  /** index 坐标（present.open/changes.diff|open 需要；缺失为 null）。 */
  index: number | null;
}

/**
 * 严格解析官方会话 query 路由的坐标（fail-closed）：sessionId 必须是 1..200
 * 字符的字符串，否则返回 null；seq/index 缺失或非法一律记为 null（不编造 0）。
 * 无法确认会话身份时调用方必须拒绝（而不是转发给上游再依赖它的 404/500）。
 */
export function sessionQueryTarget(query: unknown): SessionQueryTarget | null {
  const sessionId = queryParam(query, 'sessionId');
  if (sessionId === null || sessionId.length > 200) return null;
  return { sessionId, seq: queryInteger(query, 'seq'), index: queryInteger(query, 'index') };
}

/**
 * 工作区白名单的"禁止所有"哨兵值：主用户选择"禁止工作区"时存入白名单，
 * 与空数组（=全部允许）区分开（空数组还是"未限制"语义，兼容默认子用户）。
 */
const DENY_ALL_WORKSPACES = '__deny__';

/**
 * 判断 host 是否私网/回环/链路本地地址（已登记 SSH 端点的 SSRF 纵深防御）。
 *
 * F-28：IP 字面量必须用真·inet_aton 语义解析——之前用 Number() 归一化，
 * 被三形态绕过（实测服务端真的解析并连接）：
 *   - 0177.0.0.1（八进制，Number('0177')=177 按十进制处理，漏拦）→ 127.0.0.1
 *   - 2130706433（单段 32 位整数，>255 被判非法放行）→ 127.0.0.1
 *   - 127.0.0.1.nip.io（域名通配，DNS 解析回私网）→ 网关层 DNS 解析后逐地址判
 * 域名（hostname）本层放行，由网关做 DNS 解析后逐地址判定。
 */
export function isPrivateHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (h === '' || h === 'localhost' || h === 'localhost.localdomain') return true;
  // 去掉 [::1] 形式的外层括号
  if (h.startsWith('[') && h.endsWith(']')) return isPrivateHost(h.slice(1, -1));
  if (h.includes(':')) {
    // G-2：zone-id（fe80::1%eth0、::1%0、%25 编码同）只出现在链路本地/回环作用域地址——
    // 语义上必属受限地址，直接判私网（Node 解析器会对部分形式抛 EINVAL/挂死，防御不依赖它）
    if (h.includes('%')) return true;
    // F-29：IPv6 真·16 字节解析后按前缀判。之前只正则匹配 ::1 / :: / fc*: / fe8*:，
    // IPv4-mapped（::ffff:127.0.0.1、::ffff:7f00:1）、IPv4-compatible（::127.0.0.1）
    // 等全部漏判放行（实测 Node socket 把映射地址按 127.0.0.1 连，SSRF 面与 IPv4 侧等同）。
    // 中括号带端口形式 [::ffff:127.0.0.1]:22 → 剥端口再判。
    const brack = /^\[([^\]]+)\]:\d+$/.exec(h);
    if (brack) return isPrivateHost(brack[1]);
    const v6 = parseIpv6Literal(h);
    if (v6 !== null) return isPrivateIpv6(v6);
    // IPv4:port 形式（host 字段可能带端口，变体段一并判）
    const m = /^([^:]+):\d+$/.exec(h);
    if (m) {
      const lit = parseIpv4Literal(m[1]);
      if (lit) return isPrivateIpv4Bytes(lit);
    }
    return false;
  }
  const lit = parseIpv4Literal(h);
  if (lit) return isPrivateIpv4Bytes(lit);
  // 非 IP 字面量（hostname）→ 本层不判，由网关 DNS 解析后逐地址再判
  return false;
}

/** IPv6 真·解析：展开 :: 压缩与尾部内嵌 IPv4 段到 16 字节；非法/非常规返回 null。
 *  严格性与 IPv4 侧一致（非字面量返回 null，由调用方按 hostname 处理）。
 *    - 支持 ::
 *    - 支持尾部内嵌 IPv4（::ffff:127.0.0.1），也支持变体段（复用 parseIpv4Literal）
 *    - 十六进制组 1-4 位
 *  输出：16 字节数组（每 16 位组展开成高/低字节），供 isPrivateIpv6 按字节前缀判定。
 *  与 Node socket / 各解析库口径一致，避免 IPv4-mapped 与压缩形式绕过。 */
function parseIpv6Literal(ip: string): number[] | null {
  const s = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (s === '' || !/^[0-9a-f:.]+$/.test(s)) return null;

  const parseSeq = (chunks: string[]): number[] | null => {
    const out: number[] = [];
    for (let i = 0; i < chunks.length; i++) {
      const raw = chunks[i];
      if (raw === '') return null;
      if (/^[0-9a-f]{1,4}$/.test(raw)) {
        out.push(parseInt(raw, 16));
      } else if (i === chunks.length - 1) {
        // G-1：末段非标准 16 位十六进制组（dotted / 单段 32 位整数 / 八进制 / 0x
        // 十六进制变体）→ 按 IPv4 展开 4 字节为 2 组。覆盖 ::ffff:2130706433 等混合形式
        // （Node 解析器虽不解析它，防御不应依赖下游能力）。只对末段生效，不影响 ::1 等合法组。
        const lit = parseIpv4Literal(raw);
        if (!lit) return null;
        out.push((lit[0] << 8) | lit[1], (lit[2] << 8) | lit[3]);
      } else {
        return null;
      }
    }
    return out;
  };

  let groups: number[] | null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  if (halves.length === 1) {
    const g = parseSeq(s.split(':'));
    groups = g !== null && g.length === 8 ? g : null;
  } else {
    // 有 :: 压缩：两端各拼，中间补零
    const head = halves[0] === '' ? [] : parseSeq(halves[0].split(':'));
    const tail = halves[1] === '' ? [] : parseSeq(halves[1].split(':'));
    if (head === null || tail === null) return null;
    const total = head.length + tail.length;
    if (total > 7) return null; // :: 至少要补 1 组（全 :: 恰好 8 组 0）
    const pad = 8 - total;
    groups = [...head, ...new Array(pad).fill(0), ...tail];
  }
  if (groups === null) return null;
  // 16 位组 → 16 字节（高字节在前）
  const bytes: number[] = [];
  for (const g of groups) {
    bytes.push((g >>> 8) & 0xff, g & 0xff);
  }
  return bytes;
}

/** IPv6 私网/回环/链路本地/映射判定（按 16 字节前缀），与 IPv4 侧同严格度。 */
function isPrivateIpv6(bytes: number[]): boolean {
  // ::（未指定）
  if (bytes.every((x) => x === 0)) return true;
  // ::1（回环）
  if (bytes.slice(0, 15).every((x) => x === 0) && bytes[15] === 1) return true;
  // IPv4-mapped ::ffff:0:0/96：前 80 位 0 + 16 位 ffff + 32 位 v4
  if (bytes.slice(0, 10).every((x) => x === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isPrivateIpv4Bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
  }
  // IPv4-compatible ::/96（已废弃）：前 96 位 0 + 32 位 v4（::127.0.0.1 一族）
  if (bytes.slice(0, 12).every((x) => x === 0)) {
    return isPrivateIpv4Bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
  }
  // NAT64 well-known 64:ff9b::/96：内嵌 v4 同判
  if (
    bytes[0] === 0 &&
    bytes[1] === 0x64 &&
    bytes[2] === 0xff &&
    bytes[3] === 0x9b &&
    bytes.slice(4, 12).every((x) => x === 0)
  ) {
    return isPrivateIpv4Bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
  }
  // ULA fc00::/7
  if ((bytes[0] & 0xfe) === 0xfc) return true;
  // 链路本地 fe80::/10
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true;
  // 站点本地 fec0::/10（已废弃）
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0xc0) return true;
  // 组播/保留 ff00::/8（对齐 IPv4 侧 a>=224）
  if (bytes[0] === 0xff) return true;
  return false;
}

/** 真·inet_aton 四字节解析：返回 [a,b,c,d]（每字节 0-255）或 null（非法）。
 *  兼容十进制 / 0x 十六进制 / 0 前导八进制；支持 1/2/3/4 段简写：
 *    - 1 段 = 完整 32 位整数（2130706433 → 127.0.0.1；> 0xffffffff 拒绝）
 *    - 2 段 = a.b，b 为 24 位（127.65534 → 127.0.255.254）
 *    - 3 段 = a.b.c，c 为 16 位（127.0.1 → 127.0.0.1）
 *    - 4 段 = 逐字节，每段 ≤ 0xff
 *  与服务端（glibc inet_aton / Node socket）实际解析口径一致。 */
function parseIpv4Literal(ip: string): [number, number, number, number] | null {
  const segs = ip.split('.');
  const n = segs.length;
  if (n < 1 || n > 4) return null;
  const parts: number[] = [];
  for (const s of segs) {
    let v: number;
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
      v = parseInt(s.slice(2), 16);
    } else if (/^0[0-7]+$/.test(s)) {
      // 八进制：前导 0 且全为 0-7。注意 Number('0177')=177（十进制）是漏洞根源
      v = parseInt(s.slice(1), 8);
    } else if (/^\d+$/.test(s)) {
      v = parseInt(s, 10);
    } else {
      return null;
    }
    parts.push(v);
  }
  // 前 n-1 段必须是单字节
  for (let i = 0; i < n - 1; i++) {
    if (parts[i] < 0 || parts[i] > 0xff) return null;
  }
  // 末段宽度 = 5-n 字节（n=1→4B、n=2→3B、n=3→2B、n=4→1B）
  const last = parts[n - 1];
  if (last < 0) return null;
  if (n === 1 && last > 0xffffffff) return null;
  if (n === 2 && last > 0xffffff) return null;
  if (n === 3 && last > 0xffff) return null;
  if (n === 4 && last > 0xff) return null;
  // 展开成 4 字节（>>> 走 ToUint32，1 段 32 位大值不会溢出成负）
  const bytes: number[] = [];
  for (let i = 0; i < n; i++) {
    if (i < n - 1) {
      bytes.push(parts[i]);
    } else {
      const lastBytes = 5 - n;
      for (let j = lastBytes - 1; j >= 0; j--) {
        bytes.push((last >>> (j * 8)) & 0xff);
      }
    }
  }
  return [bytes[0], bytes[1], bytes[2], bytes[3]];
}

/** IPv4 私网/回环/链路本地字节判定（与旧 isPrivateIpv4 同口径） */
function isPrivateIpv4Bytes(bytes: [number, number, number, number]): boolean {
  const [a, b] = bytes;
  return (
    a === 0 || // 0.0.0.0/8
    a === 10 || // 10.0.0.0/8
    a === 127 || // 127.0.0.0/8
    (a === 169 && b === 254) || // 169.254.0.0/16（链路本地 + 云元数据 169.254.169.254）
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) || // 192.168.0.0/16
    (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10（CGNAT）
    (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15（benchmark）
    a >= 224 // 组播/保留
  );
}

/** 上传文件名高危扩展名（Web 服务器可解释/可执行类）：
 *  网关层纵深防御——
 *  若上传目录未来被 Web 面暴露，.php/.jsp/.svg 等可被直接执行/承载脚本。
 *  .py/.sh 等 agent 合法使用的脚本类型不拦（当前下载头已强制 octet-stream+nosniff）。 */
export function isDangerousUploadName(name: string): boolean {
  if (typeof name !== 'string' || name === '') return false;
  if (name.includes('..')) return true; // 路径穿越形态
  return /\.(php\d*|phtml|phar|jspx?|asp|aspx|asa|cer|cfm|shtml|cgi|hta|svg)(\.|$)/i.test(name);
}

/** 隐藏/隐形 Unicode 字符（F-A2）：人对“不可见”、对 AI agent 是可见指令/内容分歧面。
 *  覆盖：零宽（ZWSP/ZWNJ/ZWJ/LRM/RLM）、bidi 控制（LRE/RLE/PDF/LRO/RLO + 新 bidi 隔离）、
 *  词连接符 WJ/隐形运算符、BOM/ZWNBSP、软连字符 SHY、蒙古元音分隔符 MVS、
 *  组合字连接符 CGJ、阿拉伯字母标记 ALM、谚文填充符（Hangul filler）。
 *  全部剥离（替换为空）——它们没有任何可见语义，删除不影响正常文本。 */
const HIDDEN_UNICODE_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u00ad\u180e\u034f\u061c\u115f\u1160]/g;

/** 剥离隐藏/隐形 Unicode 字符（F-A2）。文件内容与消息在进 AI 模型前必经网关代理，
 *  在网关代理点清洗——供应商（dsh）不处理，网关补偿即可，不必等上游修复。 */
export function sanitizeHiddenUnicode(content: string): string {
  return content.replace(HIDDEN_UNICODE_RE, '');
}
 /** 消息内容净化：剥离 HTML/CSS 结构 + 隐藏 Unicode 字符。聊天是纯文本场景——
 *  服务端剥掉标签/样式块/事件属性/CSS 函数载荷/零宽字符后，
 *  1) 渲染链即使未来改成富文本也不会爆发存储型 XSS；
 *  2) AI agent 读取消息时看不到 CSS 隐藏文本/伪元素/零宽注入等
 *     间接提示注入载体（“人看无害、agent 读是指令”的内容分歧面）。 */
export function sanitizeText(content: string): string {
  return content
    // 整块移除 style/script（含其内容，避免隐藏文本残留）
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    // 移除 HTML 注释（含内容，避免隐藏文本残留）
    .replace(/<!--[\s\S]*?-->/g, ' ')
    // 移除其余标签（仅“像标签”的模式：< 后跟字母或 /字母；保留数学比较符如 x < 10 and y > 5）
    .replace(/<\/?[a-zA-Z][^>]*>/g, ' ')
    // 剥离纯文本中的事件属性与 CSS 函数式载荷（无标签场景）
    .replace(/\son\w+\s*=\s*(['"]).*?\1/gi, ' ')
    .replace(/\son\w+\s*=\s*[^\s>]+/gi, ' ')
    .replace(/url\(\s*['"]?[^)'"]+['"]?\s*\)/gi, ' ')
    .replace(/image-set\([^)]*\)/gi, ' ')
    // F-A2：剥离隐藏/隐形 Unicode（零宽/bidi/词连接符等）——AI 提示注入载体
    .replace(HIDDEN_UNICODE_RE, '')
    // 压缩连续空白（保留换行）
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/** 子用户是否受工作区约束（白名单非空，含"禁止所有"哨兵或真实路径） */
export function isWorkspaceRestricted(allowedFolders: string[]): boolean {
  return allowedFolders.length > 0;
}

/**
 * path 是否命中 allowed 白名单（相等或为某白名单目录的子路径；空白名单 = 全部允许；
 * 含 DENY_ALL_WORKSPACES 哨兵 = 禁止所有）。白名单条目为 `/`（根）时视为全盘允许。
 */
export function folderAllowed(path: string, allowedFolders: string[]): boolean {
  if (allowedFolders.length === 0) return true;
  if (allowedFolders.includes(DENY_ALL_WORKSPACES)) return false;
  const p = normalizePath(path);
  return allowedFolders.some((entry) => {
    const base = normalizePath(entry);
    // normalize('') → '.'：空条目与根（'/'）都视为全盘允许
    if (base === '.' || base === '/') return true;
    return p === base || p.startsWith(base + '/');
  });
}

/**
 * 递归过滤 JSON 里路径字段不在白名单的对象（session.list 用 field='cwd'，workspace.list 用 field='path'）：
 * 只对数组元素中带该路径字段的对象做白名单判定，白名单外的直接丢弃；其余字段原样递归保留。
 * depth 上限 8：防上游投毒深嵌套 JSON 导致栈溢出 DoS（与同文件其他递归函数口径一致）。
 */
export function filterByPathField(value: unknown, allowedFolders: string[], field: string, depth = 0): unknown {
  return filterByPathFieldWithPredicate(value, field, (candidate) => folderAllowed(candidate, allowedFolders), depth);
}

/** 与 filterByPathField 相同，但由调用方提供路径可见性规则。 */
export function filterByPathFieldWithPredicate(
  value: unknown,
  field: string,
  allowed: (candidate: string) => boolean,
  depth = 0,
): unknown {
  // 深度超限时无法可靠检查路径字段，丢弃该子树而不是原样返回（fail-closed）。
  if (depth > 8) return null;
  if (value === null) return value;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) {
      if (
        item !== null &&
        typeof item === 'object' &&
        typeof (item as Record<string, unknown>)[field] === 'string' &&
        (item as Record<string, unknown>)[field] !== '' &&
        !allowed((item as Record<string, unknown>)[field] as string)
      ) {
        continue;
      }
      out.push(filterByPathFieldWithPredicate(item, field, allowed, depth + 1));
    }
    return out;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = filterByPathFieldWithPredicate(v, field, allowed, depth + 1);
    }
    return out;
  }
  return value;
}

/** 递归收集 {workspaceId, path} 对（workspace.list 响应用，建 workspaceId → 路径 映射）。
 *  ⚠ dsh 工作区对象的 id 字段是 workspaceId（实测 items 里是 {workspaceId, path, ...}，
 *  没有顶层 id）——同时兼容 obj.id 与 obj.workspaceId，否则 session.create 带 workspaceId
 *  时缓存搜不到路径、fail-closed 403（功能缺失）。depth 上限 8。 */
export function collectIdPathPairs(value: unknown, out: Map<string, string> = new Map(), depth = 0): Map<string, string> {
  if (depth > 8 || value === null) return out;
  if (Array.isArray(value)) {
    for (const item of value) collectIdPathPairs(item, out, depth + 1);
  } else if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.path === 'string') {
      const id = typeof obj.workspaceId === 'string' ? obj.workspaceId : typeof obj.id === 'string' ? obj.id : null;
      if (id !== null) out.set(id, obj.path);
    }
    for (const v of Object.values(obj)) collectIdPathPairs(v, out, depth + 1);
  }
  return out;
}

/** 从 session.list 响应收集 sessionId → cwd 映射（供会话作用域 RPC 的目录白名单校验）。 */
export function collectSessionCwd(value: unknown, out: Map<string, string> = new Map(), depth = 0): Map<string, string> {
  if (depth > 8 || value === null) return out;
  if (Array.isArray(value)) {
    for (const item of value) collectSessionCwd(item, out, depth + 1);
  } else if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.sessionId === 'string' && typeof obj.cwd === 'string' && obj.cwd.length > 0) {
      out.set(obj.sessionId, obj.cwd);
    }
    for (const v of Object.values(obj)) collectSessionCwd(v, out, depth + 1);
  }
  return out;
}


/** 从 workspace.list 响应收集会话 cwd：工作区 path → 其 sessionIds 对应会话的 cwd（无则覆盖）。 */
export function collectSessionCwdFromWorkspaces(value: unknown, out: Map<string, string> = new Map(), depth = 0): Map<string, string> {
  if (depth > 8 || value === null) return out;
  if (Array.isArray(value)) {
    for (const item of value) collectSessionCwdFromWorkspaces(item, out, depth + 1);
  } else if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (typeof obj.path === 'string' && Array.isArray(obj.sessionIds)) {
      for (const sid of obj.sessionIds) {
        if (typeof sid === 'string' && !out.has(sid)) out.set(sid, obj.path);
      }
    }
    for (const v of Object.values(obj)) collectSessionCwdFromWorkspaces(v, out, depth + 1);
  }
  return out;
}

/**
 * 递归查找请求体里的 workspaceId（session.create 可能带 workspaceId 而非 cwd）。
 * 已识别的 0.1.7 ClientConnection 信封只采信 payload.args（或 args.request）；
 * 信封外字段不可能到达 DSH，不能成为网关授权依据。
 */
export function extractWorkspaceId(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const args = depth === 0 ? clientConnectionArgs(value) : null;
  if (args !== null) {
    const request = args.request;
    if (request !== null && typeof request === 'object' && !Array.isArray(request)) {
      return extractWorkspaceId(request, depth + 1);
    }
    const workspaceId = args.workspaceId;
    return typeof workspaceId === 'string' && workspaceId.length > 0 ? workspaceId : null;
  }
  const obj = value as Record<string, unknown>;
  if (typeof obj.workspaceId === 'string' && obj.workspaceId.length > 0) return obj.workspaceId;
  for (const key of Object.keys(obj)) {
    if (key === 'args') continue;
    const nested = extractWorkspaceId(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/** 从工作区删除/重命名请求中提取明确的旧路径和新路径。缺任一项就返回 null，调用方应保持 fail-closed。 */
export function extractWorkspaceRenamePaths(value: unknown): { oldPath: string; newPath: string } | null {
  const oldKeys = new Set(['oldPath', 'previousPath', 'sourcePath', 'fromPath']);
  const newKeys = new Set(['newPath', 'targetPath', 'destinationPath', 'toPath']);
  let oldPath: string | null = null;
  let newPath: string | null = null;
  const visit = (current: unknown, depth: number): void => {
    if (depth > 6 || current === null || typeof current !== 'object' || (oldPath !== null && newPath !== null)) return;
    if (Array.isArray(current)) {
      for (const item of current) visit(item, depth + 1);
      return;
    }
    for (const [key, item] of Object.entries(current as Record<string, unknown>)) {
      if (typeof item === 'string' && item.trim() !== '') {
        if (oldKeys.has(key) && oldPath === null) oldPath = item;
        if (newKeys.has(key) && newPath === null) newPath = item;
      }
      visit(item, depth + 1);
    }
  };
  visit(value, 0);
  return oldPath !== null && newPath !== null ? { oldPath, newPath } : null;
}

/** 沙盒权限级别（dsh SANDBOX_MODES）+ 严重度排序（越靠后越宽松） */
type SandboxMode = 'read-only' | 'workspace-write' | 'danger-full-access';
export const SANDBOX_RANK: Record<SandboxMode, number> = {
  'read-only': 0,
  'workspace-write': 1,
  'danger-full-access': 2,
};

/** 递归查找某个字符串字段（settings.mutate 里找 defaultPreset 用） */
export function findStringField(value: unknown, field: string, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  const v = obj[field];
  if (typeof v === 'string' && v.length > 0) return v;
  for (const key of Object.keys(obj)) {
    const nested = findStringField(obj[key], field, depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/** preset → 沙盒 rank：按 SANDBOX_RANK 精确映射；未知值按最宽松=2 处理（防止越权切换） */
export function sandboxPresetRank(preset: string): number {
  return SANDBOX_RANK[preset as SandboxMode] ?? 2;
}

/**
 * 从 slash 命令行解析 /permission 的 preset 参数。
 * 例："/permission workspace-write" → "workspace-write"；非该命令或无参数返回 null。
 */
export function permissionPresetFromCommand(line: string): string | null {
  const match = /^\/permission\s+([A-Za-z0-9_-]+)/.exec(line.trim());
  return match ? match[1] : null;
}

/**
 * 从 settings.mutate 请求体里找 permission.defaultPreset 写入。
 * 该字段是 ops[].path 数组里的元素（不是对象字段键），所以不能用 findStringField 找；
 * 递归找到某个带 `path` 数组且含 'defaultPreset' 的对象，返回其 `value` 字符串。
 */
export function presetFromSettingsMutate(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  if (Array.isArray(obj.path) && obj.path.includes('defaultPreset')) {
    const v = obj.value;
    if (typeof v === 'string' && v.length > 0) return v;
  }
  for (const key of Object.keys(obj)) {
    const nested = presetFromSettingsMutate(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * 递归把审批响应里的 outcome 强制改成 'rejected'（受限子用户的 AI 提权一律取消）。
 * /api/respond 的 body 是 ClientResponse 信封：outcome/approvalId 位于 result.value，
 * 因此这里递归找到同时带字符串 approvalId + outcome 的对象并改值；返回是否有实际改动。
 * （ask_user_question 的响应用的是 answer 字段，不会被误伤。）
 */
export function forceRejectApproval(value: unknown, depth = 0): boolean {
  if (depth > 6 || value === null || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  let changed = false;
  if (typeof obj.approvalId === 'string' && typeof obj.outcome === 'string' && obj.outcome !== 'rejected') {
    obj.outcome = 'rejected';
    changed = true;
  }
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v !== null && typeof v === 'object') {
      if (forceRejectApproval(v, depth + 1)) changed = true;
    }
  }
  return changed;
}

/**
 * 会话历史沙盒降级：子用户打开共享会话时，会话 log 里可能已带更高权限的
 * permission/preset 与 sandbox/mode（主用户设置过 danger-full-access）——
 * 直接继承会导致子用户无操作即提权。这里把超过授权级别的 preset/mode 统一
 * 降级为子用户授权级别，并同步修正 projections.values.permissions.currentValue。
 * 返回是否有实际改动。
 */
export function clampSessionHistorySandbox(value: unknown, allowedMode: SandboxMode | null, depth = 0): boolean {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  if (allowedMode === null) return false;
  const obj = value as Record<string, unknown>;
  let changed = false;
  const allowedRank = SANDBOX_RANK[allowedMode];

  // permission/preset 事件：{ type: 'permission/preset', data: { preset } }
  if (obj.type === 'permission/preset' && obj.data && typeof obj.data === 'object') {
    const data = obj.data as Record<string, unknown>;
    const preset = data.preset;
    if (typeof preset === 'string' && SANDBOX_RANK[preset as SandboxMode] !== undefined) {
      const presetRank = SANDBOX_RANK[preset as SandboxMode];
      if (presetRank > allowedRank) {
        data.preset = allowedMode;
        changed = true;
      }
    }
  }
  // sandbox/mode 事件：{ type: 'sandbox/mode', data: { mode } }
  if (obj.type === 'sandbox/mode' && obj.data && typeof obj.data === 'object') {
    const data = obj.data as Record<string, unknown>;
    const mode = data.mode;
    if (typeof mode === 'string' && SANDBOX_RANK[mode as SandboxMode] !== undefined) {
      const modeRank = SANDBOX_RANK[mode as SandboxMode];
      if (modeRank > allowedRank) {
        data.mode = allowedMode;
        changed = true;
      }
    }
  }
  // projections.values.permissions.currentValue：客户端投影显示的当前 preset
  if (obj.currentValue === 'danger-full-access' || obj.currentValue === 'workspace-write' || obj.currentValue === 'read-only') {
    const curRank = SANDBOX_RANK[obj.currentValue as SandboxMode];
    if (curRank > allowedRank) {
      obj.currentValue = allowedMode;
      changed = true;
    }
  }
  // 递归（同时覆盖 events[].event 和 projections.values 两层结构）
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v !== null && typeof v === 'object') {
      if (clampSessionHistorySandbox(v, allowedMode, depth + 1)) changed = true;
    }
  }
  return changed;
}

// ── 上传 / git / 轮询的官方端点判定（纯路径 + 方法，不读请求体） ──────────
//
// 说明：普通扩展端点不在这里按插件协议猜测；已加载扩展由 DSH 运行时清单统一分类。
// 这里仅保留官方上传/git/轮询以及宿主级边界的通用规则。

/** 上传相关端点：官方会话二进制上传与官方 fileUploads 上传。 */
export function isUploadRequest(method: string, pathname: string): boolean {
  if (method !== 'POST' && method !== 'PUT') return false;
  return (
    pathname === '/api/session/uploadFileBinary' ||
    pathname === '/api/fileUploads/upload'
  );
}

/**
 * git 相关端点（dsh 内置 git 工具 RPC：git.clone / git.pull / git.fetch 等）
 * 与“从服务器拿走数据”的官方通道：session.export 会话日志 ZIP。
 * 只匹配 git 前缀的 RPC（不拦 session.fetch 这类普通端点）。
 * ⚠ 0.1.7 官方已无 git 命名空间 RPC（见 LEGACY_OFFICIAL_API_ROUTE_RE）：这里
 * 的 git 前缀只对应旧线（0.1.2/0.1.3/0.1.5）保留端点，且旧的兼容白名单只列
 * 取数据/只读动词；写类动词在子用户侧是 third-party（fail-closed）。
 */
export function isGitRequest(pathname: string): boolean {
  return (
    /^\/api\/git[-.\/]/i.test(pathname) ||
    /^\/api\/session[.\/]export/.test(pathname)
  );
}

/** 工作区创建端点；创建权限与其他工作区管理权限分开控制。 */
export function isWorkspaceCreate(pathname: string): boolean {
  return /^\/api\/workspace[.\/](add|create)([.\/]|$)/.test(pathname);
}

/**
 * 目录选择器创建实际目录后，才由 workspace.create 登记工作区。0.1.7 使用
 * directoryPicker/createDirectory；保留 host.createDirectory 是为旧 dsh 兼容
 * （旧端点仅按精确路由保留，见 LEGACY_OFFICIAL_API_ROUTE_RE）。
 */
export function isWorkspaceDirectoryCreate(pathname: string): boolean {
  return /^(?:\/api\/host|\/api\/directoryPicker)[.\/]createDirectory(?:[.\/]|$)/.test(pathname);
}

/** 当前 dsh 已提供的删除/重命名端点；移动、导入暂不纳入子用户权限。 */
export function isWorkspaceDeleteOrRename(pathname: string): boolean {
  return /^\/api\/workspace[.\/](remove|delete|rename|update)([.\/]|$)/.test(pathname);
}

/** 纯工作区/会话排序 RPC；它不创建、删除或移动文件系统内容。 */
export function isWorkspaceOrderWrite(pathname: string): boolean {
  return /^\/api\/workspace[.\/](insertBefore|insertSessionBefore)([.\/]|$)/.test(pathname);
}

/**
 * 工作区管理写操作（创建/删除/重命名由 allowWorkspaceCreate 控制；纯排序由网关对象级可见性校验）。
 *
 * `workspace/initializeDefault`（0.1.7，dsh-api-workspace-controller）按
 * `request.directoryName` 在宿主文件系统里**创建并登记**一个新工作区目录，属于
 * 工作区写，但它的入参不是路径（没有 path 可供白名单校验，也无法与
 * workspaceRegistrationAllowed 的“已分配/已拥有/刚创建”三选一比对），因此纳入本
 * 谓词后对子用户 fail-closed：网关侧的 isManagedWorkspaceWrite（= isWorkspaceCreate ||
 * isWorkspaceDeleteOrRename）不含它，即使主用户勾选 allowWorkspaceCreate 也不会被
 * 顺带放行。
 */
export function isWorkspaceWrite(pathname: string): boolean {
  return (
    isWorkspaceCreate(pathname) ||
    isWorkspaceDeleteOrRename(pathname) ||
    isWorkspaceOrderWrite(pathname) ||
    /^\/api\/workspace[.\/](import|move|materialize|adopt|initializeDefault)([.\/]|$)/.test(pathname)
  );
}

/** 0.1.7 目录浏览器的一层列表 RPC（in-app picker 的浏览动词）。 */
export function isDirectoryListRequest(pathname: string): boolean {
  return /^\/api\/(?:directoryPicker[.\/]list|host[.\/]listDirectory)(?:[.\/]|$)/.test(pathname);
}

/** candidate 是否位于 root 内（相等或为其子路径；空白/当前目录根无效，'/' 视为全盘）。 */
export function pathWithin(candidate: string, root: string): boolean {
  const c = normalizePath(candidate);
  const r = normalizePath(root);
  if (r === '' || r === '.') return false;
  if (r === '/') return true;
  return c === r || c.startsWith(r + '/');
}

/**
 * 子用户能否把 canonical 目录登记为工作区（workspace/create）：仅接受
 * ① 主用户显式分配的精确目录；② 该子用户自己创建的工作区子树；
 * ③ 该子用户刚通过目录选择器成功创建、尚未过期的目录。
 * 其余（一切预存在且未分配的目录）一律拒绝——目录树授权只授予使
 * 用权，不授予登记权。
 */
export function workspaceRegistrationAllowed(
  candidate: string,
  assignedFolders: readonly string[],
  ownedWorkspaces: readonly string[],
  pendingCreated: readonly string[],
): boolean {
  const c = normalizePath(candidate);
  if (c === '' || c === '.' || c === '/') return false;
  for (const entry of assignedFolders) {
    if (entry === '__deny__') continue;
    if (normalizePath(entry) === c) return true;
  }
  for (const owned of ownedWorkspaces) {
    if (pathWithin(c, owned)) return true;
  }
  for (const pending of pendingCreated) {
    if (normalizePath(pending) === c) return true;
  }
  return false;
}

/** 目录浏览条目可见性：只显示授权子树或通往授权根的祖先。 */
export function directoryEntryVisible(entryPath: string, authorizedRoots: readonly string[]): boolean {
  return authorizedRoots.some((root) => pathWithin(entryPath, root) || pathWithin(root, entryPath));
}

// ── 工作区/会话文件夹限制：需要读 JSON 请求体 ──────────────────────────

/** 涉及创建工作区的 dsh typert RPC（斜杠风格：/api/session/create 等；兼容点号风格）
 *  只含 create——fork 继承源会话的 cwd，目标目录由源会话决定（其工作区授权已由
 *  SESSION_SCOPED_RE/needsOwnershipCheck 校验），无需也不应再做文件夹白名单。 */
export const WORKSPACE_ENDPOINT_RE = /^\/api\/session[.\/](create)([.\/]|$)/;

/**
 * 会话作用域 RPC：这些端点带一个会话身份，能读/写/改某个会话——
 * 子用户必须启用其所在工作区，且该会话未被管理员单独关闭。
 * create 无源会话、list 单独做工作区/会话过滤，均不在此列。
 *
 * workspaceFiles（dsh-api-workspace-files）全部已知方法都是会话作用域：read /
 * readBytes / stat / list / changes 是 0.1.7 的 wire 方法，readAll / readRelated
 * 是 0.1.6 及更早的 **legacy 方法**（0.1.7 包内已移除，保留在本集合只为兼容旧线）。
 * 所有方法的 wire 参数 `workspaceFileScopeId` 由 workspaceFileScope lookup 解析为
 * **SessionId**（活会话读 header.cwd，冷会话读持久化 stat）。纳入本 RE 后它们会走
 * 网关的会话归属校验（needsOwnershipCheck），未授权会话直接 403。
 * ⚠ 会话作用域不等于文件作用域：服务端允许读工作区**外**的绝对路径
 * （见官方 README “files outside it are allowed”），所以调用方还需对请求里的
 * 目标路径做目录白名单判定（见 parseWorkspaceFilesCall /
 * workspaceFilesTargetAllowed）。
 * ⚠ changes 例外：0.1.7 的 changes 已是 `@Remote({ mode: 'stream' })` 且 wire 新增了
 * `path: string`，“没有 path 参数”不再能当作它进不了 HTTP 守卫的依据；但它的变更流
 * 只按工作区根过滤、不校验会话归属，网关两条通道都对子用户拒绝（mux 侧显式回
 * gateway/forbidden），因此它进本 RE 只表示“带会话身份、必须做归属校验”，不表示
 * 可用。本模块对 changes 恒返回 targetPath=null（target 判定恒 false），保持
 * fail-closed，不让新增的 path 变成放行依据。
 *
 * present/open 与 changes/open（dsh-client-ui-deliverables）同样使用 query 中的会话
 * 坐标；0.1.7 的两者都支持 GET（查询关联应用）和 POST（执行宿主打开）。网关对
 * 两种方法统一做会话归属校验，未授权会话的宿主桌面动作直接 403。
 * ⚠ 同一批路由里只有 GET 的成员（changes.summary / changes.diff、
 * present.host、/api/file）本 RE 盖不到——网关的归属校验只跑 POST/PUT/PATCH/
 * DELETE，GET 侧必须由调用方用 isOfficialSessionQueryRoute / sessionQueryTarget /
 * fileReadTargetFromQuery 自行判定。
 *
 * 0.1.7 增补（dsh-api-session-controller / dsh-api-workspace-controller /
 * sessionFeedback / goals 实测）：
 *   - `session/projections`：请求体带 `request.sessionId`（SessionProjectionsRequest）；
 *   - `sessionFeedback/record`（dsh-command-feedback）：日志型会话反馈。反馈挂在
 *     具体会话上，必须逐会话归属校验，否则子用户可写他人会话的反馈；
 *   - `goals/get`：与已在表内的 goals/clear|complete|create|edit|pause|resume 同类，
 *     读的是某个会话的目标状态，必须逐会话归属校验（wire 里取不到会话身份时由
 *     网关 fail-closed）；
 *   - `workspace/pinSession` / `unpinSession` / `unarchiveSession`：请求体带
 *     `request.sessionId`，与已在表内的 `workspace/archiveSession` 同类（改的是
 *     某个会话在工作区导航里的状态），必须逐会话做归属校验。
 *
 * 0.1.7-rc.2 增补（dsh-schedule）：`schedule/list` / `history` / `update` / `delete`
 * 的 wire 请求都带 `request.sessionId`（ScheduleListRequest 及其扩展），读/改的是
 * 绑定到某个会话的提醒任务，因此必须逐会话归属校验：否则子用户可读甚至删除其它
 * 会话的提醒。`schedule/catalog` **不**进本 RE——它无参、返回宿主全局提醒及其原始
 * Session id，wire 里没有任何会话身份可取；对子用户由官方分类放行，并由 gateway
 * 按每个条目的 sessionId 逐条响应过滤（见 proxy 的 SCHEDULE_CATALOG_RE）。
 * ⚠ 0.1.7 起 `session/openWorkspacePath` / `canOpenWorkspacePath` /
 * `workspacePathApplications` 不再进本 RE：它们的 wire 里没有会话身份（分别只带
 * `request.path` 或无参），本 RE 的归属校验取不到身份、判定无意义，已改为
 * SUBUSER_BLOCKED_API_ENDPOINTS 硬拒绝。
 * ⚠ `dynamicCordisRunner` 整个命名空间都不进本 RE：它是宿主级动态包执行面，直接由
 * SUBUSER_BLOCKED_API_NAMESPACES 硬拒绝（硬拒绝先于本 RE，无需逐方法重复登记）。
 * 本次只加“要校验归属”的范围，不把任何新命名空间/方法变成官方放行：
 * job/account 的只读面进入官方分类；job 的会话身份仍由 SESSION_SCOPED_RE/Remote
 * 开流校验，account 的登录写操作由 SUBUSER_BLOCKED_API_ENDPOINTS 硬拒绝。
 */
export const SESSION_SCOPED_RE =
  /^\/api\/(?:schedule[.\/](?:list|history|update|delete)|session[.\/](?:history|prompt|respond|archive|delete|rename|retitle|title|resume|fork|truncate|export|attachment|updateQueue|cancel|page|projections|selectModel)|workspace[.\/](?:archiveSession|pinSession|unpinSession|unarchiveSession)|commands[.\/](?:list|execute)|subagents[.\/](?:list|prompt|interruptByParent)|fileUploads[.\/](?:upload)|fileReferences[.\/](?:list)|sessionReferenceResolver[.\/](?:candidates)|skills[.\/](?:list)|messageFeedback[.\/](?:list|put|delete)|sessionFeedback[.\/](?:record)|goals[.\/](?:clear|complete|create|edit|get|pause|resume)|workspaceFiles[.\/](?:read|readAll|readBytes|stat|readRelated|list|changes)|present[.\/](?:open)|changes[.\/](?:open)|userQuestions[.\/](?:answer)|job[.\/](?:kill))([.\/]|$)/;

/**
 * workspaceFiles 的会话作用域方法（与 SESSION_SCOPED_RE 里的方法列表一致）。
 * ⚠ `readAll` / `readRelated` 是 0.1.6 及更早的 **legacy 方法**，0.1.7 包内已移除
 * （0.1.7 为 read / readBytes / stat / list / changes）。保留它们只为兼容旧线客户
 * 端：形状解析与归属校验口径不变，未知的**新**方法（未来的写方法）仍为 null。
 */
export const WORKSPACE_FILES_SESSION_METHODS = [
  'read',
  'readAll', // legacy（0.1.6 及更早）
  'readBytes',
  'stat',
  'readRelated', // legacy（0.1.6 及更早）
  'list',
  'changes',
] as const;

export type WorkspaceFilesMethod = (typeof WORKSPACE_FILES_SESSION_METHODS)[number];

/**
 * 从 wire 路径取 workspaceFiles 方法名（点号/斜杠两种形状）；非该命名空间或
 * 方法不在已知集合（例如未来的写方法）一律 null（调用方 fail-closed）。
 */
export function workspaceFilesMethodOf(pathname: string): WorkspaceFilesMethod | null {
  const endpoint = apiEndpointOf(pathname);
  if (endpoint === null || endpoint.namespace !== 'workspaceFiles' || endpoint.method === null) return null;
  return (WORKSPACE_FILES_SESSION_METHODS as readonly string[]).includes(endpoint.method)
    ? (endpoint.method as WorkspaceFilesMethod)
    : null;
}

/** 该路径是否为 workspaceFiles 的会话作用域 RPC（与 SESSION_SCOPED_RE 同口径）。 */
export function isWorkspaceFilesSessionScopedRequest(pathname: string): boolean {
  return workspaceFilesMethodOf(pathname) !== null;
}

/** workspaceFiles 调用的严格解析结果（字段名取自官方 typert wire 定义）。 */
export interface WorkspaceFilesCall {
  method: WorkspaceFilesMethod;
  /** wire `workspaceFileScopeId`：由 workspaceFileScope lookup 解析为 SessionId。 */
  scopeId: string;
  /** 需要做目录边界判定的目标路径；不带路径的方法（changes）为 null。 */
  targetPath: string | null;
  /** targetPath 是否为绝对路径（相对路径由调用方按该会话工作区根解析后判定）。 */
  absolute: boolean;
}

/**
 * 严格解析 workspaceFiles 调用（fail-closed）：只认 0.1.7 的 ClientConnection
 * 信封（payload.args），因为只有 args 里的参数会被 DSH 真正解码执行；信封外观
 * 的伪字段不能成为授权依据。形状不符一律返回 null，调用方必须拒绝。
 *
 * wire 参数名（typert.host.js 实测，0.1.7 与 0.1.6 同形）：
 *   - workspaceFileScopeId  SessionId（所有方法）
 *   - path                  目标路径（0.1.7 起 changes 也带 path）
 *   - relativePath          readRelated（legacy）的相对路径（相对 path 所在目录解析）
 *   - options               readBytes 的字节选项（0.1.7 新增，见下）
 */
export function parseWorkspaceFilesCall(pathname: string, body: unknown): WorkspaceFilesCall | null {
  const method = workspaceFilesMethodOf(pathname);
  if (method === null) return null;
  const args = clientConnectionArgs(body);
  if (args === null) return null;
  const scopeId = args.workspaceFileScopeId;
  if (typeof scopeId !== 'string' || scopeId === '' || scopeId.length > 200) return null;
  // changes：0.1.7 已是 stream 且带 path，但变更流不校验会话归属、网关对子用户
  // 整类拒绝；这里恒不产出 targetPath，保持 fail-closed（path 不作为放行依据）。
  if (method === 'changes') return { method, scopeId, targetPath: null, absolute: false };
  // readBytes 独有：0.1.7 把第三个 wire 参数换成 options（字节窗口与
  // 解析基准）。它不改变授权输入，但能改变真实读取目标，必须在转发前判定。
  if (method === 'readBytes' && !workspaceFilesReadBytesOptionsAllowed(args.options)) return null;
  const rawPath = args.path;
  if (typeof rawPath !== 'string' || rawPath === '' || rawPath.includes('\u0000')) return null;
  if (method !== 'readRelated') {
    const target = normalizePath(rawPath);
    return { method, scopeId, targetPath: target, absolute: isAbsoluteLike(target) };
  }
  const relative = args.relativePath;
  if (typeof relative !== 'string' || relative.includes('\u0000')) return null;
  const target = resolveRelatedReadPath(rawPath, relative);
  if (target === null) return null;
  return { method, scopeId, targetPath: target, absolute: isAbsoluteLike(target) };
}

/**
 * `workspaceFiles/readBytes` 的第三个 wire 参数 `options`
 * （0.1.7：`{ range?: { offset?: number, length?: number }, baseFile?: string }`）。
 *
 * 为什么必须在这里 fail-closed：`path` 本身还只是目标路径，但 `options.baseFile`
 * 会改变它的**解析基准**——官方语义是“把相对 `path` 从 baseFile 所在目录解析”，
 * 且 baseFile 自身可以是绝对路径或工作区相对路径。网关实际守卫会按同一规则解析
 * baseFile 与最终目标，并对两者执行工作区、白名单和 canonical realpath 校验；本纯函数
 * 只负责旧调用方的形状解析，不能单独作为运行时授权结论。
 *
 * 口径（与调用方 fail-closed 一致，返回 false 即必须拒绝）：
 *   - `options` 缺失：视为 0.1.6 旧的两参数 readBytes（那代 wire 里根本没有
 *     options）——此时不存在 baseFile，真实目标就是 `path`，仍由调用方的
 *     目录白名单判定，不因本次收紧而回归；
 *   - `options` 存在：必须是 pure plain object（非数组、原型为 Object.prototype
 *     或 null）；
 *   - 键只允许 `range` / `baseFile`，未知键（未来的新参数）一律拒绝；
 *   - `baseFile` 的形状由网关运行时按 0.1.7 规则解析；本纯函数不以该字段单独
 *     推断授权；测试调用方若不能安全重现解析必须拒绝；
 *   - `range` 若存在：必须是 plain object，键只允许 `offset` / `length`，值若存在
 *     必须是非负安全整数（与上游“非整数即 bad-request”同口径）。range 不参与
 *     目标解析，收紧它只为不把未知形状当已知形状。
 *
 * 0.1.6 的 read / readAll / readRelated / stat 没有 options 参数，不经本函数。
 */
function workspaceFilesReadBytesOptionsAllowed(value: unknown): boolean {
  if (value === undefined) return true;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const options = value as Record<string, unknown>;
  for (const key of Object.keys(options)) {
    if (key !== 'range' && key !== 'baseFile') return false;
  }
  if (Object.hasOwn(options, 'baseFile')) return false;
  const range = options.range;
  if (range === undefined) return true;
  if (range === null || typeof range !== 'object' || Array.isArray(range)) return false;
  const rangePrototype = Object.getPrototypeOf(range);
  if (rangePrototype !== Object.prototype && rangePrototype !== null) return false;
  for (const [key, raw] of Object.entries(range as Record<string, unknown>)) {
    if (key !== 'offset' && key !== 'length') return false;
    if (raw !== undefined && (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0)) return false;
  }
  return true;
}

/**
 * readRelated（legacy，0.1.7 已从包内移除）的真实读取目标：与旧宿主实现一致
 * （`path.resolve(dirname(path), relativePath)`）——相对第二参数按第一参数的
 * 目录拼接，绝对第二参数直接取其本身（绝对路径优先）。
 */
function resolveRelatedReadPath(basePath: string, relativePath: string): string | null {
  const relative = relativePath.replace(/\\/g, '/');
  // 旧线的上游明确要求 relativePath 是相对文件系统路径；绝对路径、盘符
  // 路径和 URL scheme 不属于 readRelated 的参数形状，直接 fail-closed。
  if (relative.startsWith('/') || /^[a-z][a-z\d+.-]*:/iu.test(relative)) return null;
  const base = normalizePath(basePath);
  return normalizePath(path.posix.join(path.posix.dirname(base), relative));
}

/**
 * 子用户的 workspaceFiles 读取目标是否落在授权目录内（纯函数，供网关判定）。
 *
 * 全部为 fail-closed 口径（与网关现行守卫一致）：
 *   - changes → false：0.1.7 的 changes 虽是带 `path` 的 stream，但变更流只按工作区
 *     根过滤、不校验会话归属，本模块也不产出它的 targetPath；网关当前对子用户整类
 *     拒绝该流。调用方若要放开必须另行显式授权，不得由本函数默认放行；
 *   - 绝对与相对路径都先解析到会话工作区根下（相对路径必须知道该根，未知则
 *     false），要求仍在根内，再套目录白名单。
 * 调用方必须已经确认会话归属（SESSION_SCOPED_RE / 会话授权快照）；本函数只再
 * 回答“这个文件在不在允许的目录里”。
 */
export function workspaceFilesTargetAllowed(
  call: Pick<WorkspaceFilesCall, 'targetPath' | 'absolute'>,
  sessionCwd: string | null,
  allowedFolders: readonly string[],
): boolean {
  if (call.targetPath === null) return false;
  if (sessionCwd === null || sessionCwd === '') return false;
  const root = normalizePath(sessionCwd);
  const target = call.absolute
    ? normalizePath(call.targetPath)
    : normalizePath(path.posix.join(root, call.targetPath));
  return pathWithin(target, root) && folderAllowed(target, [...allowedFolders]);
}

export type SessionAddress =
  | { kind: 'session'; sessionId: string }
  | {
      kind: 'subagent';
      parentSessionId: string;
      childSessionId: string;
      /**
       * 0.1.7 的 SessionAddress 在 'one-shot' | 'continuable' 之外新增
       * 'unknown'（子代理谱系尚未确定/未记录）。网关只用 parentSessionId 做授权，
       * mode 原样转发给 DSH 自行校验，因此必须认识 'unknown'——否则新线客户端
       * 的合法子代理请求会被整类拒绝（fail-closed 变成功能回归），而放开它并不
       * 放宽授权口径（授权仍只认 parent/child 的严格格式）。
       */
      mode: 'one-shot' | 'continuable' | 'unknown';
    };

/**
 * Parse the RC.1 SessionAddress without changing any protocol fields. The
 * gateway uses only the parent identity for authorization; DSH still receives
 * and validates the complete address.
 */
export function parseSessionAddress(value: unknown): SessionAddress | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const row = value as Record<string, unknown>;
  const validId = (id: unknown): id is string =>
    typeof id === 'string' && id.length > 0 && id.length <= 200;
  if (row.kind === 'session' && validId(row.sessionId)) {
    return { kind: 'session', sessionId: row.sessionId };
  }
  if (
    row.kind === 'subagent' &&
    validId(row.parentSessionId) &&
    validId(row.childSessionId) &&
    (row.mode === 'one-shot' || row.mode === 'continuable' || row.mode === 'unknown')
  ) {
    return {
      kind: 'subagent',
      parentSessionId: row.parentSessionId,
      childSessionId: row.childSessionId,
      mode: row.mode,
    };
  }
  return null;
}

/**
 * Collect only the session identities that authorize a request. RC.1 child
 * addresses intentionally contribute their parent ID, while the child ID and
 * mode remain in the forwarded payload for DSH's own lineage validation.
 * A malformed structured subagent request returns null so callers can reject
 * it instead of falling back to recursive, ambiguous ID guessing.
 *
 * 除 sessionId / agentId 外还收 0.1.7 的 `workspaceFileScopeId`
 * （dsh-api-workspace-files / dsh-office-to-pdf 的 wire 参数）：其值就是 SessionId
 * 本身（workspaceFileScope lookup 就是按 SessionId 查工作区根），因此它必须与
 * sessionId 同等参与归属校验——否则 workspaceFiles 入 SESSION_SCOPED_RE 后会因
 * “找不到会话身份”被整类 403，而只看 sessionId 的旧口径更会让场景走偏。
 * 非字符串值一律返回 false（fail-closed），不用伪造/默认身份继续。
 */
export function collectAuthorizedSessionIds(value: unknown): Set<string> | null {
  const out = new Set<string>();
  const visit = (current: unknown, depth: number): boolean => {
    if (depth > 8 || current === null || typeof current !== 'object') return true;
    if (Array.isArray(current)) return current.every((item) => visit(item, depth + 1));
    const row = current as Record<string, unknown>;
    if (Object.hasOwn(row, 'address')) {
      const address = parseSessionAddress(row.address);
      if (address === null) return false;
      if (address.kind === 'session') out.add(address.sessionId);
      else out.add(address.parentSessionId);
    }
    const hasSubagentFields = Object.hasOwn(row, 'parentSessionId') ||
      Object.hasOwn(row, 'childSessionId');
    if (hasSubagentFields) {
      const hasChildFields = Object.hasOwn(row, 'childSessionId') || Object.hasOwn(row, 'mode');
      if (hasChildFields) {
        const address = parseSessionAddress({
          kind: 'subagent',
          parentSessionId: row.parentSessionId,
          childSessionId: row.childSessionId,
          mode: row.mode,
        });
        if (address === null || address.kind !== 'subagent') return false;
        out.add(address.parentSessionId);
      } else if (typeof row.parentSessionId === 'string') {
        out.add(row.parentSessionId);
      } else {
        return false;
      }
    }
    for (const [key, child] of Object.entries(row)) {
      if (key === 'address' || key === 'parentSessionId' || key === 'childSessionId' || key === 'mode') continue;
      // workspaceFileScopeId：官方 workspaceFiles/officeToPdf 的会话身份 wire 字段
      if (key === 'sessionId' || key === 'agentId' || key === 'workspaceFileScopeId') {
        if (typeof child !== 'string') return false;
        out.add(child);
        continue;
      }
      if (!visit(child, depth + 1)) return false;
    }
    return true;
  };
  return visit(value, 0) ? out : null;
}

/** 递归查找请求体里的 sessionId（typert wire 字段）；找不到返回 null */
export function extractSessionId(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const obj = value as Record<string, unknown>;
  if (typeof obj.sessionId === 'string' && obj.sessionId.length > 0) return obj.sessionId;
  for (const key of Object.keys(obj)) {
    const nested = extractSessionId(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * 0.1.7 的 ClientConnection envelope 把实际参数放在 payload.args；部分 Session
 * endpoint 再把业务请求放进 args.request。只有严格识别的 envelope 才进入 args，
 * 避免旧协议里未被 dsh 消费的伪 args 字段成为授权依据。
 */
export function clientConnectionArgs(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const outer = value as Record<string, unknown>;
  // 0.1.7 ClientConnection endpoint 是 namespace/method。旧 rc.2 的点号
  // method 不得因此获得 args 解释权，防止伪 args 绕过路径授权。
  if (outer.type !== 'client-request' || typeof outer.method !== 'string' || !outer.method.includes('/')) return null;
  const payload = outer.payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const args = (payload as Record<string, unknown>).args;
  return args !== null && typeof args === 'object' && !Array.isArray(args)
    ? args as Record<string, unknown>
    : null;
}

/** 收集请求体中的全部会话地址，避免只校验第一个字段而让第二个目标绕过授权。
 * 覆盖 0.1.7 commands 的 agentId、subagent 的 parent/childSessionId 以及旧 sessionId。
 * 无论值是否符合格式都收集；调用方会让空值/超长值自然无法命中授权快照，fail-closed。 */
export function collectSessionIds(value: unknown, out: Set<string> = new Set(), depth = 0): Set<string> {
  if (depth > 6 || value === null || typeof value !== 'object') return out;
  const args = depth === 0 ? clientConnectionArgs(value) : null;
  if (args !== null) {
    collectSessionIds(args, out, depth + 1);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectSessionIds(item, out, depth + 1);
    return out;
  }
  const obj = value as Record<string, unknown>;
  for (const field of ['sessionId', 'agentId', 'parentSessionId', 'childSessionId']) {
    if (typeof obj[field] === 'string') out.add(obj[field] as string);
  }
  for (const [key, child] of Object.entries(obj)) {
    if (key !== 'args') collectSessionIds(child, out, depth + 1);
  }
  return out;
}


/** 归档会话快照容量上限：超过时拒绝更新，不能截断后把遗漏会话错误放行。 */
export const MAX_ARCHIVED_SESSION_IDS = 10_000;

/**
 * 用上游响应中显式出现的 archivedSessionIds 数组原子替换快照。
 *
 * 返回 false 表示找不到合法字段或输入超限，此时 target 保持不变。dsh rc.8 将归档
 * 状态保存在 workspace registry，因此不能把“字段缺失”误解为“当前没有归档”。
 */
export function replaceArchivedSessionSnapshot(target: Set<string>, value: unknown): boolean {
  const candidate = new Set<string>();
  let found = false;
  let oversized = false;

  const visit = (node: unknown, depth: number): void => {
    if (oversized || depth > 8 || node === null || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1);
      return;
    }
    const obj = node as Record<string, unknown>;
    if (Array.isArray(obj.archivedSessionIds)) {
      found = true;
      for (const id of obj.archivedSessionIds) {
        if (typeof id !== 'string' || id.length === 0 || id.length > 200) continue;
        candidate.add(id);
        if (candidate.size > MAX_ARCHIVED_SESSION_IDS) {
          oversized = true;
          return;
        }
      }
    }
    for (const child of Object.values(obj)) visit(child, depth + 1);
  };

  visit(value, 0);
  if (!found || oversized) return false;
  target.clear();
  for (const id of candidate) target.add(id);
  return true;
}

/** 收集全局/工作区 archivedSessionIds，供 workspace.list 同时过滤 sessionIds。 */
export function collectArchivedSessionIds(value: unknown, out: Set<string> = new Set(), depth = 0): Set<string> {
  if (depth > 8 || value === null || typeof value !== 'object') return out;
  if (Array.isArray(value)) {
    for (const item of value) collectArchivedSessionIds(item, out, depth + 1);
    return out;
  }
  const obj = value as Record<string, unknown>;
  if (Array.isArray(obj.archivedSessionIds)) {
    for (const id of obj.archivedSessionIds) if (typeof id === 'string') out.add(id);
  }
  for (const value of Object.values(obj)) collectArchivedSessionIds(value, out, depth + 1);
  return out;
}

/**
 * 递归过滤 archivedSessionIds，只保留当前用户可见的归档会话。
 *
 * DSH 的归档契约会把归档会话继续保留在工作区 sessionIds 中，以便取消归档时
 * 恢复原位置；前端依靠 archivedSessionIds 把这些会话从普通分组中隐藏。因此
 * 不能简单清空 archivedSessionIds 后再从 sessionIds 删除归档项，否则完整的
 * session.list 条目会被前端当成「未分组」会话。
 */
export function filterArchivedSessionIds(
  value: unknown,
  keep: (id: string) => boolean,
  depth = 0,
): boolean {
  if (depth > 8 || value === null || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  let changed = false;
  if (Array.isArray(obj.archivedSessionIds)) {
    const original = obj.archivedSessionIds;
    const filtered = original.filter(
      (id): id is string => typeof id === 'string' && keep(id),
    );
    if (
      filtered.length !== original.length ||
      filtered.some((id, index) => id !== original[index])
    ) {
      obj.archivedSessionIds = filtered;
      changed = true;
    }
  }
  for (const key of Object.keys(obj)) {
    const nested = obj[key];
    if (nested !== null && typeof nested === 'object') {
      if (filterArchivedSessionIds(nested, keep, depth + 1)) changed = true;
    }
  }
  return changed;
}

/**
 * 递归清空 archivedSessionIds 数组（F-25 枚举源：workspace.list 把他人会话 ID
 * 直接漏给受限子用户）。返回是否有改动。
 */
export function stripArchivedSessionIds(value: unknown, depth = 0): boolean {
  return filterArchivedSessionIds(value, () => false, depth);
}

/**
 * 递归把 JSON 里所有 string[] 的 sessionIds 字段按 keep(id) 过滤：
 * workspace.list 的 items[].sessionIds 会枚举出该工作区全部会话 ID，受限子用户
 * 也只应保留被授权（未禁用/未归档）的会话——这里用 keep 谓词统一过滤。
 * 原地修改，不返回新对象。
 */
export function filterOwnedSessionIds(
  value: unknown,
  keep: (id: string) => boolean,
  depth = 0,
): void {
  if (value === null || typeof value !== 'object') return;
  // 深度超限时清空该容器，不能把不可验证的深层 sessionIds 原样保留。
  if (depth > 8) {
    if (Array.isArray(value)) value.length = 0;
    else {
      const obj = value as Record<string, unknown>;
      delete obj.sessionId;
      delete obj.sessionIds;
      delete obj.cwd;
      delete obj.path;
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) filterOwnedSessionIds(item, keep, depth + 1);
    return;
  }
  const obj = value as Record<string, unknown>;
  if (Array.isArray(obj.sessionIds)) {
    // fail-closed：非字符串 id 一律丢弃——不能因数组混入一个异常元素就整体跳过会话过滤
    obj.sessionIds = obj.sessionIds.filter((id): id is string => typeof id === 'string' && keep(id));
  }
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    if (v !== null && typeof v === 'object') filterOwnedSessionIds(v, keep, depth + 1);
  }
}

/**
 * 递归过滤会话条目（带 sessionId 字符串字段的对象，session.list 响应）：
 * - keep(id) 返回 false 时从所在数组移除。用于子用户只看到被授权（未禁用/未归档）
 *   的会话。
 * - cwdAllowed 非 null 时（授权目录受限的子用户），额外要求条目 cwd 在白名单内：
 *   权限撤销前在老目录创建的旧会话，其工作区已被 workspace.list 白名单隐藏，
 *   若不按 cwd 丢弃，前端会把这条孤会话归入「未分组」并在侧栏显示幽灵「新会话」。
 *   cwd 缺失/非字符串 = 无法确认在白名单内 → fail-closed 丢弃。
 * 只要 sessionId 是字符串就执行过滤（不再要求 cwd 必填——
 *  无工作区的会话也要过滤，否则侧栏泄露未被授权的会话标题）。
 * 注意：typert 线上格式的会话条目是 { sessionId, cwd, ... }（不是 id）。
 */
export function filterSessionItems(
  value: unknown,
  keep: (id: string) => boolean,
  cwdAllowed: ((cwd: string) => boolean) | null = null,
  depth = 0,
): unknown {
  // 真实 session.list 的 permissions.options 投影可到深度 9；深度 16
  // 仍保持有界递归，同时避免把合法权限选项截断为 null。
  if (depth > 16) return null;
  if (value === null) return value;
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) {
      const obj = item as Record<string, unknown> | null;
      const sidRaw = obj === null || typeof obj === 'object' ? obj?.sessionId : undefined;
      const hasSessionId = typeof sidRaw === 'string' && sidRaw.length > 0;
      // 只要 sessionId 是字符串就走过滤判定（fail-closed：keep 不通过 → 整条丢弃）
      if (hasSessionId && !keep(sidRaw as string)) {
        continue;
      }
      // 受限子用户：cwd 不在授权目录的会话丢弃（含 cwd 缺失/非法）
      if (hasSessionId && cwdAllowed !== null) {
        const cwd = obj!.cwd;
        if (typeof cwd !== 'string' || cwd.length === 0 || !cwdAllowed(cwd)) {
          continue;
        }
      }
      out.push(filterSessionItems(item, keep, cwdAllowed, depth + 1));
    }
    return out;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = filterSessionItems(v, keep, cwdAllowed, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * 过滤 rc.1 session.search 的结果项。
 *
 * 搜索结果只有 sessionId 与 snippet，没有 cwd；调用方必须先用当前用户的
 * workspace/session 授权快照建立 keep 谓词。没有可验证 sessionId 的条目直接丢弃，
 * 不能把未知结构当作可见结果透传。
 */
export function filterSessionSearchItems(
  value: unknown,
  keep: (id: string) => boolean,
): unknown[] | null {
  if (!Array.isArray(value)) return null;
  const output: unknown[] = [];
  for (const item of value) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) continue;
    const row = item as Record<string, unknown>;
    if (typeof row.sessionId !== 'string' || row.sessionId.length === 0 || !keep(row.sessionId)) continue;
    output.push({ ...row });
  }
  return output;
}

/** 请求体里可能携带目标路径的字段名（按优先级） */
const PATH_FIELDS = [
  'cwd',
  'path',
  'directory',
  'dir',
  'folder',
  'workspace',
  'root',
  'workspacePath',
  'absolutePath',
  'target',
  'targetPath',
];

/**
 * 递归查找请求体里可能携带目标路径的字段名。
 *
 * 0.1.7 ClientConnection 只把 `payload.args` 交给 RPC owner；部分 Session RPC
 * 再把业务请求放到 `args.request`。已识别的信封必须只从该容器取值：回退扫描
 * 信封外层会让网关校验被 DSH 丢弃的 decoy 路径，形成“校验 A、执行 B”的 fail-open。
 * 非 ClientConnection 形状继续保留旧协议兼容扫描。
 */
export function extractPathFromBody(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const args = depth === 0 ? clientConnectionArgs(value) : null;
  if (args !== null) {
    const request = args.request;
    if (request !== null && typeof request === 'object' && !Array.isArray(request)) {
      return extractPathFromBody(request, depth + 1);
    }
    // directoryPicker/createDirectory 的真实 0.1.7 参数直接位于 args.path.
    for (const field of PATH_FIELDS) {
      const candidate = args[field];
      if (typeof candidate === 'string' && candidate.length > 0) return candidate;
    }
    return null;
  }
  const obj = value as Record<string, unknown>;
  for (const field of PATH_FIELDS) {
    const v = obj[field];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  for (const key of Object.keys(obj)) {
    if (key === 'args') continue; // 旧协议中 args 不被 dsh 消费
    const nested = extractPathFromBody(obj[key], depth + 1);
    if (nested !== null) return nested;
  }
  return null;
}

/**
 * 取 directoryPicker/createDirectory 的实际 wire 路径。
 * 已识别的 ClientConnection envelope 只能使用 args.path；不能用 cwd 等
 * 兼容字段替代它，因为上游会忽略这些字段而仍按 path 执行。
 */
export function extractDirectoryCreatePath(value: unknown): string | null {
  const args = clientConnectionArgs(value);
  if (args !== null) return typeof args.path === 'string' && args.path.length > 0 ? args.path : null;
  return extractPathFromBody(value);
}

/**
 * 取 workspace/create 的实际 wire 路径。
 * 已识别的 envelope 只能使用 args.request.path；其余形状走旧协议解析。
 */
export function extractWorkspaceCreatePath(value: unknown): string | null {
  const args = clientConnectionArgs(value);
  if (args !== null) {
    const request = args.request;
    if (request === null || typeof request !== 'object' || Array.isArray(request)) return null;
    const path = (request as Record<string, unknown>).path;
    return typeof path === 'string' && path.length > 0 ? path : null;
  }
  return extractPathFromBody(value);
}

// ── token 用量：已迁移到客户端 TokenReporter（client/token.tsx 读 dsh 的
// liveTokenUsage 投影并增量上报 /gateway/api/usage/report），本模块不再计量。

/** 当日日期（本地时区 YYYY-MM-DD，与"每日使用时长"语义一致） */
export function todayLocal(): string {
  const d = new Date();
  const y = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  return `${y}-${mm}-${dd}`;
}

/** 是否应跳过用量计时/扣减的静态资源路径（减少无意义的活跃时间累计） */
export function isStaticAsset(pathname: string): boolean {
  return (
    pathname.startsWith('/assets/') ||
    (pathname.startsWith('/plugins/') && pathname.includes('rev=')) ||
    pathname === '/favicon.ico'
  );
}

/**
 * 配额计时锚点：子用户“说第一句话”才启动当日计时（发消息端点）。
 * 页面浏览/轮询等不会创建用量记录——未开始使用的子用户不受配额限制。
 */
export function isUsageAnchorRequest(pathname: string): boolean {
  return (
    /^\/api\/session[.\/]prompt$/.test(pathname) ||
    /^\/api\/subagent[.\/]prompt$/.test(pathname) ||
    /^\/api\/agent[.\/]prompt$/.test(pathname)
  );
}

/**
 * 轮询 / 心跳 / SSE 事件流端点（官方通道 + 通用命名模式）：页面开着就持续
 * 请求，不代表真实使用，不计入每日使用时长（否则子用户只要开着页面就把时长
 * 配额耗尽）。扩展自身的轮询节流由宿主清单和请求生命周期统一处理。
 */
export function isPollingRequest(pathname: string): boolean {
  return (
    pathname === '/api/events.mux' ||
    pathname === '/api/events.host' ||
    pathname === '/plugins/events' ||
    pathname === '/api/session.title' ||
    /^\/api\/[^/]*heartbeat[^/]*/.test(pathname) ||
    /^\/api\/[^/]*poll[^/]*/.test(pathname)
  );
}
