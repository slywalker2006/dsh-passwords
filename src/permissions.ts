// 子用户权限模型 + 网关侧强制执行的纯函数（无 DB/框架依赖，便于复用与测试）。
//
// 权限（主用户在设置卡片里为每个子用户配置）：
//   - allowedFolders         允许打开的工作区/项目文件夹（绝对路径；空数组 = 全部允许，
//                            __deny__ 哨兵 = 禁止所有）
//   - hourlyTokenLimit       每小时 token 上限（null = 不限）
//   - dailyMinutesLimit      每日使用时长上限，分钟（从当天首次使用起算；null = 不限）
//   - allowUpload            是否使用大请求体/大文件上传档位（false = 64 MiB，true = 300 MiB）
//   - allowGitDownload       是否允许 git 下载（clone/pull 等）
//   - allowWorkspaceCreate   是否允许创建/删除/重命名工作区
//   - allowedWebSocketPaths  授权可访问的 WebSocket 路径（子用户仅能用勾选的子路径）
//   - allowedSessionIds      显式会话授权（未初始化前自动种子化可见会话；保存后新会话不再自动加入）
//   - disabledSessions       已授权工作区内逐会话关闭的会话 ID（兼容旧行为）
//   - sandboxMode            沙盒级别（read-only / workspace-write / danger-full-access）
//   - banned                 是否封禁（封禁后经密码门的请求全部 403）
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

export type WebSocketAccess = 'deny' | 'authenticated';

/**
 * 解析逗号分隔的 WebSocket 路径白名单。规则刻意保持最小：精确路径或尾部
 * `/*` 表示显式子路径（只匹配其直接下级）。WebSocket 规则是权限边界，
 * 格式非法的输入直接报错（启动阶段 fail-closed），而不是被静默放宽或忽略。
 */
export function parseWebSocketAllowlist(raw: string | undefined, envName: string): string[] {
  if (raw === undefined || raw.trim() === '') return [];
  const rules = new Set<string>();
  for (const item of raw.split(',')) {
    const rule = item.trim();
    if (rule === '') continue;
    if (rule.length > 256) throw new Error(`${envName}: rule is longer than 256 characters`);
    if (!rule.startsWith('/')) throw new Error(`${envName}: rule must start with /: ${rule}`);
    if (/[? #%\\\\\u0000-\u001f\u007f]/.test(rule)) {
      throw new Error(`${envName}: rule contains query, encoding, backslash, or control characters: ${rule}`);
    }
    const wildcard = rule.endsWith('/*');
    if (rule.includes('*') && !wildcard) {
      throw new Error(`${envName}: only a trailing /* wildcard is supported: ${rule}`);
    }
    const pathPart = wildcard ? rule.slice(0, -2) : rule;
    if (pathPart === '' || pathPart === '/') throw new Error(`${envName}: root and /* are not allowed`);
    if (pathPart === '/gateway' || pathPart.startsWith('/gateway/')) {
      throw new Error(`${envName}: gateway paths cannot be allowlisted: ${rule}`);
    }
    if (pathPart === '/api/dsh-passwords/internal' || pathPart.startsWith('/api/dsh-passwords/internal/')) {
      throw new Error(`${envName}: internal gateway paths cannot be allowlisted: ${rule}`);
    }
    const segments = pathPart.split('/').slice(1);
    if (segments.some((segment) => segment === '.' || segment === '..' || segment === '')) {
      throw new Error(`${envName}: rule contains an empty or dot path segment: ${rule}`);
    }
    rules.add(rule);
    if (rules.size > 64) throw new Error(`${envName}: at most 64 rules are supported`);
  }
  return [...rules];
}

export function matchesWebSocketRule(pathname: string, rule: string): boolean {
  if (rule.endsWith('/*')) {
    const prefix = rule.slice(0, -2);
    return pathname.startsWith(`${prefix}/`);
  }
  return pathname === rule;
}

export function webSocketAccessForPath(
  pathname: string,
  configuredRules: readonly string[],
  grantedRules: readonly string[],
  userRole: 'admin' | 'user',
  builtin: boolean,
): WebSocketAccess {
  // dsh 内置事件通道对所有已认证用户开放
  if (builtin) return 'authenticated';
  if (!configuredRules.some((rule) => matchesWebSocketRule(pathname, rule))) return 'deny';
  // 主用户可用全部已配置路径；子用户只能用主用户在设置卡片中显式勾选的路径
  if (userRole === 'admin' || grantedRules.some((rule) => matchesWebSocketRule(pathname, rule))) {
    return 'authenticated';
  }
  return 'deny';
}

/**
 * 工作区白名单的"禁止所有"哨兵值：主用户选择"禁止工作区"时存入白名单，
 * 与空数组（=全部允许）区分开（空数组还是"未限制"语义，兼容默认子用户）。
 */
const DENY_ALL_WORKSPACES = '__deny__';

/**
 * 判断 host 是否私网/回环/链路本地地址（dsh-ssh 等第三方插件 SSRF 纵深防御）。
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
    // IPv4:port 形式（dsh-ssh 的 host 字段可能带端口，变体段一并判）
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
 *  第三方 dsh-uploads 不限制类型，网关层纵深防御——
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
 *  ⚠ 递归时跳过 args 子对象（同 extractPathFromBody：args 是 dsh 不消费的伪字段）。
 */
export function extractWorkspaceId(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const args = depth === 0 ? clientConnectionArgs(value) : null;
  if (args !== null) {
    const request = args.request;
    if (request !== null && typeof request === 'object' && !Array.isArray(request)) {
      return extractWorkspaceId(request, depth + 1);
    }
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

// ── 上传 / git 拦截的路径判定（纯路径 + 方法，不读请求体） ──────────────

/** 上传相关端点：dsh-file-uploads 插件 + dsh-file-path 的"复制到工作区"桥 + dsh-ssh 远程上传 */
export function isUploadRequest(method: string, pathname: string): boolean {
  if (method !== 'POST' && method !== 'PUT') return false;
  return (
    pathname === '/api/dsh-uploads' ||
    pathname.startsWith('/api/dsh-uploads/') ||
    pathname === '/api/filePathBridge/importFile' ||
    pathname === '/api/dsh-ssh/upload' ||
    pathname === '/api/session/uploadFileBinary' ||
    pathname === '/api/fileUploads/upload'
  );
}

/**
 * git 相关端点（dsh 内置 git 工具 RPC：git.clone / git.pull / git.fetch 等；
 * git-graph 插件；aionui-panel 的 git 面板；以及“从服务器拿走数据”的其它通道：
 * session.export 会话日志 ZIP、dsh-ssh 远程文件下载、dsh-uploads 文件下载）。
 * 只匹配 git 前缀的 RPC（不拦 session.fetch 这类普通端点）。
 */
export function isGitRequest(pathname: string): boolean {
  return (
    /^\/api\/git[-.\/]/i.test(pathname) ||
    /^\/aionui-panel\/git[-.]/.test(pathname) ||
    /^\/api\/session[.\/]export/.test(pathname) ||
    /^\/api\/dsh-ssh[.\/](download|ls)/.test(pathname) ||
    /^\/api\/dsh-uploads[.\/]download/.test(pathname)
  );
}

 /** better-sidebar 的宿主侧文件、Git、上传、预览和终端管理面（仅主用户可访问）。 */
 export function isAdminOnlySidebarEndpoint(pathname: string): boolean {
   return pathname === '/sidebar' || pathname.startsWith('/sidebar/');
 }

/** SSH 插件路由族；子用户只有在 allowSsh 且 alias 归属当前用户时可访问。 */
export function isSshPluginEndpoint(pathname: string): boolean {
  return pathname === '/api/dsh-ssh' || pathname.startsWith('/api/dsh-ssh/');
}

/** SSH 不具备单 alias 归属的批量/导入能力，始终仅限主用户。 */
export function isUnscopedSshEndpoint(pathname: string): boolean {
  return pathname === '/api/dsh-ssh/hosts/import-ssh-config' ||
    pathname === '/api/dsh-ssh/cluster' || pathname === '/api/dsh-ssh/tunnel';
}

/** 使用 query alias 的 SSH 操作；调用方必须在转发前检查归属。 */
export function isSshAliasQueryEndpoint(pathname: string): boolean {
  return pathname === '/api/dsh-ssh/ls' || pathname === '/api/dsh-ssh/download' || pathname === '/api/dsh-ssh/upload';
}

/** 使用 JSON body alias 的 SSH 操作；调用方必须在转发前检查归属。 */
export function isSshAliasBodyEndpoint(pathname: string): boolean {
  return pathname === '/api/dsh-ssh/test' || pathname === '/api/dsh-ssh/exec';
}

/** PTY terminal is a real WebSocket and carries its alias in the query string. */
export function isSshTerminalEndpoint(pathname: string): boolean {
  return pathname === '/api/dsh-ssh/terminal';
}

/** dsh-ssh 客户端只读的静态依赖，不携带 host 凭据或远端资源标识。 */
export function isSshPublicAssetEndpoint(method: string, pathname: string): boolean {
  return (method === 'GET' || method === 'HEAD') && pathname.startsWith('/api/dsh-ssh/vendor/');
}

 /** 第三方插件“运维面”端点（仅主用户可访问）：
 *   - dsh-ssh 的未纳入子用户 alias 授权的管理能力仍由网关单独拒绝；
 *     可归属 alias 的 SSH 操作由 allowSsh 和 alias 归属规则控制；
 *   - skin-center —— 皮肤中心（未纳入网关权限模型）；
 *   - modlens —— 模型透镜（未纳入网关权限模型）；
 *   - dsh-uploads —— 共享上传存储的【列表/删除】（F-12）：枚举全部用户上传文件清单
 *     与删除他人文件均仅主用户；上传（POST）仍由 allow_upload 门控、下载
 *     （GET /download）仍由 allowGitDownload 门控，保持原权限语义。
 * 这些端点不在白名单/沙盒/配额模型内，对子用户一律 403（deny-list 兜底）。
 */
export function isAdminOnlyPluginEndpoint(method: string, pathname: string): boolean {
  return (
    pathname === '/api/skin-center' ||
    pathname.startsWith('/api/skin-center/') ||
    pathname === '/modlens' ||
    pathname.startsWith('/modlens/') ||
    // F-12：仅精确匹配 /api/dsh-uploads（不含 /download 子路径），且只看
    // GET（列表）/DELETE（删除）；POST 上传由 isUploadRequest 按 allow_upload 判定
    (pathname === '/api/dsh-uploads' && (method === 'GET' || method === 'DELETE'))
  );
}

/** aionui-panel 文件树：读取/下载文件内容的端点（raw 为 GET 流式传输，read 为 POST JSON） */
export function isAionuiFileRead(method: string, pathname: string): boolean {
  if (pathname === '/aionui-panel/raw') return method === 'GET' || method === 'HEAD';
  return method === 'POST' && pathname === '/aionui-panel/read';
}

/** aionui-panel 文件树：写文件/删除的端点（与上传权限对称） */
export function isAionuiFileWrite(method: string, pathname: string): boolean {
  if (method !== 'POST' && method !== 'PUT' && method !== 'DELETE') return false;
  return (
    pathname === '/aionui-panel/write' ||
    pathname === '/aionui-panel/delete' ||
    pathname === '/aionui-panel/git-stage' ||
    pathname === '/aionui-panel/git-unstage' ||
    pathname === '/aionui-panel/git-discard'
  );
}

/** aionui-panel 文件树：任意端点（用于 allowedFolders 白名单校验 root） */
export function isAionuiPanel(pathname: string): boolean {
  return pathname.startsWith('/aionui-panel/');
}

/**
 * 从 aionui-panel 请求中提取 root（工作区路径）：GET/HEAD/DELETE 取 query
 * （F-17b：DELETE 的 root 在 query 而非 body，之前漏读导致白名单校验跳过），
 * POST/PUT 取 JSON body。提取不到返回 null（调用方必须 fail-closed）。
 */
export function aionuiRootFrom(
  method: string,
  pathname: string,
  query: URLSearchParams,
  bodyJson: unknown,
): string | null {
  if (!isAionuiPanel(pathname)) return null;
  if (method === 'GET' || method === 'HEAD' || method === 'DELETE') {
    const root = query.get('root');
    if (root !== null && root.length > 0) return root;
    if (method === 'GET' || method === 'HEAD') return null;
    // DELETE：query 无 root 时兜底读 body
  }
  if (typeof bodyJson === 'object' && bodyJson !== null) {
    const root = (bodyJson as Record<string, unknown>).root;
    return typeof root === 'string' && root.length > 0 ? root : null;
  }
  return null;
}

/** 工作区创建端点；创建权限与其他工作区管理权限分开控制。 */
export function isWorkspaceCreate(pathname: string): boolean {
  return /^\/api\/workspace[.\/](add|create)([.\/]|$)/.test(pathname);
}

/**
 * 目录选择器创建实际目录后，才由 workspace.create 登记工作区。alpha.3 使用
 * directoryPicker/createDirectory；保留 host.createDirectory 是为旧 dsh 兼容。
 */
export function isWorkspaceDirectoryCreate(pathname: string): boolean {
  return /^(?:\/api\/host|\/api\/directoryPicker)[.\/]createDirectory(?:[.\/]|$)/.test(pathname);
}

/** 当前 dsh 已提供的删除/重命名端点；移动、导入暂不纳入子用户权限。 */
export function isWorkspaceDeleteOrRename(pathname: string): boolean {
  return /^\/api\/workspace[.\/](remove|delete|rename|update)([.\/]|$)/.test(pathname);
}

/** 工作区管理写操作（默认仅主用户；子用户由 allowWorkspaceCreate 控制创建/删除/重命名）。 */
export function isWorkspaceWrite(pathname: string): boolean {
  return (
    isWorkspaceCreate(pathname) ||
    isWorkspaceDeleteOrRename(pathname) ||
    /^\/api\/workspace[.\/](import|move|insertBefore|insertSessionBefore|materialize|adopt)([.\/]|$)/.test(pathname)
  );
}

// ── 工作区/会话文件夹限制：需要读 JSON 请求体 ──────────────────────────

/** 涉及创建工作区的 dsh typert RPC（斜杠风格：/api/session/create 等；兼容点号风格）
 *  只含 create——fork 继承源会话的 cwd，目标目录由源会话决定（其工作区授权已由
 *  SESSION_SCOPED_RE/needsOwnershipCheck 校验），无需也不应再做文件夹白名单。 */
export const WORKSPACE_ENDPOINT_RE = /^\/api\/session[.\/](create)([.\/]|$)/;

/**
 * 会话作用域 RPC：这些端点带一个 sessionId，能读/写/改某个会话——
 * 子用户必须启用其所在工作区，且该会话未被管理员单独关闭。
 * create 无源会话、list 单独做工作区/会话过滤，均不在此列。
 */
export const SESSION_SCOPED_RE =
  /^\/api\/(?:session[.\/](?:history|prompt|respond|archive|delete|rename|retitle|title|resume|fork|truncate|export|attachment|updateQueue|cancel|page|openWorkspacePath|selectModel)|workspace[.\/](?:archiveSession)|commands[.\/](?:list|execute)|subagents[.\/](?:list|prompt|interruptByParent)|fileUploads[.\/](?:upload)|fileReferences[.\/](?:list)|sessionReferenceResolver[.\/](?:candidates)|skills[.\/](?:list)|messageFeedback[.\/](?:list|put|delete)|goals[.\/](?:clear|complete|create|edit|pause|resume)|dynamicCordisRunner[.\/](?:getClientCode|reportClientGuardFailure|reportRenderFailure|resolveInspectQuery|runHostHalf|settleUserRun|stopFromPanel|undefineFromPanel))([.\/]|$)/;

export type SessionAddress =
  | { kind: 'session'; sessionId: string }
  | {
      kind: 'subagent';
      parentSessionId: string;
      childSessionId: string;
      mode: 'one-shot' | 'continuable';
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
    (row.mode === 'one-shot' || row.mode === 'continuable')
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
      if (key === 'sessionId' || key === 'agentId') {
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
 * alpha.3 的 ClientConnection envelope 把实际参数放在 payload.args；部分 Session
 * endpoint 再把业务请求放进 args.request。只有严格识别的 envelope 才进入 args，
 * 避免旧协议里未被 dsh 消费的伪 args 字段成为授权依据。
 */
export function clientConnectionArgs(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const outer = value as Record<string, unknown>;
  // alpha.3 ClientConnection endpoint 是 namespace/method。旧 rc.2 的点号
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
 * 覆盖 alpha.3 commands 的 agentId、subagent 的 parent/childSessionId 以及旧 sessionId。
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
 * 递归查找请求体里第一个字符串路径字段（兼容 typert 信封 {type,rpcId,method,payload}）。
 * ⚠ 递归时跳过 args 子对象——实测 {payload:{args:{cwd:'/root/11'}}} 会被 dsh 忽略 args、
 *  用默认工作区（/opt），而网关若把 args.cwd 当白名单依据会误放行（fail-open 越权）。
 *  真实 wire 路径是 payload.cwd（payload 层），args 是 dsh 不消费的伪字段。
 */
export function extractPathFromBody(value: unknown, depth = 0): string | null {
  if (depth > 6 || value === null || typeof value !== 'object') return null;
  const args = depth === 0 ? clientConnectionArgs(value) : null;
  if (args !== null) {
    const request = args.request;
    if (request !== null && typeof request === 'object' && !Array.isArray(request)) {
      return extractPathFromBody(request, depth + 1);
    }
    // directoryPicker/createDirectory 的真实 alpha.3 参数直接位于 args.path。
    for (const field of PATH_FIELDS) {
      const candidate = args[field];
      if (typeof candidate === 'string' && candidate.length > 0) return candidate;
    }
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
 * 轮询 / 心跳 / SSE 事件流端点：页面开着就持续请求，不代表真实使用，
 * 不计入每日使用时长（否则子用户只要开着页面就把时长配额耗尽）。
 */
export function isPollingRequest(pathname: string): boolean {
  return (
    pathname === '/api/pet/state' ||
    pathname === '/api/pair/heartbeat' ||
    pathname === '/api/pair/status' ||
    pathname === '/api/events.mux' ||
    pathname === '/api/events.host' ||
    pathname === '/plugins/events' ||
    pathname.startsWith('/aionui-panel/events') ||
    pathname === '/api/live-stats' ||
    pathname === '/api/session.title' ||
    /^\/api\/[^/]*heartbeat[^/]*/.test(pathname) ||
    /^\/api\/[^/]*poll[^/]*/.test(pathname)
  );
}
