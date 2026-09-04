// 认证服务：首次配置（预设密钥+用户名+密码）、登录（JWT）
// 安全强化：
//   1. 密码策略：≥12 位，大写/小写/数字/符号各至少一位
//   2. 反 SQL 注入：全链参数化查询（根本防线）+ 输入特征检测（纵深防御）
//   3. 网络安全审查：审计日志（登录成功/失败/锁定/配置）+ 防暴力破解（5 次失败锁定，时长随轮次退避）
//
// 错误文案：AuthError 只携带稳定 code + 参数，文案由 i18n.ts 按语言渲染
// （网关页面按页面语言、dsh 设置卡片按 dsh 语言本地化）。
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { PlatformConfig } from './config.js';
import { Database } from './db.js';
import { t, type Lang } from './i18n.js';

const BCRYPT_ROUNDS = 10;
const TOKEN_TTL = '12h';
const MAX_FAILED = 5;
const LOCK_MINUTES = 15;
/** 锁定时长随失败轮次退避（round 0→1 分钟、1→5、2→15、3+→60 封顶）：降低攻击者循环锁死账号的可持续性 */
const LOCK_STEPS = [1, 5, 15, 60] as const;
/**
 * IP 级节流（F-11 密码喷洒）：单 IP 在窗口内失败达阈值 → 该 IP 全局节流。
 * 覆盖“单 IP 轮换多用户名”的喷洒手法——每个 (用户名,IP) 对只贡献几次失败，
 * 单用户锁定触发不了，但同一 IP 的总失败数会快速达到阈值。
 * 阈值/窗口取宽松值：切断自动化喷洒，同时避免大 NAT（公司/校园共享出口）误伤。
 */
const IP_MAX_FAILED = 50;
const IP_WINDOW_MS = 15 * 60 * 1000;
const IP_THROTTLE_MINUTES = 15;
/** 时序均衡用空跑哈希：用户不存在时也执行一次 bcrypt，抹平“快=不存在”的枚举差异 */
const DUMMY_HASH = bcrypt.hashSync('dsh-passwords-timing-equalizer', BCRYPT_ROUNDS);

export class AuthError extends Error {
  constructor(
    public readonly code: string,
    public readonly params: Record<string, string | number> = {},
    public readonly status = 400,
  ) {
    super(t('zh', `err.${code}`, params));
  }

  /** 按语言返回用户可读文案（默认 zh；en 跟随 dsh/浏览器语言） */
  localize(lang: Lang): string {
    return t(lang, `err.${this.code}`, this.params);
  }
}

const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;

/** 密码策略：12-128 位（字符），且大写、小写、数字、符号各至少一位
 *  注：bcryptjs 内部按 UTF-8 字节做 72 字节截断——超过 72 字节的多字节密码后缀
 *  会被静默丢弃。assertPassword() 在字符匹配后再做 byteLength 校验（≤72 字节），
 *  不在正则里用字节数（JS regex 不支持）。 */
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$/;

/**
 * SQL 注入结构化特征（纵深防御层）。
 * 所有数据库查询均已参数化（占位符 + 值绑定），此检测针对会进入
 * 请求解析的字符串字段（password 除外——密码必须允许符号，且经 bcrypt
 * 哈希 + 参数化写入，无注入面）。只拒绝结构化 SQL 注入特征（引号/分号/
 * 注释符），不匹配英文关键词（union/select 等），避免误伤合法密钥。
 */
const SQLI_PATTERN = /(['";]|--|\/\*|\*\/|`)/;

export function assertNoSqlInjection(value: unknown, field: string): void {
  if (typeof value !== 'string' || value === '') return;
  if (SQLI_PATTERN.test(value)) {
    throw new AuthError('SQL_INJECTION_REJECTED', { field });
  }
}

function assertUsername(username: unknown): string {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new AuthError('INVALID_USERNAME');
  }
  return username;
}

function assertPassword(password: unknown): string {
  if (typeof password !== 'string' || !PASSWORD_RE.test(password)) {
    throw new AuthError('INVALID_PASSWORD');
  }
  // UTF-8 字节上限 72：bcryptjs 静默截断 72 字节之后的内容（多字节字符如中文会
  // 提早截断）。按字符数限 12-128 不足以防截断——必须按 byteLength 校验。
  if (Buffer.byteLength(password, 'utf8') > 72) {
    throw new AuthError('INVALID_PASSWORD');
  }
  return password;
}

export interface RequestMeta {
  ip?: string | null;
  userAgent?: string | null;
}

/** 已认证调用方（dsh 插件路由从网关 JWT cookie 解析出的身份） */
export interface AuthedUser {
  userId: number;
  username: string;
  role: 'admin' | 'user';
}

export class AuthService {
  constructor(
    private config: PlatformConfig,
    private db: Database,
  ) {}

  /** 平台是否已初始化（存在至少一个用户） */
  async isInitialized(): Promise<boolean> {
    return (await this.db.countUsers()) > 0;
  }

  /**
   * 首次配置：校验预设密钥 + 创建首个用户。
   * 已初始化后再次调用会失败（单次初始化语义）。
   */
  async setup(
    input: { setupKey: string; username: string; password: string },
    meta: RequestMeta = {},
  ): Promise<void> {
    // 先做快速检查，最终由 setupInitialAdmin 的 BEGIN IMMEDIATE 再做原子判定。
    if (await this.isInitialized()) {
      throw new AuthError('ALREADY_INITIALIZED', {}, 409);
    }
    // 注入特征拦截（setupKey 与 username 进系统前先查）
    assertNoSqlInjection(input.setupKey, 'setupKey');
    if (input.setupKey !== this.config.setupKey) {
      await this.db.audit('setup_failure', {
        username: input.username || null,
        ip: meta.ip,
        userAgent: meta.userAgent,
        detail: '预设密钥错误',
      });
      throw new AuthError('INVALID_SETUP_KEY', {}, 401);
    }
    const username = assertUsername(input.username);
    const password = assertPassword(input.password);

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    // 最终 check + insert 必须处于同一 SQLite 写事务，避免两个并发 setup 都创建 admin。
    if (this.db.setupInitialAdmin(username, hash) === null) {
      throw new AuthError('ALREADY_INITIALIZED', {}, 409);
    }
    await this.db.audit('setup_success', {
      username,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail: '平台初始化完成',
    });
  }

  /** 登录：用户名 + 密码 → JWT（含防暴力破解与审计） */
  async login(
    input: { username: string; password: string },
    meta: RequestMeta = {},
  ): Promise<{ token: string; username: string }> {
    // 输入长度上限：防止未认证请求用超长字符串消耗 HMAC/bcrypt CPU
    const username = (typeof input.username === 'string' ? input.username : '').trim().slice(0, 64);
    const password = typeof input.password === 'string' ? input.password.slice(0, 256) : '';
    const ip = meta.ip ?? 'unknown';

    // 0) IP 级节流检查（F-11 密码喷洒）：先于凭据校验，节流期间不消耗 bcrypt
    const ipThrottle = this.db.getIpThrottle(ip);
    if (ipThrottle?.throttled_until && ipThrottle.throttled_until.getTime() > Date.now()) {
      const remainMin = Math.ceil((ipThrottle.throttled_until.getTime() - Date.now()) / 60000);
      await this.db.audit('ip_throttled_blocked', {
        username,
        ip,
        userAgent: meta.userAgent,
        detail: `IP 触发节流，拒绝登录，剩余 ${remainMin} 分钟`,
      });
      throw new AuthError('IP_THROTTLED', { minutes: remainMin }, 429);
    }

    // 1) 锁定检查（防暴力破解）——锁定响应与凭据错误统一（401 + 同文案），
    //    消除“429=账号存在且被锁 / 401=账号不存在”的用户名枚举；
    //    锁定信息只进审计日志（运维可查）。
    //    IP 级节流保留 429（跨账号维度、不泄露账号存在性）。
    const attempt = await this.db.getLoginAttempt(username, ip);
    if (attempt?.locked_until && attempt.locked_until.getTime() > Date.now()) {
      const remainMin = Math.ceil((attempt.locked_until.getTime() - Date.now()) / 60000);
      await this.db.audit('account_locked_blocked', {
        username,
        ip,
        userAgent: meta.userAgent,
        detail: `锁定期间拒绝登录，剩余 ${remainMin} 分钟`,
      });
      // 时序均衡：锁定路径不跑真实 bcrypt，但空跑一次抹平与凭据校验的耗时差
      await bcrypt.compare('dsh-passwords-locked', DUMMY_HASH);
      throw new AuthError('INVALID_CREDENTIALS', {}, 401);
    }

    // 2) 凭据校验（统一错误信息，避免用户名枚举；时序上用户不存在也空跑 bcrypt）
    const user = await this.db.getUserByUsername(username);
    let valid = false;
    if (user) {
      valid = await bcrypt.compare(password, user.password_hash);
    } else {
      await bcrypt.compare(password, DUMMY_HASH); // 空跑一次，抹平时序差异
    }
    if (!user || !valid) {
      // 0.5) 记录 IP 级失败（跨用户名累计，防密码喷洒）；达阈值 → 该 IP 全局节流
      const ipCount = this.db.recordIpFailure(ip, IP_WINDOW_MS);
      if (ipCount >= IP_MAX_FAILED) {
        const until = new Date(Date.now() + IP_THROTTLE_MINUTES * 60000);
        this.db.throttleIp(ip, until);
        await this.db.audit('ip_throttled', {
          username,
          ip,
          userAgent: meta.userAgent,
          detail: `IP ${IP_WINDOW_MS / 60000} 分钟内失败 ${ipCount} 次，节流 ${IP_THROTTLE_MINUTES} 分钟`,
        });
        throw new AuthError('IP_THROTTLED', { minutes: IP_THROTTLE_MINUTES }, 429);
      }
      const count = await this.db.recordLoginFailure(username, ip);
      // 锁定时长随失败轮次退避（round 0 → 1 分钟，1 → 5，2 → 15，3+ → 60 封顶）
      const round = Math.max(0, Math.floor((count - 1) / MAX_FAILED));
      const lockMinutes = LOCK_STEPS[Math.min(round, LOCK_STEPS.length - 1)];
      if (count >= MAX_FAILED) {
        const until = new Date(Date.now() + lockMinutes * 60000);
        await this.db.lockLoginAttempt(username, ip, until);
        await this.db.audit('account_locked', {
          username,
          ip,
          userAgent: meta.userAgent,
          detail: `连续失败 ${count} 次，锁定 ${lockMinutes} 分钟（退避第 ${round} 轮）`,
        });
        throw new AuthError('ACCOUNT_LOCKED_FRESH', { count, minutes: lockMinutes }, 429);
      }
      // 分布式爆破兑底：轮换 IP 时单 (user,ip) 计数到不了 MAX_FAILED，
      // 但该用户名在所有 IP 上的总失败数达到阈值 → 全局锁定（所有 IP 一起拦）。
      // 主用户（admin 角色）不参与全局锁：防止攻击者用多 IP 轮换把管理员
      // 永久锁死（账号级 DoS）。主用户的 (user,ip) 级锁定仍生效。
      const isAdmin = user !== null && user.role === 'admin';
      if (!isAdmin && (await this.db.countFailuresByUsername(username)) >= MAX_FAILED * 3) {
        const until = new Date(Date.now() + LOCK_MINUTES * 60000);
        await this.db.lockAllAttemptsByUsername(username, until);
        await this.db.audit('account_locked', {
          username,
          ip,
          userAgent: meta.userAgent,
          detail: `分布式爆破检测：累计失败达阈值，全局锁定 ${LOCK_MINUTES} 分钟`,
        });
        throw new AuthError('ACCOUNT_LOCKED_FRESH', { count: MAX_FAILED * 3, minutes: LOCK_MINUTES }, 429);
      }
      await this.db.audit('login_failure', {
        username,
        ip,
        userAgent: meta.userAgent,
        detail: `第 ${count} 次失败（${MAX_FAILED} 次锁定）`,
      });
      throw new AuthError('INVALID_CREDENTIALS', {}, 401);
    }

    // 3) 成功：清除失败计数 + IP 节流 + 记录审计
    await this.db.resetLoginAttempts(username, ip);
    this.db.resetIpThrottle(ip);
    await this.db.touchLogin(user.id);
    await this.db.audit('login_success', { username, ip, userAgent: meta.userAgent });

    const token = jwt.sign(
      { sub: String(user.id), username: user.username, cv: user.credential_version },
      this.config.jwtSecret,
      { expiresIn: TOKEN_TTL },
    );
    return { token, username: user.username };
  }

  /** 校验 JWT（Web 中间件用）；cv 为签入时的凭据版本，改密后旧 token 失效。
   *  exp 为 JWT 自身的到期时间（秒级 epoch，无则 undefined）——网关会话缓存
   *  的 TTL 必须与其取最小值，否则缓存命中会在 JWT 过期后额外接受最多 30 秒。 */
  verifyToken(token: string): { userId: number; username: string; cv: number; exp?: number } {
    try {
      // 算法白名单：只接受 HS256（对称密钥），拒绝 alg:none / RS→HS 混淆等变体
      const payload = jwt.verify(token, this.config.jwtSecret, { algorithms: ['HS256'] }) as jwt.JwtPayload;
      const cv = typeof payload.cv === 'number' ? payload.cv : 0;
      const exp = typeof payload.exp === 'number' && Number.isFinite(payload.exp) ? payload.exp : undefined;
      return { userId: Number(payload.sub), username: String(payload.username), cv, exp };
    } catch {
      throw new AuthError('INVALID_TOKEN', {}, 401);
    }
  }

  // ── 用户管理（dsh 设置页卡片调用） ────────────────────────────

  /** 改密：本人可改自己（需提供当前密码）；主用户可重置任何人（无需当前密码）。改后旧会话全部失效。 */
  async changePassword(
    caller: AuthedUser,
    target: string,
    newPassword: string,
    meta: RequestMeta = {},
    currentPassword?: string,
  ): Promise<void> {
    const targetUser = await this.db.getUserByUsername(target.trim());
    if (!targetUser) throw new AuthError('NO_SUCH_USER', {}, 404);
    const isSelf = caller.username === targetUser.username;
    if (caller.role !== 'admin' && !isSelf) {
      throw new AuthError('FORBIDDEN_PASSWORD', {}, 403);
    }
    // F-06：自助改密必须验证当前密码（防会话劫持后改密“账号接管持久化”）；
    // 主用户重置他人密码属于高权限操作，不需要当前密码（主用户凭据已是最强认证）
    if (isSelf) {
      const current = typeof currentPassword === 'string' ? currentPassword : '';
      if (current === '' || !(await bcrypt.compare(current, targetUser.password_hash))) {
        throw new AuthError('INVALID_CURRENT_PASSWORD', {}, 401);
      }
    }
    const password = assertPassword(newPassword);
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await this.db.updatePasswordHash(targetUser.id, hash);
    await this.db.audit('password_changed', {
      username: targetUser.username,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail: isSelf ? '用户自助修改密码（已验证当前密码）' : `由主用户 ${caller.username} 重置`,
    });
  }

  /** 改名：本人可改自己；主用户可改任何人。改名后旧会话失效（需重新登录）。 */
  async renameUser(
    caller: AuthedUser,
    target: string,
    newUsername: string,
    meta: RequestMeta = {},
  ): Promise<void> {
    const targetUser = await this.db.getUserByUsername(target.trim());
    if (!targetUser) throw new AuthError('NO_SUCH_USER', {}, 404);
    if (caller.role !== 'admin' && caller.username !== targetUser.username) {
      throw new AuthError('FORBIDDEN_USERNAME', {}, 403);
    }
    const username = assertUsername(newUsername);
    assertNoSqlInjection(username, 'username');
    if (this.db.getUserByUsername(username) !== null) {
      throw new AuthError('USERNAME_TAKEN', {}, 409);
    }
    await this.db.updateUsername(targetUser.id, username);
    await this.db.audit('username_changed', {
      username: targetUser.username,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail:
        caller.username === targetUser.username
          ? `自助改名 → ${username}`
          : `由主用户 ${caller.username} 改名 → ${username}`,
    });
  }

  /** 新增子用户（仅主用户） */
  async addSubUser(
    caller: AuthedUser,
    username: string,
    password: string,
    meta: RequestMeta = {},
  ): Promise<void> {
    if (caller.role !== 'admin') throw new AuthError('FORBIDDEN_ADD_USER', {}, 403);
    const name = assertUsername(username);
    assertNoSqlInjection(name, 'username');
    if (this.db.getUserByUsername(name) !== null) {
      throw new AuthError('USERNAME_TAKEN', {}, 409);
    }
    const pw = assertPassword(password);
    const hash = await bcrypt.hash(pw, BCRYPT_ROUNDS);
    const user = await this.db.createUser(name, hash, 'user');
    // 新子用户默认关闭全部工作区；主用户在权限面板中逐个滑动开启。
    this.db.setPermissions(user.id, {
      allowedFolders: ['__deny__'],
      hourlyTokenLimit: null,
      dailyMinutesLimit: null,
      // 新子用户默认使用 64 MiB 请求体档位；主用户可在权限卡片勾选
      // “大请求体/大文件上传”后提升到 rc.2 上游一致的 300 MiB。
      allowUpload: false,
      allowGitDownload: false,
      allowWorkspaceCreate: false,
      allowSsh: false,
      allowedAgentPresets: [],
      banned: false,
      sandboxMode: null,
      disabledSessions: [],
    });
    await this.db.audit('subuser_created', {
      username: name,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail: `由主用户 ${caller.username} 创建`,
    });
  }

  /** 删除子用户（仅主用户；不能删除自己） */
  async removeUser(
    caller: AuthedUser,
    target: string,
    meta: RequestMeta = {},
  ): Promise<void> {
    if (caller.role !== 'admin') throw new AuthError('FORBIDDEN_REMOVE_USER', {}, 403);
    const targetUser = await this.db.getUserByUsername(target.trim());
    if (!targetUser) throw new AuthError('NO_SUCH_USER', {}, 404);
    if (targetUser.username === caller.username) {
      throw new AuthError('CANNOT_REMOVE_SELF', {}, 400);
    }
    // 主用户是平台恢复与权限管理的根信任；禁止管理员之间互删以保证始终保留管理面。
    if (targetUser.role === 'admin') {
      throw new AuthError('CANNOT_REMOVE_ADMIN', {}, 400);
    }
    await this.db.deleteUser(targetUser.id);
    this.db.clearLoginAttemptsOf(targetUser.username);
    await this.db.audit('subuser_removed', {
      username: targetUser.username,
      ip: meta.ip,
      userAgent: meta.userAgent,
      detail: `由主用户 ${caller.username} 删除`,
    });
  }
}
