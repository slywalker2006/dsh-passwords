// SQLite 数据层：Node 内置 node:sqlite（零外部数据库依赖）
// 表结构：users / platform_settings / audit_logs / login_attempts / ip_throttle /
// user_permissions / user_usage / messages / user_workspaces / user_session_grants
//
// 静态加密（见 src/encrypt.ts）：
//   - users.username         → AES-256-GCM 密文存储；username_hash（HMAC）做等值索引
//   - audit_logs 的 username/ip/user_agent/detail → AES-256-GCM 密文存储
//   - login_attempts         → 只存 username_hash/ip_hash（HMAC，不可逆）
//   密码始终只存 bcrypt 哈希（不可逆，无明文，无需加密）。
//   旧明文数据在 init() 时一次性自动迁移为密文（幂等，检测 v1:/h1: 前缀）。
//
// 性能：预处理语句按 SQL 文本缓存（每个代理请求都要查询会话，
// 避免逐请求重复编译 SQL 的开销）。
import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import type { FieldCrypto } from './encrypt.js';
import { normalizePath } from './permissions.js';

type UserRole = 'admin' | 'user';

interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  role: UserRole;
  /** 改密时 +1：旧 JWT（签入时的版本号）立即失效 */
  credential_version: number;
  created_at: string;
  last_login_at: string | null;
}

/** 用户列表条目（已解密的展示字段） */
export interface UserListRow {
  id: number;
  username: string;
  role: UserRole;
  created_at: string;
  last_login_at: string | null;
}

interface AuditLogRow {
  id: number;
  event_type: string;
  username: string | null;
  ip: string | null;
  user_agent: string | null;
  detail: string | null;
  created_at: string;
}

/** 子用户权限（对应 user_permissions 表；缺行 = 默认全量权限） */
export interface UserPermissionsRow {
  user_id: number;
  allowed_folders: string[];
  hourly_token_limit: number | null;
  daily_minutes_limit: number | null;
  allow_upload: boolean;
  allow_git_download: boolean;
  allow_workspace_create: boolean;
  allow_ssh: boolean;
  allowed_websocket_paths: string[];
  /** NULL = unrestricted; [] = no agent preset is allowed. */
  allowed_agent_presets: string[] | null;
  banned: boolean;
  sandbox_mode: string | null;
  disabled_sessions: string[];
  updated_at: string;
}

/** 用户用量（对应 user_usage 表） */
interface UsageRow {
  user_id: number;
  day: string;
  first_seen_at: string | null;
  last_active_at: string | null;
  active_seconds: number;
  hourly_window_start: string | null;
  hourly_tokens: number;
}

/** 留言/聊天消息（含发送者用户名，列表时联表带出） */
export interface MessageRow {
  id: number;
  sender_id: number;
  sender_name: string;
  recipient_id: number | null;
  content: string;
  tags: string[];
  created_at: string;
}


const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  username           TEXT    NOT NULL,
  username_hash      TEXT,
  password_hash      TEXT    NOT NULL,
  role               TEXT    NOT NULL DEFAULT 'user',
  credential_version INTEGER NOT NULL DEFAULT 0,
  created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  last_login_at      TEXT
);
CREATE TABLE IF NOT EXISTS platform_settings (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  username   TEXT,
  ip         TEXT,
  user_agent TEXT,
  detail     TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username_hash TEXT NOT NULL,
  ip_hash       TEXT NOT NULL,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(username_hash, ip_hash)
);
CREATE TABLE IF NOT EXISTS ip_throttle (
  ip_hash        TEXT PRIMARY KEY,
  failed_count   INTEGER NOT NULL DEFAULT 0,
  window_started TEXT NOT NULL DEFAULT (datetime('now')),
  throttled_until TEXT,
  updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user_permissions (
  user_id            INTEGER PRIMARY KEY,
  allowed_folders    TEXT,                          -- JSON 字符串数组（绝对路径）
  hourly_token_limit INTEGER,                       -- NULL = 不限
  daily_minutes_limit INTEGER,                      -- NULL = 不限
  allow_upload       INTEGER NOT NULL DEFAULT 0, -- 是否提升子用户请求体上限到 300 MiB
  allow_git_download INTEGER NOT NULL DEFAULT 0,
  allow_workspace_create INTEGER NOT NULL DEFAULT 0,
  allow_ssh          INTEGER NOT NULL DEFAULT 0,       -- 子用户 SSH 开关；具体 alias 另按归属控制
  allowed_websocket_paths TEXT NOT NULL DEFAULT '[]', -- 第三方 WebSocket 子用户授权路径
  allowed_agent_presets TEXT,                         -- NULL = unrestricted；JSON agent preset ID 白名单
  banned             INTEGER NOT NULL DEFAULT 0,
  sandbox_mode       TEXT,                          -- NULL = 不更改；read-only/workspace-write/danger-full-access
  disabled_sessions  TEXT NOT NULL DEFAULT '[]',    -- 已开启工作区内逐会话关闭的 sessionId JSON 数组
  updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ssh_host_owners (
  alias              TEXT PRIMARY KEY,
  user_id            INTEGER NOT NULL,
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ssh_host_owners_user ON ssh_host_owners(user_id);
CREATE TABLE IF NOT EXISTS user_usage (
  user_id             INTEGER,
  day                 TEXT,                          -- YYYY-MM-DD（本地时区）
  first_seen_at       TEXT,                          -- 当日首次使用时间（ISO）
  last_active_at      TEXT,                          -- 最近活跃时间（ISO，用于累计活跃跨度）
  active_seconds      INTEGER NOT NULL DEFAULT 0,
  hourly_window_start TEXT,                          -- 当前小时窗口起点（ISO）
  hourly_tokens       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
CREATE TABLE IF NOT EXISTS messages (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id    INTEGER NOT NULL,
  recipient_id INTEGER,                              -- NULL = 广播给所有人
  content      TEXT NOT NULL,
  tags         TEXT NOT NULL DEFAULT '[]',           -- JSON 字符串数组
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(id DESC);
CREATE TABLE IF NOT EXISTS user_workspaces (
  user_id    INTEGER NOT NULL,
  path       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, path)
);
CREATE INDEX IF NOT EXISTS idx_user_workspaces_path ON user_workspaces(path);
CREATE TABLE IF NOT EXISTS user_session_grants (
  user_id    INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  granted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_user_session_grants_session ON user_session_grants(session_id);

`;

/** 安全解析 JSON 字符串数组（权限目录 / 留言标签）；损坏时返回空数组 */
function parseJsonArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * 权限目录 JSON 的严格解析：
 *   - NULL 表示旧库/缺省配置，保持“未限制”兼容语义；
 *   - 非空但损坏或包含非字符串元素表示权限数据损坏，必须“禁止所有”，
 *     不能把损坏值降级为空数组后放开全盘访问。
 */
function parseAllowedFolders(raw: string | null): string[] {
  if (raw === null) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== 'string')) return ['__deny__'];
    return sanitizeAllowedFolders(parsed);
  } catch {
    return ['__deny__'];
  }
}

function sanitizeAllowedFolders(folders: string[]): string[] {
  if (folders.length === 0) return [];
  if (folders.includes('__deny__')) return ['__deny__'];
  const cleaned = folders.map((folder) => folder.trim().replace(/\\/g, '/'));
  const invalid = cleaned.some((folder) => {
    const absolute = folder.startsWith('/') || /^[A-Za-z]:\//.test(folder);
    if (folder === '' || !absolute) return true;
    if (/(^|\/)\.\.?($|\/)/.test(folder)) return true;
    const normalized = path.posix.normalize(folder);
    return normalized === '.' || normalized === '/' || /^[a-z]:\/$/i.test(normalized);
  });
  return invalid ? ['__deny__'] : cleaned;
}

/**
 * 密文判定（users.username / audit_logs 各列共用）：不能只看 v1: 前缀——
 * 明文值恰好以 v1: 开头时会被误判为密文。只有同时满足
 * “v1: 前缀 + 合法 base64 + 长度 ≥ 28（iv12+tag16）”才视为密文。
 */
function looksLikeCipher(s: string): boolean {
  if (!s.startsWith('v1:')) return false;
  try {
    return Buffer.from(s.slice(3), 'base64').length >= 28;
  } catch {
    return false;
  }
}

export class Database {
  private db: DatabaseSync;
  private crypto: FieldCrypto;
  /** 预处理语句缓存：按 SQL 文本复用，避免每次请求重复编译 */
  private stmts = new Map<string, StatementSync>();

  constructor(dbPath: string, crypto: FieldCrypto) {
    mkdirSync(path.dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.crypto = crypto;
    // 网关进程与 dsh 插件进程共享同一个库文件：写锁竞争时等待而不是立刻报错
    this.db.exec('PRAGMA busy_timeout = 5000');
    // WAL 允许网关读请求与插件写入并行，降低双进程共享 SQLite 时的锁竞争。
    // 运行时检测结果由 health/启动日志暴露，若文件系统不支持则保留 SQLite 默认模式。
    try {
      this.db.exec('PRAGMA journal_mode = WAL');
    } catch {
      // 某些只读/特殊挂载环境不支持 WAL，不阻断启动。
    }
  }

  private stmt(sql: string): StatementSync {
    let s = this.stmts.get(sql);
    if (!s) {
      s = this.db.prepare(sql);
      this.stmts.set(sql, s);
    }
    return s;
  }

  /** 显式释放 SQLite 文件句柄（测试/一次性工具使用；常驻服务由进程退出回收）。 */
  close(): void {
    this.stmts.clear();
    this.db.close();
  }

  /** 建表（幂等）+ 旧明文数据一次性迁移为密文 */
  init(): void {
    // 删除内容清零，防止已删除的明文残留在空闲页可被文件扫描恢复
    this.db.exec('PRAGMA secure_delete = ON');
    this.db.exec(SCHEMA);
    this.migrateRoles();
    this.migratePermissions();
    const changedUsers = this.migrateUsers();
    const changedAudit = this.migrateAuditLogs();
    const changedAttempts = this.migrateLoginAttempts();
    const changed = changedUsers || changedAudit || changedAttempts;
    // 密文比明文长：UPDATE 会写新页，旧页上的明文留在空闲页里。
    // VACUUM 重写整个文件，彻底清除可被 raw 扫描恢复的残留明文。
    // 用 platform_settings 标记确保每个库只执行一次（旧库即使本次
    // 迁移无变化也会补一次 VACUUM）。
    const vacuumed = this.getSetting('enc_migrated_v1') === '1';
    if (changed || !vacuumed) {
      this.db.exec('VACUUM');
      this.setSetting('enc_migrated_v1', '1');
    }
  }

  // ── 迁移：role / credential_version 列补齐 + 首个用户升级为主用户 ──
  private migrateRoles(): void {
    const cols = this.stmt('PRAGMA table_info(users)').all() as { name: string }[];
    if (!cols.some((c) => c.name === 'role')) {
      this.db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'");
    }
    if (!cols.some((c) => c.name === 'credential_version')) {
      this.db.exec('ALTER TABLE users ADD COLUMN credential_version INTEGER NOT NULL DEFAULT 0');
    }
    // 若库中还没有主用户（老数据迁移/异常状态），把最早创建的账号提为主用户；
    // 其余账号保持子用户角色。判断只看 role 字段，与账号叫什么名字无关。
    const hasAdmin = this.stmt("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get();
    if (!hasAdmin) {
      this.db.exec("UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)");
    }
  }

  // ── 迁移：user_permissions 补 sandbox_mode / disabled_sessions 列 ─────────────────
  private migratePermissions(): void {
    const cols = this.stmt('PRAGMA table_info(user_permissions)').all() as { name: string }[];
    if (!cols.some((c) => c.name === 'allow_upload')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN allow_upload INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some((c) => c.name === 'allow_git_download')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN allow_git_download INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some((c) => c.name === 'sandbox_mode')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN sandbox_mode TEXT');
    }
    if (!cols.some((c) => c.name === 'disabled_sessions')) {
      this.db.exec("ALTER TABLE user_permissions ADD COLUMN disabled_sessions TEXT NOT NULL DEFAULT '[]'");
    }
    if (!cols.some((c) => c.name === 'allow_workspace_create')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN allow_workspace_create INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some((c) => c.name === 'allow_ssh')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN allow_ssh INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.some((c) => c.name === 'allowed_websocket_paths')) {
      this.db.exec("ALTER TABLE user_permissions ADD COLUMN allowed_websocket_paths TEXT NOT NULL DEFAULT '[]'");
    }
    if (!cols.some((c) => c.name === 'allowed_agent_presets')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN allowed_agent_presets TEXT');
    }
    // Issue #19：显式会话授权上线前的旧数据迁移标记。字段缺失=未初始化；
    // 已初始化的用户不会因后续新会话自动加入授权。
    if (!cols.some((c) => c.name === 'session_grants_seeded')) {
      this.db.exec('ALTER TABLE user_permissions ADD COLUMN session_grants_seeded INTEGER NOT NULL DEFAULT 0');
    }
  }

  // ── 迁移：users.username 明文 → 密文 + username_hash ──────────
  private migrateUsers(): boolean {
    const cols = this.stmt('PRAGMA table_info(users)').all() as { name: string }[];
    if (!cols.some((c) => c.name === 'username_hash')) {
      this.db.exec('ALTER TABLE users ADD COLUMN username_hash TEXT');
    }
    // 索引必须在列存在之后创建（旧库无此列时不能在建表阶段引用它）
    this.db.exec(
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_hash ON users(username_hash) WHERE username_hash IS NOT NULL',
    );
    const rows = this.stmt('SELECT id, username, username_hash FROM users').all() as {
      id: number;
      username: string;
      username_hash: string | null;
    }[];
    const upd = this.stmt('UPDATE users SET username = ?, username_hash = ? WHERE id = ?');
    let changed = false;
    for (const row of rows) {
      // 密文判定与 users 表同口径（looksLikeCipher）；
      // 明文恰好以 v1: 开头但不满足密文形态的（如伪造 UA）也会被加密。
      const isCipher = looksLikeCipher(row.username);
      let plain: string | null = null;
      if (isCipher) {
        const decrypted = this.crypto.decrypt(row.username);
        // 解密失败返回 '⟨无法解密⟩' 占位符：跳过该行并告警，
        // 绝不能把占位符当明文加密写回（否则原始密文被覆盖，数据永久丢失）
        if (decrypted === '⟨无法解密⟩') {
          console.error(`[dsh-passwords] 迁移跳过用户 id=${row.id}：username 解密失败（密钥不匹配或数据损坏）`);
          continue;
        }
        plain = decrypted;
      } else {
        plain = row.username;
      }
      if (!isCipher || !row.username_hash) {
        this.db.exec('BEGIN');
        try {
          upd.run(this.crypto.encrypt(plain!), this.crypto.lookupHash(plain!), row.id);
          this.db.exec('COMMIT');
          changed = true;
        } catch (error) {
          this.db.exec('ROLLBACK');
          throw error;
        }
      }
    }
    return changed;
  }

  // ── 迁移：audit_logs 敏感列明文 → 密文 ─────────────────────────
  private migrateAuditLogs(): boolean {
    const rows = this.stmt('SELECT id, username, ip, user_agent, detail FROM audit_logs').all() as {
      id: number;
      username: string | null;
      ip: string | null;
      user_agent: string | null;
      detail: string | null;
    }[];
    const upd = this.stmt(
      'UPDATE audit_logs SET username = ?, ip = ?, user_agent = ?, detail = ? WHERE id = ?',
    );
    let changed = false;
    for (const row of rows) {
      // 与 users 表同口径的密文判定：v1: 前缀 + 合法 base64 + 长度足够才视为已加密，
      // 否则按明文加密写回（明文恰好以 v1: 开头也不会残留）
      const encIfNeeded = (v: string | null) =>
        v !== null && !looksLikeCipher(v) ? this.crypto.encrypt(v) : v;
      const username = encIfNeeded(row.username);
      const ip = encIfNeeded(row.ip);
      const userAgent = encIfNeeded(row.user_agent);
      const detail = encIfNeeded(row.detail);
      if (username !== row.username || ip !== row.ip || userAgent !== row.user_agent || detail !== row.detail) {
        this.db.exec('BEGIN');
        try {
          upd.run(username, ip, userAgent, detail, row.id);
          this.db.exec('COMMIT');
          changed = true;
        } catch (error) {
          this.db.exec('ROLLBACK');
          throw error;
        }
      }
    }
    return changed;
  }

  // ── 迁移：login_attempts 明文 username/ip → HMAC 散列 ─────────
  private migrateLoginAttempts(): boolean {
    const cols = this.stmt('PRAGMA table_info(login_attempts)').all() as { name: string }[];
    if (cols.some((c) => c.name === 'username_hash')) return false; // 已迁移
    const rows = this.stmt(
      'SELECT username, ip, failed_count, locked_until, updated_at FROM login_attempts',
    ).all() as {
      username: string;
      ip: string | null;
      failed_count: number;
      locked_until: string | null;
      updated_at: string;
    }[];
    this.db.exec('BEGIN');
    try {
      this.db.exec(`
        CREATE TABLE login_attempts_new (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          username_hash TEXT NOT NULL,
          ip_hash       TEXT NOT NULL,
          failed_count INTEGER NOT NULL DEFAULT 0,
          locked_until TEXT,
          updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
          UNIQUE(username_hash, ip_hash)
        );
      `);
      const ins = this.stmt(
        'INSERT INTO login_attempts_new (username_hash, ip_hash, failed_count, locked_until, updated_at) VALUES (?, ?, ?, ?, ?)',
      );
      for (const row of rows) {
        ins.run(
          this.crypto.lookupHash(row.username),
          this.crypto.lookupHash(row.ip ?? ''),
          Number(row.failed_count),
          row.locked_until,
          row.updated_at,
        );
      }
      this.db.exec('DROP TABLE login_attempts');
      this.db.exec('ALTER TABLE login_attempts_new RENAME TO login_attempts');
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  async health(): Promise<boolean> {
    try {
      this.stmt('SELECT 1').get();
      return true;
    } catch {
      return false;
    }
  }

  getUserByUsername(username: string): UserRow | null {
    const hash = this.crypto.lookupHash(username);
    const row = this.stmt(
      'SELECT id, username, password_hash, role, credential_version, created_at, last_login_at FROM users WHERE username_hash = ?',
    ).get(hash) as Omit<UserRow, 'username'> & { username: string } | undefined;
    if (!row) return null;
    return { ...row, username: this.crypto.decrypt(row.username) ?? username };
  }

  getUserById(id: number): UserRow | null {
    const row = this.stmt(
      'SELECT id, username, password_hash, role, credential_version, created_at, last_login_at FROM users WHERE id = ?',
    ).get(id) as Omit<UserRow, 'username'> & { username: string } | undefined;
    if (!row) return null;
    return { ...row, username: this.crypto.decrypt(row.username) ?? '' };
  }

  /**
   * 单用户的安全投影（不含 password_hash / credential_version），
   * 供外部接口返回“自己”行时使用（F-10：state 接口不得泄露 bcrypt 哈希）。
   */
  getUserListRowById(id: number): UserListRow | null {
    const row = this.stmt(
      'SELECT id, username, role, created_at, last_login_at FROM users WHERE id = ?',
    ).get(id) as (Omit<UserListRow, 'username'> & { username: string }) | undefined;
    if (!row) return null;
    return {
      id: row.id,
      username: this.crypto.decrypt(row.username) ?? '',
      role: row.role === 'admin' ? 'admin' : 'user',
      created_at: row.created_at,
      last_login_at: row.last_login_at,
    };
  }

  /** 用户列表（用户名已解密），按创建顺序 */
  listUsers(): UserListRow[] {
    const rows = this.stmt(
      'SELECT id, username, role, created_at, last_login_at FROM users ORDER BY id ASC',
    ).all() as (Omit<UserListRow, 'username'> & { username: string })[];
    return rows.map((row) => ({
      id: row.id,
      username: this.crypto.decrypt(row.username) ?? '',
      role: row.role === 'admin' ? 'admin' : 'user',
      created_at: row.created_at,
      last_login_at: row.last_login_at,
    }));
  }

  /**
   * 与某用户有消息往来的其他用户（F-05：子用户的 state 接口只暴露这些人，
   * 避免全量用户目录泄露给低权限账号）。含主动/被动双向：我是发件人或收件人。
   */
  listMessageContacts(userId: number): UserListRow[] {
    const rows = this.stmt(
      `SELECT DISTINCT u.id, u.username, u.role, u.created_at, u.last_login_at
       FROM messages m
       JOIN users u ON u.id = m.sender_id OR u.id = m.recipient_id
       WHERE (m.sender_id = ? OR m.recipient_id = ?) AND u.id != ?`,
    ).all(userId, userId, userId) as (Omit<UserListRow, 'username'> & { username: string })[];
    return rows.map((row) => ({
      id: row.id,
      username: this.crypto.decrypt(row.username) ?? '',
      role: row.role === 'admin' ? 'admin' : 'user',
      created_at: row.created_at,
      last_login_at: row.last_login_at,
    }));
  }

  countUsers(): number {
    const row = this.stmt('SELECT COUNT(*) AS n FROM users').get() as { n: number };
    return Number(row?.n ?? 0);
  }

  createUser(username: string, passwordHash: string, role: UserRole = 'user'): UserRow {
    const result = this.stmt(
      'INSERT INTO users (username, username_hash, password_hash, role) VALUES (?, ?, ?, ?)',
    ).run(this.crypto.encrypt(username), this.crypto.lookupHash(username), passwordHash, role);
    return {
      id: Number(result.lastInsertRowid),
      username,
      password_hash: passwordHash,
      role,
      credential_version: 0,
      created_at: new Date().toISOString(),
      last_login_at: null,
    };
  }

  /** 原子地创建首个主用户；并发 setup 时仅一个调用能成功。 */
  setupInitialAdmin(username: string, passwordHash: string): UserRow | null {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.countUsers() > 0) {
        this.db.exec('COMMIT');
        return null;
      }
      const user = this.createUser(username, passwordHash, 'admin');
      this.setSetting('installed_at', new Date().toISOString());
      this.db.exec('COMMIT');
      return user;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  /** 改名（用户名密文 + 等值索引一起更新；同时 bump credential_version 使旧会话全部失效） */
  updateUsername(id: number, username: string): void {
    this.stmt('UPDATE users SET username = ?, username_hash = ?, credential_version = credential_version + 1 WHERE id = ?').run(
      this.crypto.encrypt(username),
      this.crypto.lookupHash(username),
      id,
    );
  }

  /** 改密：credential_version +1，旧会话（签入时版本号）立即失效 */
  updatePasswordHash(id: number, passwordHash: string): void {
    this.stmt(
      'UPDATE users SET password_hash = ?, credential_version = credential_version + 1 WHERE id = ?',
    ).run(passwordHash, id);
  }

  deleteUser(id: number): void {
    // 无外键约束（SQLite 未开 FK），关联行需手动级联清理：
    // 权限、用量、留言（发件人/收件人）以及登录失败记录。
    const user = this.getUserById(id);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (user) {
        this.stmt('DELETE FROM login_attempts WHERE username_hash = ?').run(this.crypto.lookupHash(user.username));
      }

      this.stmt('DELETE FROM user_permissions WHERE user_id = ?').run(id);
      this.stmt('DELETE FROM ssh_host_owners WHERE user_id = ?').run(id);
      this.stmt('DELETE FROM user_session_grants WHERE user_id = ?').run(id);
      this.stmt('DELETE FROM user_usage WHERE user_id = ?').run(id);
      this.stmt('DELETE FROM messages WHERE sender_id = ? OR recipient_id = ?').run(id, id);
      this.stmt('DELETE FROM users WHERE id = ?').run(id);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  touchLogin(userId: number): void {
    this.stmt("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(userId);
  }

  /** 登录失败锁定清理目标也同步抹掉（删除用户时调用） */
  clearLoginAttemptsOf(username: string): void {
    this.stmt('DELETE FROM login_attempts WHERE username_hash = ?').run(
      this.crypto.lookupHash(username),
    );
  }

  getSetting(key: string): string | null {
    const row = this.stmt('SELECT v FROM platform_settings WHERE k = ?').get(key) as
      | { v: string }
      | undefined;
    return row ? String(row.v) : null;
  }

  setSetting(key: string, value: string): void {
    this.stmt(
      'INSERT INTO platform_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
    ).run(key, value);
  }

  // ── 网络安全审查：审计日志（敏感字段静态加密） ────────────────
  /** 审计写入计数：每 500 条修剪一次最旧记录（上限保护，防长期运行/攻击刷爆磁盘） */
  private auditInsertCount = 0;
  private static readonly AUDIT_MAX_ROWS = 50_000;
  private static readonly AUDIT_PRUNE_EVERY = 500;

  audit(
    eventType: string,
    opts: { username?: string | null; ip?: string | null; userAgent?: string | null; detail?: string | null } = {},
  ): void {
    try {
      this.stmt(
        'INSERT INTO audit_logs (event_type, username, ip, user_agent, detail) VALUES (?, ?, ?, ?, ?)',
      ).run(
        eventType,
        this.crypto.encrypt(opts.username ?? null),
        this.crypto.encrypt(opts.ip ?? null),
        this.crypto.encrypt(opts.userAgent ?? null),
        this.crypto.encrypt(opts.detail ?? null),
      );
      this.auditInsertCount++;
      if (this.auditInsertCount % Database.AUDIT_PRUNE_EVERY === 0) {
        try {
          this.stmt('DELETE FROM audit_logs WHERE id <= (SELECT MAX(id) - ? FROM audit_logs)').run(
            Database.AUDIT_MAX_ROWS,
          );
        } catch (error) {
          // 修剪失败（磁盘满/数据库锁）：记录告警——表会持续增长，不能静默
          console.warn('[dsh-passwords] 审计日志修剪失败（表可能持续增长）:', String(error));
        }
      }
    } catch {
      // 审计写入失败不阻断主流程
    }
  }

  listAuditLogs(limit = 30): AuditLogRow[] {
    const rows = this.stmt(
      'SELECT id, event_type, username, ip, user_agent, detail, created_at FROM audit_logs ORDER BY id DESC LIMIT ?',
    ).all(Math.min(Math.max(limit, 1), 100)) as unknown as AuditLogRow[];
    return rows.map((row) => ({
      ...row,
      username: this.crypto.decrypt(row.username),
      ip: this.crypto.decrypt(row.ip),
      user_agent: this.crypto.decrypt(row.user_agent),
      detail: this.crypto.decrypt(row.detail),
    }));
  }

  // ── 网络安全审查：防暴力破解（仅存 HMAC 散列，不含明文） ────────
  getLoginAttempt(username: string, ip: string): { failed_count: number; locked_until: Date | null } | null {
    const row = this.stmt(
      'SELECT failed_count, locked_until FROM login_attempts WHERE username_hash = ? AND ip_hash = ?',
    ).get(this.crypto.lookupHash(username), this.crypto.lookupHash(ip)) as
      | { failed_count: number; locked_until: string | null }
      | undefined;
    return row
      ? { failed_count: Number(row.failed_count), locked_until: row.locked_until ? new Date(row.locked_until) : null }
      : null;
  }

  recordLoginFailure(username: string, ip: string): number {
    this.stmt(
      `INSERT INTO login_attempts (username_hash, ip_hash, failed_count, updated_at) VALUES (?, ?, 1, datetime('now'))
       ON CONFLICT(username_hash, ip_hash) DO UPDATE SET
         failed_count = failed_count + 1,
         updated_at = datetime('now')`,
    ).run(this.crypto.lookupHash(username), this.crypto.lookupHash(ip));
    return this.getLoginAttempt(username, ip)?.failed_count ?? 1;
  }

  /** 该用户名在所有 IP 上的总失败次数（防分布式爆破：轮换 IP 绕过单 (user,ip) 锁定） */
  countFailuresByUsername(username: string): number {
    const row = this.stmt(
      'SELECT COALESCE(SUM(failed_count), 0) AS n FROM login_attempts WHERE username_hash = ?',
    ).get(this.crypto.lookupHash(username)) as { n: number } | undefined;
    return Number(row?.n ?? 0);
  }

  /** 锁定该用户名在所有 IP 上的失败记录（分布式爆破兜底） */
  lockAllAttemptsByUsername(username: string, until: Date): void {
    this.stmt("UPDATE login_attempts SET locked_until = ?, updated_at = datetime('now') WHERE username_hash = ?").run(
      until.toISOString(),
      this.crypto.lookupHash(username),
    );
  }

  lockLoginAttempt(username: string, ip: string, until: Date): void {
    this.stmt(
      `INSERT INTO login_attempts (username_hash, ip_hash, failed_count, locked_until, updated_at) VALUES (?, ?, 0, ?, datetime('now'))
       ON CONFLICT(username_hash, ip_hash) DO UPDATE SET
         locked_until = excluded.locked_until,
         updated_at = datetime('now')`,
    ).run(this.crypto.lookupHash(username), this.crypto.lookupHash(ip), until.toISOString());
  }

  resetLoginAttempts(username: string, ip: string): void {
    this.stmt('DELETE FROM login_attempts WHERE username_hash = ? AND ip_hash = ?').run(
      this.crypto.lookupHash(username),
      this.crypto.lookupHash(ip),
    );
  }

  // ── 网络安全审查：IP 级节流（防密码喷洒：单 IP 轮换多用户名） ─────
  getIpThrottle(ip: string): { failed_count: number; window_started: Date; throttled_until: Date | null } | null {
    const row = this.stmt(
      'SELECT failed_count, window_started, throttled_until FROM ip_throttle WHERE ip_hash = ?',
    ).get(this.crypto.lookupHash(ip)) as
      | { failed_count: number; window_started: string; throttled_until: string | null }
      | undefined;
    return row
      ? {
          failed_count: Number(row.failed_count),
          window_started: new Date(row.window_started),
          throttled_until: row.throttled_until ? new Date(row.throttled_until) : null,
        }
      : null;
  }

  /**
   * 记录该 IP 的一次登录失败（跨用户名累计）。窗口过期或上次节流已到期时
   * 重置计数，避免被误伤用户“试一次又续 30 分钟”。返回窗口内累计失败数。
   */
  recordIpFailure(ip: string, windowMs: number): number {
    const now = new Date();
    const hash = this.crypto.lookupHash(ip);
    const existing = this.getIpThrottle(ip);
    if (!existing) {
      this.stmt("INSERT INTO ip_throttle (ip_hash, failed_count, window_started, updated_at) VALUES (?, 1, ?, datetime('now'))").run(
        hash,
        now.toISOString(),
      );
      return 1;
    }
    const windowExpired = now.getTime() - existing.window_started.getTime() > windowMs;
    const throttleExpired = existing.throttled_until !== null && existing.throttled_until.getTime() <= now.getTime();
    if (windowExpired || throttleExpired) {
      this.stmt(
        "UPDATE ip_throttle SET failed_count = 1, window_started = ?, throttled_until = NULL, updated_at = datetime('now') WHERE ip_hash = ?",
      ).run(now.toISOString(), hash);
      return 1;
    }
    this.stmt("UPDATE ip_throttle SET failed_count = failed_count + 1, updated_at = datetime('now') WHERE ip_hash = ?").run(hash);
    return existing.failed_count + 1;
  }

  /** 节流该 IP：窗口内失败达阈值后设置过期时间（期间拒绝一切登录尝试） */
  throttleIp(ip: string, until: Date): void {
    this.stmt('UPDATE ip_throttle SET throttled_until = ?, updated_at = datetime(\'now\') WHERE ip_hash = ?').run(
      until.toISOString(),
      this.crypto.lookupHash(ip),
    );
  }

  /** 登录成功后清除该 IP 的节流记录（正常用户不再受限） */
  resetIpThrottle(ip: string): void {
    this.stmt('DELETE FROM ip_throttle WHERE ip_hash = ?').run(this.crypto.lookupHash(ip));
  }

  // ── 子用户权限（网关强制执行） ────────────────────────────
  getPermissions(userId: number): UserPermissionsRow | null {
    const row = this.stmt(
      'SELECT user_id, allowed_folders, hourly_token_limit, daily_minutes_limit, allow_upload, allow_git_download, allow_workspace_create, allow_ssh, allowed_websocket_paths, allowed_agent_presets, banned, sandbox_mode, disabled_sessions, updated_at FROM user_permissions WHERE user_id = ?',
    ).get(userId) as
      | {
          user_id: number;
          allowed_folders: string | null;
          hourly_token_limit: number | null;
          daily_minutes_limit: number | null;
          allow_upload: number;
          allow_git_download: number;
          allow_workspace_create: number;
          allow_ssh: number;
          allowed_websocket_paths: string | null;
          allowed_agent_presets: string | null;
          banned: number;
          sandbox_mode: string | null;
          disabled_sessions: string | null;
          updated_at: string;
        }
      | undefined;
    if (!row) return null;
    return {
      user_id: row.user_id,
      allowed_folders: parseAllowedFolders(row.allowed_folders),
      hourly_token_limit: row.hourly_token_limit,
      daily_minutes_limit: row.daily_minutes_limit,
      allow_upload: row.allow_upload === 1,
      allow_git_download: row.allow_git_download === 1,
      allow_workspace_create: row.allow_workspace_create === 1,
      allow_ssh: row.allow_ssh === 1,
      allowed_websocket_paths: parseJsonArray(row.allowed_websocket_paths),
      allowed_agent_presets: row.allowed_agent_presets === null ? null : parseJsonArray(row.allowed_agent_presets),
      banned: row.banned === 1,
      sandbox_mode: row.sandbox_mode,
      disabled_sessions: parseJsonArray(row.disabled_sessions),
      updated_at: row.updated_at,
    };
  }

  setPermissions(
    userId: number,
    perms: {
      allowedFolders: string[];
      hourlyTokenLimit: number | null;
      dailyMinutesLimit: number | null;
      allowUpload: boolean;
      allowGitDownload: boolean;
      allowWorkspaceCreate: boolean;
      allowSsh?: boolean;
      allowedWebSocketPaths?: string[];
      allowedAgentPresets?: string[] | null;
      banned: boolean;
      sandboxMode?: string | null;
      disabledSessions?: string[];
      allowedSessionIds?: string[];
    },
  ): void {
    // 防御性清洗：空串/当前目录/根目录条目在 folderAllowed 里语义=全盘允许
    // （fail-open 陷阱）——网关端点已拒绝，数据层再兑底一次。
    const allowedFolders = sanitizeAllowedFolders(perms.allowedFolders);
    const current = this.getPermissions(userId);
    const disabledSessions = [...new Set(
      (perms.disabledSessions ?? current?.disabled_sessions ?? [])
        .filter((id) => typeof id === 'string' && id.length > 0 && id.length <= 200),
    )].slice(0, 2000);
    const sandboxMode = perms.sandboxMode === undefined ? current?.sandbox_mode ?? null : perms.sandboxMode;
    const allowedWebSocketPaths = [...new Set(
      (perms.allowedWebSocketPaths ?? current?.allowed_websocket_paths ?? [])
        .filter((path) => typeof path === 'string' && path.length > 0 && path.length <= 256),
    )].slice(0, 64);
    const allowedSessionIds = [...new Set(
      (perms.allowedSessionIds ?? []).filter((id) => typeof id === 'string' && id.length > 0 && id.length <= 200),
    )].slice(0, 2000);
    const allowSsh = perms.allowSsh ?? current?.allow_ssh ?? false;
    const allowedAgentPresets = perms.allowedAgentPresets === undefined
      ? current?.allowed_agent_presets ?? null
      : perms.allowedAgentPresets === null
        ? null
        : [...new Set(perms.allowedAgentPresets.filter((id) => typeof id === 'string' && id.length > 0 && id.length <= 200))].slice(0, 256);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.stmt(
      `INSERT INTO user_permissions (user_id, allowed_folders, hourly_token_limit, daily_minutes_limit, allow_upload, allow_git_download, allow_workspace_create, allow_ssh, allowed_websocket_paths, allowed_agent_presets, banned, sandbox_mode, disabled_sessions)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         allowed_folders = excluded.allowed_folders,
         hourly_token_limit = excluded.hourly_token_limit,
         daily_minutes_limit = excluded.daily_minutes_limit,
         allow_upload = excluded.allow_upload,
         allow_git_download = excluded.allow_git_download,
         allow_workspace_create = excluded.allow_workspace_create,
         allow_ssh = excluded.allow_ssh,
         allowed_websocket_paths = excluded.allowed_websocket_paths,
         allowed_agent_presets = excluded.allowed_agent_presets,
         banned = excluded.banned,
         sandbox_mode = excluded.sandbox_mode,
         disabled_sessions = excluded.disabled_sessions,
         updated_at = datetime('now')`,
    ).run(
      userId,
      JSON.stringify(allowedFolders),
      perms.hourlyTokenLimit,
      perms.dailyMinutesLimit,
      perms.allowUpload ? 1 : 0,
      perms.allowGitDownload ? 1 : 0,
      perms.allowWorkspaceCreate ? 1 : 0,
      allowSsh ? 1 : 0,
      JSON.stringify(allowedWebSocketPaths),
      allowedAgentPresets === null ? null : JSON.stringify(allowedAgentPresets),
      perms.banned ? 1 : 0,
      sandboxMode,
      JSON.stringify(disabledSessions),
      );
      if (perms.allowedSessionIds !== undefined) {
        this.stmt('DELETE FROM user_session_grants WHERE user_id = ?').run(userId);
        const insertGrant = this.stmt('INSERT INTO user_session_grants (user_id, session_id) VALUES (?, ?)');
        for (const sessionId of allowedSessionIds) insertGrant.run(userId, sessionId);
      }
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  // ── SSH host alias 归属 ─────────────────────────
  /** 未登记的 alias 属于历史/管理员全局配置，不自动对外共享。 */
  getSshHostOwner(alias: string): number | null {
    const row = this.stmt('SELECT user_id FROM ssh_host_owners WHERE alias = ?').get(alias) as { user_id: number } | undefined;
    return row?.user_id ?? null;
  }

  listSshHostAliases(userId: number): string[] {
    return (this.stmt('SELECT alias FROM ssh_host_owners WHERE user_id = ? ORDER BY alias').all(userId) as { alias: string }[]).map((row) => row.alias);
  }

  claimSshHost(alias: string, userId: number): boolean {
    if (typeof alias !== 'string' || alias.length === 0 || alias.length > 256) return false;
    this.stmt('INSERT OR IGNORE INTO ssh_host_owners (alias, user_id) VALUES (?, ?)').run(alias, userId);
    return this.getSshHostOwner(alias) === userId;
  }

  releaseSshHost(alias: string, userId: number): void {
    this.stmt('DELETE FROM ssh_host_owners WHERE alias = ? AND user_id = ?').run(alias, userId);
  }

  // ── 子用户显式会话授权 ──────────────────────────
  /** 读取用户已被管理员明确授予的会话 ID；空数组表示未授予任何会话。 */
  listUserSessionGrants(userId: number): string[] {
    return (
      this.stmt('SELECT session_id FROM user_session_grants WHERE user_id = ? ORDER BY session_id').all(userId) as {
        session_id: string;
      }[]
    ).map((row) => row.session_id);
  }

  /** Issue #19 旧数据迁移标记：该用户的显式会话授权是否已初始化。
   *  未初始化时，网关会在其首次 workspace.list 成功后种子化可见既有会话。 */
  isSessionGrantsSeeded(userId: number): boolean {
    const row = this.stmt('SELECT session_grants_seeded FROM user_permissions WHERE user_id = ?').get(userId) as {
      session_grants_seeded: number;
    } | undefined;
    return row?.session_grants_seeded === 1;
  }

  markSessionGrantsSeeded(userId: number): void {
    this.stmt(
      "UPDATE user_permissions SET session_grants_seeded = 1, updated_at = datetime('now') WHERE user_id = ?",
    ).run(userId);
  }

  hasUserSessionGrant(userId: number, sessionId: string): boolean {
    if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 200) return false;
    return this.stmt('SELECT 1 FROM user_session_grants WHERE user_id = ? AND session_id = ?').get(userId, sessionId) !== undefined;
  }

  /** 原子替换一个用户的全部显式会话授权；任何异常都会保留原集合。 */
  replaceUserSessionGrants(userId: number, sessionIds: string[]): void {
    const normalized = [...new Set(
      sessionIds.filter((id): id is string => typeof id === 'string' && id.length > 0 && id.length <= 200),
    )].slice(0, 2000);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.stmt('DELETE FROM user_session_grants WHERE user_id = ?').run(userId);
      const insert = this.stmt('INSERT INTO user_session_grants (user_id, session_id) VALUES (?, ?)');
      for (const sessionId of normalized) insert.run(userId, sessionId);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  // ── 子用户创建的工作区 ─────────────────────────
  addUserWorkspace(userId: number, workspacePath: string): void {
    this.stmt(
      'INSERT OR IGNORE INTO user_workspaces (user_id, path) VALUES (?, ?)',
    ).run(userId, normalizePath(workspacePath));
  }

  addAllowedFolder(userId: number, workspacePath: string): void {
    const canonical = normalizePath(workspacePath);
    const current = this.getPermissions(userId);
    if (!current || current.allowed_folders.includes('__deny__')) {
      if (current) this.setPermissions(userId, { allowedFolders: [canonical], hourlyTokenLimit: current.hourly_token_limit, dailyMinutesLimit: current.daily_minutes_limit, allowUpload: current.allow_upload, allowGitDownload: current.allow_git_download, allowWorkspaceCreate: current.allow_workspace_create, allowedWebSocketPaths: current.allowed_websocket_paths, banned: current.banned, sandboxMode: current.sandbox_mode, disabledSessions: current.disabled_sessions });
      return;
    }
    if (!current.allowed_folders.some((entry) => normalizePath(entry) === canonical)) {
      this.setPermissions(userId, { allowedFolders: [...current.allowed_folders, canonical], hourlyTokenLimit: current.hourly_token_limit, dailyMinutesLimit: current.daily_minutes_limit, allowUpload: current.allow_upload, allowGitDownload: current.allow_git_download, allowWorkspaceCreate: current.allow_workspace_create, allowedWebSocketPaths: current.allowed_websocket_paths, banned: current.banned, sandboxMode: current.sandbox_mode, disabledSessions: current.disabled_sessions });
    }
  }

  listUserWorkspacePaths(userId: number): string[] {
    return (this.stmt('SELECT path FROM user_workspaces WHERE user_id = ?').all(userId) as { path: string }[]).map((row) => row.path);
  }

  listWorkspaceOwners(): Array<{ userId: number; path: string }> {
    return (this.stmt('SELECT user_id AS userId, path FROM user_workspaces').all() as Array<{ userId: number; path: string }>).map((row) => ({ ...row, path: normalizePath(row.path) }));
  }

  removeUserWorkspace(userId: number, workspacePath: string): void {
    this.stmt('DELETE FROM user_workspaces WHERE user_id = ? AND path = ?').run(userId, normalizePath(workspacePath));
  }

  renameUserWorkspace(userId: number, oldPath: string, newPath: string): void {
    this.stmt('UPDATE user_workspaces SET path = ? WHERE user_id = ? AND path = ?').run(normalizePath(newPath), userId, normalizePath(oldPath));
  }

  // ── 用户用量（时间 / token 配额） ─────────────────────────
  getUsage(userId: number, day: string): UsageRow | null {
    const row = this.stmt(
      'SELECT user_id, day, first_seen_at, last_active_at, active_seconds, hourly_window_start, hourly_tokens FROM user_usage WHERE user_id = ? AND day = ?',
    ).get(userId, day) as UsageRow | undefined;
    return row ?? null;
  }

  /**
   * 记录活跃时间：从 last_active_at 起累计活跃跨度。
   * 网关 15 秒节流一次 touch；为覆盖节流间隙与网络抖动，单次最多累计 30 秒
   * （封顶语义：防止页面挂机把时长无限拉长；配合节流，正常连续使用误差很小）。
   */
  touchUsage(userId: number, day: string, nowIso: string): UsageRow {
    const existing = this.getUsage(userId, day);
    if (!existing) {
      this.stmt(
        'INSERT INTO user_usage (user_id, day, first_seen_at, last_active_at, active_seconds, hourly_window_start, hourly_tokens) VALUES (?, ?, ?, ?, 0, ?, 0)',
      ).run(userId, day, nowIso, nowIso, nowIso);
      return this.getUsage(userId, day)!;
    }
    let delta = 0;
    if (existing.last_active_at) {
      const last = new Date(existing.last_active_at).getTime();
      const now = new Date(nowIso).getTime();
      if (now > last) {
        delta = Math.round(Math.min((now - last) / 1000, 30));
      }
    }
    this.stmt(
      'UPDATE user_usage SET last_active_at = ?, active_seconds = active_seconds + ? WHERE user_id = ? AND day = ?',
    ).run(nowIso, delta, userId, day);
    return this.getUsage(userId, day)!;
  }

  /** 累计 token 用量（小时窗口起点不在当前窗口时自动重置计数） */
  addTokens(userId: number, day: string, tokens: number, nowIso: string): UsageRow {
    const existing = this.getUsage(userId, day);
    if (!existing) {
      this.stmt(
        'INSERT INTO user_usage (user_id, day, first_seen_at, last_active_at, active_seconds, hourly_window_start, hourly_tokens) VALUES (?, ?, ?, ?, 0, ?, ?)',
      ).run(userId, day, nowIso, nowIso, nowIso, tokens);
      return this.getUsage(userId, day)!;
    }
    const windowStart = existing.hourly_window_start ?? nowIso;
    const windowAge = new Date(nowIso).getTime() - new Date(windowStart).getTime();
    if (windowAge >= 3600_000) {
      this.stmt(
        'UPDATE user_usage SET hourly_window_start = ?, hourly_tokens = ? WHERE user_id = ? AND day = ?',
      ).run(nowIso, tokens, userId, day);
    } else {
      this.stmt('UPDATE user_usage SET hourly_tokens = hourly_tokens + ? WHERE user_id = ? AND day = ?').run(
        tokens,
        userId,
        day,
      );
    }
    return this.getUsage(userId, day)!;
  }

  /**
   * 重置用户用量（主用户改配额时调用）：删除该用户全部 user_usage 记录，
   * 下次使用从零重新计时/计数——"改配额 = 重新给额度"。
   */
  resetUsage(userId: number): void {
    this.stmt('DELETE FROM user_usage WHERE user_id = ?').run(userId);
  }

  // ── 留言 / 聊天 ───────────────────────────────────────────
  // ⚠ 多租户可见性必须在 SQL 层先过滤再 LIMIT：旧实现先全局 LIMIT 300 再到
  // 网关里按接收人过滤，其他用户的私信会堵住当前用户的增量拉取（复现：A 游标 1，
  // 之后 300 条他人私信占满窗口，A 的新消息 id 排在 300 条之后永远取不到）；
  // 且“全局最大 id”还会泄露全平台消息活动量，并让 reset 判断失真。
  // 可见性口径：广播（recipient_id NULL）∨ 发给我的 ∨ 我发的。
  private static readonly MESSAGE_VISIBILITY_SQL =
    '(m.recipient_id IS NULL OR m.recipient_id = ? OR m.sender_id = ?)';

  listMessagesForUser(userId: number, limit = 100): MessageRow[] {
    return this.mapMessageRows(
      this.stmt(
        `SELECT m.id, m.sender_id, u.username, m.recipient_id, m.content, m.tags, m.created_at
       FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE ${Database.MESSAGE_VISIBILITY_SQL}
       ORDER BY m.id DESC LIMIT ?`,
      ).all(userId, userId, Math.min(Math.max(limit, 1), 500)),
    );
  }

  /** 增量拉取：只返回 id > sinceId 且当前用户可见的消息（升序），供客户端轮询避免全量下载 */
  listMessagesAfterForUser(userId: number, sinceId: number, limit = 300): MessageRow[] {
    return this.mapMessageRows(
      this.stmt(
        `SELECT m.id, m.sender_id, u.username, m.recipient_id, m.content, m.tags, m.created_at
       FROM messages m JOIN users u ON u.id = m.sender_id
       WHERE ${Database.MESSAGE_VISIBILITY_SQL} AND m.id > ?
       ORDER BY m.id ASC LIMIT ?`,
      ).all(userId, userId, sinceId, Math.min(Math.max(limit, 1), 500)),
    );
  }

  /** 当前用户可见的最大消息 id（无可见消息时 null）——增量接口用：
   *  since 超过它即游标已失效（DB 重建），按用户口径避免泄露全局消息活动量 */
  latestMessageIdForUser(userId: number): number | null {
    const row = this.stmt(
      `SELECT MAX(m.id) AS n FROM messages m WHERE ${Database.MESSAGE_VISIBILITY_SQL}`,
    ).get(userId, userId) as { n: number | null } | undefined;
    return row?.n === null || row?.n === undefined ? null : Number(row.n);
  }

  private mapMessageRows(
    rows: unknown,
  ): MessageRow[] {
    return (rows as {
      id: number;
      sender_id: number;
      username: string;
      recipient_id: number | null;
      content: string;
      tags: string;
      created_at: string;
    }[]).map((row) => ({
      id: row.id,
      sender_id: row.sender_id,
      sender_name: this.crypto.decrypt(row.username) ?? '',
      recipient_id: row.recipient_id,
      content: row.content,
      tags: parseJsonArray(row.tags),
      created_at: row.created_at,
    }));
  }

  /** 留言写入计数：每 100 条修剪一次最旧记录（留言表长期运行也会无限增长） */
  private messageInsertCount = 0;
  private static readonly MESSAGES_MAX_ROWS = 2_000;
  private static readonly MESSAGES_PRUNE_EVERY = 100;

  addMessage(senderId: number, recipientId: number | null, content: string, tags: string[]): MessageRow {
    const result = this.stmt('INSERT INTO messages (sender_id, recipient_id, content, tags) VALUES (?, ?, ?, ?)').run(
      senderId,
      recipientId,
      content,
      JSON.stringify(tags),
    );
    this.messageInsertCount++;
    if (this.messageInsertCount % Database.MESSAGES_PRUNE_EVERY === 0) {
      try {
        this.stmt('DELETE FROM messages WHERE id <= (SELECT MAX(id) - ? FROM messages)').run(
          Database.MESSAGES_MAX_ROWS,
        );
      } catch (error) {
        // 修剪失败（磁盘满/数据库锁）：记录告警——留言表会持续增长，不能静默
        console.warn('[dsh-passwords] 留言修剪失败（表可能持续增长）:', String(error));
      }
    }
    const sender = this.getUserById(senderId);
    return {
      id: Number(result.lastInsertRowid),
      sender_id: senderId,
      sender_name: sender?.username ?? '',
      recipient_id: recipientId,
      content,
      tags,
      created_at: new Date().toISOString(),
    };
  }


  /** 平台主用户 id（首个 admin）；平台必有主用户，缺失说明数据损坏 */
  findAdminId(): number | null {
    const row = this.stmt("SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1").get() as
      | { id: number }
      | undefined;
    return row ? Number(row.id) : null;
  }


  /** 登录失败/节流表修剪：防随机用户名+轮换 IP 喷洒让表无界增长 */
  pruneStaleSecurityRows(days = 7): void {
    const cutoff = `-${Math.max(days, 1)} days`;
    this.stmt("DELETE FROM login_attempts WHERE updated_at < datetime('now', ?)").run(cutoff);
    this.stmt("DELETE FROM ip_throttle WHERE updated_at < datetime('now', ?)").run(cutoff);
  }

}
