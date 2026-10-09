import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { Database, pathWithinDeletedTree, PermissionStateConflictError, SessionGrantsConflictError } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';

test('pathWithinDeletedTree：多层不存在子路径仍遵循文件系统大小写语义', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-case-path-'));
  const owner = path.join(tempDir, 'Owned');
  const caseAlias = path.join(tempDir, 'owned');
  mkdirSync(owner);
  try {
    let caseInsensitiveVolume = false;
    try {
      caseInsensitiveVolume = realpathSync(caseAlias).toLowerCase() === realpathSync(owner).toLowerCase();
    } catch {
      caseInsensitiveVolume = false;
    }

    const candidate = path.join(caseAlias, 'missing', 'deep', 'secret.txt');
    assert.equal(
      pathWithinDeletedTree(candidate, owner),
      caseInsensitiveVolume,
      'canonicalization must resolve the nearest existing ancestor before restoring missing path segments',
    );
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('Issue #19：显式会话 grant 原子持久化、隔离且拒绝非法 ID', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-session-grants-'));
  const dbPath = path.join(tempDir, 'grants.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    const first = db.createUser('first-user', '$2a$10$dummyhashdummyhashdummyhashdu');
    const second = db.createUser('second-user', '$2a$10$dummyhashdummyhashdummyhashdu');

    db.replaceUserSessionGrants(first.id, ['s-one', 's-one', '', 'x'.repeat(201), 's-two']);
    assert.deepEqual(db.listUserSessionGrants(first.id), ['s-one', 's-two']);
    assert.equal(db.hasUserSessionGrant(first.id, 's-one'), true);
    assert.equal(db.hasUserSessionGrant(second.id, 's-one'), false, '授权不得跨用户泄露');

    db.replaceUserSessionGrants(first.id, ['s-three']);
    assert.deepEqual(db.listUserSessionGrants(first.id), ['s-three'], '替换必须移除旧授权');
    db.close();

    const reopened = new Database(dbPath, crypto);
    try {
      reopened.init();
      assert.deepEqual(reopened.listUserSessionGrants(first.id), ['s-three'], '重启后授权必须持久化');
    } finally {
      reopened.close();
    }
  } finally {
    try { db.close(); } catch { /* already closed for reopen assertion */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('SSH alias 归属读写 API 已退役（表仅为旧库迁移保留）', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-ssh-owner-'));
  const dbPath = path.join(tempDir, 'owners.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    // 退役后不得再暴露逐 alias 归属读写能力（改由主用户登记的端点表统一管）
    assert.equal(typeof (db as unknown as Record<string, unknown>).claimSshHost, 'undefined');
    assert.equal(typeof (db as unknown as Record<string, unknown>).getSshHostOwner, 'undefined');
    assert.equal(typeof (db as unknown as Record<string, unknown>).listSshHostAliases, 'undefined');
    assert.equal(typeof (db as unknown as Record<string, unknown>).releaseSshHost, 'undefined');
  } finally {
    try { db.close(); } catch { /* already closed */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('极旧 user_permissions 表缺少上传与 git 列时会补齐并默认关闭', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-db-legacy-upload-'));
  const dbPath = path.join(tempDir, 'legacy-upload.db');
  const raw = new DatabaseSync(dbPath);
  raw.exec(`
    CREATE TABLE user_permissions (
      user_id INTEGER PRIMARY KEY,
      allowed_folders TEXT,
      hourly_token_limit INTEGER,
      daily_minutes_limit INTEGER,
      banned INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO user_permissions (user_id, allowed_folders) VALUES (7, '["/srv/project"]');
  `);
  raw.close();

  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const migrated = db.getPermissions(7);
    assert.equal(migrated?.allow_upload, false);
    assert.equal(migrated?.allow_git_download, false);
    assert.equal(migrated?.allow_ssh, false);
  } finally {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('旧 user_permissions 表会迁移缺失列，并保留现有权限', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-db-'));
  const dbPath = path.join(tempDir, 'legacy.db');
  const raw = new DatabaseSync(dbPath);
  raw.exec(`
    CREATE TABLE user_permissions (
      user_id INTEGER PRIMARY KEY,
      allowed_folders TEXT,
      hourly_token_limit INTEGER,
      daily_minutes_limit INTEGER,
      allow_upload INTEGER NOT NULL DEFAULT 1,
      allow_git_download INTEGER NOT NULL DEFAULT 0,
      banned INTEGER NOT NULL DEFAULT 0,
      sandbox_mode TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO user_permissions
      (user_id, allowed_folders, hourly_token_limit, daily_minutes_limit, allow_upload, allow_git_download, banned, sandbox_mode)
    VALUES (7, '["/srv/project"]', 10, 20, 1, 1, 0, 'workspace-write');
  `);
  raw.close();

  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const migrated = db.getPermissions(7);
    assert.deepEqual(migrated, {
      user_id: 7,
      allowed_folders: ['/srv/project'],
      hourly_token_limit: 10,
      daily_minutes_limit: 20,
      allow_upload: true,
      allow_git_download: true,
      allow_workspace_create: false,
      allow_ssh: false,
      allowed_agent_presets: null,
      allowed_models: null,
      allow_chat_media: false,
      banned: false,
      sandbox_mode: 'workspace-write',
      disabled_sessions: [],
      updated_at: migrated?.updated_at,
    });

    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      allowedAgentPresets: ['system/default'],
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    assert.deepEqual(db.getPermissions(7)?.allowed_agent_presets, ['system/default']);
    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      allowedAgentPresets: null,
      banned: false,
      sandboxMode: 'workspace-write',
      disabledSessions: [],
    });
    assert.equal(db.getPermissions(7)?.allowed_agent_presets, null, 'NULL 必须保留不限制的兼容语义');

    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      banned: false,
    });
    assert.equal(db.getPermissions(7)?.sandbox_mode, 'workspace-write', '省略 sandboxMode 不得清除既有策略');
    assert.deepEqual(db.getPermissions(7)?.disabled_sessions, [], '省略 disabledSessions 应保留当前集合');

    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      banned: false,
      disabledSessions: ['disabled-session'],
    });
    db.setPermissions(7, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: 10,
      dailyMinutesLimit: 20,
      allowUpload: true,
      allowGitDownload: true,
      allowWorkspaceCreate: false,
      banned: false,
    });
    assert.deepEqual(db.getPermissions(7)?.disabled_sessions, ['disabled-session'], '省略 disabledSessions 不得恢复被禁用会话');
  } finally {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
});



test('删除用户级联清理工作区所有权；启动迁移清除孤儿所有权行', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-orphan-ownership-'));
  const dbPath = path.join(tempDir, 'orphan.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    const gone = db.createUser('gone-user', '$2a$10$dummyhashdummyhashdummyhashdu');
    const keeper = db.createUser('keeper-user', '$2a$10$dummyhashdummyhashdummyhashdu');
    db.addUserWorkspace(gone.id, '/srv/gone-ws');
    db.addUserWorkspace(keeper.id, '/srv/keeper-ws');
    db.replaceUserSessionGrants(gone.id, ['s-gone']);
    db.setPermissions(gone.id, {
      allowedFolders: ['/srv/gone-ws'], hourlyTokenLimit: null, dailyMinutesLimit: null,
      allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
      banned: false, sandboxMode: null, disabledSessions: [],
    });

    // deleteUser 必须带走所有权/授权/权限行：残留会被当作「另一子用户的所有权」
    // 阻断 baseline 可见性与该目录的登记/创建（112233 事故根因）。
    db.deleteUser(gone.id);
    assert.deepEqual(db.listWorkspaceOwners().map((o) => o.path), ['/srv/keeper-ws'], '删除用户必须级联清理其所有权行');
    assert.deepEqual(db.listUserSessionGrants(gone.id), []);
    assert.equal(db.getPermissions(gone.id), null);

    // 历史残留（旧版 deleteUser 未清理）由 init() 迁移幂等清除；权限/授权行
    // 不在迁移清理范围（旧库可能先导权限行后建用户，不能误删）。
    (db as unknown as { db: DatabaseSync }).db.exec(
      "INSERT INTO user_workspaces (user_id, path) VALUES (9999, '/srv/legacy-orphan')",
    );
    (db as unknown as { db: DatabaseSync }).db.exec(
      "INSERT INTO user_session_grants (user_id, session_id) VALUES (9999, 's-orphan')",
    );
    db.close();
    const reopened = new Database(dbPath, crypto);
    try {
      reopened.init();
      assert.deepEqual(
        reopened.listWorkspaceOwners().map((o) => o.path).sort(),
        ['/srv/keeper-ws'],
        'init 迁移必须清除已删除用户残留的所有权行',
      );
      assert.deepEqual(
        reopened.listUserSessionGrants(9999),
        ['s-orphan'],
        '迁移不得误删孤儿授权行（无害且可能来自旧库分步导入）',
      );
    } finally {
      reopened.close();
    }
  } finally {
    try { db.close(); } catch { /* 用例内已关闭并重开 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

const GRANT_CAS_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';

/** 会话授权写入的基线校验：管理员草稿读取之后子用户 session/create 追加的 grant
 *  绝不能被 DELETE+INSERT 覆盖；冲突必须整体回滚（含同一事务里的其它权限字段）。 */
test('Issue #25：会话授权基线不匹配时原子拒绝，不覆盖并发新增 grant', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-cas-'));
  const dbPath = path.join(tempDir, 'cas.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  const base = {
    allowedFolders: ['/srv/project'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
  };
  try {
    db.init();
    const user = db.createUser('grant-cas-user', GRANT_CAS_HASH);
    db.setPermissions(user.id, { ...base, allowedSessionIds: ['s-one'] });
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-one']);

    // 管理员持有旧草稿期间，子用户 session/create 并发追加了一个 grant
    db.replaceUserSessionGrants(user.id, ['s-one', 's-concurrent']);

    assert.throws(
      () => db.setPermissions(user.id, {
        ...base,
        allowedFolders: ['/srv/other'],
        allowedSessionIds: ['s-one'],
        expectedAllowedSessionIds: ['s-one'],
      }),
      (error: unknown) => error instanceof SessionGrantsConflictError,
      '基线不匹配必须抛出具名冲突错误',
    );
    assert.deepEqual(
      db.listUserSessionGrants(user.id),
      ['s-concurrent', 's-one'],
      '冲突必须保留并发新增的 grant',
    );
    assert.deepEqual(
      db.getPermissions(user.id)?.allowed_folders,
      ['/srv/project'],
      '冲突必须回滚整个事务，不能落下部分权限改动',
    );

    // 基线一致（或调用方未声明基线）时才允许替换
    db.setPermissions(user.id, {
      ...base,
      allowedSessionIds: ['s-one'],
      expectedAllowedSessionIds: ['s-one', 's-concurrent'],
    });
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-one'], '基线一致时替换必须生效');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/** 禁用会话写入的基线校验：旧权限草稿不能恢复并发新增的禁用项。 */
test('权限行并发修改时整笔保存回滚，不恢复已撤销的 SSH 权限', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-permission-cas-'));
  const db = new Database(path.join(tempDir, 'permissions.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('permission-cas-user', GRANT_CAS_HASH);
    const base = {
      allowedFolders: ['/srv/project'], hourlyTokenLimit: 100, dailyMinutesLimit: null,
      allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
      allowSsh: true, banned: false, sandboxMode: null,
    };
    db.setPermissions(user.id, base);
    const stale = db.getPermissions(user.id);
    assert.ok(stale);
    db.setPermissions(user.id, { ...base, allowSsh: false });
    assert.throws(() => db.setPermissions(user.id, {
      ...base, allowedFolders: ['/srv/changed'], expectedPermissionState: stale,
    }), (error: unknown) => error instanceof PermissionStateConflictError);
    assert.equal(db.getPermissions(user.id)?.allow_ssh, false);
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/project']);
    db.setPermissions(user.id, {
      ...base, allowSsh: false, allowedFolders: ['/srv/changed'], expectedPermissionState: db.getPermissions(user.id),
    });
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/changed']);
  } finally {
    try { db.close(); } catch { /* already closed */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('Issue #25：禁用会话基线不匹配时原子拒绝，不恢复并发禁用变更', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-disabled-cas-'));
  const dbPath = path.join(tempDir, 'disabled-cas.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  const base = {
    allowedFolders: ['/srv/project'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
  };
  try {
    db.init();
    const user = db.createUser('disabled-cas-user', GRANT_CAS_HASH);
    db.setPermissions(user.id, { ...base, disabledSessions: ['s-one'] });
    db.setPermissions(user.id, { ...base, disabledSessions: ['s-one', 's-two'] });

    assert.throws(
      () => db.setPermissions(user.id, {
        ...base,
        allowedFolders: ['/srv/other'],
        disabledSessions: ['s-one'],
        expectedDisabledSessions: ['s-one'],
      }),
      (error: unknown) => error instanceof SessionGrantsConflictError && error.scope === 'disabled_sessions',
      '禁用会话基线不匹配必须抛出带 scope 的具名冲突错误',
    );
    assert.deepEqual(db.getPermissions(user.id)?.disabled_sessions, ['s-one', 's-two']);
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/project'], '冲突必须回滚其它权限字段');

    db.setPermissions(user.id, {
      ...base,
      disabledSessions: ['s-one'],
      expectedDisabledSessions: ['s-one', 's-two'],
    });
    assert.deepEqual(db.getPermissions(user.id)?.disabled_sessions, ['s-one'], '基线一致时替换必须生效');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/** 沙盒收紧后的回收只删除被撤销的 ID：请求 `await` 期间并发追加的 grant 不得被整表替换抹掉。 */
test('Issue #25：显式会话授权和迁移标记在同一权限事务提交', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-seeded-'));
  const dbPath = path.join(tempDir, 'seeded.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('grant-seeded-user', GRANT_CAS_HASH);
    db.setPermissions(user.id, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: null,
      dailyMinutesLimit: null,
      allowUpload: false,
      allowGitDownload: false,
      allowWorkspaceCreate: false,
      banned: false,
      sandboxMode: null,
      disabledSessions: [],
      allowedSessionIds: ['s-one'],
      sessionGrantsSeeded: true,
    });
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-one']);
    assert.equal(db.isSessionGrantsSeeded(user.id), true, '提交显式 grant 时必须同步阻止旧数据种子覆盖');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/** 沙盒收紧后的回收只删除被撤销的 ID：请求 `await` 期间并发追加的 grant 不得被整表替换抹掉。 */
test('Issue #25：按 ID 回收 grant 不影响其它并发授权', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-delete-'));
  const dbPath = path.join(tempDir, 'delete.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    const user = db.createUser('grant-delete-user', GRANT_CAS_HASH);
    db.replaceUserSessionGrants(user.id, ['s-one', 's-two']);

    db.deleteUserSessionGrants(user.id, ['s-one', 'not-granted', '', 'x'.repeat(201)]);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-two'], '只删除显式给出的已授权 ID');

    db.deleteUserSessionGrants(user.id, []);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-two'], '空集合必须是无副作用的 no-op');

    db.deleteUserSessionGrants(user.id, ['s-two']);
    assert.deepEqual(db.listUserSessionGrants(user.id), []);
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * 追加式授权（最小原子 API）：只新增一条，不重写整表，因此与 replaceUserSessionGrants
 * 的「整表替换」语义必须保持可区分；重复追加幂等，非法 ID 无副作用。
 */
test('追加会话授权：单条 OR IGNORE 追加、重复幂等、非法 ID 无副作用', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-add-'));
  const dbPath = path.join(tempDir, 'grant-add.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  try {
    db.init();
    const user = db.createUser('grant-add-user', GRANT_CAS_HASH);
    const other = db.createUser('grant-add-other', GRANT_CAS_HASH);

    assert.equal(db.addUserSessionGrant(user.id, 's-one'), true, '首次追加必须报告新增');
    assert.equal(db.addUserSessionGrant(user.id, 's-two'), true);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-one', 's-two'], '追加不得影响已有授权');
    assert.equal(db.hasUserSessionGrant(other.id, 's-two'), false, '追加不得跨用户泄露');

    assert.equal(db.addUserSessionGrant(user.id, 's-one'), false, '重复追加必须是幂等 no-op');
    assert.equal(db.addUserSessionGrant(user.id, 's-two'), false);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-one', 's-two'], '重复追加不得改变集合');

    // 整表替换仍是显式操作：替换后才不会有旧授权残留
    db.replaceUserSessionGrants(user.id, ['s-three']);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-three'], '整表替换语义必须保留');
    assert.equal(db.addUserSessionGrant(user.id, 's-four'), true);
    // listUserSessionGrants 按 session_id 升序返回
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-four', 's-three']);

    assert.equal(db.addUserSessionGrant(user.id, ''), false, '空串不是合法会话 ID');
    assert.equal(db.addUserSessionGrant(user.id, 'x'.repeat(201)), false, '超长 ID 必须被拒绝');
    assert.equal(db.addUserSessionGrant(user.id, 123 as unknown as string), false, '非字符串必须被拒绝');
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-four', 's-three'], '非法 ID 必须无副作用');

    db.close();
    const reopened = new Database(dbPath, crypto);
    try {
      reopened.init();
      assert.deepEqual(reopened.listUserSessionGrants(user.id), ['s-four', 's-three'], '追加必须持久化');
    } finally {
      reopened.close();
    }
  } finally {
    try { db.close(); } catch { /* 重开后已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * Issue #19 旧数据种子化：首次 OR IGNORE 追加并置于同一持写锁事务里置位标记，
 * 之后（标记已置位）整体 no-op。种子集合外的既有授权、迁移期间并发追加的授权
 * 都不得被抹掉（禁止 DELETE+INSERT）。
 */
test('seedUserSessionGrants：首次 OR IGNORE 追加并置位，已 seed 后 no-op', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-seed-'));
  const dbPath = path.join(tempDir, 'grant-seed.db');
  const crypto = createFieldCrypto('test-key', 'test-key');
  const db = new Database(dbPath, crypto);
  const base = {
    allowedFolders: ['/srv/project'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    banned: false,
    sandboxMode: null,
    disabledSessions: [],
  };
  try {
    db.init();
    const user = db.createUser('grant-seed-user', GRANT_CAS_HASH);
    // 管理员已显式授权 s-admin（同时创建了种子化标记要落在上面的权限行）
    db.setPermissions(user.id, { ...base, allowedSessionIds: ['s-admin'] });
    assert.equal(db.isSessionGrantsSeeded(user.id), false, '显式整表授权不等于完成旧数据种子化');

    // 种子集合不含 s-admin，且自身有重复项与非法项：既不删既有授权，也不写入非法 ID
    assert.equal(db.seedUserSessionGrants(user.id, ['s-visible', 's-visible', '', 'x'.repeat(201)]), true);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-admin', 's-visible'], '种子化必须追加而非整表替换');
    assert.equal(db.isSessionGrantsSeeded(user.id), true, '种子化必须与授权同事务置位迁移标记');

    // 已 seed：整体 no-op，种子集合之外新出现的会话不得再被自动授权
    assert.equal(db.seedUserSessionGrants(user.id, ['s-later']), false);
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-admin', 's-visible']);

    // 幂等：迁移期间并发追加的授权也不会被后续 seed 调用抹掉
    db.addUserSessionGrant(user.id, 's-concurrent');
    assert.equal(db.seedUserSessionGrants(user.id, ['s-visible']), false);
    assert.equal(db.seedUserSessionGrants(user.id, []), false, '空集合在已 seed 后同样是 no-op');
    assert.deepEqual(db.listUserSessionGrants(user.id), ['s-admin', 's-concurrent', 's-visible']);

    // 无会话可迁移也属于「完成种子化」：置位后不再自动授权
    const emptyUser = db.createUser('grant-seed-empty-user', GRANT_CAS_HASH);
    db.setPermissions(emptyUser.id, { ...base, allowedSessionIds: [] });
    assert.equal(db.seedUserSessionGrants(emptyUser.id, ['', 'x'.repeat(201)]), true);
    assert.deepEqual(db.listUserSessionGrants(emptyUser.id), []);
    assert.equal(db.isSessionGrantsSeeded(emptyUser.id), true);
    assert.equal(db.seedUserSessionGrants(emptyUser.id, ['s-visible']), false, '置位后不得再追加');
    assert.deepEqual(db.listUserSessionGrants(emptyUser.id), []);

    db.close();
    const reopened = new Database(dbPath, crypto);
    try {
      reopened.init();
      assert.equal(reopened.isSessionGrantsSeeded(user.id), true, '迁移标记必须持久化');
      assert.deepEqual(
        reopened.listUserSessionGrants(user.id),
        ['s-admin', 's-concurrent', 's-visible'],
        '种子化结果必须持久化',
      );
    } finally {
      reopened.close();
    }
  } finally {
    try { db.close(); } catch { /* 重开后已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * 缺 user_permissions 行的用户默认拒绝全部目录：种子化不得隐式补出权限行
 * （补出来的行 allowed_folders 为 NULL，读取侧按「空白名单 = 不限目录」解释，
 * 等于借迁移放大权限），也不得只写一半授权。
 */
test('seedUserSessionGrants：缺权限行时 fail-closed 整体 no-op，不补权限行', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-grant-seed-norow-'));
  const dbPath = path.join(tempDir, 'grant-seed-norow.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('grant-seed-norow-user', GRANT_CAS_HASH);
    assert.equal(db.getPermissions(user.id), null, '前置条件：该用户没有权限行');

    assert.equal(db.seedUserSessionGrants(user.id, ['s-visible']), false);
    assert.deepEqual(db.listUserSessionGrants(user.id), [], '无法置位时不得留下部分写入的授权');
    assert.equal(db.getPermissions(user.id), null, '不得隐式创建权限行（会把 deny-all 放大为不限目录）');
    assert.equal(db.isSessionGrantsSeeded(user.id), false);

    // 反复调用保持同一 no-op，不累积状态
    assert.equal(db.seedUserSessionGrants(user.id, ['s-visible', 's-later']), false);
    assert.deepEqual(db.listUserSessionGrants(user.id), []);
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * addAllowedFolder 是 workspace/create 成功回调里的读-改-写：旧实现先
 * getPermissions() 读整行，再 setPermissions() 把 hourly/daily 限额、allow_*、
 * banned、sandbox_mode、disabled_sessions 用读到的旧值整体回写。调用方在读取
 * 与写入之间会 await 上游，这段时间里并发收紧的安全字段会被旧快照静默回滚。
 * 修复后只改 allowed_folders 一列，其余字段完全不动。
 */
test('addAllowedFolder：原子窄更新只改白名单，保留并发改写的安全字段', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-add-folder-race-'));
  const dbPath = path.join(tempDir, 'add-folder-race.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('add-folder-race-user', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
    const base = {
      allowedFolders: ['/workspaces/a'], hourlyTokenLimit: 100, dailyMinutesLimit: 60,
      allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: true, allowSsh: true,
      allowedAgentPresets: ['preset-a'], allowedModels: ['provider/model-a'], allowChatMedia: true,
      banned: false, sandboxMode: 'workspace-write', disabledSessions: ['sess-a'],
    } as const;
    db.setPermissions(user.id, { ...base, allowedFolders: [...base.allowedFolders] });

    // 读取旧快照 … 随后并发收紧安全字段（模拟 await 期间的另一次权限保存）。
    const stale = db.getPermissions(user.id)!;
    db.setPermissions(user.id, {
      ...base, allowedFolders: [...base.allowedFolders],
      allowUpload: false, allowGitDownload: false, banned: true,
      sandboxMode: 'read-only', disabledSessions: ['sess-b'], allowChatMedia: false,
    });

    // 把读到的旧快照固定在 getPermissions 上：窄更新不得依赖也不得回放它。
    const realGetPermissions = db.getPermissions.bind(db);
    (db as unknown as { getPermissions: typeof realGetPermissions }).getPermissions = () => stale;
    try {
      db.addAllowedFolder(user.id, '/workspaces/b');
    } finally {
      (db as unknown as { getPermissions: typeof realGetPermissions }).getPermissions = realGetPermissions;
    }

    const after = db.getPermissions(user.id)!;
    assert.deepEqual(after.allowed_folders, ['/workspaces/a', '/workspaces/b']);
    assert.equal(after.allow_upload, false, '并发收紧的 allow_upload 不得被旧快照回滚');
    assert.equal(after.allow_git_download, false, '并发收紧的 allow_git_download 不得被回滚');
    assert.equal(after.banned, true, '并发封禁不得被回滚');
    assert.equal(after.sandbox_mode, 'read-only', '并发收紧的沙盒不得被回滚');
    assert.deepEqual(after.disabled_sessions, ['sess-b'], '并发改写的中断会话集合不得被回滚');
    assert.equal(after.allow_chat_media, false, '并发关闭的聊天媒体不得被回滚');
    assert.equal(after.hourly_token_limit, 100);
    assert.equal(after.daily_minutes_limit, 60);
    assert.deepEqual(after.allowed_agent_presets, ['preset-a']);
    assert.deepEqual(after.allowed_models, ['provider/model-a']);
    assert.equal(after.allow_workspace_create, true);
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('addAllowedFolder：去重、__deny__ 替换、不限目录与缺权限行 no-op', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-add-folder-semantics-'));
  const dbPath = path.join(tempDir, 'add-folder-semantics.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const perms = (folders: string[]) => ({
      allowedFolders: folders, hourlyTokenLimit: null, dailyMinutesLimit: null,
      allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
      banned: false, sandboxMode: null as string | null, disabledSessions: [] as string[],
    });

    // 去重（含 .. 规范形态）
    const dedupe = db.createUser('add-folder-dedupe', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
    db.setPermissions(dedupe.id, perms(['/workspaces/a']));
    db.addAllowedFolder(dedupe.id, '/workspaces/a');
    db.addAllowedFolder(dedupe.id, '/workspaces/a/../a');
    assert.deepEqual(db.getPermissions(dedupe.id)?.allowed_folders, ['/workspaces/a']);
    db.addAllowedFolder(dedupe.id, '/workspaces/b');
    db.addAllowedFolder(dedupe.id, '/workspaces/b');
    assert.deepEqual(db.getPermissions(dedupe.id)?.allowed_folders, ['/workspaces/a', '/workspaces/b']);

    // __deny__（尚无预分配根）登记后以新目录替换哨兵
    const denied = db.createUser('add-folder-deny', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
    db.setPermissions(denied.id, perms(['__deny__']));
    db.addAllowedFolder(denied.id, '/workspaces/c');
    assert.deepEqual(db.getPermissions(denied.id)?.allowed_folders, ['/workspaces/c']);

    // 空白名单 = 不限目录：登记不得收窄
    const unrestricted = db.createUser('add-folder-unrestricted', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
    db.setPermissions(unrestricted.id, perms([]));
    db.addAllowedFolder(unrestricted.id, '/workspaces/d');
    assert.deepEqual(db.getPermissions(unrestricted.id)?.allowed_folders, []);

    // 缺权限行 = 默认拒绝全部：不得隐式补行
    const noRow = db.createUser('add-folder-norow', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
    db.addAllowedFolder(noRow.id, '/workspaces/e');
    assert.equal(db.getPermissions(noRow.id), null, '缺权限行必须保持 no-op（不补行、不放宽）');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

const OWNED_WS_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';

const ownedWsPerms = (folders: string[]) => ({
  allowedFolders: folders, hourlyTokenLimit: null, dailyMinutesLimit: null,
  allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
  banned: false, sandboxMode: null as string | null, disabledSessions: [] as string[],
});

/**
 * workspace/delete 成功回调的 DB 收口：只回收该用户「自建工作区」对应的精确白名单
 * 条目（自建自动授予与归属行成对出现），管理员分配的父目录/其它目录不得被误删，
 * 同工作区的会话授权一并清理，且绝不波及其它用户。
 */
test('removeUserOwnedWorkspace：清理自建归属/白名单/授权，保留管理员分配与其它用户', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-rm-owned-ws-'));
  const db = new Database(path.join(tempDir, 'rm-owned-ws.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('owned-ws-user', OWNED_WS_HASH, 'user');
    db.setPermissions(user.id, ownedWsPerms(['/srv/admin-root', '/srv/other']));
    // 自建工作区：归属行 + addAllowedFolder 自动并入精确路径。
    db.addUserWorkspace(user.id, '/srv/admin-root/proj');
    db.addAllowedFolder(user.id, '/srv/admin-root/proj');
    db.addUserSessionGrant(user.id, 'sess-proj');
    db.addUserSessionGrant(user.id, 'sess-keep');

    const other = db.createUser('owned-ws-other', OWNED_WS_HASH, 'user');
    db.setPermissions(other.id, ownedWsPerms(['/srv/admin-root/proj']));
    db.addUserWorkspace(other.id, '/srv/admin-root/proj');
    db.addUserSessionGrant(other.id, 'sess-proj');

    const result = db.removeUserOwnedWorkspace(user.id, '/srv/admin-root/proj', ['sess-proj']);
    assert.deepEqual(result, { removedWorkspace: true, removedFolder: true, removedGrants: 1 });
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/admin-root', '/srv/other'],
      '只回收精确相等的自建条目，管理员分配的父目录/其它目录必须保留');
    assert.equal(db.listUserWorkspacePaths(user.id).includes('/srv/admin-root/proj'), false, '归属行应被清理');
    assert.deepEqual(db.listUserSessionGrants(user.id), ['sess-keep'], '只清理明确归属该工作区的授权');

    // 其它用户同路径的归属/白名单/授权不得受影响（清理严格按 user_id 隔离）。
    assert.equal(db.listUserWorkspacePaths(other.id).includes('/srv/admin-root/proj'), true);
    assert.deepEqual(db.getPermissions(other.id)?.allowed_folders, ['/srv/admin-root/proj']);
    assert.deepEqual(db.listUserSessionGrants(other.id), ['sess-proj']);
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('removeUserOwnedWorkspace：删空回落 __deny__；无匹配/不限/哨兵/缺行均 no-op', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-rm-owned-ws-edge-'));
  const db = new Database(path.join(tempDir, 'rm-owned-ws-edge.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();

    // 唯一自建条目被删空：必须回落 __deny__，绝不能留空数组（空 = 不限目录 fail-open）。
    const denyStart = db.createUser('owned-ws-deny-start', OWNED_WS_HASH, 'user');
    db.setPermissions(denyStart.id, ownedWsPerms(['__deny__']));
    db.addUserWorkspace(denyStart.id, '/ws/only');
    db.addAllowedFolder(denyStart.id, '/ws/only');
    assert.equal(db.removeUserOwnedWorkspace(denyStart.id, '/ws/only').removedFolder, true);
    assert.deepEqual(db.getPermissions(denyStart.id)?.allowed_folders, ['__deny__'], '删空必须回落 __deny__');

    // 管理员只分配父目录、无精确自建条目：不匹配任何白名单项，白名单不动。
    const parentOnly = db.createUser('owned-ws-parent-only', OWNED_WS_HASH, 'user');
    db.setPermissions(parentOnly.id, ownedWsPerms(['/srv/parent']));
    db.addUserWorkspace(parentOnly.id, '/srv/parent/x');
    assert.equal(db.removeUserOwnedWorkspace(parentOnly.id, '/srv/parent/x').removedFolder, false);
    assert.deepEqual(db.getPermissions(parentOnly.id)?.allowed_folders, ['/srv/parent'], '管理员分配不得被误删');

    // 空白名单 = 不限目录：登记是 no-op，删除也不得把它收窄成白名单。
    const unrestricted = db.createUser('owned-ws-unrestricted', OWNED_WS_HASH, 'user');
    db.setPermissions(unrestricted.id, ownedWsPerms([]));
    db.addUserWorkspace(unrestricted.id, '/ws/u');
    assert.equal(db.removeUserOwnedWorkspace(unrestricted.id, '/ws/u').removedFolder, false);
    assert.deepEqual(db.getPermissions(unrestricted.id)?.allowed_folders, []);

    // __deny__ 哨兵本身不是可回收项。
    const sentinel = db.createUser('owned-ws-sentinel', OWNED_WS_HASH, 'user');
    db.setPermissions(sentinel.id, ownedWsPerms(['__deny__']));
    db.addUserWorkspace(sentinel.id, '/ws/s');
    assert.equal(db.removeUserOwnedWorkspace(sentinel.id, '/ws/s').removedFolder, false);
    assert.deepEqual(db.getPermissions(sentinel.id)?.allowed_folders, ['__deny__']);

    // 缺权限行：不补行、不抛错（归属行仍按需清理）。
    const noRow = db.createUser('owned-ws-norow', OWNED_WS_HASH, 'user');
    db.addUserWorkspace(noRow.id, '/ws/n');
    const noRowResult = db.removeUserOwnedWorkspace(noRow.id, '/ws/n');
    assert.equal(noRowResult.removedWorkspace, true);
    assert.equal(noRowResult.removedFolder, false);
    assert.equal(db.getPermissions(noRow.id), null, '缺权限行必须保持 no-op（不补行）');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * 来源区分：同一路径既可能是管理员显式分配，也可能是子用户自建自动授予。
 * addAllowedFolder 只在本次真正新增/替换哨兵时写来源标记；若该目录本来就在白名单里
 * （管理员已分配），走「已包含」no-op 不写标记——删除自建工作区时保留管理员分配。
 */
test('removeUserOwnedWorkspace：管理员先分配的同路径条目不被自建登记标记，删除保留', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-rm-owned-ws-admin-'));
  const db = new Database(path.join(tempDir, 'rm-owned-ws-admin.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('owned-ws-admin-exact', OWNED_WS_HASH, 'user');
    db.setPermissions(user.id, ownedWsPerms(['/srv/exact']));
    // 用户把管理员已分配的目录登记为工作区：addAllowedFolder 是 no-op，不写标记。
    db.addUserWorkspace(user.id, '/srv/exact');
    db.addAllowedFolder(user.id, '/srv/exact');
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/exact'],
      '已分配路径不得因自建登记而重复');

    const result = db.removeUserOwnedWorkspace(user.id, '/srv/exact');
    assert.equal(result.removedWorkspace, true);
    assert.equal(result.removedFolder, false, '管理员分配的同路径白名单不得因自建登记被回收');
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/exact'], '管理员分配必须保留');

    // 对照：纯自建（addAllowedFolder 实际新增）会被标记，删除时回收。
    db.addUserWorkspace(user.id, '/srv/self');
    db.addAllowedFolder(user.id, '/srv/self');
    assert.equal(db.removeUserOwnedWorkspace(user.id, '/srv/self').removedFolder, true);
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/exact'], '自建条目被回收，管理员分配保留');
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * 存量升级兼容（fail-closed）：user_auto_granted_folders 随本版本新增，升级前已存在的
 * 自建条目没有来源标记。此时无法可靠区分「自建自动授予」与「管理员显式授权」，删除会
 * 误伤后者的风险不可接受，因此**保留条目**（removedFolder=false）——但这意味着本次不能
 * 宣称已完全回收，残留条目需管理员在权限面板手动清理。
 *
 * 回归意义：若哪天为了“完整回收”而改成无标记也删，本用例会立刻失败，从而阻止一次会
 * 误删管理员显式授权的破坏性变更。
 */
test('removeUserOwnedWorkspace：升级前无来源标记的自建条目一律保留（fail-closed，不误删管理员授权）', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-rm-owned-ws-stock-'));
  const db = new Database(path.join(tempDir, 'rm-owned-ws-stock.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('owned-ws-stock', OWNED_WS_HASH, 'user');
    // 模拟升级前状态：白名单里已有该自建路径、归属行也在，但没有来源标记
    // （不调用 addAllowedFolder，即不会写入 user_auto_granted_folders）。
    db.setPermissions(user.id, ownedWsPerms(['/srv/admin-a', '/srv/legacy-self']));
    db.addUserWorkspace(user.id, '/srv/legacy-self');

    const result = db.removeUserOwnedWorkspace(user.id, '/srv/legacy-self', ['sess-legacy']);
    assert.equal(result.removedWorkspace, true, '归属行仍按精确路径清理');
    assert.equal(result.removedFolder, false, '无标记无法区分来源：不得回收白名单条目');
    assert.deepEqual(
      db.getPermissions(user.id)?.allowed_folders,
      ['/srv/admin-a', '/srv/legacy-self'],
      '无标记条目必须原样保留，绝不误删管理员显式授权',
    );
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

/**
 * 先自建自动标记，后管理员重新显式分配同路径，再 workspace/delete 的行为锁定。
 *
 * 策略（显式 fail-closed，非静默）：来源标记只表示“该条起源于自建”，一旦存在就按自建
 * 回收（拒绝访问）。不能因为有管理员重新保存过就反向放行一条可能过期的标记；管理员需在
 * 删除后重新分配。测试同时验证：回收后管理员重新分配是持久的——再次删除时因标记已清、
 * 且路径本就在（管理员）白名单里而保留，不会二次被回收。
 */
test('removeUserOwnedWorkspace：自建后管理员重分配同路径仍 fail-closed 回收；其后重分配持久', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-rm-owned-ws-reassign-'));
  const db = new Database(path.join(tempDir, 'rm-owned-ws-reassign.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const user = db.createUser('owned-ws-reassign', OWNED_WS_HASH, 'user');

    // 1) 自建：__deny__ 起点 → addAllowedFolder 实际新增，写入来源标记。
    db.setPermissions(user.id, ownedWsPerms(['__deny__']));
    db.addUserWorkspace(user.id, '/srv/reproj');
    db.addAllowedFolder(user.id, '/srv/reproj');
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/reproj']);

    // 2) 管理员重新显式分配同路径（并新增 /srv/other）。标记不经 setPermissions，仍在。
    db.setPermissions(user.id, ownedWsPerms(['/srv/reproj', '/srv/other']));
    assert.deepEqual(db.getPermissions(user.id)?.allowed_folders, ['/srv/reproj', '/srv/other']);

    // 3) workspace/delete：有标记 → 精确回收该自建条目（fail-closed：拒绝访问）。
    const reclaimed = db.removeUserOwnedWorkspace(user.id, '/srv/reproj');
    assert.equal(reclaimed.removedFolder, true, '标记仍在：按自建来源精确回收，策略为显式 fail-closed');
    assert.deepEqual(
      db.getPermissions(user.id)?.allowed_folders,
      ['/srv/other'],
      '只回收该精确条目，管理员新增的 /srv/other 不受影响',
    );

    // 4) 管理员在删除后重新分配同路径 → 标记已清，重登记不再写标记 → 后续删除保留。
    db.setPermissions(user.id, ownedWsPerms(['/srv/other', '/srv/reproj']));
    db.addUserWorkspace(user.id, '/srv/reproj');
    db.addAllowedFolder(user.id, '/srv/reproj');
    const retained = db.removeUserOwnedWorkspace(user.id, '/srv/reproj');
    assert.equal(retained.removedFolder, false, '重分配后无标记：不再被视为自建条目回收');
    assert.deepEqual(
      db.getPermissions(user.id)?.allowed_folders,
      ['/srv/other', '/srv/reproj'],
      '管理员重新分配必须持久保留',
    );
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

// ── Issue #38：workspaceCreationRoots 已退役：allowed_folders 是唯一创建范围 ─────
//
// 统一目录授权后 DB 不再保留 workspace_creation_roots 列：旧列既不参与判定，也不再
// 暴露给读写模型。创建范围（含可创建位置）完全由 allowed_folders 表达，
// allow_workspace_create 仅作为前置开关。

test('Issue #38：user_permissions 不再含 workspace_creation_roots 列，读模型也不暴露该字段', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-issue38-retired-'));
  const db = new Database(path.join(tempDir, 'perms.db'), createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const columns = (db as unknown as { db: DatabaseSync }).db
      .prepare('PRAGMA table_info(user_permissions)').all() as Array<{ name: string }>;
    assert.equal(
      columns.some((column) => column.name === 'workspace_creation_roots'),
      false,
      '退役列不得再出现在权限表中',
    );

    const user = db.createUser('issue38-retired', '$2a$10$dummyhashdummyhashdummyhashdu');
    db.setPermissions(user.id, {
      allowedFolders: ['/srv/project'],
      hourlyTokenLimit: null,
      dailyMinutesLimit: null,
      allowUpload: false,
      allowGitDownload: false,
      allowWorkspaceCreate: true,
      banned: false,
      sandboxMode: null,
      disabledSessions: [],
    });
    const perms = db.getPermissions(user.id);
    assert.ok(perms);
    assert.deepEqual(perms.allowed_folders, ['/srv/project'], '创建范围只由 allowed_folders 表达');
    assert.equal(
      Object.prototype.hasOwnProperty.call(perms, 'workspace_creation_roots'),
      false,
      '读模型不得再暴露退役字段',
    );
  } finally {
    try { db.close(); } catch { /* 已关闭 */ }
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('Issue #38：旧表迁移不新增 workspace_creation_roots 列', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-issue38-legacy-'));
  const dbPath = path.join(tempDir, 'legacy.db');
  const raw = new DatabaseSync(dbPath);
  raw.exec(`
    CREATE TABLE user_permissions (
      user_id INTEGER PRIMARY KEY,
      allowed_folders TEXT,
      hourly_token_limit INTEGER,
      daily_minutes_limit INTEGER,
      allow_workspace_create INTEGER NOT NULL DEFAULT 1,
      banned INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    INSERT INTO user_permissions (user_id, allowed_folders, allow_workspace_create) VALUES (7, '["/srv/project"]', 1);
  `);
  raw.close();

  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  try {
    db.init();
    const columns = (db as unknown as { db: DatabaseSync }).db
      .prepare('PRAGMA table_info(user_permissions)').all() as Array<{ name: string }>;
    assert.equal(
      columns.some((column) => column.name === 'workspace_creation_roots'),
      false,
      '迁移不得重建退役列',
    );
    const migrated = db.getPermissions(7);
    assert.equal(migrated?.allow_workspace_create, true, '迁移不得改动既有创建权限');
    assert.deepEqual(migrated?.allowed_folders, ['/srv/project']);
  } finally {
    db.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
});
