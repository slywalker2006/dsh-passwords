import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { normalizePath } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

let appDir: string;
let workspaceDir: string;
let otherWorkspaceDir: string;
let sharedRootDir: string;
let sharedOwnedDir: string;
let sharedForeignDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let gatewayPort = 0;
let adminCookie = '';
let downloadsAllowedCookie = '';
let downloadsDeniedCookie = '';
let bannedCookie = '';
let otherFolderCookie = '';
let sharedOwnerCookie = '';
let sharedPeerCookie = '';
let ordinaryFile = '';
let otherFile = '';
let envFile = '';
let sharedOwnedFile = '';
let sharedForeignFile = '';
let escapeLink: string | null = null;

function request(pathname: string, cookie?: string): Promise<{ status: number; body: Buffer; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port: gatewayPort,
      path: pathname,
      headers: cookie === undefined ? {} : { cookie },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks), headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

function downloadPath(file: string): string {
  return `/gateway/api/download?path=${encodeURIComponent(file)}`;
}

function postJson(pathname: string, cookie: string, body: unknown): Promise<{ status: number; body: Buffer; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1',
      port: gatewayPort,
      path: pathname,
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json', 'content-length': String(payload.length) },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks), headers: res.headers }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

/** 目录选择器返回路径的比较口径：反斜杠归一 + 盘符小写 + 去尾斜杠。 */
function pickerNorm(candidate: string): string {
  return candidate.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (match) => match.toLowerCase()).replace(/\/+$/, '');
}

function directoryPickerPath(dir: string): string {
  return `/gateway/api/directory-picker/list?path=${encodeURIComponent(dir)}`;
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-download-app-'));
  workspaceDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-download-workspace-'));
  otherWorkspaceDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-download-other-'));
  sharedRootDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-download-shared-'));
  sharedOwnedDir = path.join(sharedRootDir, 'owned');
  sharedForeignDir = path.join(sharedRootDir, 'foreign');
  mkdirSync(sharedOwnedDir);
  mkdirSync(sharedForeignDir);
  mkdirSync(path.join(appDir, 'data'));
  ordinaryFile = path.join(workspaceDir, 'generated.md');
  otherFile = path.join(otherWorkspaceDir, 'other.md');
  envFile = path.join(appDir, '.env');
  sharedOwnedFile = path.join(sharedOwnedDir, 'own.md');
  sharedForeignFile = path.join(sharedForeignDir, 'secret.md');
  const candidateEscapeLink = path.join(workspaceDir, 'escape-link');
  writeFileSync(ordinaryFile, 'ordinary workspace content');
  writeFileSync(otherFile, 'outside subuser allowlist');
  writeFileSync(envFile, 'SETUP_KEY=must-not-download');
  writeFileSync(sharedOwnedFile, 'shared owner own content');
  writeFileSync(sharedForeignFile, 'shared peer private content');

  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const allowed = db.createUser('allowed', '$2a$10$dummyhashdummyhashdummyhashdu');
  const denied = db.createUser('denied', '$2a$10$dummyhashdummyhashdummyhashdu');
  const banned = db.createUser('banned', '$2a$10$dummyhashdummyhashdummyhashdu');
  const otherFolder = db.createUser('otherfolder', '$2a$10$dummyhashdummyhashdummyhashdu');
  const sharedOwner = db.createUser('sharedowner', '$2a$10$dummyhashdummyhashdummyhashdu');
  const sharedPeer = db.createUser('sharedpeer', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(allowed.id, {
    allowedFolders: [workspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  db.setPermissions(denied.id, {
    allowedFolders: [workspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  db.setPermissions(banned.id, {
    allowedFolders: [workspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: true, sandboxMode: null,
  });
  db.setPermissions(otherFolder.id, {
    allowedFolders: [otherWorkspaceDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  // 共享父目录场景：两个子用户都被分配同一父目录，但各自在父目录下自建了
  // 私有 workspace 子树。白名单只到父目录，归属由 user_workspaces 行区分。
  for (const user of [sharedOwner, sharedPeer]) {
    db.setPermissions(user.id, {
      allowedFolders: [sharedRootDir], hourlyTokenLimit: null, dailyMinutesLimit: null,
      allowUpload: true, allowGitDownload: true, allowWorkspaceCreate: false,
      banned: false, sandboxMode: null,
    });
  }
  db.addUserWorkspace(sharedOwner.id, sharedOwnedDir);
  db.addUserWorkspace(sharedPeer.id, sharedForeignDir);
  try {
    symlinkSync(dbPath, candidateEscapeLink);
    escapeLink = candidateEscapeLink;
  } catch {
    // Windows symlink creation needs Developer Mode or elevated privileges. The rest
    // of the path guard suite remains valid on constrained test hosts.
  }

  // 权限保存会在 allowedFolders 非空时向上游拉取「可分配资源」清单作为正向权威。
  // 这里返回合法空清单（folders/sessions 皆空），使保存回退到「真实目录」分支，
  // 从而可验证 allowedFolders 的正向校验；其余请求保持空响应。
  upstream = http.createServer((req, res) => {
    if (req.url === '/api/dsh-passwords/internal/assignable-resources') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ ok: true, sessions: [], folders: [], retainedSessions: [] }));
      return;
    }
    res.end();
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;
  const config: PlatformConfig = {
    setupKey: 'test-setup-key', dbPath, dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
    // 选择器浏览根显式限定到夹具所在的临时目录：默认根是 os.homedir()，而 POSIX 的
    // os.tmpdir()（/tmp）不在家目录内，管理员选择器会按设计 fail-closed 回 403。
    directoryPickerRoots: [os.tmpdir()],
  };
  const tokenFor = (user: { id: number; username: string }) =>
    `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  adminCookie = tokenFor(admin);
  downloadsAllowedCookie = tokenFor(allowed);
  downloadsDeniedCookie = tokenFor(denied);
  bannedCookie = tokenFor(banned);
  otherFolderCookie = tokenFor(otherFolder);
  sharedOwnerCookie = tokenFor(sharedOwner);
  sharedPeerCookie = tokenFor(sharedPeer);

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstream?.close();
  for (const dir of [appDir, workspaceDir, otherWorkspaceDir, sharedRootDir]) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows file handles are best-effort. */ }
  }
});

test('Issue #15: admin can download ordinary files outside subuser allowlists', async () => {
  const inside = await request(downloadPath(ordinaryFile), adminCookie);
  assert.equal(inside.status, 200);
  assert.equal(inside.body.toString(), 'ordinary workspace content');
  assert.equal(inside.headers['content-length'], String(Buffer.byteLength('ordinary workspace content')));

  const outside = await request(downloadPath(otherFile), adminCookie);
  assert.equal(outside.status, 200);
  assert.equal(outside.body.toString(), 'outside subuser allowlist');
});

test('Issue #15: admin operational access still cannot download sensitive files or symlink escapes', async () => {
  const sensitiveTargets = [path.join(appDir, 'data', 'test.db'), envFile];
  const externalFile = path.join(otherWorkspaceDir, 'ssh-target');
  const sshHome = path.join(appDir, 'ssh-home');
  const sshDirLink = path.join(sshHome, '.ssh');
  writeFileSync(externalFile, 'external ordinary file');
  mkdirSync(sshHome, { recursive: true });
  try {
    symlinkSync(otherWorkspaceDir, sshDirLink, process.platform === 'win32' ? 'junction' : 'dir');
    sensitiveTargets.push(path.join(sshDirLink, 'ssh-target'));
  } catch {
    // The existing direct sensitive-path checks still run where symlinks are unavailable.
  }
  if (escapeLink !== null) sensitiveTargets.push(escapeLink);
  for (const target of sensitiveTargets) {
    const response = await request(downloadPath(target), adminCookie);
    assert.equal(response.status, 403, `${target} must remain protected`);
  }
});

test('Issue #15: subuser download requires both the download grant and folder allowlist', async () => {
  const allowed = await request(downloadPath(ordinaryFile), downloadsAllowedCookie);
  assert.equal(allowed.status, 200);

  const noDownloadGrant = await request(downloadPath(ordinaryFile), downloadsDeniedCookie);
  assert.equal(noDownloadGrant.status, 403);

  const outsideAllowlist = await request(downloadPath(ordinaryFile), otherFolderCookie);
  assert.equal(outsideAllowlist.status, 403);
});

test('Issue #15: banned subusers cannot use the direct download route', async () => {
  const response = await request(downloadPath(ordinaryFile), bannedCookie);
  assert.equal(response.status, 403);
});

test('Issue #15: download requires an authenticated session and regular file', async () => {
  const unauthenticated = await request(downloadPath(ordinaryFile));
  assert.equal(unauthenticated.status, 401);

  const directory = await request(downloadPath(workspaceDir), adminCookie);
  assert.equal(directory.status, 400);

  const missing = await request(downloadPath(path.join(workspaceDir, 'missing.md')), adminCookie);
  assert.equal(missing.status, 404);
});

// 回归：子用户 A 的 allowed_folders 覆盖共享父目录，但同父目录下 B 自建的
// workspace 子树属于 B。download 路由必须与 /api/file 一样做对象级归属校验，
// 不能因为白名单包含父目录就放行 B 的私有文件。
test('Issue #15: subuser cannot download a peer tenant workspace subtree inside a shared allowlisted parent', async () => {
  const leaked = await request(downloadPath(sharedForeignFile), sharedOwnerCookie);
  assert.equal(leaked.status, 403);
  assert.notEqual(leaked.body.toString(), 'shared peer private content');

  const unauthenticated = await request(downloadPath(sharedForeignFile));
  assert.equal(unauthenticated.status, 401);

  const sensitive = await request(downloadPath(envFile), sharedOwnerCookie);
  assert.equal(sensitive.status, 403);
});

test('Issue #15: peer tenant keeps access to its own workspace and its own allowlisted subtree', async () => {
  const owner = await request(downloadPath(sharedForeignFile), sharedPeerCookie);
  assert.equal(owner.status, 200);
  assert.equal(owner.body.toString(), 'shared peer private content');

  const ownSubtree = await request(downloadPath(sharedOwnedFile), sharedOwnerCookie);
  assert.equal(ownSubtree.status, 200);
  assert.equal(ownSubtree.body.toString(), 'shared owner own content');
});

// ── 管理员目录选择器：为 allowedFolders 浏览可选目录 ──────────────
test('目录选择器：未认证与非主用户一律拒绝，仅主用户可浏览', async () => {
  const unauthenticated = await request('/gateway/api/directory-picker/list');
  assert.equal(unauthenticated.status, 401);
  const subuser = await request('/gateway/api/directory-picker/list', downloadsAllowedCookie);
  assert.equal(subuser.status, 403);
});

test('目录选择器：只列直接子目录、绝不返回文件，并过滤敏感路径与 realpath 敏感子目录', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-')));
  mkdirSync(path.join(root, 'alpha'));
  mkdirSync(path.join(root, 'beta'));
  writeFileSync(path.join(root, 'note.txt'), 'file, not a directory');
  let linkedSensitive = false;
  try {
    // appDir 含 data/test.db，落在敏感基内：指向它的符号链接必须被 realpath 过滤。
    symlinkSync(appDir, path.join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
    linkedSensitive = true;
  } catch {
    // Windows 非管理员可能无法建符号链接；其余断言仍然有效。
  }
  try {
    const response = await request(directoryPickerPath(root), adminCookie);
    assert.equal(response.status, 200, response.body.toString());
    assert.equal(response.headers['cache-control'], 'no-store');
    const payload = JSON.parse(response.body.toString()) as {
      ok: boolean; currentPath: string | null; parentPath: string | null;
      selectable: boolean; truncated: boolean;
      entries: Array<{ name: string; path: string; selectable: boolean }>;
    };
    assert.equal(payload.ok, true);
    assert.equal(payload.currentPath, pickerNorm(root));
    assert.equal(payload.selectable, true, '普通目录可选作创建根');
    assert.equal(payload.truncated, false, '小目录不得标记截断');
    assert.deepEqual(payload.entries.map((entry) => entry.name).sort(), ['alpha', 'beta']);
    assert.ok(!payload.entries.some((entry) => entry.name === 'note.txt'), '不得返回文件名');
    if (linkedSensitive) {
      assert.ok(!payload.entries.some((entry) => entry.name === 'escape'), 'realpath 敏感的符号链接必须过滤');
    }
    for (const entry of payload.entries) {
      assert.equal(entry.selectable, true, '普通子目录可选作创建根');
      assert.equal(entry.path, pickerNorm(path.join(root, entry.name)));
    }
  } finally {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows 文件句柄尽力而为 */ }
  }
});

test('目录选择器：父子导航返回一致的 currentPath/parentPath', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-nav-')));
  const child = path.join(root, 'child');
  mkdirSync(child);
  try {
    const rootResponse = await request(directoryPickerPath(root), adminCookie);
    assert.equal(rootResponse.status, 200, rootResponse.body.toString());
    const rootPayload = JSON.parse(rootResponse.body.toString()) as {
      currentPath: string; parentPath: string | null; selectable: boolean; truncated: boolean;
      entries: Array<{ name: string; path: string; selectable: boolean }>;
    };
    assert.equal(rootPayload.currentPath, pickerNorm(root));
    assert.equal(rootPayload.parentPath, pickerNorm(path.dirname(root)));
    assert.equal(rootPayload.selectable, true);
    assert.equal(rootPayload.truncated, false);
    const childEntry = rootPayload.entries.find((entry) => entry.name === 'child');
    assert.ok(childEntry, 'child 目录必须出现在列表');
    assert.equal(childEntry.path, pickerNorm(child));

    const childResponse = await request(directoryPickerPath(child), adminCookie);
    assert.equal(childResponse.status, 200, childResponse.body.toString());
    const childPayload = JSON.parse(childResponse.body.toString()) as {
      currentPath: string; parentPath: string | null; selectable: boolean; truncated: boolean;
      entries: Array<{ name: string; path: string; selectable: boolean }>;
    };
    assert.equal(childPayload.currentPath, pickerNorm(child));
    assert.equal(childPayload.parentPath, pickerNorm(root));
    assert.equal(childPayload.selectable, true);
    assert.deepEqual(childPayload.entries, []);
  } finally {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows 文件句柄尽力而为 */ }
  }
});

test('目录选择器：相对路径、不存在、非目录与敏感路径 fail-closed', async () => {
  const relative = await request('/gateway/api/directory-picker/list?path=relative/path', adminCookie);
  assert.equal(relative.status, 400);

  const missing = await request(directoryPickerPath(path.join(os.tmpdir(), `dshpw-picker-missing-${Date.now()}`)), adminCookie);
  assert.equal(missing.status, 404);

  const notDirectory = await request(directoryPickerPath(ordinaryFile), adminCookie);
  assert.equal(notDirectory.status, 400);

  const sensitive = await request(directoryPickerPath(appDir), adminCookie);
  assert.equal(sensitive.status, 403);

  if (process.platform === 'win32') {
    // '/foo' 是 root-relative（默认盘）而非 drive-qualified，必须拒绝而不是按当前盘解析。
    const defaultDrive = await request(`/gateway/api/directory-picker/list?path=${encodeURIComponent('/foo')}`, adminCookie);
    assert.equal(defaultDrive.status, 400);
  }
});

test('目录选择器：文件系统根与 Windows 盘符根不可作为创建根', async () => {
  const response = await request('/gateway/api/directory-picker/list', adminCookie);
  assert.equal(response.status, 200, response.body.toString());
  const payload = JSON.parse(response.body.toString()) as {
    currentPath: string | null; parentPath: string | null; selectable: boolean; truncated: boolean;
    rootPaths: string[];
    entries: Array<{ name: string; path: string; selectable: boolean }>;
  };
  // 无 path：返回安全 browse roots 的入口，currentPath/parentPath 为空，入口本身不可作为落点。
  assert.equal(payload.currentPath, null);
  assert.equal(payload.parentPath, null);
  assert.equal(payload.selectable, false, 'roots 入口不可作为创建根');
  assert.equal(payload.truncated, false);
  assert.ok(payload.entries.length >= 1, '至少存在一个安全 browse root');
  assert.deepEqual(payload.rootPaths, payload.entries.map((entry) => entry.path), 'rootPaths 必须与入口条目一致');
  for (const entry of payload.entries) {
    assert.equal(entry.selectable, true, '安全 browse root 可选作创建根');
    assert.ok(
      entry.path !== '/' && !/^[a-z]:\/$/i.test(entry.path),
      `文件系统根/盘符根绝不作为 browse root：${entry.path}`,
    );
  }
});

test('权限保存：allowedFolders 正向校验（不存在路径 400、正常目录 200），旧 workspaceCreationRoots 字段显式 400', async () => {
  const target = db.createUser('picker-perm-target', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(target.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null,
  });
  const validRoot = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-perm-')));
  const missingRoot = path.join(os.tmpdir(), `dshpw-picker-perm-missing-${Date.now()}`);
  try {
    // workspaceCreationRoots 已退役：allowedFolders 是唯一工作区/创建范围。旧客户端提交该
    // 字段必须显式 400，不能静默忽略后让管理员误以为旧创建根已生效。
    const retiredField = await postJson('/gateway/api/permissions', adminCookie, {
      userId: target.id, workspaceCreationRoots: [validRoot],
    });
    assert.equal(retiredField.status, 400, retiredField.body.toString());
    assert.match(retiredField.body.toString(), /workspaceCreationRoots/);
    assert.deepEqual(db.getPermissions(target.id)?.allowed_folders ?? null, [], '退役字段不得落库');

    // allowedFolders 正向校验：不存在/不可分配路径 400 且不落库。
    const denied = await postJson('/gateway/api/permissions', adminCookie, {
      userId: target.id, allowedFolders: [missingRoot],
    });
    assert.equal(denied.status, 400, denied.body.toString());
    assert.deepEqual(db.getPermissions(target.id)?.allowed_folders ?? null, [], '不存在路径不得落库');

    // 真实、非敏感目录接受并落库（上游清单为空，走真实目录回退分支）。
    const accepted = await postJson('/gateway/api/permissions', adminCookie, {
      userId: target.id, allowedFolders: [validRoot],
    });
    assert.equal(accepted.status, 200, accepted.body.toString());
    assert.deepEqual(
      (db.getPermissions(target.id)?.allowed_folders ?? []).map(normalizePath),
      [normalizePath(validRoot)],
    );
  } finally {
    try { rmSync(validRoot, { recursive: true, force: true }); } catch { /* Windows 文件句柄尽力而为 */ }
  }
});

test('目录选择器：真实后端返回统一 listing shape', async () => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-shape-')));
  mkdirSync(path.join(root, 'only-subdir'));
  try {
    const response = await request(directoryPickerPath(root), adminCookie);
    assert.equal(response.status, 200, response.body.toString());
    const payload = JSON.parse(response.body.toString()) as Record<string, unknown>;
    assert.deepEqual(
      Object.keys(payload).sort(),
      ['currentPath', 'entries', 'ok', 'parentPath', 'rootPath', 'rootPaths', 'selectable', 'truncated'],
    );
    assert.equal(payload.ok, true);
    assert.equal(typeof payload.currentPath, 'string');
    assert.equal(typeof payload.parentPath, 'string');
    assert.equal(typeof payload.rootPath, 'string');
    assert.ok(Array.isArray(payload.rootPaths));
    assert.equal(typeof payload.selectable, 'boolean');
    assert.equal(typeof payload.truncated, 'boolean');
    assert.ok(Array.isArray(payload.entries));
    for (const entry of payload.entries as Array<Record<string, unknown>>) {
      assert.deepEqual(Object.keys(entry).sort(), ['name', 'path', 'selectable']);
      assert.equal(typeof entry.name, 'string');
      assert.equal(typeof entry.path, 'string');
      assert.equal(typeof entry.selectable, 'boolean');
    }
  } finally {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows 文件句柄尽力而为 */ }
  }
});

test('目录选择器：canonical 落到文件系统根的符号链接不可作为创建根', async (t) => {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-rootlink-')));
  const rootTarget = process.platform === 'win32' ? `${(root[0] ?? 'C').toUpperCase()}:\\` : '/';
  try {
    try {
      symlinkSync(rootTarget, path.join(root, 'to-root'), process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      // 无符号链接权限时显式跳过（而非静默 return 通过），让跳过在测试报告里可见。
      t.skip('无符号链接权限，跳过 canonical 落根的过滤断言');
      return;
    }
    const response = await request(directoryPickerPath(root), adminCookie);
    assert.equal(response.status, 200, response.body.toString());
    const payload = JSON.parse(response.body.toString()) as {
      entries: Array<{ name: string; path: string; selectable: boolean }>;
    };
    const entry = payload.entries.find((candidate) => candidate.name === 'to-root');
    assert.equal(entry, undefined, '符号链接（含指向文件系统根）一律不返回，绝不可作为创建根');
  } finally {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows 文件句柄尽力而为 */ }
  }
});
