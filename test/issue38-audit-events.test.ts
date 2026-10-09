// Issue #38 审计回归：子用户新建目录 / 工作区登记的成功与拒绝事件，以及权限保存的
// actor/ip/user-agent 归属（真实 HTTP + 本地 DSH 上游桩）。
//
// 断言口径：
//   · directoryPicker/createDirectory：成功记账 pending 时写 `directory_created`；
//     父目录越权/敏感或关闭 allowWorkspaceCreate 被 403 时写 `directory_create_denied`；
//   · workspace/create：登记成功写 `workspace_registered`；未分配目录被 403 时写
//     `workspace_registration_denied`；
//   · 权限保存 `permissions_changed` 记录 ip/user-agent 与 detail.actor（操作者主用户），
//     同时保留既有 detail 字段（含 allow_ssh）以兼容既有事件格式；
//   · 所有新事件都带 actor（username）、ip、user-agent，且不落完整敏感主机路径、token 或密码。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { normalizePath } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

const DUMMY_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';
const UA = 'issue38-audit-probe/1.0';

let appDir: string;
let db: Database;
let upstream: http.Server | null = null;
let gateway: http.Server | null = null;
let gatewayPort = 0;
let config: PlatformConfig;
let admin: { id: number; username: string };
const roots: string[] = [];

interface Reply {
  status: number;
  body: string;
}

interface AuditRow {
  event_type: string;
  username: string | null;
  ip: string | null;
  user_agent: string | null;
  detail: string | null;
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

/** 真实临时目录的 canonical（realpath + 归一）形态：与网关创建/登记同口径。 */
function realTempDir(prefix: string): string {
  const dir = normalizePath(realpathSync(mkdtempSync(path.join(os.tmpdir(), prefix))));
  roots.push(dir);
  return dir;
}

function readArgs(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { payload?: { args?: Record<string, unknown> } };
        resolve(parsed.payload?.args ?? {});
      } catch {
        resolve({});
      }
    });
  });
}

function post(pathname: string, body: unknown, cookie: string): Promise<Reply> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1', port: gatewayPort, method: 'POST', path: pathname,
        headers: {
          cookie, 'user-agent': UA,
          'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

function cookieFor(user: { id: number; username: string }): string {
  return `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
}

const createDirectory = (cookie: string, parent: string, name: string, rpcId: string): Promise<Reply> =>
  post('/api/directoryPicker/createDirectory', {
    type: 'client-request', rpcId, method: 'directoryPicker/createDirectory',
    payload: { args: { path: parent, name } },
  }, cookie);

const createWorkspace = (cookie: string, target: string, rpcId: string): Promise<Reply> =>
  post('/api/workspace/create', {
    type: 'client-request', rpcId, method: 'workspace/create',
    payload: { args: { request: { path: target } } },
  }, cookie);

const savePerms = (cookie: string, body: Record<string, unknown>): Promise<Reply> =>
  post('/gateway/api/permissions', body, cookie);

/** 该用户的审计行（新到旧）。 */
function eventsFor(username: string, eventType: string): AuditRow[] {
  return (db.listAuditLogs(100) as unknown as AuditRow[])
    .filter((row) => row.username === username && row.event_type === eventType);
}

function setPerms(userId: number, folders: string[], allowCreate: boolean): void {
  db.setPermissions(userId, {
    allowedFolders: folders, hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: allowCreate,
    allowedAgentPresets: null, banned: false, sandboxMode: null, disabledSessions: [],
  });
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-i38-audit-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  db.init();
  admin = db.createUser('i38-audit-admin', DUMMY_HASH, 'admin');

  let workspaceSeq = 0;
  upstream = await new Promise<http.Server>((resolve) => {
    const server = http.createServer((req, res) => {
      void (async () => {
        const url = req.url ?? '';
        const reply = (value: unknown) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ type: 'server-response', result: { ok: true, value } }));
        };
        if (req.method === 'GET' && url.startsWith('/api/dsh-passwords/internal/assignable-resources')) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, folders: [], assignableSessions: [], retainedSessions: [] }));
          return;
        }
        if (req.method === 'POST' && url.startsWith('/api/directoryPicker/createDirectory')) {
          const args = await readArgs(req);
          const parent = typeof args.path === 'string' ? args.path : '';
          const name = typeof args.name === 'string' ? args.name : '';
          reply(`${parent}/${name}`);
          return;
        }
        if (req.method === 'POST' && url.startsWith('/api/workspace/create')) {
          const args = await readArgs(req);
          const request = args.request as Record<string, unknown> | undefined;
          const target = typeof request?.path === 'string' ? request.path : '';
          workspaceSeq += 1;
          reply({ created: true, workspace: { workspaceId: `i38-audit-${workspaceSeq}`, path: target, title: 't', sessionIds: [] } });
          return;
        }
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end('{}');
      })();
    });
    listen(server).then(() => resolve(server));
  });
  const upstreamPort = (upstream.address() as { port: number }).port;

  config = {
    setupKey: 'test-setup-key', dbPath, dbEncKey: 'test-key',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };
  gateway = createGatewayServer(config, new AuthService(config, db), db);
  gatewayPort = await listen(gateway);
});

after(() => {
  gateway?.close();
  upstream?.close();
  try { db.close(); } catch { /* 已关闭 */ }
  for (const dir of roots) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
  }
  try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
});

test('createDirectory 成功记账写入 directory_created（actor/ip/ua + 非敏感路径）', async () => {
  const user = db.createUser('i38-audit-dir-ok', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-dirok-');
  setPerms(user.id, [root], true);
  const cookie = cookieFor(user);

  const created = await createDirectory(cookie, root, 'proj', 'mk-ok');
  assert.equal(created.status, 200, created.body);

  const rows = eventsFor(user.username, 'directory_created');
  assert.equal(rows.length, 1, '成功记账必须写一条 directory_created');
  assert.equal(rows[0].ip !== null && rows[0].ip !== '', true, '必须记录 ip');
  assert.equal(rows[0].user_agent, UA, '必须记录 user-agent');
  const detail = JSON.parse(rows[0].detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.result, 'ok');
  assert.equal(detail.path, `${root}/proj`, '非敏感路径按规范化形态记录');
});

test('createDirectory 父目录越权/敏感基被拒时写 directory_create_denied 且不落完整敏感路径', async () => {
  const user = db.createUser('i38-audit-dir-deny', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-dirdeny-');
  setPerms(user.id, [root], true);
  const cookie = cookieFor(user);

  // appDir 因 dbPath 祖先链落在敏感基内，且不在该用户白名单：父目录双重越权。
  const denied = await createDirectory(cookie, appDir, 'leak', 'mk-deny');
  assert.equal(denied.status, 403, denied.body);

  const rows = eventsFor(user.username, 'directory_create_denied');
  assert.equal(rows.length, 1, '拒绝必须写一条 directory_create_denied');
  assert.equal(rows[0].user_agent, UA);
  const detail = JSON.parse(rows[0].detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.result, 'denied');
  assert.equal(detail.reason, 'path_not_allowed');
  assert.deepEqual(detail.target, { sensitive: true, leaf: 'leak' }, '敏感路径只留叶子名');
  assert.ok(!(rows[0].detail ?? '').includes(path.basename(appDir)),
    '完整敏感主机路径不得落入审计详情');
});

test('关闭 allowWorkspaceCreate 时目录创建被拒写 directory_create_denied（reason=create_disabled）', async () => {
  const user = db.createUser('i38-audit-dir-off', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-diroff-');
  setPerms(user.id, [root], false);
  const cookie = cookieFor(user);

  const denied = await createDirectory(cookie, root, 'x', 'mk-off');
  assert.equal(denied.status, 403, denied.body);

  const rows = eventsFor(user.username, 'directory_create_denied');
  assert.equal(rows.length, 1);
  const detail = JSON.parse(rows[0].detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.reason, 'create_disabled');
  assert.equal(detail.result, 'denied');
});

test('workspace/create 登记成功写入 workspace_registered', async () => {
  const user = db.createUser('i38-audit-ws-ok', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-wsok-');
  setPerms(user.id, [root], true);
  const cookie = cookieFor(user);

  assert.equal((await createDirectory(cookie, root, 'proj', 'ws-mk')).status, 200);
  const created = await createWorkspace(cookie, `${root}/proj`, 'ws-create');
  assert.equal(created.status, 200, created.body);

  const rows = eventsFor(user.username, 'workspace_registered');
  assert.equal(rows.length, 1, '登记成功必须写一条 workspace_registered');
  assert.equal(rows[0].user_agent, UA);
  const detail = JSON.parse(rows[0].detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.result, 'ok');
  assert.equal(detail.path, `${root}/proj`);
});

test('workspace/create 未分配目录被拒写入 workspace_registration_denied（reason=not_assigned_or_created）', async () => {
  const user = db.createUser('i38-audit-ws-deny', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-wsdeny-');
  setPerms(user.id, [root], true);
  const cookie = cookieFor(user);

  // 白名单内（folderAllowed 通过）但未分配精确目录、非自建、非 pending：
  // 只应命中登记门禁的 not_assigned_or_created。
  const denied = await createWorkspace(cookie, `${root}/other`, 'ws-deny');
  assert.equal(denied.status, 403, denied.body);

  const rows = eventsFor(user.username, 'workspace_registration_denied');
  assert.equal(rows.length, 1, '拒绝必须写一条 workspace_registration_denied');
  assert.equal(rows[0].user_agent, UA);
  const detail = JSON.parse(rows[0].detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.result, 'denied');
  assert.equal(detail.reason, 'not_assigned_or_created');
  assert.equal(detail.target, `${root}/other`);
});

test('权限保存审计记录 actor/ip/user-agent 并保留既有字段（含 allow_ssh）', async () => {
  const target = db.createUser('i38-audit-perm-target', DUMMY_HASH);
  const root = realTempDir('dshpw-i38-audit-perm-');
  setPerms(target.id, [root], true);

  const saved = await savePerms(cookieFor(admin), { userId: target.id, allowWorkspaceCreate: true });
  assert.equal(saved.status, 200, saved.body);

  const rows = eventsFor(target.username, 'permissions_changed');
  assert.ok(rows.length >= 1, '权限保存必须写 permissions_changed');
  const row = rows[0];
  assert.equal(row.username, target.username, 'username 仍是被改权限的子用户（格式兼容）');
  assert.equal(row.user_agent, UA, '必须记录 user-agent');
  assert.equal(row.ip !== null && row.ip !== '', true, '必须记录 ip');
  const detail = JSON.parse(row.detail ?? '{}') as Record<string, unknown>;
  assert.equal(detail.actor, admin.username, 'detail.actor 必须是操作者主用户');
  // 既有字段保持存在：allow_ssh 等业务开关不因本次审计扩展而改动或丢失。
  for (const key of ['allowedFolders', 'allowWorkspaceCreate', 'allowSsh', 'allowedModels', 'allowedSessionIds']) {
    assert.ok(Object.hasOwn(detail, key), `既有 detail 字段 ${key} 必须保留`);
  }
  assert.equal(detail.allowSsh, db.getPermissions(target.id)?.allow_ssh, 'allow_ssh 必须与落库值一致');
});

test('审计行不落 token/密码/完整敏感路径', () => {
  const jwtLike = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
  for (const row of db.listAuditLogs(100) as unknown as AuditRow[]) {
    const blob = [row.event_type, row.username, row.ip, row.user_agent, row.detail].join('\n');
    assert.doesNotMatch(blob, jwtLike, '审计不得落 JWT/会话令牌');
    assert.doesNotMatch(blob, /password|passwd|密码/i, '审计不得落密码相关明文');
  }
});
