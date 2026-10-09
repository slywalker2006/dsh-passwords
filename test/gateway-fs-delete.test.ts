// POST /gateway/api/fs/delete-directory：目录选择器删除按钮的后端契约测试。
//
// 授权模型：仅主用户（requireAdmin）；子用户 403。
// 安全约束：realpath 防逃逸、必须目录、敏感基列表（部署根/数据库/DSH 目录/
// SSH 凭据/OS 系统目录）及其子路径与祖先、文件系统根与用户主目录本身、审计留痕。
//
// 目录删除联动：删除命中 DSH sidebar workspace 的路径时，网关必须在 rmSync 之前
// 经上游 rc.2 Remote 协议快照注册表，之后按同一协议删除树内全部 workspace，
// 并清理插件 DB 的 ownership / allowed_folders / 会话 grants。
//   · 列表：WS /api/remote.mux → open(workspace/follow, { args: {} }) → baseline item
//   · 删除：POST /api/workspace/delete → { type:'client-request', rpcId,
//           method:'workspace/delete', payload:{ args:{ request:{ workspaceId } } } }
// 本文件的假上游按上述真实信封实现，任何凭空猜测的字段都会在断言处失败。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database, samePathForMatch } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { interpretDeleteResponse } from '../src/client/picker-delete.js';
import { folderAllowed, normalizePath } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

const require = createRequire(import.meta.url);
const { WebSocket, WebSocketServer } = require('ws') as {
  WebSocket: new (url: string, options?: { headers?: Record<string, string> }) => any;
  WebSocketServer: new (options: { noServer: true }) => {
    handleUpgrade(req: http.IncomingMessage, socket: unknown, head: Buffer, callback: (client: any) => void): void;
    close(callback?: () => void): void;
  };
};

let appDir: string;
let rootDir: string;
// 通过 DSH_PASSWORDS_ENV_FILE 注入的部署目录：其父级必须被祖先保护拦下。
let sensitiveAncestor: string;
let db: Database;
let gateway: http.Server;
let config: PlatformConfig;
let upstream: http.Server;
let upstreamWss: InstanceType<typeof WebSocketServer>;
let gatewayPort = 0;
let adminCookie = '';
let adminBCookie = '';
let adminCCookie = '';
let subuserCookie = '';
let syncUserCookie = '';

type FakeWorkspace = { workspaceId: string; path: string; sessionIds: string[] };
let upstreamWorkspaces: FakeWorkspace[] = [];
const followSockets = new Set<any>();
let followOpens: Array<Record<string, unknown>> = [];
let deleteCalls: Array<{ body: Record<string, unknown>; workspaceId: string }> = [];
let followCookies: string[] = [];
let deleteCookies: string[] = [];
let deleteReplyOverride: ((rpcId: unknown) => unknown) | null = null;
let rejectFollowUpgrade = false;
/** null = 不限制；数字 = 最多放行多少次 /api/remote.mux upgrade（用于首次快照成功、复核失败）。 */
let followUpgradeBudget: number | null = null;
/** 非空时挂起 workspace/follow baseline 回包，制造「快照后、realpath 复核前」的并发删除窗口。 */
let followBaselineGate: Promise<void> | null = null;
let snapshotDirCheck: string | null = null;
let deleteDirCheck: string | null = null;
let dirExistedAtSnapshot: boolean | null = null;
let dirExistedAtDelete: boolean | null = null;

function resetUpstreamProbe(): void {
  for (const socket of followSockets) {
    try { socket.close(); } catch { /* 已关闭 */ }
  }
  followSockets.clear();
  upstreamWorkspaces = [];
  followOpens = [];
  deleteCalls = [];
  followCookies = [];
  deleteCookies = [];
  deleteReplyOverride = null;
  rejectFollowUpgrade = false;
  followUpgradeBudget = null;
  followBaselineGate = null;
  snapshotDirCheck = null;
  deleteDirCheck = null;
  dirExistedAtSnapshot = null;
  dirExistedAtDelete = null;
}

/** 轮询等待条件成立（测试内并发时序用）。 */
async function waitForCondition(condition: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error('等待条件超时');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function registerWorkspace(workspaceId: string, workspacePath: string, sessionIds: string[] = []): void {
  upstreamWorkspaces.push({ workspaceId, path: workspacePath, sessionIds });
}

function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>);
      } catch {
        resolve({});
      }
    });
  });
}

function post(url: string, body: unknown, cookie: string, port = gatewayPort): Promise<{ status: number; json: Record<string, unknown> }> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: url,
        headers: { cookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>;
          } catch {
            /* 非 JSON */
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

const del = (target: string, cookie = adminCookie) => post('/gateway/api/fs/delete-directory', { path: target }, cookie);

/** 删除响应 workspaces 字段的条目契约（与 src/admin.ts 的响应组装一致）。 */
type WorkspaceSyncTarget = { workspaceId: string; path: string };
type WorkspaceSyncFailure = WorkspaceSyncTarget & { error: string };
type WorkspaceSyncReport = {
  deleted: string[];
  failed: WorkspaceSyncFailure[];
  unverified: WorkspaceSyncTarget[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isWorkspaceSyncTarget(value: unknown): value is WorkspaceSyncTarget {
  return isRecord(value) && typeof value.workspaceId === 'string' && typeof value.path === 'string';
}

function isWorkspaceSyncFailure(value: unknown): value is WorkspaceSyncFailure {
  if (!isRecord(value)) return false;
  return typeof value.workspaceId === 'string' && typeof value.path === 'string' && typeof value.error === 'string';
}

function readWorkspaceArray<T>(
  value: unknown,
  guard: (item: unknown) => item is T,
  field: string,
  json: Record<string, unknown>,
): T[] {
  if (!Array.isArray(value)) throw new Error(`响应 workspaces.${field} 不是数组：${JSON.stringify(json)}`);
  const result: T[] = [];
  for (const item of value) {
    if (!guard(item)) throw new Error(`响应 workspaces.${field} 条目契约不符：${JSON.stringify(json)}`);
    result.push(item);
  }
  return result;
}

/**
 * 收窄删除响应中的 workspaces。网络响应是真实信任边界，形状不符即失败，
 * 而不是用断言把契约漂移掩盖成测试通过。
 */
function workspaceSyncReport(json: Record<string, unknown>): WorkspaceSyncReport {
  const report = json.workspaces;
  if (!isRecord(report)) throw new Error(`响应缺少 workspaces 字段：${JSON.stringify(json)}`);
  return {
    deleted: readWorkspaceArray(report.deleted, (item): item is string => typeof item === 'string', 'deleted', json),
    failed: readWorkspaceArray(report.failed, isWorkspaceSyncFailure, 'failed', json),
    unverified: readWorkspaceArray(report.unverified, isWorkspaceSyncTarget, 'unverified', json),
  };
}

/**
 * 以子用户身份打开网关 Remote mux 的 workspace/follow 并等待 baseline。
 * 网关的过滤基线是本进程内 workspaceId→path 缓存（暖缓存）的唯一来源；
 * 返回的连接保持打开，调用方负责 close()。
 */
async function followWorkspaceBaseline(cookie: string): Promise<any> {
  const client = new WebSocket(`ws://127.0.0.1:${gatewayPort}/api/remote.mux`, { headers: { cookie } });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('mux baseline 超时')), 4_000);
    client.on('open', () => {
      client.send(JSON.stringify({ type: 'open', streamId: 'seed-workspaces', endpoint: 'workspace/follow', payload: { args: {} } }));
    });
    client.on('message', (data: Buffer) => {
      try {
        const frame = JSON.parse(data.toString('utf8')) as { streamId?: string; type?: string; value?: { type?: string } };
        if (frame.streamId === 'seed-workspaces' && frame.type === 'item' && frame.value?.type === 'baseline') {
          clearTimeout(timer);
          resolve();
        }
      } catch {
        /* 非 JSON 帧：忽略 */
      }
    });
    client.on('error', (error: Error) => { clearTimeout(timer); reject(error); });
    client.on('close', () => { clearTimeout(timer); reject(new Error('mux 在 baseline 前关闭')); });
  });
  return client;
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-fsdel-app-'));
  rootDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-fsdel-root-'));
  // 部署目录的父级：注入 DSH_PASSWORDS_ENV_FILE 后 configuredRoot = <sensitiveAncestor>/cfg，
  // 祖先保护测试将以 <sensitiveAncestor> 为目标（若保护缺失，删除范围也仅限本测试自建目录）。
  sensitiveAncestor = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'dshpw-fsdel-anc-')));
  mkdirSync(path.join(sensitiveAncestor, 'cfg'));
  process.env.DSH_PASSWORDS_ENV_FILE = path.join(sensitiveAncestor, 'cfg', '.env');
  mkdirSync(path.join(appDir, 'data'));
  // 待删目录：嵌套内容 + 隐藏目录（模拟 /root 下的测试工作区）
  mkdirSync(path.join(rootDir, 'e2e-target', 'nested'), { recursive: true });
  writeFileSync(path.join(rootDir, 'e2e-target', 'nested', 'file.txt'), 'x');
  mkdirSync(path.join(rootDir, '.e2e-hidden', 'inner'), { recursive: true });
  writeFileSync(path.join(rootDir, 'plain-file.txt'), 'not a directory');
  // 部署目录内的真实文件/目录（敏感基列表的测试目标必须存在：realpath 先行）
  writeFileSync(path.join(appDir, '.env'), 'SETUP_KEY=x');
  mkdirSync(path.join(appDir, 'dist'));
  mkdirSync(path.join(appDir, 'deploy-backups'));

  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  // 第二个主用户：删除端点有每用户 30 次/分钟限流；新增回归用例独立计数，避免耗尽 admin 配额。
  const adminB = db.createUser('admin-b', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  // 第三个主用户：为 cleanupOnly 冲突与别名/大小写场景提供独立删除限流桶。
  const adminC = db.createUser('admin-c', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const subuser = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(subuser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });
  // 联动测试用子用户：ownership / 白名单 / grants 在每个用例内单独铺设。
  const syncUser = db.createUser('sync-user', '$2a$10$dummyhashdummyhashdummyhashdu');
  db.setPermissions(syncUser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null,
  });

  // ── 假上游：rc.2 Remote 协议（workspace/follow 快照 + workspace/delete）──
  upstreamWss = new WebSocketServer({ noServer: true });
  upstream = http.createServer();
  upstream.on('upgrade', (req, socket, head) => {
    const pathname = new URL(req.url ?? '/', 'http://upstream.invalid').pathname;
    const budgetExhausted = followUpgradeBudget !== null && followUpgradeBudget <= 0;
    if (pathname !== '/api/remote.mux' || rejectFollowUpgrade || budgetExhausted) {
      socket.destroy();
      return;
    }
    if (followUpgradeBudget !== null) followUpgradeBudget -= 1;
    followCookies.push(String(req.headers.cookie ?? ''));
    upstreamWss.handleUpgrade(req, socket, head, (client: any) => {
      client.on('message', (data: Buffer) => {
        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(data.toString('utf8')) as Record<string, unknown>;
        } catch {
          return;
        }
        if (frame.type === 'open' && frame.endpoint === 'workspace/follow') {
          followOpens.push(frame);
          followSockets.add(client);
          client.streamId = frame.streamId;
          // 只记首次快照时刻的目录状态（删除后的复核快照不能覆盖）
          if (snapshotDirCheck !== null && dirExistedAtSnapshot === null) dirExistedAtSnapshot = existsSync(snapshotDirCheck);
          const sendBaseline = (): void => {
            try {
              client.send(JSON.stringify({
                type: 'item',
                streamId: frame.streamId,
                value: {
                  type: 'baseline',
                  value: { items: upstreamWorkspaces.map((workspace) => ({ ...workspace })), archivedSessionIds: [] },
                },
              }));
            } catch {
              /* 连接已在回包前关闭（竞态测试） */
            }
          };
          // 竞态测试：先挂起回包，被测方删除目录后再放行，确保 realpath 复核必定看不到目录。
          if (followBaselineGate !== null) void followBaselineGate.then(sendBaseline);
          else sendBaseline();
        } else if (frame.type === 'cancel') {
          followSockets.delete(client);
        }
      });
      client.on('close', () => followSockets.delete(client));
    });
  });
  upstream.on('request', (req, res) => {
    // 子用户 directoryPicker/createDirectory 记账测试：按真实 DSH 契约（path=父目录 + name=单段）
    // 回 join(path, name) 作为新建目录，网关据此登记 pending。
    if (req.method === 'POST' && req.url === '/api/directoryPicker/createDirectory') {
      void (async () => {
        const body = await readJsonBody(req);
        const payload = body.payload as Record<string, unknown> | undefined;
        const args = payload?.args as Record<string, unknown> | undefined;
        const parent = typeof args?.path === 'string' ? args.path : '';
        const name = typeof args?.name === 'string' ? args.name : '';
        const created = parent === '' || name === '' ? parent : path.join(parent, name);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ type: 'server-response', rpcId: body.rpcId, result: { ok: true, value: created } }));
      })();
      return;
    }
    if (req.method === 'POST' && req.url === '/api/workspace/delete') {
      void (async () => {
        const body = await readJsonBody(req);
        const payload = body.payload as Record<string, unknown> | undefined;
        const args = payload?.args as Record<string, unknown> | undefined;
        const request = args?.request as Record<string, unknown> | undefined;
        const workspaceId = typeof request?.workspaceId === 'string' ? request.workspaceId : '';
        deleteCalls.push({ body, workspaceId });
        deleteCookies.push(String(req.headers.cookie ?? ''));
        if (deleteDirCheck !== null && dirExistedAtDelete === null) dirExistedAtDelete = existsSync(deleteDirCheck);
        const override = deleteReplyOverride === null ? null : deleteReplyOverride(body.rpcId);
        if (override !== null) {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(override));
          return;
        }
        const index = upstreamWorkspaces.findIndex((workspace) => workspace.workspaceId === workspaceId);
        if (index >= 0) {
          upstreamWorkspaces.splice(index, 1);
          for (const client of followSockets) {
            try {
              client.send(JSON.stringify({ type: 'item', streamId: client.streamId, value: { type: 'remove', workspaceId } }));
            } catch {
              /* 已断开 */
            }
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ type: 'server-response', rpcId: body.rpcId, result: { ok: true, value: { deleted: true } } }));
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          type: 'server-response',
          rpcId: body.rpcId,
          result: { ok: false, error: { code: 'workspace/not-found', message: 'not found', details: {} } },
        }));
      })();
      return;
    }
    res.end();
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const upstreamPort = (upstream.address() as { port: number }).port;
  config = {
    setupKey: 'test-setup-key', dbPath, dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };
  const tokenFor = (user: { id: number; username: string }) =>
    `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  adminCookie = tokenFor(admin);
  adminBCookie = tokenFor(adminB);
  adminCCookie = tokenFor(adminC);
  subuserCookie = tokenFor(subuser);
  syncUserCookie = tokenFor(syncUser);

  // 只允许经受保护通道登记的上游 dsh-auth：删除联动的快照/删除请求都使用它，
  // 浏览器 Cookie（含 dsh-auth-*）永不转发给 loopback 上游。
  process.env.DSH_UPSTREAM_AUTH_COOKIE = 'dsh-auth-test=registered';
  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstreamWss?.close();
  upstream?.close();
  delete process.env.DSH_PASSWORDS_ENV_FILE;
  delete process.env.DSH_UPSTREAM_AUTH_COOKIE;
  try {
    rmSync(appDir, { recursive: true, force: true });
    rmSync(rootDir, { recursive: true, force: true });
    rmSync(sensitiveAncestor, { recursive: true, force: true });
  } catch {
    /* Windows 文件占用：忽略 */
  }
});

test('仅主用户：子用户调用 403，未登录 401', async () => {
  const sub = await del(path.join(rootDir, 'e2e-target'), subuserCookie);
  assert.equal(sub.status, 403);
  assert.equal(sub.json.ok, false);
  const anon = await post('/gateway/api/fs/delete-directory', { path: rootDir }, '');
  assert.equal(anon.status, 401);
  // 目录必须仍然存在（谁都没删成）
  assert.equal(existsSync(path.join(rootDir, 'e2e-target')), true);
});

test('主用户递归删除普通目录（含嵌套内容）并审计留痕', async () => {
  const target = path.join(rootDir, 'e2e-target');
  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.ok, true);
  assert.equal(res.json.deleted, target);
  assert.equal(existsSync(target), false);
});

test('主用户可删除隐藏目录（. 开头）', async () => {
  const target = path.join(rootDir, '.e2e-hidden');
  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(existsSync(target), false);
});

test('非目录返回 400；不存在返回 404；空路径返回 400', async () => {
  const fileTarget = path.join(rootDir, 'plain-file.txt');
  assert.equal((await del(fileTarget)).status, 400);
  assert.equal((await del(path.join(rootDir, 'no-such-dir'))).status, 404);
  assert.equal((await del('')).status, 400);
  // ../ 逃逸解析到不存在的路径 → 404；存在与否不改变“不许探测敏感目录”的语义
  assert.equal((await del(path.join(rootDir, 'no-such', '..', 'no-such'))).status, 404);
});

test('敏感目录不可删除：部署根、数据库、部署目录内子目录（.env 同级与 dist）', async () => {
  for (const target of [appDir, path.join(appDir, 'data'), path.join(appDir, 'dist'), appDir + path.sep + 'deploy-backups']) {
    const res = await del(target);
    assert.equal(res.status, 403, `${target} 应当被敏感目录保护：${JSON.stringify(res.json)}`);
    assert.equal(res.json.code, 'FORBIDDEN');
  }
});

test('文件系统根与用户主目录本身不可删除', async () => {
  assert.equal((await del(path.parse(rootDir).root)).status, 403);
  assert.equal((await del(os.homedir())).status, 403);
});

test('路径遍历变体：/../ 指向部署目录内的目标被敏感基列表拦截', async () => {
  const sneaky = path.join(appDir, '..', path.basename(appDir), 'data');
  const res = await del(sneaky);
  assert.equal(res.status, 403, JSON.stringify(res.json));
});

test('路由白名单：未知 /gateway/api/fs/* 子路径不透传到上游（404）', async () => {
  const res = await post('/gateway/api/fs/other', { path: rootDir }, adminCookie);
  assert.equal(res.status, 404);
});

test('敏感路径祖先保护：删除部署目录的上级目录被拒绝且不落盘', async () => {
  const res = await del(sensitiveAncestor);
  assert.equal(res.status, 403, JSON.stringify(res.json));
  assert.equal(res.json.code, 'FORBIDDEN');
  assert.equal(existsSync(sensitiveAncestor), true);
  assert.equal(existsSync(path.join(sensitiveAncestor, 'cfg')), true);
});

test('删除命中 workspace：rmSync 前快照、按 rc.2 信封删除注册表条目并清理 DB', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-hit');
  const keepFolder = path.join(rootDir, 'sync-keep');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-sync-hit', target, ['sess-sync-1']);
  snapshotDirCheck = target;
  deleteDirCheck = target;

  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, target);
  db.setPermissions(syncUser.id, {
    allowedFolders: [target, keepFolder],
    hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
    allowedSessionIds: ['sess-sync-1', 'sess-keep'],
  });

  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.ok, true);
  assert.equal(res.json.deleted, target);
  assert.equal(res.json.registrySnapshot, 'upstream');
  assert.deepEqual(res.json.workspaces, { deleted: ['ws-sync-hit'], failed: [], unverified: [] });

  // 上游快照信封：WS 打开 workspace/follow，payload 必须是 { args: {} }
  assert.equal(followOpens.length >= 1, true);
  const open = followOpens[followOpens.length - 1]!;
  assert.equal(open.type, 'open');
  assert.equal(open.endpoint, 'workspace/follow');
  assert.deepEqual(open.payload, { args: {} });

  // 上游删除信封：client-request + workspace/delete + payload.args.request.workspaceId
  assert.equal(deleteCalls.length, 1);
  assert.equal(deleteCalls[0]!.body.type, 'client-request');
  assert.equal(deleteCalls[0]!.body.method, 'workspace/delete');
  assert.equal(typeof deleteCalls[0]!.body.rpcId, 'string');
  assert.deepEqual((deleteCalls[0]!.body.payload as Record<string, unknown>).args, {
    request: { workspaceId: 'ws-sync-hit' },
  });

  // 顺序：快照时目录还在；上游删除时目录已被物理删除（不可回滚）
  assert.equal(dirExistedAtSnapshot, true);
  assert.equal(dirExistedAtDelete, false);
  assert.equal(existsSync(target), false);

  // DB 清理：ownership 删除、白名单只保留树外条目、树内会话 grant 删除
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(target)), false);
  const perms = db.getPermissions(syncUser.id)!;
  assert.deepEqual(perms.allowed_folders, [keepFolder.replace(/\\/g, '/')]);
  assert.deepEqual(db.listUserSessionGrants(syncUser.id), ['sess-keep']);
});

test('删除父目录命中子 workspace：树内全部删除，分隔符边界外的兄弟/前缀不误删', async () => {
  resetUpstreamProbe();
  const parent = path.join(rootDir, 'sync-parent');
  mkdirSync(path.join(parent, 'child'), { recursive: true });
  // 树内两个 workspace（一个与父目录同名？否）——嵌套子路径必须命中
  registerWorkspace('ws-child', path.join(parent, 'child'));
  // 分隔符边界：/sync-parent-2 与 /sync-parent2 都不在 /sync-parent 树内
  mkdirSync(path.join(rootDir, 'sync-parent-2'), { recursive: true });
  mkdirSync(path.join(rootDir, 'sync-parent2'), { recursive: true });
  registerWorkspace('ws-sibling', path.join(rootDir, 'sync-parent-2'));
  registerWorkspace('ws-prefix', path.join(rootDir, 'sync-parent2'));

  const res = await del(parent);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.workspaces, { deleted: ['ws-child'], failed: [], unverified: [] });
  assert.deepEqual(deleteCalls.map((call) => call.workspaceId), ['ws-child']);
  assert.equal(existsSync(parent), false);
  // 兄弟/前缀 workspace 仍在注册表，且目录未被连带删除
  assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId).sort(), ['ws-prefix', 'ws-sibling']);
  assert.equal(existsSync(path.join(rootDir, 'sync-parent-2')), true);
  assert.equal(existsSync(path.join(rootDir, 'sync-parent2')), true);
});

test('分隔符边界反向：删除 /ws2 不命中 /ws', async () => {
  resetUpstreamProbe();
  const bound = path.join(rootDir, 'sync-bound');
  mkdirSync(bound, { recursive: true });
  const ws = path.join(bound, 'ws');
  const ws2 = path.join(bound, 'ws2');
  mkdirSync(ws, { recursive: true });
  mkdirSync(ws2, { recursive: true });
  registerWorkspace('ws-exact', ws);

  const res = await del(ws2);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(deleteCalls, []);
  assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId), ['ws-exact']);
  assert.equal(existsSync(ws), true);
  assert.equal(existsSync(ws2), false);
});

test('无命中：读取注册表但不调用上游删除，也不清空无关授权', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-nohit');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-elsewhere', path.join(rootDir, 'sync-elsewhere'));
  const syncUser = db.getUserByUsername('sync-user')!;
  db.setPermissions(syncUser.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
  });

  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.workspaces, { deleted: [], failed: [], unverified: [] });
  assert.equal(deleteCalls.length, 0);
  assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId), ['ws-elsewhere']);
  // 未命中不得把“不限制（空数组）”改写成 __deny__ 之类的其它状态
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, []);
});

test('已不存在路径：workspace 子目录早已消失也按规范化字符串命中', async () => {
  resetUpstreamProbe();
  const ghostRoot = path.join(rootDir, 'sync-ghost');
  mkdirSync(ghostRoot, { recursive: true });
  // 注册表里的 workspace 路径在磁盘上不存在（子目录从未创建/早已被删）
  registerWorkspace('ws-ghost', path.join(ghostRoot, 'sub', 'deep'));

  const res = await del(ghostRoot);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(res.json.workspaces, { deleted: ['ws-ghost'], failed: [], unverified: [] });
  assert.equal(existsSync(ghostRoot), false);
});

test('DB 清理不 fail-open：白名单删空必须回落 __deny__', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-deny');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-deny', target, ['sess-deny']);
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, target);
  db.setPermissions(syncUser.id, {
    allowedFolders: [target], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
    allowedSessionIds: ['sess-deny'],
  });

  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  const perms = db.getPermissions(syncUser.id)!;
  assert.deepEqual(perms.allowed_folders, ['__deny__']);
  // 关键：空数组会被 folderAllowed 视为全盘允许，绝不允许出现
  assert.equal(folderAllowed(os.homedir(), perms.allowed_folders), false);
  assert.equal(folderAllowed(target, perms.allowed_folders), false);
  assert.deepEqual(db.listUserSessionGrants(syncUser.id), []);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(target)), false);
});

test('workspace 删除失败可观测：目录已删除但响应不假装全成功', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-partial');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-partial', target);
  deleteReplyOverride = (rpcId: unknown) => ({
    type: 'server-response',
    rpcId,
    result: { ok: false, error: { code: 'gateway/internal', message: 'boom', details: {} } },
  });

  const res = await del(target);
  assert.equal(res.json.ok, false);
  assert.equal(res.json.code, 'WORKSPACE_SYNC_FAILED');
  assert.equal(res.json.deleted, target);
  const workspaces = res.json.workspaces as {
    deleted: string[];
    failed: Array<{ workspaceId: string; path: string; error: string }>;
  };
  assert.deepEqual(workspaces.deleted, []);
  assert.equal(workspaces.failed.length, 1);
  assert.equal(workspaces.failed[0]!.workspaceId, 'ws-partial');
  assert.equal(typeof workspaces.failed[0]!.error, 'string');
  // 物理删除已经发生且不可回滚；HTTP 状态必须让客户端/监控看出部分失败
  assert.equal(existsSync(target), false);
  assert.equal(res.status >= 500, true);
  assert.equal(res.json.retryable, true);
  assert.notEqual(db.findWorkspaceCleanupIntent(target), null, 'workspace/delete 失败时必须保留持久化重试意图');

  // 上游恢复后只重试联动，不重新删除文件系统；原注册表条目必须收敛。
  deleteReplyOverride = null;
  const retry = await post('/gateway/api/fs/delete-directory', { path: target, cleanupOnly: true }, adminCookie);
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.cleanupOnly, true);
  assert.equal(existsSync(target), false);
  assert.equal(upstreamWorkspaces.some((workspace) => workspace.workspaceId === 'ws-partial'), false);
  assert.equal(db.findWorkspaceCleanupIntent(target), null);
});

test('缓存命中 + 上游快照失败：零上游删除、本地缓存仅报告并显式 fail-closed', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-nosnapshot');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-cached', target);
  const syncUser = db.getUserByUsername('sync-user')!;
  db.setPermissions(syncUser.id, {
    allowedFolders: [target], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [],
  });
  // 先在上游可达时让该子用户的 Remote mux baseline 写满网关内的暖缓存。
  const mux = await followWorkspaceBaseline(syncUserCookie);
  mux.close();
  assert.equal(followOpens.length, 1, '预热 baseline 应经过 workspace/follow');
  rejectFollowUpgrade = true;

  const res = await del(target);
  assert.equal(res.status, 503, JSON.stringify(res.json));
  assert.equal(res.json.ok, false);
  assert.equal(res.json.code, 'WORKSPACE_SYNC_UNAVAILABLE');
  assert.equal(res.json.retryable, true);
  assert.equal(res.json.deleted, target);
  assert.equal(res.json.registrySnapshot, 'unavailable');
  assert.equal(existsSync(target), false);
  assert.notEqual(db.findWorkspaceCleanupIntent(target), null, '上游不可用时必须保留持久化重试意图');
  // 暖缓存绝不能驱动删除：一次 workspace/delete 都不允许发出
  assert.deepEqual(deleteCalls, []);
  assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId), ['ws-cached']);
  const unverified = workspaceSyncReport(res.json).unverified;
  assert.deepEqual(unverified.map((entry) => entry.workspaceId), ['ws-cached']);
  assert.ok((res.json.warnings as string[]).some((warning) => warning.includes('ws-cached')));

  // 上游恢复：cleanupOnly 应使用保存的 root 只收敛 sidebar/DB 状态。
  rejectFollowUpgrade = false;
  const retry = await post('/gateway/api/fs/delete-directory', { path: target, cleanupOnly: true }, adminBCookie);
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.cleanupOnly, true);
  assert.equal(retry.json.alreadyDeleted, true);
  assert.equal(upstreamWorkspaces.some((workspace) => workspace.workspaceId === 'ws-cached'), false);
  assert.equal(db.findWorkspaceCleanupIntent(target), null);
});

test('删除后复核：上游假成功但条目仍在 → 报失败（no false success）', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-verify');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-verify', target);
  // 假成功：返回 ok:true 但不从注册表移除
  deleteReplyOverride = (rpcId: unknown) => ({
    type: 'server-response',
    rpcId,
    result: { ok: true, value: { deleted: true } },
  });

  const res = await del(target);
  assert.equal(res.status >= 500, true);
  assert.equal(res.json.ok, false);
  assert.equal(res.json.code, 'WORKSPACE_SYNC_FAILED');
  assert.equal(res.json.deleted, target);
  assert.equal(existsSync(target), false);
  const workspaces = res.json.workspaces as { deleted: string[]; failed: Array<{ workspaceId: string; error: string }>; unverified: unknown[] };
  assert.deepEqual(workspaces.deleted, []);
  assert.equal(workspaces.failed.length, 1);
  assert.equal(workspaces.failed[0]!.workspaceId, 'ws-verify');
  assert.match(workspaces.failed[0]!.error, /still present/);
  // 注册表条目还在（复核未被假成功骗过）
  assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId), ['ws-verify']);
});

test('上游 workspace/not-found 幂等成功（复核通过才计删除）', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-idem');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-idem', target);
  deleteReplyOverride = (rpcId: unknown) => {
    // 模拟目标已被其他进程删除：先移除注册表条目，再回 not-found
    upstreamWorkspaces = upstreamWorkspaces.filter((workspace) => workspace.workspaceId !== 'ws-idem');
    return {
      type: 'server-response',
      rpcId,
      result: { ok: false, error: { code: 'workspace/not-found', message: 'not found', details: {} } },
    };
  };

  const res = await del(target);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.ok, true);
  assert.deepEqual(res.json.workspaces, { deleted: ['ws-idem'], failed: [], unverified: [] });
  assert.equal(existsSync(target), false);
});

test('未登记上游凭据：fail-closed，不转发浏览器 dsh-auth、不发任何上游请求', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-noauth');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-noauth', target);
  const saved = process.env.DSH_UPSTREAM_AUTH_COOKIE;
  delete process.env.DSH_UPSTREAM_AUTH_COOKIE;
  const gatewayNoAuth = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gatewayNoAuth.listen(0, '127.0.0.1', resolve));
  const noAuthPort = (gatewayNoAuth.address() as { port: number }).port;
  try {
    const res = await post(
      '/gateway/api/fs/delete-directory',
      { path: target },
      `${adminCookie}; dsh-auth-browser=evil`,
      noAuthPort,
    );
    assert.equal(res.status, 503, JSON.stringify(res.json));
    assert.equal(res.json.code, 'WORKSPACE_SYNC_UNAVAILABLE');
    assert.equal(res.json.deleted, target);
    assert.equal(res.json.registrySnapshot, 'unavailable');
    assert.equal(existsSync(target), false);
    // 浏览器自带 dsh-auth 绝不能触发上游请求（fail-closed）
    assert.deepEqual(followCookies, []);
    assert.deepEqual(deleteCalls, []);
    assert.deepEqual(upstreamWorkspaces.map((workspace) => workspace.workspaceId), ['ws-noauth']);
    assert.ok((res.json.warnings as string[]).some((warning) => warning.includes('dsh-auth')));
  } finally {
    gatewayNoAuth.close();
    if (saved === undefined) delete process.env.DSH_UPSTREAM_AUTH_COOKIE;
    else process.env.DSH_UPSTREAM_AUTH_COOKIE = saved;
  }
});

test('有登记凭据时只转发登记 Cookie，浏览器 dsh-auth 不进入 loopback 上游', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-cookie');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-cookie', target);

  const res = await del(target, `${adminCookie}; dsh-auth-browser=evil`);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.ok(followCookies.length >= 1, '快照必须发生');
  for (const cookie of followCookies) assert.equal(cookie, 'dsh-auth-test=registered');
  assert.equal(deleteCookies.length, 1);
  assert.equal(deleteCookies[0], 'dsh-auth-test=registered');
  assert.equal([...followCookies, ...deleteCookies].some((cookie) => cookie.includes('dsh-auth-browser')), false);
});

test('删除父目录时按树内命中清理 DB 归属与白名单（树外保留）', async () => {
  resetUpstreamProbe();
  const parent = path.join(rootDir, 'sync-dbparent');
  const keep = path.join(rootDir, 'sync-dbkeep');
  mkdirSync(path.join(parent, 'child'), { recursive: true });
  mkdirSync(keep, { recursive: true });
  registerWorkspace('ws-dbchild', path.join(parent, 'child'));
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, parent);
  db.setPermissions(syncUser.id, {
    allowedFolders: [parent, keep], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
  });

  const res = await del(parent);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(workspaceSyncReport(res.json).deleted, ['ws-dbchild']);
  assert.equal(existsSync(parent), false);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(parent)), false);
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, [keep.replace(/\\/g, '/')]);
});

test('DB 清理失败：返回 DB_CLEANUP_FAILED、仍报告目录已删、失效 mux 且可重试收敛', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-dbfail');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-dbfail', target, ['sess-dbfail']);
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, target);
  db.setPermissions(syncUser.id, {
    allowedFolders: [target], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
    allowedSessionIds: ['sess-dbfail'],
  });
  // 先建一条已生效的 mux 订阅：DB 清理失败时它也必须被失效（关闭）。
  const mux = await followWorkspaceBaseline(syncUserCookie);
  const closedCode = new Promise<number>((resolve) => mux.on('close', (code: number) => resolve(code)));
  const originalCleanup = db.cleanupDeletedWorkspaceTree;
  db.cleanupDeletedWorkspaceTree = () => { throw new Error('injected cleanup failure'); };
  let res: { status: number; json: Record<string, unknown> };
  try {
    res = await del(target);
  } finally {
    db.cleanupDeletedWorkspaceTree = originalCleanup;
  }
  assert.equal(res.status, 500, JSON.stringify(res.json));
  assert.equal(res.json.code, 'DB_CLEANUP_FAILED');
  // 稳定可重试契约：客户端凭它保留墓碑行与重试入口（否则唯一的重试通道会随行移除）
  assert.equal(res.json.retryable, true);
  assert.equal(res.json.deleted, target);
  assert.equal(existsSync(target), false);
  // workspace 同步成功仍然上报（不能因为 DB 失败就丢掉已完成的删除）
  const workspaces = res.json.workspaces as { deleted: string[]; failed: unknown[] };
  assert.deepEqual(workspaces.deleted, ['ws-dbfail']);
  assert.equal(workspaces.failed.length, 0);
  assert.ok((res.json.warnings as string[]).some((warning) => warning.includes('重试')));
  // 失效 mux 快照：旧连接被网关关闭；DB 事务回滚但不 fail-open
  assert.equal(await Promise.race([
    closedCode,
    new Promise<number>((resolve) => setTimeout(() => resolve(-1), 1_500)),
  ]), 1012);
  const rolledBack = db.getPermissions(syncUser.id)!;
  assert.deepEqual(rolledBack.allowed_folders, [target.replace(/\\/g, '/')]);
  assert.notDeepEqual(rolledBack.allowed_folders, []);

  // 重试安全：目录已不存在，但 DB 仍有引用 → 允许重入并在清理成功后收敛
  const retry = await del(target);
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.alreadyDeleted, true);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(target)), false);
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, ['__deny__']);
});

test('清理意图持久化：DB 清理失败且仅剩会话 grants，模拟重启后重试仍能收敛', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-intent-only');
  const keep = path.join(rootDir, 'sync-intent-keep');
  mkdirSync(target, { recursive: true });
  mkdirSync(keep, { recursive: true });
  registerWorkspace('ws-intent-only', target, ['sess-intent-only']);
  const syncUser = db.getUserByUsername('sync-user')!;
  // 目录树内不铺任何 ownership / allowed_folders：首次删除失败回滚后唯一残留是
  // 会话 grants。此时 pathReferencedByWorkspaceState 返回 false，普通重试会 404，
  // 准入只能依赖持久化的清理意图。
  db.setPermissions(syncUser.id, {
    allowedFolders: [keep], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
    allowedSessionIds: ['sess-intent-only'],
  });

  const originalCleanup = db.cleanupDeletedWorkspaceTree;
  db.cleanupDeletedWorkspaceTree = () => { throw new Error('injected intent cleanup failure'); };
  let first: { status: number; json: Record<string, unknown> };
  try {
    first = await del(target, adminBCookie);
  } finally {
    db.cleanupDeletedWorkspaceTree = originalCleanup;
  }
  assert.equal(first.status, 500, JSON.stringify(first.json));
  assert.equal(first.json.code, 'DB_CLEANUP_FAILED');
  assert.equal(first.json.retryable, true);
  assert.equal(first.json.deleted, target);
  assert.equal(existsSync(target), false);
  // 事务回滚：grants 仍在；没有任何 ownership 行可供重试准入使用
  assert.deepEqual(db.listUserSessionGrants(syncUser.id), ['sess-intent-only']);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(target)), false);
  // 无关白名单保留（未 fail-open，也未误清）
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, [keep.replace(/\\/g, '/')]);
  // 受信元数据已持久化：根 + 受影响会话 —— 重启后唯一的重试凭证
  const intent = db.findWorkspaceCleanupIntent(target);
  assert.notEqual(intent, null);
  assert.deepEqual(intent!.sessionIds, ['sess-intent-only']);
  assert.ok(samePathForMatch(intent!.root, target));
  // 准入门槛：意图只对「同一路径」生效——同树但未记录的路径必须维持 404，
  // 不得凭意图对任意不存在路径做注册表/DB 操作。
  const unrecorded = await del(path.join(target, 'sub'), adminBCookie);
  assert.equal(unrecorded.status, 404, JSON.stringify(unrecorded.json));
  assert.notEqual(db.findWorkspaceCleanupIntent(target), null);

  // 模拟进程重启：全新网关实例（独立内存缓存/限流状态），共用同一数据库。
  const freshGateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => freshGateway.listen(0, '127.0.0.1', resolve));
  const freshPort = (freshGateway.address() as { port: number }).port;
  let retry: { status: number; json: Record<string, unknown> };
  const deletesBeforeRetry = deleteCalls.length;
  try {
    retry = await post('/gateway/api/fs/delete-directory', { path: target }, adminBCookie, freshPort);
  } finally {
    freshGateway.close();
  }
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.alreadyDeleted, true);
  // 上游条目早已删除：纯清理重试不得再发任何 workspace/delete
  assert.equal(deleteCalls.length, deletesBeforeRetry);
  assert.deepEqual(db.listUserSessionGrants(syncUser.id), []);
  // 只有 DB 清理成功后才清除意图：成功后不得再有残留重试凭证
  assert.equal(db.findWorkspaceCleanupIntent(target), null);
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, [keep.replace(/\\/g, '/')]);
});

test('cleanupOnly 无持久化意图时拒绝任意缺失路径', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'cleanup-only-no-intent');
  const res = await post('/gateway/api/fs/delete-directory', { path: target, cleanupOnly: true }, adminCookie);
  assert.equal(res.status, 404, JSON.stringify(res.json));
  assert.equal(res.json.code, 'NOT_FOUND');
  assert.equal(existsSync(target), false);
});

test('cleanupOnly 遇到重建目录返回冲突且保留原 intent，不删除新内容', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'cleanup-only-recreated');
  mkdirSync(target, { recursive: true });
  const syncUser = db.getUserByUsername('sync-user')!;
  db.recordWorkspaceCleanupIntent(target, [], syncUser.id);
  const res = await post('/gateway/api/fs/delete-directory', { path: target, cleanupOnly: true }, adminCCookie);
  assert.equal(res.status, 409, JSON.stringify(res.json));
  assert.equal(res.json.code, 'CLEANUP_RETRY_CONFLICT');
  assert.equal(existsSync(target), true, 'cleanupOnly 绝不能删除重建后的新目录');
  assert.notEqual(db.findWorkspaceCleanupIntent(target), null, '冲突时旧 intent 仍需保留供后续完整流程收敛');
  db.clearWorkspaceCleanupIntent(target);
  rmSync(target, { recursive: true, force: true });
});

test('清理意图无法持久化：返回显式不可重试 code，不虚假宣称可重试', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-intent-nosave');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-intent-nosave', target, ['sess-intent-nosave']);
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, target);

  const originalCleanup = db.cleanupDeletedWorkspaceTree;
  const originalRecord = db.recordWorkspaceCleanupIntent;
  db.cleanupDeletedWorkspaceTree = () => { throw new Error('injected cleanup failure'); };
  db.recordWorkspaceCleanupIntent = () => { throw new Error('injected intent persistence failure'); };
  let res: { status: number; json: Record<string, unknown> };
  try {
    res = await del(target, adminBCookie);
  } finally {
    db.cleanupDeletedWorkspaceTree = originalCleanup;
    db.recordWorkspaceCleanupIntent = originalRecord;
  }
  assert.equal(res.status, 500, JSON.stringify(res.json));
  assert.equal(res.json.code, 'DB_CLEANUP_FAILED_NO_RETRY');
  assert.equal(res.json.retryable, false);
  assert.equal(res.json.deleted, target);
  assert.equal(existsSync(target), false);
  assert.ok((res.json.warnings as string[]).some((warning) => warning.includes('人工')));
  assert.equal(db.findWorkspaceCleanupIntent(target), null);
  // 收尾：本用例残留的 ownership 行不留给后续用例
  db.removeUserWorkspace(syncUser.id, target);
});

test('别名：注册路径是指向被删目录的符号链接也命中（尽力 realpath）', async (t) => {
  resetUpstreamProbe();
  const realTarget = path.join(rootDir, 'sync-alias-real');
  const link = path.join(rootDir, 'sync-alias-link');
  mkdirSync(realTarget, { recursive: true });
  try {
    symlinkSync(realTarget, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    t.skip('当前环境不允许创建目录符号链接');
    return;
  }
  registerWorkspace('ws-alias', link);

  const res = await del(realTarget, adminCCookie);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.deepEqual(workspaceSyncReport(res.json).deleted, ['ws-alias']);
  assert.equal(existsSync(realTarget), false);
});

test('Windows 大小写不敏感：DB 中不同大小写的路径随目录删除清理', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('仅在 Windows 上可验证');
    return;
  }
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-case');
  mkdirSync(target, { recursive: true });
  const upper = target.toUpperCase();
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, upper);
  db.setPermissions(syncUser.id, {
    allowedFolders: [upper], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
  });

  const res = await del(target, adminCCookie);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(existsSync(target), false);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(upper)), false);
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, ['__deny__']);
});

// ── 审计回归：DB 别名清理 / 并发删除竞态 / pending 授权清理 / 复核不可用 ──

test('DB 别名清理：归属与白名单存别名时随真实目录删除清理，且重试准入与清理同口径', async (t) => {
  resetUpstreamProbe();
  const real = path.join(rootDir, 'sync-dbalias-real');
  const sub = path.join(real, 'sub');
  const link = path.join(rootDir, 'sync-dbalias-link');
  const keep = path.join(rootDir, 'sync-dbalias-keep');
  mkdirSync(sub, { recursive: true });
  mkdirSync(keep, { recursive: true });
  try {
    symlinkSync(real, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch {
    t.skip('当前环境不允许创建目录符号链接');
    return;
  }
  const syncUser = db.getUserByUsername('sync-user')!;
  // DB 行存“别名/sub”形态：只有 realpath 归位（父目录回退）才能命中被删的真实根。
  const aliasRow = path.join(link, 'sub');
  db.addUserWorkspace(syncUser.id, aliasRow);
  db.setPermissions(syncUser.id, {
    allowedFolders: [aliasRow, keep], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
    allowedSessionIds: [],
  });

  // 第一次注入 DB 清理失败：目录已删但别名行必须保留（事务回滚），契约可重试。
  const originalCleanup = db.cleanupDeletedWorkspaceTree;
  db.cleanupDeletedWorkspaceTree = () => { throw new Error('injected alias cleanup failure'); };
  let first: { status: number; json: Record<string, unknown> };
  try {
    first = await del(sub, adminBCookie);
  } finally {
    db.cleanupDeletedWorkspaceTree = originalCleanup;
  }
  assert.equal(first.status, 500, JSON.stringify(first.json));
  assert.equal(first.json.code, 'DB_CLEANUP_FAILED');
  assert.equal(first.json.retryable, true);
  assert.equal(existsSync(sub), false);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(aliasRow)), true);

  // 重试：真实路径已不存在；准入必须凭别名行归位放行，DB 清理也必须命中同一别名行。
  const retry = await del(sub, adminBCookie);
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.alreadyDeleted, true);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(aliasRow)), false);
  assert.deepEqual(db.getPermissions(syncUser.id)!.allowed_folders, [keep.replace(/\\/g, '/')]);
});

test('并发删除竞态：快照后路径消失走幂等清理（非 404），注册表/DB 仍收敛', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-race');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-race', target, ['sess-race']);
  const syncUser = db.getUserByUsername('sync-user')!;
  db.addUserWorkspace(syncUser.id, target);

  // 挂起首次快照回包：网关已通过删除前准入、正等 baseline；此时目录被并发删除。
  let release!: () => void;
  followBaselineGate = new Promise<void>((resolve) => { release = resolve; });
  const pending = del(target, adminBCookie);
  await waitForCondition(() => followOpens.length > 0, 3_000);
  rmSync(target, { recursive: true, force: true });
  release();
  followBaselineGate = null;

  const res = await pending;
  // 绝不能 404 跳过清理：目录已不存在 = 幂等已删除路径，注册表/DB 联动照常收尾。
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(res.json.alreadyDeleted, true);
  assert.equal(existsSync(target), false);
  const workspaces = res.json.workspaces as { deleted: string[]; failed: unknown[] };
  assert.deepEqual(workspaces.deleted, ['ws-race']);
  assert.equal(workspaces.failed.length, 0);
  assert.equal(db.listUserWorkspacePaths(syncUser.id).includes(normalizePath(target)), false);
});

test('删除树内 pending 目录：所有 owner 的临时授权被清理并失效 mux（不依赖 DB 清理）', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-pending-tree');
  const keep = path.join(rootDir, 'sync-pending-keep');
  const pendingDir = path.join(target, 'made');
  mkdirSync(pendingDir, { recursive: true });
  mkdirSync(keep, { recursive: true });

  // subuser 先不限目录（[]）以便成功记账 pending；随后收紧为仅 keep。
  // 该用户没有任何指向被删树内的 DB 行（allowed_folders/ownership），
  // 旧实现的 DB invalidation 不会覆盖它 —— 只有 pending 扫描能看到。
  const sub = db.getUserByUsername('subuser')!;
  db.setPermissions(sub.id, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
  });
  const mux = await followWorkspaceBaseline(subuserCookie);
  const closedCode = new Promise<number>((resolve) => mux.on('close', (code: number) => resolve(code)));

  // 官方目录创建 RPC：按真实契约 path=父目录 + name=单段；假上游回 join(path, name) → 网关记账 pending。
  const created = await post('/api/directoryPicker/createDirectory', {
    type: 'client-request',
    rpcId: 'rpc-mkdir-pending',
    method: 'directoryPicker/createDirectory',
    payload: { args: { path: target, name: 'made' } },
  }, subuserCookie);
  assert.equal(created.status, 200, JSON.stringify(created.json));

  db.setPermissions(sub.id, {
    allowedFolders: [keep], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: true,
    banned: false, sandboxMode: null, disabledSessions: [],
  });

  const res = await del(target, adminBCookie);
  assert.equal(res.status, 200, JSON.stringify(res.json));
  assert.equal(existsSync(target), false);
  // pending owner 必须被纳入失效：旧 mux baseline 不能继续授权树内目录。
  assert.equal(await Promise.race([
    closedCode,
    new Promise<number>((resolve) => setTimeout(() => resolve(-1), 1_500)),
  ]), 1012);

  // 路径被重建后，陈旧 pending 不得再放行工作区登记（清理后走常规白名单判定 → 403）。
  mkdirSync(pendingDir, { recursive: true });
  const denied = await post('/api/workspace/create', {
    type: 'client-request',
    rpcId: 'rpc-register-after-delete',
    method: 'workspace/create',
    payload: { args: { path: pendingDir } },
  }, subuserCookie);
  assert.equal(denied.status, 403, JSON.stringify(denied.json));
});

test('删除后复核不可用：workspace/follow 重读被拒 → 计失败（no false success）', async () => {
  resetUpstreamProbe();
  const target = path.join(rootDir, 'sync-verify-down');
  mkdirSync(target, { recursive: true });
  registerWorkspace('ws-verify-down', target);
  // 只放行首次快照连接；删除后的复核连接被上游拒绝 → 无法确认移除，必须报告失败。
  followUpgradeBudget = 1;
  const res = await del(target, adminBCookie);
  assert.equal(res.status, 500, JSON.stringify(res.json));
  assert.equal(res.json.code, 'WORKSPACE_SYNC_FAILED');
  assert.equal(res.json.retryable, true);
  assert.equal(res.json.deleted, target);
  assert.equal(existsSync(target), false);
  assert.equal(res.json.registrySnapshot, 'upstream');
  assert.notEqual(db.findWorkspaceCleanupIntent(target), null, '复核不可用时必须保留持久化重试意图');
  const workspaces = res.json.workspaces as {
    deleted: string[];
    failed: Array<{ workspaceId: string; path: string; error: string }>;
  };
  assert.deepEqual(workspaces.deleted, []);
  assert.equal(workspaces.failed.length, 1);
  assert.equal(workspaces.failed[0].workspaceId, 'ws-verify-down');
  assert.match(workspaces.failed[0].error, /verification unavailable/);

  // 复核通道恢复后，条目已在首次删除中被上游移除；cleanupOnly 只需重读权威快照
  // 并清理持久化 intent，不得再次执行物理删除。
  followUpgradeBudget = null;
  const retry = await post('/gateway/api/fs/delete-directory', { path: target, cleanupOnly: true }, adminBCookie);
  assert.equal(retry.status, 200, JSON.stringify(retry.json));
  assert.equal(retry.json.cleanupOnly, true);
  assert.equal(retry.json.alreadyDeleted, true);
  assert.equal(db.findWorkspaceCleanupIntent(target), null);
});

// ── 选择器客户端契约（目录已删但联动部分失败时仍移除行并展示警告）──

test('选择器契约：部分失败（已删但同步失败）仍确认删除并携带警告', () => {
  const partial = interpretDeleteResponse(false, {
    ok: false,
    code: 'WORKSPACE_SYNC_FAILED',
    error: '目录已删除，但 1 个侧边栏工作区未能确认从 DSH 注册表移除',
    deleted: '/data/ws',
    warnings: ['未能读取 DSH 工作区注册表'],
    workspaces: { deleted: [], failed: [{ workspaceId: 'ws-1' }], unverified: [] },
  });
  // 行必须被移除（deleted=true 驱动 dropRowAfterDelete），同时展示错误+警告
  assert.equal(partial.deleted, true);
  assert.equal(partial.error, true);
  // workspace 同步失败不宣称可重试（重试准入可能已无残留引用）
  assert.equal(partial.retry, false);
  assert.match(partial.message!, /未能读取 DSH 工作区注册表/);
  assert.match(partial.message!, /目录已删除/);

  // 未删除的失败保留行
  const notDeleted = interpretDeleteResponse(false, { ok: false, code: 'NOT_FOUND', error: '目录不存在' });
  assert.deepEqual(notDeleted, { deleted: false, message: '目录不存在', error: true, retry: false });

  // 成功但有警告（如注册表快照降级）：仍移除行并展示警告
  const warned = interpretDeleteResponse(true, { ok: true, deleted: '/data/ws', warnings: ['快照不可用'] });
  assert.deepEqual(warned, { deleted: true, message: '快照不可用', error: true, retry: false });

  // 干净成功：无提示
  assert.deepEqual(interpretDeleteResponse(true, { ok: true, deleted: '/data/ws', warnings: [] }), {
    deleted: true, message: null, error: false, retry: false,
  });
});

test('选择器契约：DB_CLEANUP_FAILED 保留墓碑行与可达重试入口（retry=true）', () => {
  const dbFailed = interpretDeleteResponse(false, {
    ok: false,
    code: 'DB_CLEANUP_FAILED',
    retryable: true,
    error: '目录已删除，但插件数据库清理失败；请重试删除以完成授权清理',
    deleted: '/data/ws',
    warnings: ['插件数据库中的工作区授权清理失败，本响应不代表清理完成；请对同一路径重试删除以完成清理'],
  });
  // 目录确实已删（不能伪装成未删除）……
  assert.equal(dbFailed.deleted, true);
  // ……但必须保留重试入口（客户端据此注入墓碑行 + 单击重试）
  assert.equal(dbFailed.retry, true);
  assert.equal(dbFailed.error, true);
  assert.match(dbFailed.message!, /重试/);

  // 兼容只带 code 的服务端（无 retryable 字段）
  assert.equal(
    interpretDeleteResponse(false, { ok: false, code: 'DB_CLEANUP_FAILED', deleted: '/data/ws', error: '清理失败' }).retry,
    true,
  );
  // 清理意图无法持久化时服务端改用显式不可重试 code：不得再假装可重试
  assert.equal(
    interpretDeleteResponse(false, { ok: false, code: 'DB_CLEANUP_FAILED_NO_RETRY', retryable: false, deleted: '/data/ws', error: 'x' }).retry,
    false,
  );
  // 非 2xx 且没有 deleted 路径时不算已删除，也不可重试
  assert.deepEqual(interpretDeleteResponse(false, { ok: false, code: 'DB_CLEANUP_FAILED', error: 'x' }), {
    deleted: false, message: 'x', error: true, retry: false,
  });
});
