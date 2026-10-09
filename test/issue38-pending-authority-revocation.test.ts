// Issue #38 pendingCreatedDirectories 撤权/换根/关开关残留回归（真实 HTTP + 本地 DSH 上游桩）。
//
// 统一目录授权：allowed_folders 是唯一的读取/创建范围，没有独立创建根。pending 目录信任窗口
// （gateway.ts，30 分钟 TTL）在 directoryPicker/createDirectory 成功后记账，是 workspace/create
// 「刚创建目录」登记通道的凭据之一（另有精确分配与自建子树）。撤权（换 allowed_folders）或关闭
// allowWorkspaceCreate 后必须立即作废，不能靠 TTL 慢慢过期，否则旧 pending 仍会替
// workspace/create 放行登记（登记门禁本身不看 allowWorkspaceCreate）。
//
// 断言口径：
//   · 换根 / 撤销白名单 / 关闭 allowWorkspaceCreate 三种权限变更后，变更前已记账的 pending
//     目录一律 403；未变更的同值保存不得清表（负向对照，pending 仍可登记）；
//   · 未做权限变更的对照用户走同一流程仍 200（证明 403 来自清表，而非该路径本就不可登记）。
import { test } from 'node:test';
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

interface Reply {
  status: number;
  body: string;
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

function jsonBody(method: string, port: number, pathname: string, body: unknown, cookie: string): Promise<Reply> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1', port, method, path: pathname,
        headers: { cookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) },
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

/** 真实临时目录的 canonical（realpath + 归一）形态：作为创建根/父路径时与网关同口径。 */
function realTempDir(prefix: string): string {
  return normalizePath(realpathSync(mkdtempSync(path.join(os.tmpdir(), prefix))));
}

test('权限变更/换根/关闭新建后旧 pending 不得继续 workspace/create 登记', async () => {
  const appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-i38-app-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  db.init();
  let upstream: http.Server | null = null;
  let gateway: http.Server | null = null;
  // 创建根与 appDir 分离：appDir 因 dbPath 祖先链落在敏感基内，不能当创建根。
  const roots: string[] = [];
  const freshRoot = (prefix: string): string => {
    const dir = realTempDir(prefix);
    roots.push(dir);
    return dir;
  };
  try {
    const setPerms = (userId: number, folders: string[], allowCreate: boolean): void => {
      db.setPermissions(userId, {
        allowedFolders: folders, hourlyTokenLimit: null, dailyMinutesLimit: null,
        allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: allowCreate,
        allowedAgentPresets: null, banned: false, sandboxMode: null, disabledSessions: [],
      });
    };

    db.createUser('i38-admin', DUMMY_HASH, 'admin');
    // 对照：同一 pending→登记流程，但不做任何权限变更。
    const control = db.createUser('i38-control', DUMMY_HASH);
    const rootControl = freshRoot('dshpw-i38-ctl-');
    setPerms(control.id, [rootControl], true);

    const offUser = db.createUser('i38-off', DUMMY_HASH);
    const rootOff = freshRoot('dshpw-i38-off-');
    setPerms(offUser.id, [rootOff], true);

    const rootUser = db.createUser('i38-root', DUMMY_HASH);
    const rootR1 = freshRoot('dshpw-i38-r1-');
    const rootR2 = freshRoot('dshpw-i38-r2-');
    setPerms(rootUser.id, [rootR1], true);

    const folderUser = db.createUser('i38-folder', DUMMY_HASH);
    const rootFolder = freshRoot('dshpw-i38-fld-');
    setPerms(folderUser.id, [rootFolder], true);

    // 负向对照：同值保存的用户。
    const sameUser = db.createUser('i38-same', DUMMY_HASH);
    const rootSame = freshRoot('dshpw-i38-same-');
    setPerms(sameUser.id, [rootSame], true);

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
            // 权限保存时的可分配资源核验探针：返回空的权威清单（本地真实目录走回退放行）。
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
            reply({ created: true, workspace: { workspaceId: `i38-${workspaceSeq}`, path: target, title: 't', sessionIds: [] } });
            return;
          }
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end('{}');
        })();
      });
      listen(server).then(() => resolve(server));
    });
    const upstreamPort = (upstream.address() as { port: number }).port;

    const config: PlatformConfig = {
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
    const gatewayPort = await listen(gateway);

    const cookieFor = (user: { id: number; username: string }): string =>
      `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
    const adminCookie = cookieFor(db.getUserByUsername('i38-admin')!);
    const controlCookie = cookieFor(control);
    const offCookie = cookieFor(offUser);
    const rootCookie = cookieFor(rootUser);
    const folderCookie = cookieFor(folderUser);
    const sameCookie = cookieFor(sameUser);

    const createDirectory = (cookie: string, parent: string, name: string, rpcId: string) =>
      jsonBody('POST', gatewayPort, '/api/directoryPicker/createDirectory', {
        type: 'client-request', rpcId, method: 'directoryPicker/createDirectory',
        payload: { args: { path: parent, name } },
      }, cookie);
    const createWorkspace = (cookie: string, target: string, rpcId: string) =>
      jsonBody('POST', gatewayPort, '/api/workspace/create', {
        type: 'client-request', rpcId, method: 'workspace/create',
        payload: { args: { request: { path: target } } },
      }, cookie);
    const savePerms = (body: Record<string, unknown>) =>
      jsonBody('POST', gatewayPort, '/gateway/api/permissions', body, adminCookie);

    // ── 对照：pending 记账后直接登记必须成功（证明本 harness 的登记通道可用） ──
    assert.equal((await createDirectory(controlCookie, rootControl, 'proj', 'ctl-mk')).status, 200);
    const controlCreate = await createWorkspace(controlCookie, `${rootControl}/proj`, 'ctl-create');
    assert.equal(controlCreate.status, 200, controlCreate.body);

    // ── 场景 1：关闭 allowWorkspaceCreate ──────────────────────────────────
    const offPending = `${rootOff}/frozen`;
    assert.equal((await createDirectory(offCookie, rootOff, 'frozen', 'off-mk')).status, 200);
    const offSave = await savePerms({ userId: offUser.id, allowWorkspaceCreate: false });
    assert.equal(offSave.status, 200, offSave.body);
    assert.equal(db.getPermissions(offUser.id)?.allow_workspace_create, false, '开关应已落库为 false');
    const offCreateProbe = await createWorkspace(offCookie, offPending, 'off-create');

    assert.equal(offCreateProbe.status, 403,
      '关闭 allowWorkspaceCreate 后，旧 pending 不得继续登记');

    // ── 场景 2：换根（allowed_folders rootR1 → rootR2） ────────────────────
    const rootPending = `${rootR1}/proj`;
    assert.equal((await createDirectory(rootCookie, rootR1, 'proj', 'root-mk')).status, 200);
    const rootSave = await savePerms({ userId: rootUser.id, allowedFolders: [rootR2] });
    assert.equal(rootSave.status, 200, rootSave.body);
    assert.deepEqual(db.getPermissions(rootUser.id)?.allowed_folders, [rootR2], '创建范围应已换为新根');
    assert.equal((await createWorkspace(rootCookie, rootPending, 'root-create')).status, 403,
      '换根后，旧根下的 pending 不得继续登记');

    // ── 场景 3：撤销白名单（撤权，allowed_folders → __deny__） ────────────────
    const folderPending = `${rootFolder}/proj`;
    assert.equal((await createDirectory(folderCookie, rootFolder, 'proj', 'fld-mk')).status, 200);
    const folderSave = await savePerms({ userId: folderUser.id, allowedFolders: ['__deny__'] });
    assert.equal(folderSave.status, 200, folderSave.body);
    assert.deepEqual(db.getPermissions(folderUser.id)?.allowed_folders, ['__deny__'], '白名单应已撤销');
    assert.equal((await createWorkspace(folderCookie, folderPending, 'fld-create')).status, 403,
      '撤权后，旧 pending 不得继续登记');

    // ── 负向对照：同值保存不是撤权，不得清表 ──────────────────────────────
    const keptPending = `${rootSame}/kept`;
    assert.equal((await createDirectory(sameCookie, rootSame, 'kept', 'same-mk')).status, 200);
    const sameSave = await savePerms({
      userId: sameUser.id, allowedFolders: [rootSame], allowWorkspaceCreate: true,
    });
    assert.equal(sameSave.status, 200, sameSave.body);
    assert.equal((await createWorkspace(sameCookie, keptPending, 'same-create')).status, 200,
      '同值保存不是撤权，pending 应保持有效');
  } finally {
    gateway?.close();
    upstream?.close();
    try { db.close(); } catch { /* 已关闭 */ }
    for (const dir of roots) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
    }
    try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
  }
});
