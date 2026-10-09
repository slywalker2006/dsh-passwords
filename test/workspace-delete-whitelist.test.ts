// 子用户自建工作区删除后的白名单/内存收口回归测试（真实 HTTP + 本地 DSH 上游桩）。
//
// 复现并锁定的缺陷（alpha.1 workspace/delete）：
//   1) 子用户 workspace/create 成功后 addUserWorkspace + addAllowedFolder 把该目录写入
//      allowed_folders；
//   2) alpha.1 workspace/delete 成功回调只调 removeUserWorkspace，白名单条目残留；
//   3) 残留条目让已删除工作区继续通过 folderAllowed，可再次 session/create 或
//      workspace/create 重新登记。
//
// 断言口径：
//   · 删除后归属行、对应自建白名单条目、工作区会话授权一并清理；
//   · 升级兼容：升级前已存在、无 user_auto_granted_folders 来源标记的自建条目无法与
//     管理员授权可靠区分，删除时保留（不误删管理员授权），残留需管理员手动清理，
//     本次不声称完全回收（DB 层回归见 test/db-permissions.test.ts）；
//   · 删除后精确回收自建白名单条目，保留管理员分配的授权根（不能留空数组 = 不限目录 fail-open）；
//   · 管理员分配的父目录/其它目录精确保留（不误删管理员分配）；
//   · 残留 pending 目录窗口不再能重新登记同一路径；重新创建同名目录后可再次登记；
//   · 删除后按旧路径/旧 workspaceId 发起 session/create 一律 403。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import { folderAllowed, normalizePath } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

const DUMMY_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';
const HOME = normalizePath(os.homedir());
const SYNTH_ROOT = normalizePath(`${HOME}/dshpw-wsdel-synth`);

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

test('子用户 workspace/delete 清理自建白名单且不误删管理员分配', async () => {
  const appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-wsdel-app-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  db.init();
  let upstream: http.Server | null = null;
  let gateway: http.Server | null = null;
  try {
    const restricted = (folders: string[], allowCreate: boolean) => ({
      allowedFolders: folders, hourlyTokenLimit: null, dailyMinutesLimit: null,
      allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: allowCreate,
      allowedAgentPresets: null, banned: false, sandboxMode: null, disabledSessions: [],
    });

    // 场景 A：管理员分配授权根 HOME，子用户在根内用目录选择器自建子工作区。
    const denyCreator = db.createUser('wsdel-deny-creator', DUMMY_HASH, 'user');
    db.setPermissions(denyCreator.id, restricted([HOME], true));
    // 场景 B：管理员分配了父目录 /assigned 与另一个目录 /other。
    const assignedOwner = db.createUser('wsdel-assigned-owner', DUMMY_HASH, 'user');
    db.setPermissions(assignedOwner.id, restricted([`${SYNTH_ROOT}/assigned`, `${SYNTH_ROOT}/other`], true));
    // 场景 C：管理员同时分配授权根与一个尚未存在的精确目录；用户随后在根内创建并登记它。
    const exactPath = `${HOME}/dshpw-wsdel-exact`;
    const exactOwner = db.createUser('wsdel-exact-owner', DUMMY_HASH, 'user');
    db.setPermissions(exactOwner.id, restricted([HOME, exactPath], true));

    let workspaceSeq = 0;
    upstream = await new Promise<http.Server>((resolve) => {
      const server = http.createServer((req, res) => {
        void (async () => {
          const url = req.url ?? '';
          const reply = (value: unknown) => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ type: 'server-response', result: { ok: true, value } }));
          };
          if (req.method === 'POST' && url.startsWith('/api/directoryPicker/createDirectory')) {
            const args = await readArgs(req);
            const parent = typeof args.path === 'string' ? args.path.replace(/\\/g, '/') : '';
            const name = typeof args.name === 'string' ? args.name : '';
            reply(`${parent}/${name}`);
            return;
          }
          if (req.method === 'POST' && url.startsWith('/api/workspace/create')) {
            const args = await readArgs(req);
            const request = args.request as Record<string, unknown> | undefined;
            const target = typeof request?.path === 'string' ? request.path : '';
            workspaceSeq += 1;
            reply({ created: true, workspace: { workspaceId: `wsdel-${workspaceSeq}`, path: target, title: 't', sessionIds: [] } });
            return;
          }
          if (req.method === 'POST' && url.startsWith('/api/workspace/delete')) {
            reply({ deleted: true });
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
    const denyCookie = cookieFor(denyCreator);
    const assignedCookie = cookieFor(assignedOwner);
    const exactCookie = cookieFor(exactOwner);

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
    const deleteWorkspace = (cookie: string, workspaceId: string, rpcId: string) =>
      jsonBody('POST', gatewayPort, '/api/workspace/delete', {
        type: 'client-request', rpcId, method: 'workspace/delete',
        payload: { args: { request: { workspaceId } } },
      }, cookie);
    const createSessionByPath = (cookie: string, target: string, rpcId: string) =>
      jsonBody('POST', gatewayPort, '/api/session.create', {
        type: 'client-request', rpcId, method: 'session/create',
        payload: { args: { request: { path: target } } },
      }, cookie);
    const createSessionById = (cookie: string, workspaceId: string, rpcId: string) =>
      jsonBody('POST', gatewayPort, '/api/session.create', {
        type: 'client-request', rpcId, method: 'session/create',
        payload: { args: { request: { workspaceId } } },
      }, cookie);

    // ── 场景 A：授权根内自建 → 删除后精确回收该自建条目，且残留 pending 不得重新登记 ──
    const denyPath = `${HOME}/wsdel-deny-created`;
    assert.equal((await createDirectory(denyCookie, HOME, 'wsdel-deny-created', 'a-mkdir')).status, 200);
    const denyCreate = await createWorkspace(denyCookie, denyPath, 'a-create');
    assert.equal(denyCreate.status, 200, denyCreate.body);
    assert.deepEqual(
      db.getPermissions(denyCreator.id)?.allowed_folders,
      [HOME, denyPath],
      '自建成功后应把新建目录并入白名单，并保留管理员分配的授权根',
    );
    assert.ok(db.listUserWorkspacePaths(denyCreator.id).includes(denyPath), '应写入归属行');

    assert.equal((await deleteWorkspace(denyCookie, 'wsdel-1', 'a-delete')).status, 200);
    const denyAfter = db.getPermissions(denyCreator.id)!;
    assert.deepEqual(denyAfter.allowed_folders, [HOME], '删后应精确回收该自建条目，保留授权根');
    assert.equal(db.listUserWorkspacePaths(denyCreator.id).includes(denyPath), false, '归属行应被清理');
    assert.equal(folderAllowed(denyPath, denyAfter.allowed_folders), true,
      '授权根仍覆盖其子目录：删除自建工作区不收回根级读取授权');

    assert.equal((await createWorkspace(denyCookie, denyPath, 'a-reregister')).status, 403, '残留 pending 不得让同一路径重新登记');
    // 已删除 workspaceId：映射已清，网关 fail-closed（403 直接拒绝，或 503 等待基线后仍解析不到）。
    const staleById = await createSessionById(denyCookie, 'wsdel-1', 'a-session-id');
    assert.notEqual(staleById.status, 200, '已删除 workspaceId 映射不得复用（不得成功建会话）');
    assert.ok([403, 503].includes(staleById.status), `fail-closed 应为 403/503，实际 ${staleById.status}`);

    // 重新通过目录选择器创建同名目录后，登记通道恢复正常（墓碑解除）。
    assert.equal((await createDirectory(denyCookie, HOME, 'wsdel-deny-created', 'a-remkdir')).status, 200);
    const denyReCreate = await createWorkspace(denyCookie, denyPath, 'a-recreate');
    assert.equal(denyReCreate.status, 200, denyReCreate.body);
    assert.ok(db.getPermissions(denyCreator.id)!.allowed_folders.includes(denyPath), '重建后应重新登记');

    // ── 场景 B：删除自建子目录，管理员分配的父目录与其它目录精确保留 ──────────
    const childPath = `${SYNTH_ROOT}/assigned/child`;
    assert.equal((await createDirectory(assignedCookie, `${SYNTH_ROOT}/assigned`, 'child', 'b-mkdir')).status, 200);
    const childCreate = await createWorkspace(assignedCookie, childPath, 'b-create');
    assert.equal(childCreate.status, 200, childCreate.body);
    assert.deepEqual(
      db.getPermissions(assignedOwner.id)?.allowed_folders,
      [`${SYNTH_ROOT}/assigned`, `${SYNTH_ROOT}/other`, childPath],
      '自建子目录应并入白名单，且保留两个管理员分配目录',
    );
    const assignedWorkspaceId = `wsdel-${workspaceSeq}`;

    assert.equal((await deleteWorkspace(assignedCookie, assignedWorkspaceId, 'b-delete')).status, 200);
    assert.deepEqual(
      db.getPermissions(assignedOwner.id)?.allowed_folders,
      [`${SYNTH_ROOT}/assigned`, `${SYNTH_ROOT}/other`],
      '只回收精确相等的自建条目，管理员分配的父目录/其它目录不得被误删',
    );
    assert.equal(db.listUserWorkspacePaths(assignedOwner.id).includes(childPath), false, '归属行应被清理');
    // 注意：管理员分配的父目录仍合法覆盖其子目录（folderAllowed 子树语义），因此这里
    // 不再断言子路径 403；关键是精确的自建条目被回收、父目录未被误删。
    assert.equal(folderAllowed(childPath, db.getPermissions(assignedOwner.id)!.allowed_folders), true,
      '管理员分配的父目录仍覆盖子目录');

    // ── 场景 C：管理员先分配的同路径条目，自建登记不得使其被回收 ──────────────
    assert.equal((await createDirectory(exactCookie, HOME, 'dshpw-wsdel-exact', 'c-mkdir')).status, 200);
    const exactCreate = await createWorkspace(exactCookie, exactPath, 'c-create');
    assert.equal(exactCreate.status, 200, exactCreate.body);
    assert.deepEqual(db.getPermissions(exactOwner.id)?.allowed_folders, [HOME, exactPath], '已分配路径不得因自建登记而重复/变源');
    const exactWorkspaceId = `wsdel-${workspaceSeq}`;

    assert.equal((await deleteWorkspace(exactCookie, exactWorkspaceId, 'c-delete')).status, 200);
    assert.deepEqual(db.getPermissions(exactOwner.id)?.allowed_folders, [HOME, exactPath],
      '管理员精确分配的白名单条目不得因自建工作区删除而被误删');
    assert.equal(folderAllowed(exactPath, db.getPermissions(exactOwner.id)!.allowed_folders), true,
      '管理员精确分配仍放行');
    assert.equal(db.listUserWorkspacePaths(exactOwner.id).includes(exactPath), false, '归属行仍应被清理');

    // ── 场景 D：共享父目录根下的自建边界（避免不必要跨租户 DoS） ──────────
    // A、B 均被管理员分配同一个共享父目录根。A 在其中自建子工作区后，只应挡住 B
    // 伸进 A 子树的路径；共享根本身与兄弟目录必须仍然可用，且把工作区建在共享根上
    // 不得把它变成私有归属（否则一个租户就能整体挡住另一个租户）。
    const sharedRoot = `${SYNTH_ROOT}/shared`;
    const sharedA = db.createUser('wsdel-shared-a', DUMMY_HASH, 'user');
    db.setPermissions(sharedA.id, restricted([sharedRoot], true));
    const sharedB = db.createUser('wsdel-shared-b', DUMMY_HASH, 'user');
    db.setPermissions(sharedB.id, restricted([sharedRoot], true));
    const sharedACookie = cookieFor(sharedA);
    const sharedBCookie = cookieFor(sharedB);

    // D1：A 在共享根下自建子工作区并取得归属。
    const aChild = `${sharedRoot}/aproj`;
    assert.equal((await createDirectory(sharedACookie, sharedRoot, 'aproj', 'd-mkdir-a')).status, 200);
    assert.equal((await createWorkspace(sharedACookie, aChild, 'd-create-a')).status, 200);
    assert.ok(db.listUserWorkspacePaths(sharedA.id).includes(aChild), 'A 应拥有其自建子工作区');

    // D2：B 不得伸进 A 的子树（现有拒绝边界）。
    assert.equal((await createWorkspace(sharedBCookie, aChild, 'd-b-in-a')).status, 403,
      'B 不得登记/占用 A 自建子树');
    assert.equal((await createSessionByPath(sharedBCookie, aChild, 'd-b-session-a')).status, 403,
      '共享根覆盖 A 子树时 B 仍不得在其中建会话（403 来自归属重叠而非白名单）');

    // D3：B 可在共享根下建兄弟工作区：不因 A 的自建被整体挡住（无多余跨租户 DoS）。
    const bChild = `${sharedRoot}/bproj`;
    assert.equal((await createDirectory(sharedBCookie, sharedRoot, 'bproj', 'd-mkdir-b')).status, 200);
    assert.equal((await createWorkspace(sharedBCookie, bChild, 'd-create-b')).status, 200,
      '兄弟目录登记不得被 A 的工作区阻断');
    assert.ok(db.listUserWorkspacePaths(sharedB.id).includes(bChild), 'B 应拥有其自建兄弟工作区');

    // D4：把工作区直接建在被分配的共享根上，不得使共享根变成私有归属，
    //     否则同一共享根下的其它租户会被整体挡住（跨租户 DoS）。
    assert.equal((await createWorkspace(sharedBCookie, sharedRoot, 'd-b-root')).status, 200);
    assert.equal(db.listUserWorkspacePaths(sharedB.id).includes(sharedRoot), false,
      '被分配的共享父目录不得因 workspace/create 变成私有工作区');
    assert.equal((await createWorkspace(sharedACookie, sharedRoot, 'd-a-root')).status, 200,
      'A 仍可继续使用共享根（未被 B 阻断）');
  } finally {
    gateway?.close();
    upstream?.close();
    try { db.close(); } catch { /* 已关闭 */ }
    try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
  }
});
