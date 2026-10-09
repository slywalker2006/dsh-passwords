// 多人会话安全：await 后重新校验（真实 HTTP + 本地 DSH 上游桩）。
//
// 覆盖两处「请求校验通过 → await 上游 → 用旧快照落库/转发」的 TOCTOU：
//   1) 受限子用户 /session/prompt、/subagents/prompt 的沙盒确认（applySandboxToSession）
//      是一次 await。管理员在等待窗口收紧 allowed_models / allowed_agent_presets 时，
//      这两类变更不推进授权 epoch（只有子集/会话授权变更才 fence），旧快照会把已撤销的
//      模型/预设放行进上游。修复后必须用当前 live 权限行复核，fail-closed 403。
//   2) 子用户 /workspace/create 回包落库（addUserWorkspace/addAllowedFolder）前，另一子
//      用户可能已在等待窗口登记同路径/祖先子树，或目标实为敏感基。修复后必须复核
//      workspaceSubtreeOverlap 与敏感基，命中则跳过登记（响应本身仍原样透传）。
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

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

function call(port: number, pathname: string, body: unknown, cookie: string): Promise<Reply> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1', port, method: 'POST', path: pathname,
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

/** 真实临时目录的 canonical（realpath + 归一）形态：与网关同口径，且避开敏感基。 */
function realTempDir(prefix: string): string {
  return normalizePath(realpathSync(mkdtempSync(path.join(os.tmpdir(), prefix))));
}

test('沙盒/工作区 register await 后必须用 live 权限与所有权复核', async () => {
  const appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-await-app-'));
  const appDataDir = path.join(appDir, 'data');
  mkdirSync(appDataDir, { recursive: true });
  const dbPath = path.join(appDataDir, 'test.db');
  const db = new Database(dbPath, createFieldCrypto('test-key', 'test-key'));
  db.init();
  let upstream: http.Server | null = null;
  let gateway: http.Server | null = null;
  const scratch: string[] = [];
  // appDir 因 dbPath 祖先链落在敏感基内，不能当工作区/创建根。
  const freshDir = (prefix: string): string => {
    const dir = realTempDir(prefix);
    scratch.push(dir);
    return dir;
  };

  // 沙盒内部调用闸门：设置后 applySandboxToSession 会挂起直到 resolve。
  let sandboxGate: Deferred | null = null;
  let sandboxArrived: Deferred | null = null;
  // workspace/create 回包闸门。
  let workspaceGate: Deferred | null = null;
  let workspaceArrived: Deferred | null = null;

  try {
    const setPerms = (
      userId: number,
      overrides: Partial<{
        allowedFolders: string[];
        allowWorkspaceCreate: boolean;
        allowedModels: string[] | null;
        allowedAgentPresets: string[] | null;
        sandboxMode: string | null;
      }>,
    ): void => {
      const p = db.getPermissions(userId);
      db.setPermissions(userId, {
        allowedFolders: overrides.allowedFolders ?? p?.allowed_folders ?? [],
        hourlyTokenLimit: p?.hourly_token_limit ?? null,
        dailyMinutesLimit: p?.daily_minutes_limit ?? null,
        allowUpload: p?.allow_upload ?? false,
        allowGitDownload: p?.allow_git_download ?? false,
        allowWorkspaceCreate: overrides.allowWorkspaceCreate ?? p?.allow_workspace_create ?? false,
        allowedAgentPresets: overrides.allowedAgentPresets !== undefined ? overrides.allowedAgentPresets : p?.allowed_agent_presets ?? null,
        allowedModels: overrides.allowedModels !== undefined ? overrides.allowedModels : p?.allowed_models ?? null,
        banned: p?.banned ?? false,
        sandboxMode: overrides.sandboxMode !== undefined ? overrides.sandboxMode : p?.sandbox_mode ?? null,
        disabledSessions: p?.disabled_sessions ?? [],
      });
    };

    const admin = db.createUser('await-admin', DUMMY_HASH, 'admin');
    const wsModel = freshDir('dshpw-await-model-ws-');
    const modelUser = db.createUser('await-model', DUMMY_HASH);
    setPerms(modelUser.id, {
      allowedFolders: [wsModel], sandboxMode: 'workspace-write',
      allowedModels: ['p/m'], allowedAgentPresets: null,
    });
    db.addUserSessionGrant(modelUser.id, 'model-sess');

    const wsPreset = freshDir('dshpw-await-preset-ws-');
    const presetUser = db.createUser('await-preset', DUMMY_HASH);
    setPerms(presetUser.id, {
      allowedFolders: [wsPreset], sandboxMode: 'workspace-write',
      allowedAgentPresets: ['preset-a'], allowedModels: null,
    });
    db.addUserSessionGrant(presetUser.id, 'preset-sess');

    const createRoot = freshDir('dshpw-await-create-root-');
    const wsUser = db.createUser('await-ws', DUMMY_HASH);
    setPerms(wsUser.id, { allowedFolders: [createRoot], allowWorkspaceCreate: true, sandboxMode: null });

    const peerRoot = freshDir('dshpw-await-peer-root-');
    const peer = db.createUser('await-peer', DUMMY_HASH);
    setPerms(peer.id, { allowedFolders: [peerRoot], allowWorkspaceCreate: false, sandboxMode: null });

    upstream = await new Promise<http.Server>((resolve) => {
      const server = http.createServer((req, res) => {
        void (async () => {
          const url = req.url ?? '';
          const reply = (value: unknown): void => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ type: 'server-response', result: { ok: true, value } }));
          };
          if (req.method === 'POST' && url.startsWith('/api/dsh-passwords/internal/sandbox')) {
            sandboxArrived?.resolve();
            const send = () => reply({ ok: true });
            if (sandboxGate !== null) void sandboxGate.promise.then(send);
            else send();
            return;
          }
          if (url.startsWith('/api/workspace.list')) {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({
              result: {
                value: {
                  items: [
                    { workspaceId: 'w-model', path: wsModel, title: 'model', sessionIds: ['model-sess'], archivedSessionIds: [] },
                    { workspaceId: 'w-preset', path: wsPreset, title: 'preset', sessionIds: ['preset-sess'], archivedSessionIds: [] },
                  ],
                  archivedSessionIds: [],
                },
              },
            }));
            return;
          }
          if (url.startsWith('/api/directoryPicker/createDirectory')) {
            const args = await readArgs(req);
            const parent = typeof args.path === 'string' ? args.path : '';
            const name = typeof args.name === 'string' ? args.name : '';
            reply(`${parent}/${name}`);
            return;
          }
          if (url.startsWith('/api/workspace.create')) {
            const args = await readArgs(req);
            const request = args.request as Record<string, unknown> | undefined;
            const target = typeof request?.path === 'string' ? request.path : '';
            workspaceArrived?.resolve();
            const send = () => reply({ created: true, workspace: { workspaceId: 'ws-await', path: target, title: 't', sessionIds: [] } });
            if (workspaceGate !== null) void workspaceGate.promise.then(send);
            else send();
            return;
          }
          if (url.startsWith('/api/session.selectModel')) {
            reply({ selected: { provider: 'p', model: 'm' } });
            return;
          }
          if (url.startsWith('/api/agentPresets.select')) {
            reply({ agentPreset: 'preset-a' });
            return;
          }
          if (url.startsWith('/api/session.prompt')) {
            reply({ ok: true });
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
    const modelCookie = cookieFor(db.getUserByUsername('await-model')!);
    const presetCookie = cookieFor(db.getUserByUsername('await-preset')!);
    const wsCookie = cookieFor(db.getUserByUsername('await-ws')!);
    void cookieFor(admin);

    // 建立两个受限用户的工作区/会话基线（sessionId→cwd 快照）。
    assert.equal((await call(gatewayPort, '/api/workspace.list', {}, modelCookie)).status, 200);
    assert.equal((await call(gatewayPort, '/api/workspace.list', {}, presetCookie)).status, 200);

    // ── 场景 1：沙盒 await 后 allowed_models 收紧 ────────────────────────────
    // 先选一个允许模型，登记 model-sess 的有效模型为 p/m（否则 prompt 在模型门禁就 403）。
    assert.equal(
      (await call(gatewayPort, '/api/session.selectModel', { sessionId: 'model-sess', provider: 'p', model: 'm' }, modelCookie)).status,
      200,
    );
    // 正向对照：不收紧时同一 prompt 可过（证明 403 来自复核，而非该路径本就不可用）。
    assert.equal((await call(gatewayPort, '/api/session.prompt', { sessionId: 'model-sess' }, modelCookie)).status, 200);

    sandboxGate = deferred();
    sandboxArrived = deferred();
    const gatedModelPrompt = call(gatewayPort, '/api/session.prompt', { sessionId: 'model-sess' }, modelCookie);
    await sandboxArrived.promise;
    // 沙盒确认在途：管理员收紧 allowed_models（不推进 epoch，模拟真实权限保存）。
    setPerms(modelUser.id, { allowedModels: ['other/x'] });
    sandboxGate.resolve();
    assert.equal((await gatedModelPrompt).status, 403, '沙盒 await 后 must 用 live allowed_models 复核');
    sandboxGate = null;
    sandboxArrived = null;

    // ── 场景 2：沙盒 await 后 allowed_agent_presets 收紧 ──────────────────────
    // 先选择允许 preset，登记 preset-sess 的当前 preset 为 preset-a。
    assert.equal(
      (await call(gatewayPort, '/api/agentPresets.select', { sessionId: 'preset-sess', agentPreset: 'preset-a' }, presetCookie)).status,
      200,
    );
    assert.equal((await call(gatewayPort, '/api/session.prompt', { sessionId: 'preset-sess' }, presetCookie)).status, 200);

    sandboxGate = deferred();
    sandboxArrived = deferred();
    const gatedPresetPrompt = call(gatewayPort, '/api/session.prompt', { sessionId: 'preset-sess' }, presetCookie);
    await sandboxArrived.promise;
    setPerms(presetUser.id, { allowedAgentPresets: ['preset-b'] });
    sandboxGate.resolve();
    assert.equal((await gatedPresetPrompt).status, 403, '沙盒 await 后必须用 live allowed_agent_presets 复核');
    sandboxGate = null;
    sandboxArrived = null;

    // ── 场景 3：workspace/create 回包落库前复核 workspaceSubtreeOverlap ──────
    const target = `${createRoot}/proj`;
    const controlTarget = `${createRoot}/proj2`;
    const createDirectory = (parent: string, name: string): Promise<Reply> =>
      call(gatewayPort, '/api/directoryPicker/createDirectory',
        { type: 'client-request', method: 'directoryPicker/createDirectory', payload: { args: { path: parent, name } } }, wsCookie);
    const createWorkspace = (workspacePath: string): Promise<Reply> =>
      call(gatewayPort, '/api/workspace.create',
        { type: 'client-request', method: 'workspace/create', payload: { args: { request: { path: workspacePath } } } }, wsCookie);

    // 记账 pending（刚创建目录）后才能走登记通道。
    assert.equal((await createDirectory(createRoot, 'proj')).status, 200);
    assert.equal((await createDirectory(createRoot, 'proj2')).status, 200);

    // 正向对照：无竞争可正常登记。
    assert.equal((await createWorkspace(controlTarget)).status, 200);
    assert.ok(
      db.listUserWorkspacePaths(wsUser.id).map(normalizePath).includes(normalizePath(controlTarget)),
      '无竞争时 workspace/create 应登记为本用户自建工作区',
    );

    workspaceGate = deferred();
    workspaceArrived = deferred();
    const gatedCreate = createWorkspace(target);
    await workspaceArrived.promise;
    // 回包在途：另一子用户登记了同路径工作区子树。
    db.addUserWorkspace(peer.id, target);
    workspaceGate.resolve();
    const gatedCreateResult = await gatedCreate;
    assert.equal(gatedCreateResult.status, 200, '响应本身原样透传');
    assert.equal(
      db.listUserWorkspacePaths(wsUser.id).map(normalizePath).includes(normalizePath(target)),
      false,
      '回包落库前发现他人子树重叠：不得登记为本用户工作区',
    );
    workspaceGate = null;
    workspaceArrived = null;
  } finally {
    gateway?.close();
    upstream?.close();
    try { db.close(); } catch { /* 已关闭 */ }
    for (const dir of scratch) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
    }
    try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
  }
});
