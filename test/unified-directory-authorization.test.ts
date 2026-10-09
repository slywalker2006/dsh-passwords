// 统一目录授权回归：allowed_folders 是唯一的读取/创建范围。
//
// 契约（本文件断言的行为）：
//   · 目录创建（directoryPicker/createDirectory）与工作区登记（workspace/create）都只认
//     当前 live 权限行的 allowed_folders；不存在独立的创建根、主目录（home）或 pending
//     创建例外。父目录与新目标必须以词法 + canonical 两个口径同时通过 folderAllowed，
//     且拒绝文件系统根、敏感基与他人工作区子树。
//   · 创建必须 allow_workspace_create；__deny__ 一律拒；[] 保持“不限读取”语义但根/敏感仍拒。
//   · 历史持久化的 workspace_creation_roots（旧列）不再参与任何判定，不能放宽也不收窄。
//   · pending 仍是创建后登记的凭据，但不得绕过当前读取权限；浏览同样不因 pending 放宽。
//   · 上游 mkdir / workspace/create 的迟到回包必须复核当前 live 权限行与请求 epoch，
//     撤权后不得补记账、不得重赋读取 grant。
//
// 本文件是独立 mock：直接以最小 ProxyDeps 注册 registerProxyRoutes，只用一个本地 HTTP
// 上游桩，不依赖 admin/db/gateway 的权限写入契约（这些正在被并发移除 workspaceCreationRoots）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Transform } from 'node:stream';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import express from 'express';

import { registerProxyRoutes, type ProxyDeps } from '../src/proxy.js';
import { normalizePath } from '../src/permissions.js';
import type { Database, UserPermissionsRow } from '../src/db.js';
import type { AuthService } from '../src/auth.js';

const TEMP_DIRS: string[] = [];
function cleanupTempDirs(): void {
  for (const dir of TEMP_DIRS.splice(0)) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* Windows 句柄尽力而为 */ }
  }
}

function realDir(prefix: string): string {
  const dir = normalizePath(realpathSync(mkdtempSync(path.join(os.tmpdir(), prefix))));
  TEMP_DIRS.push(dir);
  return dir;
}

function readJson(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>);
      } catch {
        resolve({});
      }
    });
  });
}

function argsOf(envelope: Record<string, unknown>): Record<string, unknown> {
  const payload = envelope.payload;
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return {};
  const args = (payload as Record<string, unknown>).args;
  return args !== null && typeof args === 'object' && !Array.isArray(args) ? args as Record<string, unknown> : {};
}

interface Reply { status: number; body: string; }

function request(port: number, method: string, pathname: string, body: unknown, headers: Record<string, string> = {}): Promise<Reply> {
  const payload = body === undefined ? '' : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1', port, method, path: pathname,
        headers: { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)), ...headers },
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

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve((server.address() as { port: number }).port)));
}

/**
 * 伪造一行持久化权限。刻意经 `unknown` 转换：workspace_creation_roots 的活跃契约正被并发
 * 从 db/permissions 移除，测试需要在本文件不依赖该字段类型的前提下模拟“旧列残留值”。
 */
function permsRow(userId: number, folders: string[], allowCreate: boolean, legacyCreationRoots: string[] | null = null): UserPermissionsRow {
  const row = {
    user_id: userId,
    allowed_folders: folders,
    hourly_token_limit: null,
    daily_minutes_limit: null,
    allow_upload: false,
    allow_git_download: false,
    allow_workspace_create: allowCreate,
    workspace_creation_roots: legacyCreationRoots,
    allow_ssh: false,
    allowed_agent_presets: null,
    allowed_models: null,
    allow_chat_media: false,
    banned: false,
    sandbox_mode: null,
    disabled_sessions: [],
    updated_at: '',
  };
  return row as unknown as UserPermissionsRow;
}

interface Harness {
  port: number;
  setPerms(userId: number, folders: string[], allowCreate: boolean, legacyCreationRoots?: string[] | null): void;
  bumpEpoch(userId: number): void;
  setSensitive(paths: string[]): void;
  setOverlap(paths: string[]): void;
  /** 写入该子用户的已授权会话→工作区路径基线（open-in-app 绑定判定用）。 */
  setSessionAccess(userId: number, entries: Record<string, string>): void;
  pending(userId: number): string[];
  ownedWorkspaces(userId: number): string[];
  /** 让上游 createDirectory 挂起；held 在请求真正挂起时 resolve，release 放行响应。 */
  holdCreateDirectory(): { held: Promise<void>; release(): void };
  close(): void;
}

async function createHarness(): Promise<Harness> {
  const permsByUser = new Map<number, UserPermissionsRow>();
  const epochs = new Map<number, number>();
  const pendingByUser = new Map<number, Set<string>>();
  const ownedByUser = new Map<number, Set<string>>();
  const sessionAccessByUser = new Map<number, Map<string, string>>();
  let sensitive = new Set<string>();
  let overlap = new Set<string>();
  let currentUser = 0;

  let held: { promise: Promise<void>; signal: () => void } | null = null;
  const holdCreateDirectory = (): { held: Promise<void>; release(): void } => {
    let release!: () => void;
    let signal!: () => void;
    const promise = new Promise<void>((r) => { release = r; });
    const heldSignal = new Promise<void>((r) => { signal = r; });
    held = { promise, signal };
    return { held: heldSignal, release };
  };

  const upstream = http.createServer((req, res) => {
    void (async () => {
      const url = (req.url ?? '').split('?')[0];
      const reply = (value: unknown): void => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ type: 'server-response', result: { ok: true, value } }));
      };
      const envelope = await readJson(req);
      if (req.method === 'POST' && url.startsWith('/api/directoryPicker/createDirectory')) {
        if (held !== null) {
          const current = held;
          current.signal();
          await current.promise;
          held = null;
        }
        const args = argsOf(envelope);
        const parent = normalizePath(typeof args.path === 'string' ? args.path : '');
        const name = typeof args.name === 'string' ? args.name : '';
        reply(`${parent}/${name}`);
        return;
      }
      if (req.method === 'POST' && url.startsWith('/api/workspace/create')) {
        if (held !== null) {
          const current = held;
          current.signal();
          await current.promise;
          held = null;
        }
        const args = argsOf(envelope);
        const requestArgs = args.request as Record<string, unknown> | undefined;
        const target = normalizePath(typeof requestArgs?.path === 'string' ? requestArgs.path : '');
        reply({ created: true, workspace: { workspaceId: 'ws-1', path: target, title: 't', sessionIds: [] } });
        return;
      }
      if (req.method === 'POST' && url.startsWith('/api/directoryPicker/list')) {
        const args = argsOf(envelope);
        const requested = normalizePath(typeof args.path === 'string' ? args.path : '');
        const root = permsByUser.get(currentUser)?.allowed_folders[0] ?? '';
        reply({
          path: requested,
          home: requested,
          crumbs: [{ name: 'other', path: '/tmp/dshpw-other' }],
          entries: [
            { name: 'other', path: '/tmp/dshpw-other', hidden: false },
            { name: 'pending-only', path: '/tmp/dshpw-pending-only', hidden: false },
            { name: 'root', path: root, hidden: false },
          ],
        });
        return;
      }
      if (req.method === 'POST' && url.startsWith('/open-in-app/open')) {
        // 官方 open-in-app 启动器：网关在转发前做子用户工作区绑定 + 敏感校验。
        reply({});
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{}');
    })();
  });
  const upstreamPort = await listen(upstream);

  const db = {
    listUserWorkspacePaths: (userId: number): string[] => [...(ownedByUser.get(userId) ?? [])],
    addUserWorkspace: (userId: number, workspacePath: string): void => {
      let set = ownedByUser.get(userId);
      if (set === undefined) { set = new Set(); ownedByUser.set(userId, set); }
      set.add(normalizePath(workspacePath));
    },
    addAllowedFolder: (): void => { /* 归属标记，本文件不校验 */ },
    hasUserSessionGrant: (): boolean => false,
    getUserById: (): null => null,
    audit: (): void => { /* 审计写入失败不阻断授权；本文件不校验审计内容 */ },
  } as unknown as Database;

  const deps: ProxyDeps = {
    db,
    auth: {} as unknown as AuthService,
    AGENT_PRESET_LIST_RE: /^$/,
    AGENT_PRESET_MUTATION_RE: /^$/,
    AGENT_PRESET_SELECT_RE: /^$/,
    agentPresetFromRequest: () => null,
    allowedModelSet: () => null,
    archivedSessionSnapshot: new Set(),
    authorizedSubuserSessionRoot: () => null,
    authorizedWorkspaceFileChangeTarget: () => null,
    canonicalizePathBestEffort: (candidate: string): string => {
      try { return normalizePath(realpathSync(candidate)); } catch { return normalizePath(candidate); }
    },
    clearPendingCreatedSession: () => { /* 本文件不涉及 */ },
    closeUserRemoteMuxClients: () => { /* 本文件不涉及 */ },
    collectSessionAgentPresets: () => { /* 本文件不涉及 */ },
    COOKIE_NAME: 'dsh_gateway_token',
    effectivePermissions: (userId: number): UserPermissionsRow =>
      permsByUser.get(userId) ?? permsRow(userId, ['__deny__'], false),
    effectiveSessionModel: () => null,
    ensureSessionCreateId: (_value, generatedId) => generatedId,
    escapeHtml: (value: string): string => value,
    filterEventWebSocketFrame: () => null,
    filterModelCatalogValue: (value: unknown): unknown => value,
    filterRemoteMuxUserItem: () => null,
    forbiddenPage: (_lang, message: string): string => `<html>${message}</html>`,
    forceRejectRemoteEventOutcome: () => false,
    gatePathOf: (reqUrl: string): string => new URL(reqUrl, 'http://localhost').pathname,
    hasImageAttachment: () => false,
    hostEventFilter: () => new Transform(),
    INJECT_SCRIPT: '',
    isPlainJsonRecord: (value: unknown): value is Record<string, unknown> =>
      typeof value === 'object' && value !== null && !Array.isArray(value),
    isSensitivePath: (candidate: string): boolean => sensitive.has(normalizePath(candidate)),
    isTokenRevoked: () => false,
    langOf: () => 'zh',
    mergeAuthorizedAccess: () => new Map(),
    mergeWorkspacePaths: () => new Map(),
    MODEL_CATALOG_RE: /^model$/,
    modelChoiceVerdict: () => ({ ok: true, reason: 'unrestricted' }),
    modelSelectionFrom: () => null,
    muxEventFilter: () => new Transform(),
    normalizeDecodedPath: (rawPath: string): string => rawPath,
    OFFICIAL_ACCOUNT_REMOTE_ENDPOINTS: new Set(),
    OFFICIAL_JOB_REMOTE_ENDPOINTS: new Set(),
    OFFICIAL_TERMINAL_HTTP_RE: /^$/,
    OFFICIAL_TERMINAL_REMOTE_ENDPOINTS: new Set(),
    originHostMatches: () => true,
    parseRemoteMuxClientFrame: () => null,
    parseRemoteMuxServerFrame: () => null,
    pendingCreatedDirectoryPaths: (userId: number): string[] => [...(pendingByUser.get(userId) ?? [])],
    pendingCreatedSessionFor: () => new Map(),
    pendingCreatedSessions: new Map(),
    readCookie: () => null,
    recordHostDefaultModel: () => { /* 本文件不涉及 */ },
    recordPendingCreatedDirectory: (userId: number, canonicalPath: string): void => {
      let set = pendingByUser.get(userId);
      if (set === undefined) { set = new Set(); pendingByUser.set(userId, set); }
      set.add(normalizePath(canonicalPath));
    },
    recordSessionModelSelection: () => { /* 本文件不涉及 */ },
    registerUserWebSocketClient: () => () => { /* 本文件不涉及 */ },
    registryAuthorizedSockets: new Set(),
    REMOTE_MUX_FRAGMENT_BYTES: 64 * 1024,
    REMOTE_MUX_PING_INTERVAL_MS: 30_000,
    REMOTE_MUX_PONG_TIMEOUT_MS: 60_000,
    REMOTE_MUX_WRITE_STALL_MS: 60_000,
    REMOTE_MUX_MAX_PAYLOAD_BYTES: 8 * 1024 * 1024,
    REMOTE_MUX_MAX_PENDING_BYTES: 8 * 1024 * 1024,
    REMOTE_MUX_MAX_STREAMS: 64,
    remoteAccountRequestIsEmpty: () => true,
    remoteEventOwnership: new Map(),
    remoteEventOwnershipKey: (eventId: string, clientId: string): string => `${eventId}:${clientId}`,
    remoteJobRequest: () => null,
    remoteMuxClientsByUser: new Map(),
    remoteMuxEmptyArgs: () => true,
    remoteMuxFollowAddress: () => null,
    remoteMuxStreamEndpoints: new Set(),
    remoteMuxSubuserRejectedEndpoints: new Map(),
    remoteWorkspaceFileChangeRequest: () => null,
    replaceUserSessionAccess: () => true,
    replaceUserWorkspacePaths: () => { /* 本文件不涉及 */ },
    requestBodyLimitFor: () => 1 << 20,
    resolveUpstreamHostSafe: async () => null,
    resolveWorkspaceFileTarget: () => null,
    rpcRequestPayload: () => null,
    sanitizeHiddenUnicodeJson: (value: unknown): unknown => value,
    sessionAgentPresetMapFor: () => new Map(),
    sessionAuthorizationId: () => '',
    sessionCwdById: new Map(),
    sessionFollowIdentityAllowed: () => false,
    stripGatewayAuthQuery: () => '',
    upstream: new URL(`http://127.0.0.1:${upstreamPort}`),
    upstreamAgent: new http.Agent({ keepAlive: false }),
    upstreamAuthority: `127.0.0.1:${upstreamPort}`,
    upstreamCookieHeader: () => undefined,
    upstreamHost: '127.0.0.1',
    upstreamIsHttps: false,
    upstreamPort,
    upstreamScheme: 'http',
    upstreamTransport: http,
    upstreamWsOptions: () => ({ headers: {}, maxPayload: 8 * 1024 * 1024 }),
    userAccessEpochFor: (userId: number): number => epochs.get(userId) ?? 0,
    userArchivedSessionIds: new Map(),
    userSessionAccess: sessionAccessByUser,
    userSessionAccessFor: () => new Map(),
    userWorkspaceIds: new Map(),
    userWorkspacePaths: new Map(),
    waitForUserSessionAccess: async () => true,
    WORKSPACE_FILES_RPC_RE: /^$/,
    workspaceFileScopeRequest: () => null,
    workspaceOwnedByAnotherSubuser: () => false,
    workspaceOwnedByUser: (userId: number, workspacePath: string): boolean =>
      (ownedByUser.get(userId) ?? new Set()).has(normalizePath(workspacePath)),
    workspacePathById: new Map(),
    workspaceSubtreeOverlap: (_userId: number, workspacePath: string): boolean => overlap.has(normalizePath(workspacePath)),
    internalSecret: 'test-internal',
    getEndpointRules: () => [],
    getDynamicPluginManifest: () => undefined,
    getUpstreamAuthCookie: () => '',
    getHostDefaultModel: () => null,
    getHostDefaultModelKnown: () => false,
    getArchivedSessionSnapshotReady: () => false,
    setArchivedSessionSnapshotReady: () => { /* 本文件不涉及 */ },
    getArchivedSessionSnapshotRevision: () => 0,
    setArchivedSessionSnapshotRevision: () => { /* 本文件不涉及 */ },
    bumpWorkspaceListRequestRevision: () => 1,
  };

  const app = express();
  app.use((req, _res, next) => {
    const stamped = req as unknown as http.IncomingMessage & {
      dshpwUser?: number;
      dshpwPerms?: UserPermissionsRow;
      dshpwIsAdmin?: boolean;
    };
    const rawUser = Number(req.headers['x-test-user'] ?? '0');
    if (Number.isInteger(rawUser) && rawUser > 0) {
      stamped.dshpwUser = rawUser;
      stamped.dshpwPerms = permsByUser.get(rawUser) ?? permsRow(rawUser, ['__deny__'], false);
    }
    if (req.headers['x-test-admin'] === '1') stamped.dshpwIsAdmin = true;
    currentUser = stamped.dshpwUser ?? 0;
    next();
  });
  registerProxyRoutes(app, deps);

  const gateway = http.createServer(app);
  const port = await listen(gateway);

  return {
    port,
    setPerms: (userId, folders, allowCreate, legacyCreationRoots = null) => {
      permsByUser.set(userId, permsRow(userId, folders, allowCreate, legacyCreationRoots));
    },
    bumpEpoch: (userId) => epochs.set(userId, (epochs.get(userId) ?? 0) + 1),
    setSensitive: (paths) => { sensitive = new Set(paths.map(normalizePath)); },
    setOverlap: (paths) => { overlap = new Set(paths.map(normalizePath)); },
    setSessionAccess: (userId, entries) => { sessionAccessByUser.set(userId, new Map(Object.entries(entries))); },
    pending: (userId) => [...(pendingByUser.get(userId) ?? [])],
    ownedWorkspaces: (userId) => [...(ownedByUser.get(userId) ?? [])],
    holdCreateDirectory,
    close: () => {
      gateway.close();
      upstream.close();
      cleanupTempDirs();
    },
  };
}

function cookie(userId: number): Record<string, string> {
  return { 'x-test-user': String(userId) };
}

const CREATE_DIR = '/api/directoryPicker/createDirectory';
const CREATE_WS = '/api/workspace/create';
const LIST = '/api/directoryPicker/list';
const OPEN_IN_APP = '/open-in-app/open';

function createDirectoryBody(parent: string, name: string, rpcId: string): unknown {
  return { type: 'client-request', rpcId, method: 'directoryPicker/createDirectory', payload: { args: { path: parent, name } } };
}
function createWorkspaceBody(target: string, rpcId: string): unknown {
  return { type: 'client-request', rpcId, method: 'workspace/create', payload: { args: { request: { path: target } } } };
}
function listBody(parent: string, rpcId: string): unknown {
  return { type: 'client-request', rpcId, method: 'directoryPicker/list', payload: { args: { path: parent } } };
}
/** 官方 open-in-app/open 是宿主根级路由，body 是平铺的 { app, path }，不是 RPC 信封。 */
function openInAppBody(target: string): unknown {
  return { app: 'vscode', path: target };
}

// ── 1. 正常：可读即创建，创建后可登记 ────────────────────────────────
test('可读根内创建目录并登记工作区：allowed_folders 是唯一范围', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-ok-');
    h.setPerms(7, [root], true);

    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(root, 'proj', 'mk1'), cookie(7));
    assert.equal(mk.status, 200, mk.body);
    assert.ok(h.pending(7).includes(`${root}/proj`), '创建成功后应写入 pending 登记凭据');

    const ws = await request(h.port, 'POST', CREATE_WS, createWorkspaceBody(`${root}/proj`, 'ws1'), cookie(7));
    assert.equal(ws.status, 200, ws.body);
    assert.ok(h.ownedWorkspaces(7).includes(`${root}/proj`), '登记成功后应记录自建工作区');
  } finally {
    h.close();
  }
});

// ── 2. 关闭 allowWorkspaceCreate ─────────────────────────────────────
test('关闭 allowWorkspaceCreate 后即使可读也不得创建', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-off-');
    h.setPerms(7, [root], false);
    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(root, 'proj', 'mk-off'), cookie(7));
    assert.equal(mk.status, 403, mk.body);
    assert.equal(h.pending(7).length, 0, '被拒的创建不得记账');
  } finally {
    h.close();
  }
});

// ── 3. 不可读的家目录：home 创建例外已删除 ───────────────────────────
test('家目录不在 allowed_folders 内时必须拒绝创建（home 例外已删除）', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-home-');
    h.setPerms(7, [root], true);
    const home = normalizePath(os.homedir());
    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(home, 'proj', 'mk-home'), cookie(7));
    assert.equal(mk.status, 403, mk.body);
    assert.equal(h.pending(7).length, 0);
  } finally {
    h.close();
  }
});

// ── 4. __deny__ 一律拒 ───────────────────────────────────────────────
test('__deny__ 白名单必须拒绝创建与登记', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-deny-');
    h.setPerms(7, ['__deny__'], true);
    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(root, 'proj', 'mk-deny'), cookie(7));
    assert.equal(mk.status, 403, mk.body);
    const ws = await request(h.port, 'POST', CREATE_WS, createWorkspaceBody(`${root}/proj`, 'ws-deny'), cookie(7));
    assert.equal(ws.status, 403, ws.body);
  } finally {
    h.close();
  }
});

// ── 5. 符号链接逃逸：词法在根内、canonical 出根 ──────────────────────
test('根内目录链接的 canonical 落到根外时必须拒绝创建', async (t) => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-link-root-');
    const outside = realDir('dshpw-unified-link-outside-');
    const link = path.join(root, 'link');
    let linked = false;
    for (const type of ['junction', 'dir'] as const) {
      try { symlinkSync(outside, link, type); linked = true; break; } catch { /* 尝试下一形态 */ }
    }
    if (!linked) {
      t.skip('当前平台无法创建目录链接/junction，跳过链接逃逸回归');
      return;
    }
    h.setPerms(7, [root], true);
    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(normalizePath(link), 'evil', 'mk-link'), cookie(7));
    assert.equal(mk.status, 403, mk.body);
    assert.equal(h.pending(7).length, 0);
  } finally {
    h.close();
  }
});

// ── 6. 陈旧创建根（旧列残留）不得放宽 ────────────────────────────────
test('旧列 workspace_creation_roots 残留值不参与判定：既不放宽也不收窄', async () => {
  const h = await createHarness();
  try {
    const readable = realDir('dshpw-unified-readable-');
    const legacy = realDir('dshpw-unified-legacy-');
    // 模拟旧版本持久化的创建根：与可读根不同。
    h.setPerms(7, [readable], true, [legacy]);

    const inReadable = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(readable, 'proj', 'mk-read'), cookie(7));
    assert.equal(inReadable.status, 200, '可读根内仍可创建（旧列不收窄）');

    const inLegacy = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(legacy, 'proj', 'mk-legacy'), cookie(7));
    assert.equal(inLegacy.status, 403, '旧创建根不可读，必须拒绝（旧列不放宽）');
  } finally {
    h.close();
  }
});

// ── 7. pending 撤权迟到响应 ──────────────────────────────────────────
test('撤权后迟到的 createDirectory 回包不得补记 pending', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-late-');
    h.setPerms(7, [root], true);
    const hold = h.holdCreateDirectory();
    const pendingReq = request(h.port, 'POST', CREATE_DIR, createDirectoryBody(root, 'late', 'mk-late'), cookie(7));
    await hold.held;

    // 上游响应在途期间发生授权变更（推进 epoch）。
    h.bumpEpoch(7);
    hold.release();

    const mk = await pendingReq;
    assert.equal(mk.status, 200, '上游 200 原样透传');
    assert.equal(h.pending(7).length, 0, 'epoch 变化后不得补记 pending');

    // 登记凭据不存在 ⇒ workspace/create 必须拒（未分配、未自建、无 pending）。
    const ws = await request(h.port, 'POST', CREATE_WS, createWorkspaceBody(`${root}/late`, 'ws-late'), cookie(7));
    assert.equal(ws.status, 403, ws.body);
    assert.equal(h.ownedWorkspaces(7).length, 0, '不得重赋工作区 grant');
  } finally {
    h.close();
  }
});

test('撤权（白名单变 __deny__）后迟到的 workspace/create 回包不得授予工作区', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-late2-');
    h.setPerms(7, [root], true);
    // 先正常创建并记账，使 pending 存在。
    const mk = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(root, 'late2', 'mk-late2'), cookie(7));
    assert.equal(mk.status, 200, mk.body);

    // 让 workspace/create 的上游回包挂起：复用同一 held 闸门（上游两条路由都等它）。
    const hold = h.holdCreateDirectory();
    const pendingWs = request(h.port, 'POST', CREATE_WS, createWorkspaceBody(`${root}/late2`, 'ws-late2'), cookie(7));
    // workspace/create 立即发往上游并挂起。
    await hold.held;

    // 挂起期间撤权。
    h.bumpEpoch(7);
    h.setPerms(7, ['__deny__'], true);
    hold.release();

    const ws = await pendingWs;
    assert.equal(ws.status, 200, '上游 200 原样透传');
    assert.equal(h.ownedWorkspaces(7).length, 0, '撤权后迟到回包不得登记自建工作区');
  } finally {
    h.close();
  }
});

// ── 8. [] 保持不限读取，但根/敏感仍拒 ────────────────────────────────
test('空白名单保持不限读取：普通目录可创建，文件系统根与敏感基仍拒', async () => {
  const h = await createHarness();
  try {
    const dir = realDir('dshpw-unified-empty-');
    h.setPerms(7, [], true);

    const ok = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(dir, 'proj', 'mk-empty'), cookie(7));
    assert.equal(ok.status, 200, ok.body);

    const fsRoot = normalizePath(path.parse(dir).root);
    const rootAttempt = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(fsRoot, 'evil', 'mk-root'), cookie(7));
    assert.equal(rootAttempt.status, 403, '文件系统根必须拒');

    const sensitiveDir = realDir('dshpw-unified-sensitive-');
    h.setSensitive([sensitiveDir]);
    const sensitiveAttempt = await request(h.port, 'POST', CREATE_DIR, createDirectoryBody(sensitiveDir, 'evil', 'mk-sensitive'), cookie(7));
    assert.equal(sensitiveAttempt.status, 403, '敏感基必须拒');
  } finally {
    h.close();
  }
});

// ── 9. 浏览不因 pending 或旧创建根放宽 ───────────────────────────────
test('目录浏览只暴露可读根：pending 与旧创建根不作为导航入口', async () => {
  const h = await createHarness();
  try {
    const root = realDir('dshpw-unified-list-');
    const legacy = realDir('dshpw-unified-list-legacy-');
    h.setPerms(7, [root], true, [legacy]);
    const home = normalizePath(os.homedir());

    const res = await request(h.port, 'POST', LIST, listBody(home, 'ls1'), cookie(7));
    assert.equal(res.status, 200, res.body);
    const parsed = JSON.parse(res.body) as { result: { value: { entries: { path?: string }[] } } };
    const paths = parsed.result.value.entries.map((e) => normalizePath(e.path ?? ''));
    assert.ok(paths.includes(root), '可读根应作为入口注入');
    assert.ok(!paths.includes(legacy), '旧创建根不得作为导航入口');
    assert.ok(!paths.includes('/tmp/dshpw-other'), '非导航目录应被剔除');
    assert.ok(!paths.includes('/tmp/dshpw-pending-only'), 'pending 不得扩大浏览范围');
  } finally {
    h.close();
  }
});

// ── 10. workspace/create 登记：敏感目录即使被显式分配也不得登记 ──────────
test('敏感目录即使被显式分配为 allowed_folders 也不得登记为工作区', async () => {
  const h = await createHarness();
  try {
    const sensitiveDir = realDir('dshpw-unified-reg-sensitive-');
    h.setPerms(7, [sensitiveDir], true);
    h.setSensitive([sensitiveDir]);
    // createDirectory 已被敏感门禁挡住；登记门禁必须与读取门禁同口径，独立复核敏感基：
    // 管理员误把敏感目录（或其祖先）误分配为工作区时，目标会同时命中白名单与 assigned。
    const ws = await request(h.port, 'POST', CREATE_WS, createWorkspaceBody(sensitiveDir, 'ws-sensitive'), cookie(7));
    assert.equal(ws.status, 403, ws.body);
    assert.equal(h.ownedWorkspaces(7).length, 0, '敏感目录不得登记为自建工作区');
  } finally {
    h.close();
  }
});

// ── 11. open-in-app 启动路径：绑定已授权工作区 + canonical/敏感复核 ──────
test('open-in-app：启动路径必须绑定已授权工作区，未登记路径与敏感目录都被拒', async () => {
  const h = await createHarness();
  try {
    const workspace = realDir('dshpw-unified-open-ws-');
    const other = realDir('dshpw-unified-open-other-');
    h.setPerms(7, [workspace], true);
    h.setSessionAccess(7, { 'sess-open': workspace });

    // 允许：路径命中授权基线的唯一工作区。
    const allowed = await request(h.port, 'POST', OPEN_IN_APP, openInAppBody(workspace), cookie(7));
    assert.equal(allowed.status, 200, allowed.body);

    // 拒绝：不在授权基线内的路径不得启动（allowed_folders 不是启动器白名单）。
    const outside = await request(h.port, 'POST', OPEN_IN_APP, openInAppBody(other), cookie(7));
    assert.equal(outside.status, 403, '未登记为工作区的路径必须拒');

    // 拒绝：授权工作区一旦命中敏感基（含误分配），启动器必须 fail-closed。
    h.setSensitive([workspace]);
    const sensitive = await request(h.port, 'POST', OPEN_IN_APP, openInAppBody(workspace), cookie(7));
    assert.equal(sensitive.status, 403, '敏感目录不得作为启动路径');
  } finally {
    h.close();
  }
});

test('open-in-app：授权工作区内的链接把 canonical 指向敏感目录时拒绝启动', async (t) => {
  const h = await createHarness();
  try {
    const parent = realDir('dshpw-unified-open-link-');
    const sensitiveTarget = path.join(parent, 'sensitive');
    mkdirSync(sensitiveTarget, { recursive: true });
    const link = path.join(parent, 'link');
    let linked = false;
    for (const type of ['junction', 'dir'] as const) {
      try { symlinkSync(sensitiveTarget, link, type); linked = true; break; } catch { /* 尝试下一形态 */ }
    }
    if (!linked) {
      t.skip('当前平台无法创建目录链接/junction，跳过 canonical 敏感逃逸回归');
      return;
    }
    // 词法在授权根内、canonical 落到同一授权根内的敏感目录：只有 canonical 敏感复核能挡住。
    h.setPerms(7, [parent], true);
    h.setSensitive([normalizePath(sensitiveTarget)]);
    h.setSessionAccess(7, { 'sess-link': normalizePath(link) });

    const denied = await request(h.port, 'POST', OPEN_IN_APP, openInAppBody(normalizePath(link)), cookie(7));
    assert.equal(denied.status, 403, 'canonical 指向敏感目录时必须拒绝启动');
  } finally {
    h.close();
  }
});
