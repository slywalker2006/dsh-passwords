// R1 回归（HTTP await 行为）：沙盒确认 await 期间权限 grant/disabled 变化后，
// 旧 prompt 不得转发到上游。
//
// 场景：受限子用户（sandboxMode='read-only'）的 session/prompt 在转发前必须先向
// DSH 内部接口确认沙盒档位（proxy.ts 的 needsSandboxRunCheck → applySandboxToSession），
// 该确认是一次真实 await。若在这次 await 期间权威权限发生变化（grant 被回收、会话被
// 逐条禁用），网关必须重读 epoch / 权威 DB grant / disabled，并在「旧请求」上
// fail-closed，绝不用请求开始时的旧快照把 prompt 转发给上游。
//
// 本文件用真实 gateway + 最小 mock 上游注入「真实延迟」：mock 上游在
// holdSandboxResponse 时挂起 /api/dsh-passwords/internal/sandbox 的响应，测试据此
// 制造确定的 await 窗口，在窗口内改写权限，再放行沙盒响应，观察旧 prompt 的去向。
//
// 限制（不伪造通过）：permission-save 触发的 epoch 栅栏（fenceUserAccessEpoch）需要
// 走 /gateway/api/permissions，而该路由依赖可用的上游资源核验；本文件不搭建整套资源
// 核验 mock，因此「epoch 不一致」这一条在 proxy.ts 里的实现只由
// r1-permission-revocation.test.ts 的源码契约断言覆盖，本文件覆盖可真实观测的
// grant / disabled 两条 DB 权威回查路径。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { createGatewayServer } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import type { PlatformConfig } from '../src/config.js';

const JWT_SECRET = 'r1-http-await-secret';
const INTERNAL_SECRET = 'r1-http-await-internal';
const DUMMY_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';

const PROMPT_BODY = JSON.stringify({
  type: 'client-request',
  rpcId: 'r1-await-prompt',
  method: 'session/prompt',
  payload: {
    args: { request: { sessionId: 'session-visible', content: [{ type: 'text', text: 'hi' }] } },
  },
});

/** 受限子用户可见工作区的 workspace.list 响应：网关据此建立会话授权快照。 */
const WORKSPACE_LIST_BODY = JSON.stringify({
  rpcId: 'r1-await-workspace-list',
  result: {
    ok: true,
    value: {
      items: [
        {
          workspaceId: 'workspace-visible',
          path: '/workspaces/visible',
          title: 'Visible workspace',
          sessionIds: ['session-visible'],
        },
      ],
      archivedSessionIds: [],
    },
  },
});

let tempDir: string;
let db: Database;
let upstream: http.Server;
let gateway: http.Server;
let gatewayPort = 0;

/** mock 上游状态：holdSandboxResponse 时挂起沙盒确认响应，直到 releaseSandbox。 */
let holdSandboxResponse = false;
let sandboxResponders: Array<() => void> = [];
let sandboxRequests: Array<{ sessionId: string; mode: string }> = [];
/** 上游收到的 session/prompt 次数（区分「转发」与「await 后 fail-closed 不转发」）。 */
let promptUpstreamCount = 0;

function startMockUpstream(): Promise<http.Server> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = req.url ?? '';
      if (url.startsWith('/api/dsh-passwords/internal/sandbox')) {
        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => {
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as {
              sessionId?: unknown;
              mode?: unknown;
            };
            if (typeof body.sessionId === 'string' && typeof body.mode === 'string') {
              sandboxRequests.push({ sessionId: body.sessionId, mode: body.mode });
            }
          } catch {
            // 形状非法的注入请求不记录：被测代码不应发出这种请求。
          }
          const respond = (): void => {
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
          };
          if (holdSandboxResponse) sandboxResponders.push(respond);
          else respond();
        });
        return;
      }
      if (/^\/api\/session[.\/]prompt(?:[?]|$)/.test(url)) {
        req.resume();
        promptUpstreamCount += 1;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ result: { ok: true, value: { accepted: true } } }));
        return;
      }
      if (/^\/api\/workspace[.\/]list$/.test(url)) {
        req.resume();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(WORKSPACE_LIST_BODY);
        return;
      }
      req.resume();
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false }));
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function gatewayReq(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method, path: url, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

function tokenFor(userId: number, username: string): string {
  return `dsh_gateway_token=${jwt.sign(
    { sub: String(userId), username, cv: 0 },
    JWT_SECRET,
    { expiresIn: '12h' },
  )}`;
}

async function waitForSandboxRequest(timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (sandboxRequests.length === 0) {
    if (Date.now() > deadline) throw new Error('mock 上游未在期限内收到沙盒确认请求（prompt 未进入 await 窗口）');
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

function releaseSandbox(): void {
  holdSandboxResponse = false;
  for (const respond of sandboxResponders) respond();
  sandboxResponders = [];
}

/**
 * 建立一个受限子用户，并用一次真实 workspace.list 建立其会话授权快照
 * （prompt 的归属校验来源；与 Remote 基线同源，均为 userSessionAccess）。
 */
async function setupRestrictedSubuser(
  label: string,
): Promise<{ userId: number; headers: Record<string, string> }> {
  const subUser = db.createUser(`r1-await-${label}`, DUMMY_HASH, 'user');
  db.setPermissions(subUser.id, {
    allowedFolders: ['/workspaces/visible'],
    hourlyTokenLimit: null,
    dailyMinutesLimit: null,
    allowUpload: false,
    allowGitDownload: false,
    allowWorkspaceCreate: false,
    allowedAgentPresets: null,
    banned: false,
    sandboxMode: 'read-only',
    disabledSessions: [],
    allowedSessionIds: ['session-visible'],
  });
  db.markSessionGrantsSeeded(subUser.id);
  const headers = { 'content-type': 'application/json', cookie: tokenFor(subUser.id, subUser.username) };
  const seeded = await gatewayReq('POST', '/api/workspace.list', headers, '{}');
  assert.equal(seeded.status, 200, `workspace.list 建立快照失败：${seeded.body}`);
  return { userId: subUser.id, headers };
}

/**
 * 发起 prompt 并让它停在沙盒确认 await：mock 上游挂起 internal/sandbox 响应。
 * 返回的 response 只有在 release() 之后才会 settle。
 */
async function beginPromptInSandboxAwait(
  headers: Record<string, string>,
): Promise<{ response: Promise<{ status: number; body: string }>; release: () => void }> {
  sandboxRequests = [];
  sandboxResponders = [];
  promptUpstreamCount = 0;
  holdSandboxResponse = true;
  const response = gatewayReq('POST', '/api/session/prompt', headers, PROMPT_BODY);
  try {
    await waitForSandboxRequest();
  } catch (error) {
    releaseSandbox();
    throw error;
  }
  // 确认确实停在沙盒 await：注入请求已到达上游，且旧 prompt 还没被转发。
  assert.deepEqual(sandboxRequests, [{ sessionId: 'session-visible', mode: 'read-only' }]);
  assert.equal(promptUpstreamCount, 0, 'sandbox await 期间旧 prompt 不得已转发');
  return { response, release: releaseSandbox };
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-r1-await-'));
  mkdirSync(path.join(tempDir, 'data'));
  db = new Database(path.join(tempDir, 'data', 'test.db'), createFieldCrypto('r1key', 'r1key'));
  db.init();
  db.createUser('admin', DUMMY_HASH, 'admin');

  upstream = await startMockUpstream();
  const upstreamPort = (upstream.address() as { port: number }).port;

  const config: PlatformConfig = {
    setupKey: 'r1-await-setup-key',
    dbPath: path.join(tempDir, 'data', 'test.db'),
    dbEncKey: 'r1key',
    gateway: {
      host: '127.0.0.1',
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null,
      redirectPort: null,
      publicHost: '',
      domain: 'localhost',
      autoTls: false,
      acmeEmail: '',
      acmeStaging: false,
    },
    jwtSecret: JWT_SECRET,
    internalSecret: INTERNAL_SECRET,
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };

  const auth = new AuthService(config, db);
  gateway = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(() => {
  releaseSandbox();
  gateway?.close();
  upstream?.close();
  // Windows 上 node:sqlite 文件句柄保持打开，临时目录清理为尽力而为。
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* 忽略：文件锁未释放，交给系统临时目录回收 */
  }
});

test('R1-await 对照：沙盒确认 await 期间权限不变 → 旧 prompt 正常转发一次', async () => {
  const { headers } = await setupRestrictedSubuser('unchanged');
  const { response, release } = await beginPromptInSandboxAwait(headers);
  try {
    release();
    const res = await response;
    assert.equal(res.status, 200, res.body);
    assert.equal(promptUpstreamCount, 1, 'await 期间权限不变时旧 prompt 必须照常转发一次');
  } finally {
    releaseSandbox();
  }
});

test('R1-await：沙盒确认 await 期间权威 grant 被回收 → 旧 prompt 不转发到上游', async () => {
  const { userId, headers } = await setupRestrictedSubuser('grant-revoked');
  const { response, release } = await beginPromptInSandboxAwait(headers);
  try {
    // await 窗口内回收权威 grant（内存快照仍含该会话，模拟沙盒回收前的并发撤销）。
    db.deleteUserSessionGrants(userId, ['session-visible']);
    assert.equal(db.hasUserSessionGrant(userId, 'session-visible'), false);

    release();
    const res = await response;
    assert.equal(res.status, 403, res.body);
    assert.equal(promptUpstreamCount, 0, 'await 期间 grant 被回收后旧 prompt 不得转发');
  } finally {
    releaseSandbox();
  }
});

test('R1-await：沙盒确认 await 期间会话被逐条禁用 → 旧 prompt 不转发到上游', async () => {
  const { userId, headers } = await setupRestrictedSubuser('session-disabled');
  const { response, release } = await beginPromptInSandboxAwait(headers);
  try {
    // await 窗口内保持 grant 不变，只把该会话逐条禁用（改变 disabled 集合）。
    db.setPermissions(userId, {
      allowedFolders: ['/workspaces/visible'],
      hourlyTokenLimit: null,
      dailyMinutesLimit: null,
      allowUpload: false,
      allowGitDownload: false,
      allowWorkspaceCreate: false,
      allowedAgentPresets: null,
      banned: false,
      sandboxMode: 'read-only',
      disabledSessions: ['session-visible'],
      allowedSessionIds: ['session-visible'],
    });
    assert.equal(db.hasUserSessionGrant(userId, 'session-visible'), true, '本用例只改 disabled，grant 必须保留');
    assert.deepEqual(db.getPermissions(userId)?.disabled_sessions, ['session-visible']);

    release();
    const res = await response;
    assert.equal(res.status, 403, res.body);
    assert.equal(promptUpstreamCount, 0, 'await 期间会话被禁用后旧 prompt 不得转发');
  } finally {
    releaseSandbox();
  }
});
