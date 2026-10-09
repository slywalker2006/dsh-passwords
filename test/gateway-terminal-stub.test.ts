// 子用户 terminal UX 桩 + allowSsh 官方 terminal / SSH 端点权限控制。
//
// 官方客户端会调用 terminal/list、environment、shells、close。allowSsh 关闭时，子用户
// 没有宿主 terminal 能力：这四者回「不放开能力」的 server-response，避免 restore/setup
// 进入常驻重试；其余 terminal RPC 保持 fail-closed 403。allowSsh 开启时，官方已知
// terminal HTTP unary RPC 原样透传到上游（与已登记第三方 SSH 共用同一个开关）。
// 主用户不受影响，官方 terminal 与登记路由原样透传。
import { after, before, test } from 'node:test';
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
import { parseEndpointAllowlist } from '../src/permissions.js';
import type { PlatformConfig } from '../src/config.js';

let appDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let upstreamHits: string[] = [];
let upstreamBodies: Array<{ url: string; body: string }> = [];
let gatewayPort = 0;
let subuserId = 0;
let adminCookie = '';
let subuserCookie = '';

function post(url: string, body: unknown, cookie: string): Promise<{ status: number; json: Record<string, unknown>; body: string }> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        method: 'POST',
        path: url,
        headers: { cookie, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            /* 403 页面等非 JSON */
          }
          resolve({ status: res.statusCode ?? 0, json, body: text });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

const envelope = (rpcId: string, method: string, args: Record<string, unknown>) => ({
  type: 'client-request', rpcId, method, payload: { args },
});

/** 任意方法/任意原始 body 的请求，用于 GET / 非 JSON / 超长 body 等 fail-closed 回归。 */
function requestRaw(
  method: string,
  url: string,
  cookie: string,
  body?: string,
): Promise<{ status: number; json: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { cookie, 'content-type': 'application/json' };
    if (body !== undefined) headers['content-length'] = String(Buffer.byteLength(body));
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method, path: url, headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json: Record<string, unknown> = {};
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            /* 403 页面等非 JSON */
          }
          resolve({ status: res.statusCode ?? 0, json, body: text });
        });
      },
    );
    req.on('error', reject);
    req.end(body ?? '');
  });
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-termstub-app-'));
  mkdirSync(path.join(appDir, 'data'));
  const dbPath = path.join(appDir, 'data', 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const admin = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const subuser = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu');
  subuserId = subuser.id;
  db.setPermissions(subuserId, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null,
  });

  upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      upstreamHits.push(String(req.url));
      upstreamBodies.push({ url: String(req.url), body: Buffer.concat(chunks).toString('utf8') });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'server-response', rpcId: 'upstream', result: { ok: true, value: [] } }));
    });
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
    // 即使 terminal 路径被误写进第三方登记表，也必须由 allowSsh 的官方分支
    // 决定是否放行；这里不使用 owner: 规则，以便单独覆盖统一开关的开/关态。
    endpointRules: parseEndpointAllowlist('/api/terminal/*,ws:/api/terminal/*', 'TEST'),
  };
  const tokenFor = (user: { id: number; username: string }) =>
    `dsh_gateway_token=${jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  adminCookie = tokenFor(admin);
  subuserCookie = tokenFor(subuser);

  gateway = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstream?.close();
  try {
    rmSync(appDir, { recursive: true, force: true });
  } catch {
    /* Windows 文件占用：忽略 */
  }
});

test('子用户 account profile/balance 仍使用已选定的宿主只读视图', async () => {
  for (const method of ['getProfile', 'getBalance']) {
    upstreamHits = [];
    const body = envelope(`rpc-account-${method}`, `account/${method}`, {});
    const res = await post(`/api/account/${method}`, body, subuserCookie);
    assert.equal(res.status, 200, `account/${method} 保持宿主只读兼容面`);
    assert.deepEqual(upstreamHits, [`/api/account/${method}`]);
  }
});

test('子用户 terminal/list → 200 空成功（value 必须是裸数组，rpcId 原样回显）', async () => {
  upstreamHits = [];
  const res = await post('/api/terminal/list', envelope('rpc-restore-1', 'terminal/list', { sessionId: 'session-x' }), subuserCookie);
  assert.equal(res.status, 200, `必须回 200 而不是 403：${res.body.slice(0, 120)}`);
  assert.equal(res.json.type, 'server-response');
  assert.equal(res.json.rpcId, 'rpc-restore-1', 'rpcId 必须逐字回显（客户端硬校验不匹配即抛错）');
  const result = res.json.result as { ok?: unknown; value?: unknown } | undefined;
  assert.equal(result?.ok, true);
  assert.deepEqual(result?.value, [], 'value 必须是裸数组 []（schema 是 z.array，非数组会抛错）');
  assert.equal(upstreamHits.length, 0, '伪装响应不得到达上游');
});

test('子用户真实 terminal RPC 一律 403（allowSsh 关闭）：登记 /api/terminal/* 也不放行', async () => {
  for (const method of ['create', 'follow', 'write', 'rename', 'resize', 'retain']) {
    upstreamHits = [];
    const res = await post(`/api/terminal/${method}`, envelope(`rpc-${method}`, `terminal/${method}`, { agentId: 'a' }), subuserCookie);
    assert.equal(res.status, 403, `allowSsh 关闭时 terminal/${method} 仍必须 403`);
    assert.equal(upstreamHits.length, 0, `allowSsh 关闭时 terminal/${method} 不得到达上游`);
  }
});

test('allowSsh 关闭时，子用户 terminal/environment、terminal/shells（点号/斜杠）→ 200 terminal/unavailable 且不触上游', async () => {
  for (const [url, method] of [
    ['/api/terminal/environment', 'terminal/environment'],
    ['/api/terminal.environment', 'terminal/environment'],
    ['/api/terminal/shells', 'terminal/shells'],
    ['/api/terminal.shells', 'terminal/shells'],
  ] as const) {
    upstreamHits = [];
    const res = await post(url, envelope(`rpc-${method}-${url}`, method, { sessionId: 'session-x', agentId: 'a' }), subuserCookie);
    assert.equal(res.status, 200, `${url} 必须回 200 而不是 403：${res.body.slice(0, 120)}`);
    assert.equal(res.json.type, 'server-response');
    assert.equal(res.json.rpcId, `rpc-${method}-${url}`, 'rpcId 必须逐字回显');
    const result = res.json.result as { ok?: unknown; error?: Record<string, unknown> } | undefined;
    assert.equal(result?.ok, false, 'environment/shells 必须 ok=false');
    assert.equal(result?.error?.code, 'terminal/unavailable', '必须回固定错误码 terminal/unavailable');
    assert.equal(typeof result?.error?.message, 'string', 'error.message 必须是字符串');
    assert.ok((result?.error?.message as string).length > 0, 'error.message 必须非空且固定');
    assert.deepEqual(result?.error?.details, {}, 'error.details 必须是 plain object');
    assert.equal(upstreamHits.length, 0, '环境/shell 桩不得到达上游');
  }
});

test('allowSsh 关闭时，子用户 terminal/close（点号/斜杠）→ 200 ok 幂等成功且不含 value（alpha.2 z.void），不触上游', async () => {
  for (const url of ['/api/terminal/close', '/api/terminal.close'] as const) {
    upstreamHits = [];
    const res = await post(url, envelope(`rpc-close-${url}`, 'terminal/close', { agentId: 'a' }), subuserCookie);
    assert.equal(res.status, 200, `${url} 必须回 200 而不是 403：${res.body.slice(0, 120)}`);
    assert.equal(res.json.type, 'server-response');
    assert.equal(res.json.rpcId, `rpc-close-${url}`, 'rpcId 必须逐字回显');
    const result = res.json.result as Record<string, unknown> | undefined;
    assert.equal(result?.ok, true, 'close 是幂等清理桩，必须 ok=true');
    assert.equal(Object.hasOwn(result ?? {}, 'value'), false, 'close 结果不得包含 value（z.void，带 value 客户端 schema 会报错）');
    assert.equal(upstreamHits.length, 0, 'close 桩不得到达上游');
  }
});

test('allowSsh 开启时，子用户官方 terminal 已知 HTTP unary RPC 原样透传到上游', async () => {
  db.setPermissions(subuserId, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    allowSsh: true, banned: false, sandboxMode: null,
  });
  try {
    // allowSsh 开启后，四个恢复/清理方法与四个真实能力方法都进入官方 terminal
    // 透传分支：不再回无能力桩，也不再 403。
    const methods = ['list', 'environment', 'shells', 'close', 'create', 'write', 'resize', 'rename'] as const;
    for (const method of methods) {
      upstreamHits = [];
      upstreamBodies = [];
      const body = envelope(`rpc-ssh-on-${method}`, `terminal/${method}`, { sessionId: 'session-x', agentId: 'a' });
      const res = await post(`/api/terminal/${method}`, body, subuserCookie);
      assert.equal(res.status, 200, `allowSsh 开启后 terminal/${method} 必须透传：${res.body.slice(0, 160)}`);
      assert.equal(res.json.type, 'server-response');
      const result = res.json.result as { ok?: unknown } | undefined;
      assert.equal(result?.ok, true, `terminal/${method} 必须拿到上游成功响应，而不是本地无能力桩`);
      assert.equal(upstreamHits.length, 1, `allowSsh 开启后 terminal/${method} 必须恰好到达上游一次`);
      assert.equal(upstreamBodies[0]?.url, `/api/terminal/${method}`);
      assert.equal(upstreamBodies[0]?.body, JSON.stringify(body), `terminal/${method} body 必须逐字透传`);
    }

    // follow/retain 是 Remote mux 端点，不是官方 terminal HTTP unary RPC；即使
    // allowSsh 开启，这两个 HTTP 形状仍命中硬拒绝分类，保持 fail-closed 403。
    for (const method of ['follow', 'retain'] as const) {
      upstreamHits = [];
      const res = await post(`/api/terminal/${method}`, envelope(`rpc-ssh-on-${method}`, `terminal/${method}`, { agentId: 'a' }), subuserCookie);
      assert.equal(res.status, 403, `terminal/${method} 不是官方 HTTP unary RPC，必须 403`);
      assert.equal(upstreamHits.length, 0, `terminal/${method} 不得到达上游`);
    }
  } finally {
    db.setPermissions(subuserId, {
      allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
      allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
      allowSsh: false, banned: false, sandboxMode: null,
    });
  }
});

test('主用户 terminal/list 正常透传到上游（不受桩影响）', async () => {
  upstreamHits = [];
  upstreamBodies = [];
  const body = envelope('rpc-admin-1', 'terminal/list', { sessionId: 'session-x' });
  const res = await post('/api/terminal/list', body, adminCookie);
  assert.equal(res.status, 200);
  assert.equal(upstreamHits.some((url) => url.includes('/api/terminal/list')), true, '主用户请求必须到达上游');
  assert.deepEqual(upstreamBodies[0]?.body, JSON.stringify(body), '主用户 RPC body 必须逐字透传');
});

test('主用户 alpha.2 terminal HTTP unary 生命周期全部开箱即用：均绕过子用户桩并到达上游', async () => {
  const methods = ['environment', 'shells', 'list', 'create', 'write', 'resize', 'rename', 'close'] as const;
  for (const method of methods) {
    upstreamHits = [];
    upstreamBodies = [];
    const body = envelope(`rpc-admin-${method}`, `terminal/${method}`, { agentId: 'agent-owner', id: 'term-owner' });
    const res = await post(`/api/terminal/${method}`, body, adminCookie);
    assert.equal(res.status, 200, `terminal/${method} 必须成功透传：${res.body.slice(0, 160)}`);
    const result = res.json.result as { ok?: unknown; value?: unknown } | undefined;
    assert.equal(result?.ok, true, `terminal/${method} 必须是上游成功响应，而不是子用户桩`);
    assert.equal(upstreamHits.length, 1, `terminal/${method} 必须恰好到达上游一次`);
    assert.equal(upstreamBodies[0]?.url, `/api/terminal/${method}`);
    assert.equal(upstreamBodies[0]?.body, JSON.stringify(body), `terminal/${method} body 必须逐字透传`);
  }
});

test('terminal 硬拒绝分类下，allowSsh 关闭时子用户真实 RPC 仍拒绝', async () => {
  for (const method of ['list', 'environment', 'shells', 'close'] as const) {
    upstreamHits = [];
    const res = await post(`/api/terminal/${method}`, envelope(`rpc-blocked-${method}`, `terminal/${method}`, {}), subuserCookie);
    assert.equal(res.status, 200, `allowSsh 关闭时 terminal/${method} 仍应返回安全桩`);
    assert.equal(upstreamHits.length, 0, `allowSsh 关闭时 terminal/${method} 不得到达上游`);
  }
  for (const method of ['create', 'write', 'resize', 'rename'] as const) {
    upstreamHits = [];
    const res = await post(`/api/terminal/${method}`, envelope(`rpc-blocked-${method}`, `terminal/${method}`, {}), subuserCookie);
    assert.equal(res.status, 403, `allowSsh 关闭时 terminal/${method} 仍必须拒绝`);
    assert.equal(upstreamHits.length, 0, `allowSsh 关闭时 terminal/${method} 不得到达上游`);
  }
});

test('terminal 桩信封不合法一律 fail-closed 403：非 POST / 畸形 JSON / 超大 body / rpcId 非法 / method 不匹配', async () => {
  upstreamHits = [];
  // 非 POST
  assert.equal((await requestRaw('GET', '/api/terminal/environment', subuserCookie)).status, 403);
  assert.equal((await requestRaw('GET', '/api/terminal/list', subuserCookie)).status, 403);
  // 非 JSON body
  assert.equal((await requestRaw('POST', '/api/terminal/shells', subuserCookie, 'not-json')).status, 403);
  // 合法 rpcId 但 method 与路径不一致
  assert.equal((await post('/api/terminal/environment', envelope('rpc-mismatch', 'terminal/shells', {}), subuserCookie)).status, 403);
  assert.equal((await post('/api/terminal/close', envelope('rpc-mismatch', 'terminal/create', {}), subuserCookie)).status, 403);
  // rpcId 缺失 / 空 / 超长 200
  assert.equal((await post('/api/terminal/close', { type: 'client-request', method: 'terminal/close', payload: { args: {} } }, subuserCookie)).status, 403);
  assert.equal((await post('/api/terminal/close', envelope('', 'terminal/close', {}), subuserCookie)).status, 403);
  assert.equal((await post('/api/terminal/close', envelope('x'.repeat(201), 'terminal/close', {}), subuserCookie)).status, 403);
  // 非 client-request 信封
  assert.equal((await post('/api/terminal/close', { type: 'server-response', rpcId: 'rpc-bad-type', method: 'terminal/close' }, subuserCookie)).status, 403);
  // body 超过 64 KiB
  const oversized = await post(
    '/api/terminal/shells',
    envelope('rpc-oversized', 'terminal/shells', { blob: 'x'.repeat(70 * 1024) }),
    subuserCookie,
  );
  assert.equal(oversized.status, 403, '信封超 64KiB 不得伪造成功');
  assert.equal(upstreamHits.length, 0, '所有 fail-closed 分支都不得到达上游');
});
