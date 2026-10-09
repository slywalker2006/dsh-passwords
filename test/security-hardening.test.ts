// 全量审计修复的回归测试（commit 后补）：每条对应审计报告的一项修复契约。
//
//   C-1  %2F 编码路径：授权判定与上游转发必须用同一规范化路径
//   H-1  过滤分支缓冲超限：fail-closed 502，绝不透传未过滤内容
//   H-2  自身插件写操作同源校验：跨源 Origin → 403
//   M-1  setup 竞态：setupInitialAdmin 原子化，并发/重复初始化只能成功一次
//   M-10 会话缓存失效内部接口：仅回环 + 内部密钥
//   M-13 allowedFolders 空条目/根目录条目拒绝（=全盘放行语义漏洞）
//   L-4  CSR 必须同时携带 CN 与 SAN（subjectAltName OID 2.5.29.17）
//   M-5  聊天游标倒退检测（服务端 DB 重建基线重建，不计未读）
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import zlib from 'node:zlib';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { generateKeyPairSync } from 'node:crypto';

import { createGatewayServer } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { buildCsr, certMatchesDomain } from '../src/acme.js';
import { isCursorReset, type ChatMessage } from '../src/client/chat.tsx';
import type { PlatformConfig } from '../src/config.js';

let tempDir: string;
let db: Database;
let crypto: ReturnType<typeof createFieldCrypto>;
let upstream: http.Server;
let gateway: http.Server;
let gatewayPort = 0;
let adminCookie = '';
let subuserCookie = '';
let subuserId = 0;
let adminId = 0;
let thirdId = 0;
/** 上游最后一次收到的路径（已解码视角，mock 直接取 req.url） */
let lastUpstreamUrl = '';
const upstreamUrls: string[] = [];
/** 高压缩比炸弹：70MiB 全零压缩后仅 ~70KB，专门验证 maxOutputLength 前置拦截 */
let gzipBomb: Buffer | null = null;

function startMockUpstream(): Promise<http.Server> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      lastUpstreamUrl = req.url ?? '';
      upstreamUrls.push(lastUpstreamUrl);
      if ((req.url ?? '').startsWith('/api/session.list') && req.headers['x-test-mode'] === 'big') {
        // 16MiB+ 超限响应：chunked 写 17MB（不设 content-length，同 dsh 行为）
        res.writeHead(200, { 'content-type': 'application/json' });
        const chunk = Buffer.alloc(1024 * 1024, 0x61); // 'a'
        let written = 0;
        const writeMore = () => {
          for (let i = 0; i < 4 && written < 17 * 1024 * 1024; i++) {
            res.write(chunk);
            written += chunk.length;
          }
          if (written < 17 * 1024 * 1024) {
            setImmediate(writeMore);
          } else {
            res.end();
          }
        };
        writeMore();
        return;
      }
      if ((req.url ?? '').startsWith('/api/session.list') && req.headers['x-test-mode'] === 'gzip-bomb') {
        // 压缩后远小于 16MiB 缓冲上限、解压后超 64MiB：旧实现事后检查拦不住内存峰值
        if (gzipBomb === null) {
          gzipBomb = zlib.gzipSync(Buffer.alloc(70 * 1024 * 1024, 0x61));
        }
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' });
        res.end(gzipBomb);
        return;
      }
      if ((req.url ?? '').startsWith('/api/dsh-passwords/internal/assignable-resources')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, folders: ['/workspaces/a'], sessions: [], retainedSessions: [] }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, method: req.method, url: req.url }));
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

function gatewayReq(
  method: string,
  url: string,
  headers: Record<string, string> = {},
  cookie = adminCookie,
  body?: string,
  localAddress?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        // 指定源地址可模拟非回环 peer（127.0.0.2 不在 originHostMatches 的回环白名单内）
        localAddress,
        method,
        path: url,
        headers: {
          cookie,
          'content-type': 'application/json',
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-harden-'));
  crypto = createFieldCrypto('testkey', 'testkey');
  db = new Database(path.join(tempDir, 'test.db'), crypto);
  db.init();
  // 主用户 + 子用户（子用户无 user_permissions 行 = 默认权限）+ 第三方账号（消息饥饿回归用）
  const adminUser = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  adminId = adminUser.id;
  const sub = db.createUser('subuser', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  subuserId = sub.id;
  const third = db.createUser('third', '$2a$10$dummyhashdummyhashdummyhashdu', 'user');
  thirdId = third.id;
  // 登录限速回归：真实 bcrypt 凭据（登录流程需要比对）
  db.createUser('ratelimit', bcrypt.hashSync('Password123!', 10), 'user');

  upstream = await startMockUpstream();
  const upstreamPort = (upstream.address() as { port: number }).port;

  const config: PlatformConfig = {
    setupKey: 'test-setup-key',
    dbPath: path.join(tempDir, 'test.db'),
    dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1',
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null,
      redirectPort: null,
      publicHost: 'public.example.test',
      domain: 'localhost',
      autoTls: false,
      acmeEmail: '',
      acmeStaging: false,
    },
    jwtSecret: 'test-secret',
    internalSecret: 'test-internal-secret',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };

  const auth = new AuthService(config, db);
  gateway = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
  gatewayPort = (gateway.address() as { port: number }).port;

  const sign = (id: number, username: string) =>
    jwt.sign({ sub: String(id), username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' });
  adminCookie = `dsh_gateway_token=${sign(1, 'admin')}`;
  subuserCookie = `dsh_gateway_token=${sign(subuserId, 'subuser')}`;
});

after(() => {
  gateway?.close();
  upstream?.close();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* 文件锁未释放：系统临时目录回收 */
  }
});

// ── C-1：编码路径在授权判定与转发间必须同口径 ─────────────────

test('C-1：受限子用户经 %2F 编码路径调用会话 RPC 无基线时仍不得转发', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq('POST', '/api%2Fsession%2Fhistory', {}, subuserCookie, '{}');
  assert.equal(r.status, 503, '基线未就绪只返回可重试状态，不能绕过会话归属检查');
  assert.ok(!upstreamUrls.includes('/api/session/history'), '请求不得转发到上游');
});

test('C-1：主用户经 %2F 编码路径转发为解码后的规范路径（判定与转发同口径）', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq('POST', '/api%2Fsession%2Fhistory', {}, adminCookie, '{}');
  assert.equal(r.status, 200);
  assert.ok(upstreamUrls.includes('/api/session/history'), '上游应收到解码归一化后的路径');
});

// ── H-2：自身插件写操作同源校验 ───────────────────────────────

test('H-2：跨源 Origin 写自身插件路由被 403 且不转发', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    { origin: 'https://evil.example' },
    adminCookie,
    '{}',
  );
  assert.equal(r.status, 403);
  assert.equal(upstreamUrls.length, 0, '跨源请求不得到达上游');
});

// 字面量 `Origin: null`（opaque 序列化）与「无 Origin」是不同语义：前者必须拒绝。
// 修复前 new URL('null') 抛异常落进 origin-unparsable；分类为 origin-null 后仍返回 false。
test('H-2：字面量 Origin: null 写自身插件路由仍 403 且不转发', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    { origin: 'null', 'sec-fetch-site': 'same-origin' },
    adminCookie,
    '{}',
  );
  assert.equal(r.status, 403, 'Origin: null 不得被当作无 Origin 放行');
  assert.equal(upstreamUrls.length, 0, 'Origin: null 请求不得到达上游');
});

test('H-2：配置的公开域名 Origin 经回环反代放行', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    { host: '127.0.0.1', origin: 'https://public.example.test' },
    adminCookie,
    '{}',
  );
  assert.equal(r.status, 200);
  assert.equal(upstreamUrls.length, 1, '配置的公开域名经受信回环反代应正常转发');
});

test('H-2：同源 Origin 写自身插件路由放行', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    { origin: `http://127.0.0.1:${gatewayPort}` },
    adminCookie,
    '{}',
  );
  assert.equal(r.status, 200);
  assert.equal(upstreamUrls.length, 1, '同源请求应正常转发');
});

// 回归：非回环反向代理把 Host 改写为内网地址，浏览器 Origin 仍是配置的公开主机。
// configuredHosts 是服务端显式配置的信任来源，匹配不得受 peer 是否回环限制；
// 但非回环 peer 携带的 X-Forwarded-Host 仍不得被采纳。
test('H-2：非回环反代改写 Host 为内网时，配置的公开主机 Origin 仍放行', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    { host: `127.0.0.1:${gatewayPort}`, origin: 'https://public.example.test' },
    adminCookie,
    '{}',
    '127.0.0.2',
  );
  assert.equal(r.status, 200, '非回环 peer 下配置的公开主机 Origin 不得被误判为跨源');
  assert.equal(upstreamUrls.length, 1, '配置的公开主机 Origin 应正常转发');
});

test('H-2：非回环 peer 的恶意 Origin 仍 403，且伪造 X-Forwarded-Host 不被采纳', async () => {
  upstreamUrls.length = 0;
  const r = await gatewayReq(
    'POST',
    '/api/dsh-passwords/password',
    {
      host: `127.0.0.1:${gatewayPort}`,
      origin: 'https://evil.example',
      'x-forwarded-host': 'evil.example',
    },
    adminCookie,
    '{}',
    '127.0.0.2',
  );
  assert.equal(r.status, 403, '非回环 peer 不得采纳 X-Forwarded-Host 绕过同源校验');
  assert.equal(upstreamUrls.length, 0, '恶意 Origin 不得到达上游');
});

// ── 兄弟子域 CSRF：apiAuth 状态变更方法必须同源 ─────────────────
// Sec-Fetch-Site 只区分 cross-site，同站兄弟子域恒为 same-site；全局
// express.urlencoded 允许无预检的简单表单 POST，因此状态变更路由必须按
// Origin vs Host 同源判定拒绝，且必须在写库前拒绝。

test('子域 CSRF：同站兄弟子域 Origin 表单 POST /gateway/api/messages → 403 且不落库', async () => {
  const before = db.listMessagesForUser(adminId, 300).length;
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    {
      host: 'app.example.com',
      origin: 'http://evil.example.com',
      'sec-fetch-site': 'same-site',
      'content-type': 'application/x-www-form-urlencoded',
    },
    subuserCookie,
    'content=csrf-pwned',
  );
  assert.equal(r.status, 403);
  assert.match(r.body, /FORBIDDEN_CSRF/);
  assert.equal(db.listMessagesForUser(adminId, 300).length, before, '被拒绝的请求不得写入消息');
});

test('子域 CSRF：无 Origin 的非浏览器/旧客户端表单 POST 仍被接受', async () => {
  const before = db.listMessagesForUser(adminId, 300).length;
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    { 'content-type': 'application/x-www-form-urlencoded' },
    subuserCookie,
    'content=no-origin-accepted',
  );
  assert.equal(r.status, 200);
  const after = db.listMessagesForUser(adminId, 300);
  assert.equal(after.length, before + 1, '无 Origin 客户端应保持原有可用性');
  assert.ok(after.some((m) => m.content === 'no-origin-accepted'));
  // 本用例必需的一次真实写入：立即清空，避免污染后续依赖消息基线的用例
  db.clearMessages();
});

test('子域 CSRF：同主 Origin 表单 POST 仍被接受', async () => {
  const before = db.listMessagesForUser(adminId, 300).length;
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    {
      origin: `http://127.0.0.1:${gatewayPort}`,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/x-www-form-urlencoded',
    },
    subuserCookie,
    'content=same-host-accepted',
  );
  assert.equal(r.status, 200);
  assert.equal(db.listMessagesForUser(adminId, 300).length, before + 1);
  db.clearMessages();
});

test('子域 CSRF：同站兄弟子域 Origin 表单 POST 管理写路由 /gateway/api/permissions → 403', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/permissions',
    {
      host: 'app.example.com',
      origin: 'http://evil.example.com',
      'sec-fetch-site': 'same-site',
      'content-type': 'application/x-www-form-urlencoded',
    },
    adminCookie,
    `userId=${subuserId}&allowedFolders=%2Ftmp`,
  );
  assert.equal(r.status, 403);
  assert.match(r.body, /FORBIDDEN_CSRF/);
});

// ── H-1：安全过滤分支缓冲超限 fail-closed ─────────────────────

test('H-1：受限子用户 session.list 响应超 16MiB → 502（不透传未过滤内容）', async () => {
  const r = await gatewayReq(
    'POST',
    '/api/session.list',
    { 'x-test-mode': 'big' },
    subuserCookie,
    '{}',
  );
  assert.equal(r.status, 502);
});

test('H-1b：gzip 高压缩比炸弹（解压后 70MiB）→ 502（maxOutputLength 前置拦截）', async () => {
  const r = await gatewayReq(
    'POST',
    '/api/session.list',
    { 'x-test-mode': 'gzip-bomb' },
    subuserCookie,
    '{}',
  );
  assert.equal(r.status, 502);
});

test('M-5b：since 超过最新消息 id（DB 重建后）返回 reset 信号 + 全量列表', async () => {
  await gatewayReq('POST', '/gateway/api/messages', {}, adminCookie, JSON.stringify({ content: 'reset-a', broadcast: true }));
  await gatewayReq('POST', '/gateway/api/messages', {}, adminCookie, JSON.stringify({ content: 'reset-b', broadcast: true }));
  const r1 = await gatewayReq('GET', '/gateway/api/messages?since=999999');
  assert.equal(r1.status, 200);
  const body1 = JSON.parse(r1.body) as { reset?: boolean; messages: Array<{ id: number }> };
  assert.equal(body1.reset, true, '游标超前必须显式告知 reset');
  assert.equal(body1.messages.length, 2, 'reset 时应回退全量列表');
  // 服务端全量列表按 id DESC 返回：最新一条是第一个元素
  const maxId = Math.max(...body1.messages.map((m) => m.id));
  const r2 = await gatewayReq('GET', `/gateway/api/messages?since=${maxId}`);
  const body2 = JSON.parse(r2.body) as { reset?: boolean; messages: Array<{ id: number }> };
  assert.notEqual(body2.reset, true, '正常增量（无新消息）不得误报 reset');
  assert.equal(body2.messages.length, 0);
});

test('M-5c：其他用户私信不堵塞当前用户增量拉取（可见性在 SQL 层 LIMIT 前过滤）', async () => {
  // 基线：admin 发的广播，增量游标从它之后开始
  const baseline = db.addMessage(adminId, null, 'baseline', []);
  // 300 条 admin 不可见的私信（subuser → third）占满全局窗口
  for (let i = 0; i < 300; i++) db.addMessage(subuserId, thirdId, `hidden-${i}`, []);
  // 之后发给 admin 的目标消息——旧实现全局 LIMIT 300 会把它的 id 挤在窗口外，永远取不到
  db.addMessage(subuserId, adminId, 'target-for-admin', []);

  // 增量：游标=基线 id，应直接拿到目标消息（不被 300 条隐藏私信堵塞）
  const r = await gatewayReq('GET', `/gateway/api/messages?since=${baseline.id}`, {}, adminCookie);
  assert.equal(r.status, 200);
  const body = JSON.parse(r.body) as { reset?: boolean; messages: Array<{ content: string }> };
  assert.notEqual(body.reset, true, '有可见新消息时不得误报 reset');
  const contents = body.messages.map((m) => m.content);
  assert.ok(contents.includes('target-for-admin'), '发给当前用户的消息必须可见');
  assert.ok(!contents.includes('hidden-0'), '他人私信不得泄露给当前用户');

  // reset：游标远超自身最新可见 id → reset=true，回退全量且不泄露他人私信
  const r2 = await gatewayReq('GET', '/gateway/api/messages?since=999999', {}, adminCookie);
  const body2 = JSON.parse(r2.body) as { reset?: boolean; messages: Array<{ content: string }> };
  assert.equal(body2.reset, true, '游标超前于自身最新可见 id 时必须报 reset');
  const resetContents = body2.messages.map((m) => m.content);
  assert.ok(resetContents.includes('target-for-admin'), 'reset 全量必须包含当前用户可见消息');
  assert.ok(!resetContents.some((c) => c.startsWith('hidden-')), 'reset 全量不得泄露他人私信');
});

// ── 消息写入：recipientId 显式校验（不再静默转广播） ─────────────

test('消息写入：非法 recipientId 不再静默转广播（400）', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    {},
    subuserCookie,
    JSON.stringify({ content: 'bad-recipient', recipientId: 'abc' }),
  );
  assert.equal(r.status, 400);
});

test('消息写入：不存在的收件人 → 404（不产生孤儿私信）', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    {},
    subuserCookie,
    JSON.stringify({ content: 'ghost-recipient', recipientId: 999999 }),
  );
  assert.equal(r.status, 404);
});

test('消息写入：子用户不能向其他子用户私信 → 403', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/messages',
    {},
    subuserCookie,
    JSON.stringify({ content: 'dm-target', recipientId: thirdId }),
  );
  assert.equal(r.status, 403);
});

// ── 会话缓存不得延长已过期 JWT ───────────────────────────────

test('会话缓存不延长已过期 JWT（缓存 TTL 与 JWT exp 取最小值）', async () => {
  const shortToken = jwt.sign({ sub: String(adminId), username: 'admin', cv: 0 }, 'test-secret', {
    expiresIn: '1s',
  });
  const cookie = `dsh_gateway_token=${shortToken}`;
  const first = await gatewayReq('GET', '/html', {}, cookie);
  assert.equal(first.status, 200, '未过期时正常通过');
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const second = await gatewayReq('GET', '/html', {}, cookie);
  assert.equal(second.status, 302, 'JWT 过期后即使仍在会话缓存窗口内也必须拒绝');
});

// ── 登录限速：revokedTokens 内存面的正当缓解 ──────────────────

function rawHttp(options: {
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method: options.method, path: options.path, headers: options.headers ?? {} },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const headers: Record<string, string> = {};
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            headers[res.rawHeaders[i].toLowerCase()] = res.rawHeaders[i + 1];
          }
          resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString('utf8') });
        });
      },
    );
    req.on('error', reject);
    req.end(options.body);
  });
}

/** 完整登录流程（CSRF 双重提交）：GET 登录页拿 cookie+表单域 → POST 表单编码凭据 */
async function loginWithCsrf(username: string, password: string): Promise<number> {
  const page = await rawHttp({ method: 'GET', path: '/gateway/login' });
  const setCookie = page.headers['set-cookie'] ?? '';
  const csrfCookie = (setCookie.match(/dsh_csrf=([^;]+)/) ?? [])[1] ?? '';
  const field = (page.body.match(/name="csrf" value="([^"]+)"/) ?? [])[1] ?? '';
  const payload = `csrf=${encodeURIComponent(field)}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;
  return (
    await rawHttp({
      method: 'POST',
      path: '/gateway/login',
      headers: { cookie: `dsh_csrf=${csrfCookie}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: payload,
    })
  ).status;
}

test('登录限速：每用户每分钟最多 10 次成功登录（revokedTokens 内存面封顶）', async () => {
  const statuses: number[] = [];
  for (let i = 0; i < 11; i++) {
    statuses.push(await loginWithCsrf('ratelimit', 'Password123!'));
  }
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(302), '前 10 次成功登录应 302');
  assert.equal(statuses[10], 429, '第 11 次应被限速');
});

// ── 登出 CSRF：同站子域强制登出被拦截 ───────────────────────

test('登出 CSRF：跨源 Origin 强制登出被拒绝（403）且不吊销 token', async () => {
  const tmp = db.createUser('logout-tmp', bcrypt.hashSync('Password123!', 4), 'user');
  const token = jwt.sign(
    { sub: String(tmp.id), username: 'logout-tmp', cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const cookie = `dsh_gateway_token=${token}`;
  const r = await gatewayReq('POST', '/gateway/logout', { origin: 'https://evil.example' }, cookie);
  assert.equal(r.status, 403, '跨源提交必须被拒绝');
  const after = await gatewayReq('GET', '/', {}, cookie);
  assert.equal(after.status, 200, '被拒登出不得吊销会话');
});

test('普通根级插件路径对子用户直通，官方根级与 /api 面保持可用', async () => {
  const tmp = db.createUser('root-scope-tmp', bcrypt.hashSync('Password123!', 4), 'user');
  const token = jwt.sign(
    { sub: String(tmp.id), username: 'root-scope-tmp', cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const cookie = `dsh_gateway_token=${token}`;
  const ordinaryPlugin = await gatewayReq('GET', '/third-party-panel/status', {}, cookie);
  assert.equal(ordinaryPlugin.status, 200, '普通根级插件路径对子用户直通');
  const officialRoot = await gatewayReq('GET', '/plugins/example/client.js', {}, cookie);
  assert.equal(officialRoot.status, 200, '官方根级静态/bundle 路径保持可用');
  const officialApi = await gatewayReq('GET', '/api/session/history', {}, cookie);
  assert.equal(officialApi.status, 200, '官方 /api 面保持可用');
});

test('登出 CSRF：同源 Origin 登出放行（302）', async () => {
  const tmp = db.createUser('logout-tmp2', bcrypt.hashSync('Password123!', 4), 'user');
  const token = jwt.sign(
    { sub: String(tmp.id), username: 'logout-tmp2', cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const cookie = `dsh_gateway_token=${token}`;
  const r = await gatewayReq(
    'POST',
    '/gateway/logout',
    { origin: `http://127.0.0.1:${gatewayPort}` },
    cookie,
  );
  assert.equal(r.status, 302, '同源登出应放行并重定向到登录页');
});

test('登出 CSRF：无 Origin（非浏览器/旧客户端）登出放行（302）', async () => {
  const tmp = db.createUser('logout-tmp3', bcrypt.hashSync('Password123!', 4), 'user');
  const token = jwt.sign(
    { sub: String(tmp.id), username: 'logout-tmp3', cv: 0 },
    'test-secret',
    { expiresIn: '12h' },
  );
  const cookie = `dsh_gateway_token=${token}`;
  const r = await gatewayReq('POST', '/gateway/logout', {}, cookie);
  assert.equal(r.status, 302);
});

// ── M-1：setup 竞态原子化 ─────────────────────────────────────

test('M-1：setupInitialAdmin 只允许成功一次，重复调用返回 null', () => {
  const raceDb = new Database(path.join(tempDir, 'race.db'), crypto);
  raceDb.init();
  const first = raceDb.setupInitialAdmin('owner', 'hash-1');
  assert.ok(first !== null, '首次初始化应创建主用户');
  assert.equal(first.role, 'admin');
  assert.equal(raceDb.countUsers(), 1);
  const second = raceDb.setupInitialAdmin('owner2', 'hash-2');
  assert.equal(second, null, '重复初始化必须失败（原子判定）');
  assert.equal(raceDb.countUsers(), 1, '不得创建第二个主用户');
  raceDb.close();
});

// ── M-10：会话缓存失效内部接口鉴权 ────────────────────────────

test('M-10：session-invalidate 内部接口错误密钥 → 403', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/internal/session-invalidate',
    { 'x-internal-secret': 'wrong-secret' },
    '',
    JSON.stringify({ userId: 1 }),
  );
  assert.equal(r.status, 403);
});

test('M-10：session-invalidate 内部接口正确密钥 → 200', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/internal/session-invalidate',
    { 'x-internal-secret': 'test-internal-secret' },
    '',
    JSON.stringify({ userId: 1 }),
  );
  assert.equal(r.status, 200);
});

// ── M-13：allowedFolders 拒绝全盘放行语义条目 ─────────────────

test('M-13：allowedFolders 含空字符串 → 400', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/permissions',
    {},
    adminCookie,
    JSON.stringify({ userId: subuserId, allowedFolders: [''] }),
  );
  assert.equal(r.status, 400);
});

test('M-13：allowedFolders 含根目录 → 400', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/permissions',
    {},
    adminCookie,
    JSON.stringify({ userId: subuserId, allowedFolders: ['/'] }),
  );
  assert.equal(r.status, 400);
});

test('M-13：allowedFolders 合法绝对路径 → 200', async () => {
  const r = await gatewayReq(
    'POST',
    '/gateway/api/permissions',
    {},
    adminCookie,
    JSON.stringify({ userId: subuserId, allowedFolders: ['/workspaces/a'] }),
  );
  assert.equal(r.status, 200);
});

// ── L-4：CSR 含 CN + SAN（RFC 5280 结构验证，非浅层字节存在性） ──

const SAN_OID = Buffer.from([0x55, 0x1d, 0x11]);

/** 极简 DER TLV 解析：返回 { tag, content, end }（content 为值域，end 为下一元素偏移） */
function parseDer(buf: Buffer, offset: number): { tag: number; content: Buffer; end: number } {
  const tag = buf[offset];
  const firstLen = buf[offset + 1];
  let len = firstLen;
  let head = 2;
  if ((firstLen & 0x80) !== 0) {
    const count = firstLen & 0x7f;
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + buf[offset + 2 + i];
    head = 2 + count;
  }
  return { tag, content: buf.subarray(offset + head, offset + head + len), end: offset + head + len };
}

/**
 * 递归找 subjectAltName 扩展并验证结构：
 *   Extension = SEQ { OID(2.5.29.17), OCTET STRING{ GeneralNames = SEQ { [2] dNSName } } }
 * 浅层字节断言（OID+域名存在）无法发现“缺 OCTET STRING 包装”的非法 DER。
 */
function hasWellFormedSan(node: { tag: number; content: Buffer }, domain: string): boolean {
  if ((node.tag & 0x20) === 0) return false; // primitive（值节点）：无子元素
  const children: Array<{ tag: number; content: Buffer; end: number }> = [];
  let off = 0;
  while (off < node.content.length) {
    const child = parseDer(node.content, off);
    children.push(child);
    off = child.end;
  }
  for (let i = 0; i + 1 < children.length; i++) {
    const head = children[i];
    const next = children[i + 1];
    if (head.tag === 0x06 && head.content.equals(SAN_OID)) {
      if (next.tag !== 0x04) return false; // extnValue 必须是 OCTET STRING
      const generalNames = parseDer(next.content, 0);
      if (generalNames.tag !== 0x30) return false;
      const dnsName = parseDer(generalNames.content, 0);
      if (dnsName.tag !== 0x82) return false;
      return dnsName.content.toString('utf8') === domain;
    }
  }
  for (const child of children) {
    if (hasWellFormedSan(child, domain)) return true;
  }
  return false;
}

test('L-4：buildCsr 的 SAN 为合法 RFC 5280 结构（OCTET STRING 包装的 dNSName）', () => {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const der = buildCsr(privateKey, 'example.com');
  const root = parseDer(der, 0);
  assert.ok(
    hasWellFormedSan(root, 'example.com'),
    'SAN 扩展必须为 SEQ{OID, OCTET STRING{SEQ{[2] dNSName}}}，缺 OCTET STRING 包装会被 CA 拒绝',
  );
  // 对照：域名字节与 SAN OID 仍应在场（浅层断言作为回归底网）
  assert.ok(der.includes(SAN_OID), 'CSR 必须包含 SAN OID');
  assert.ok(der.includes(Buffer.from('example.com', 'utf8')), 'CSR 必须包含域名');
});

test('L-4b：certMatchesDomain 存在 DNS SAN 时以 SAN 为准（CN 不参与，RFC 6125）', (t) => {
  let hasOpenssl = false;
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    hasOpenssl = true;
  } catch {
    // 环境无 openssl：跳过（CI 可选）
  }
  if (!hasOpenssl) {
    t.skip('openssl 不可用，跳过 SAN 优先级测试');
    return;
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-cert-'));
  try {
    // 证书 1：SAN=other.example，CN=target.example——浏览器以 SAN 为准，不得回退 CN
    const cert1 = path.join(dir, 'c1.pem');
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k1.pem'), '-out', cert1,
        '-subj', '/CN=target.example', '-addext', 'subjectAltName=DNS:other.example', '-days', '1'],
      { stdio: 'ignore' },
    );
    assert.equal(certMatchesDomain(cert1, 'target.example'), false, 'SAN 存在且不含域名时不得回退 CN');
    assert.equal(certMatchesDomain(cert1, 'other.example'), true);
    // 证书 2：无 SAN，仅 CN——允许回退 CN（自签/旧证书兼容）
    const cert2 = path.join(dir, 'c2.pem');
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k2.pem'), '-out', cert2,
        '-subj', '/CN=cnonly.example', '-days', '1'],
      { stdio: 'ignore' },
    );
    assert.equal(certMatchesDomain(cert2, 'cnonly.example'), true);
    assert.equal(certMatchesDomain(cert2, 'other.example'), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── M-5：聊天游标倒退检测（纯函数） ───────────────────────────

const chatMsg = (id: number): ChatMessage => ({
  id,
  sender_id: 1,
  sender_name: 'u',
  recipient_id: null,
  content: 'x',
  tags: [],
  created_at: new Date().toISOString(),
});

test('保命技能密码错误第五次限流，锁定期间不继续尝试 bcrypt', async () => {
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const response = await gatewayReq('POST', '/gateway/api/dsh-passwords/purge', {}, adminCookie, JSON.stringify({
      password: 'not-the-admin-password',
      confirm: true,
    }));
    assert.equal(response.status, attempt === 5 ? 429 : 401);
  }
  const blocked = await gatewayReq('POST', '/gateway/api/dsh-passwords/purge', {}, adminCookie, JSON.stringify({
    password: 'not-the-admin-password',
    confirm: true,
  }));
  assert.equal(blocked.status, 429);
  assert.match(blocked.body, /IP_THROTTLED/);
});

test('M-5：返回 id ≤ 游标 = 游标倒退（DB 重建）', () => {
  assert.equal(isCursorReset(10, [chatMsg(9), chatMsg(10)]), true);
  assert.equal(isCursorReset(10, [chatMsg(11)]), false);
  assert.equal(isCursorReset(0, [chatMsg(1)]), false, '无基线时不视为倒退');
  assert.equal(isCursorReset(10, []), false, '空响应不是倒退信号');
});
