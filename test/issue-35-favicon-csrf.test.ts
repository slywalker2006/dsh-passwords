// Issue #35 回归：登录 / 首次配置首次提交被 favicon 触发的 CSRF cookie 轮换打断（403）
//
// 根因回顾：`GET /gateway/login` 每次渲染都无条件 `newCsrfToken()` 并写 `dsh_csrf`
// cookie。浏览器在登录页会自动请求 `/favicon.ico`；未登录时该请求被 302 重定向回
// 登录页，于是登录页被再次渲染、CSRF cookie 被轮换，而用户手里表单的隐藏域仍是
// 旧 token —— 首次提交必然 `csrfMatches` 失败 → 403。
//
// 修复契约（不放宽任何校验）：
//   1. 未登录请求精确路径 `/favicon.ico` → 204，不渲染、不重定向、不下发 cookie；
//      其他静态/未知路径仍然重定向，不得因此扩大匿名放行面。
//   2. `GET /gateway/login` 仅在现有 cookie 通不过双重提交校验时才换发新 token；
//      有效则原样复用，保证"原表单 token + 原 cookie"始终可提交。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

import { createGatewayServer } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import type { PlatformConfig } from '../src/config.js';

interface Harness {
  server: http.Server;
  port: number;
  config: PlatformConfig;
  db: Database;
}

interface Reply {
  status: number;
  setCookies: string[];
  location: string;
  body: string;
  headers: http.IncomingHttpHeaders;
}

let tempDir: string;
let upstream: http.Server;
let upstreamHits: string[] = [];
let login: Harness;
let setup: Harness;
let adminId = 0;

function call(
  port: number,
  options: {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: string;
    localAddress?: string;
  },
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        localAddress: options.localAddress,
        method: options.method,
        path: options.path,
        headers: options.headers ?? {},
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const setCookies: string[] = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            if (res.rawHeaders[i].toLowerCase() === 'set-cookie') setCookies.push(res.rawHeaders[i + 1]);
          }
          resolve({
            status: res.statusCode ?? 0,
            setCookies,
            location: typeof res.headers.location === 'string' ? res.headers.location : '',
            body: Buffer.concat(chunks).toString('utf8'),
            headers: res.headers,
          });
        });
      },
    );
    req.on('error', reject);
    req.end(options.body);
  });
}

function csrfCookieOf(reply: Reply): string {
  for (const cookie of reply.setCookies) {
    const match = /(?:^|;\s*)dsh_csrf=([^;]+)/.exec(cookie);
    if (match) return match[1];
  }
  return '';
}

function csrfFieldOf(reply: Reply): string {
  return (reply.body.match(/name="csrf" value="([^"]+)"/) ?? [])[1] ?? '';
}

function platformConfig(dbPath: string, upstreamPort: number, publicHost = ''): PlatformConfig {
  return {
    setupKey: 'test-setup-key',
    dbPath,
    dbEncKey: 'testkey',
    gateway: {
      host: '127.0.0.1',
      port: 0,
      upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null,
      redirectPort: null,
      publicHost,
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
}

async function startHarness(
  dbPath: string,
  upstreamPort: number,
  withAdmin: boolean,
  publicHost = '',
): Promise<Harness> {
  const db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  if (withAdmin) db.createUser('admin', bcrypt.hashSync('Admin123!', 4), 'admin');
  const config = platformConfig(dbPath, upstreamPort, publicHost);
  const server = createGatewayServer(config, new AuthService(config, db), db);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as { port: number }).port;
  return { server, port, config, db };
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-issue35-'));
  // 首次配置成功后会调用 hardenSecretsAfterSetup 固化密钥；把 env 文件指向临时目录，
  // 避免测试触碰项目真实 `.env`。
  process.env.DSH_PASSWORDS_ENV_FILE = path.join(tempDir, 'harness.env');

  upstream = http.createServer((req, res) => {
    upstreamHits.push(req.url ?? '');
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>upstream</body></html>');
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
  const upstreamPort = (upstream.address() as { port: number }).port;

  login = await startHarness(path.join(tempDir, 'login.db'), upstreamPort, true, 'public.example.test');
  adminId = login.db.getUserByUsername('admin')?.id ?? 0;
  setup = await startHarness(path.join(tempDir, 'setup.db'), upstreamPort, false);
});

after(() => {
  login?.server.close();
  setup?.server.close();
  upstream?.close();
  // Windows 上 SQLite 文件句柄不释放会让 rmSync 失败并残留临时库；与其他
  // 测试一致先显式关闭 Database，再删除临时目录。
  try {
    login?.db.close();
  } catch {
    /* 已关闭 */
  }
  try {
    setup?.db.close();
  } catch {
    /* 已关闭 */
  }
  delete process.env.DSH_PASSWORDS_ENV_FILE;
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* 文件锁未释放：系统临时目录回收 */
  }
});

// ── 登录页：favicon 干扰序列 ─────────────────────────────────
test('Issue #35：登录页 favicon 不再轮换 CSRF，原 token + cookie 仍可登录', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  assert.equal(first.status, 200);
  const cookie = csrfCookieOf(first);
  const field = csrfFieldOf(first);
  assert.ok(cookie !== '' && field !== '', '登录页必须同时下发 CSRF cookie 与表单隐藏域');
  assert.equal(cookie, field, '同一渲染下 cookie 与表单域必须一致');

  // 浏览器自动请求 favicon：必须 204 且不下发任何 cookie（不触发轮换）。
  upstreamHits = [];
  const favicon = await call(login.port, { method: 'GET', path: '/favicon.ico' });
  assert.equal(favicon.status, 204, '未登录 favicon 必须 204');
  assert.equal(favicon.setCookies.length, 0, 'favicon 响应不得下发 cookie');
  assert.equal(favicon.location, '', 'favicon 不得重定向');
  assert.deepEqual(upstreamHits, [], 'favicon 请求不得转发上游');

  // 即使登录页被再次请求（重定向/刷新），有效 cookie 也必须原样复用。
  const second = await call(login.port, {
    method: 'GET',
    path: '/gateway/login',
    headers: { cookie: `dsh_csrf=${cookie}` },
  });
  assert.equal(csrfCookieOf(second), cookie, '有效 CSRF cookie 必须复用而非轮换');
  assert.equal(csrfFieldOf(second), cookie, '复用后表单域必须等于现有 cookie');

  // 原表单 token + 原 cookie 提交：必须成功 302，而不是 CSRF 403。
  const submit = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    headers: { cookie: `dsh_csrf=${cookie}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: `csrf=${encodeURIComponent(field)}&username=admin&password=Admin123!`,
  });
  assert.equal(submit.status, 302, 'favicon 干扰后的原表单提交必须成功');
});

// ── 首次配置：favicon 干扰序列 ───────────────────────────────
test('Issue #35：首次配置页 favicon 不再轮换 CSRF，原 token + cookie 仍可初始化', async () => {
  const first = await call(setup.port, { method: 'GET', path: '/gateway/login' });
  assert.equal(first.status, 200);
  const cookie = csrfCookieOf(first);
  const field = csrfFieldOf(first);
  assert.ok(cookie !== '' && field !== '', '首次配置页必须同时下发 CSRF cookie 与表单隐藏域');

  const favicon = await call(setup.port, { method: 'GET', path: '/favicon.ico' });
  assert.equal(favicon.status, 204, '首次配置阶段的未登录 favicon 也必须 204');
  assert.equal(favicon.setCookies.length, 0);

  const second = await call(setup.port, {
    method: 'GET',
    path: '/gateway/login',
    headers: { cookie: `dsh_csrf=${cookie}` },
  });
  assert.equal(csrfCookieOf(second), cookie, '首次配置阶段有效 CSRF cookie 必须复用');

  const submit = await call(setup.port, {
    method: 'POST',
    path: '/gateway/setup',
    headers: { cookie: `dsh_csrf=${cookie}`, 'content-type': 'application/x-www-form-urlencoded' },
    body:
      `csrf=${encodeURIComponent(field)}&setupKey=${encodeURIComponent('test-setup-key')}` +
      `&username=${encodeURIComponent('owner')}&password=${encodeURIComponent('OwnerPassword123!')}`,
  });
  assert.equal(submit.status, 302, `favicon 干扰后的首次配置提交必须成功：${submit.body.slice(0, 500)}`);
});

// ── 边界：无效 cookie 仍换发、非 favicon 未登录仍重定向 ─────
test('Issue #35：无效 CSRF cookie 仍被换发新 token（不放宽校验）', async () => {
  const invalid = `deadbeef.${'a'.repeat(32)}`;
  const r = await call(login.port, {
    method: 'GET',
    path: '/gateway/login',
    headers: { cookie: `dsh_csrf=${invalid}` },
  });
  const issued = csrfCookieOf(r);
  assert.ok(issued !== '' && issued !== invalid, '无效 cookie 必须被替换为新 token');
  assert.equal(csrfFieldOf(r), issued, '换发后表单域必须等于新 cookie');
});

test('Issue #35：非 favicon 的未登录路径仍然重定向登录页（不放宽匿名放行）', async () => {
  for (const target of ['/dashboard', '/favicon.png', '/assets/app.js', '/api/session.list']) {
    const r = await call(login.port, { method: 'GET', path: target });
    assert.equal(r.status, 302, `${target} 未登录必须重定向`);
    assert.ok(r.location.startsWith('/gateway/login'), `${target} 应重定向到登录页`);
  }
});

test('Issue #35：已登录用户请求 favicon 仍按原样转发上游', async () => {
  const token = jwt.sign({ sub: String(adminId), username: 'admin', cv: 0 }, login.config.jwtSecret, {
    expiresIn: '12h',
  });
  upstreamHits = [];
  const r = await call(login.port, {
    method: 'GET',
    path: '/favicon.ico',
    headers: { cookie: `dsh_gateway_token=${token}` },
  });
  assert.equal(r.status, 200, '已登录 favicon 不应被 204 短路');
  assert.deepEqual(upstreamHits, ['/favicon.ico'], '已登录 favicon 应正常转发上游');
});

// ── 审计 P0：畸形签名不得抛异常打挂网关进程（GET 复用分支）─────
test('审计 P0：GET /gateway/login 带多字节签名 cookie 返回 200 而非崩溃', async () => {
  // 31 个 ASCII + U+00E9（%C3%A9）：JS `.length` = 32，UTF-8 字节 = 33。
  // 修复前 csrfMatches 的字符串长度检查放行，随后 timingSafeEqual 因字节数不等
  // 抛 RangeError；该 GET 复用分支在 async 路由内 → 未处理拒绝 → 进程退出。
  const malformed = `deadbeef.${'a'.repeat(31)}%C3%A9`;
  const r = await call(login.port, {
    method: 'GET',
    path: '/gateway/login',
    headers: { cookie: `dsh_csrf=${malformed}` },
  });
  assert.equal(r.status, 200, '畸形签名必须被当作无效 token 处理，而不是抛异常');
  const issued = csrfCookieOf(r);
  assert.match(issued, /^[0-9a-f]{32}\.[0-9a-f]{32}$/, '必须换发规范形式的新 token');
  assert.equal(csrfFieldOf(r), issued, '换发后表单域必须等于新 cookie');
});

// ── 审计 P2：登录 / 首次配置 POST 同源校验（子域 cookie-tossing CSRF）──
test('审计 P2：POST /gateway/login 拒绝跨源 Origin', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  const r = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    headers: {
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://evil.example',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(r.status, 403, '跨源登录 POST 必须 403');
  assert.equal(r.body, '403 Forbidden');
});

test('审计 P2：POST /gateway/login 同源 Origin 正常放行（浏览器主路径不受影响）', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  // 真实浏览器同源表单 POST 同时带 Origin 与 Sec-Fetch-Site: same-origin；
  // 这是下方「Origin: null + Sec-Fetch-Site: same-origin 仍 403」负向用例的正向对照，
  // 两者除 Origin 取值外请求形态一致，确保修复只放行真实同源、不放宽 null。
  const r = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    headers: {
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: `http://127.0.0.1:${login.port}`,
      'sec-fetch-site': 'same-origin',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(r.status, 302, `同源登录必须成功：${r.body.slice(0, 300)}`);
});

test('审计 P2：非回环反代改写 Host 时，配置的公开主机 Origin 登录 POST 仍放行', async () => {
  // 根因复现：反向代理 peer 非回环（127.0.0.2 不在回环白名单）并把 Host 改写为内网
  // 地址，而浏览器 Origin 是配置的公开主机（public.example.test）。configuredHosts
  // 是服务端显式声明，匹配不得因 peer 非回环而失效，否则登录 POST 被误判 403。
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  const r = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    localAddress: '127.0.0.2',
    headers: {
      host: `127.0.0.1:${login.port}`,
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://public.example.test',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(r.status, 302, `非回环反代 + 配置公开主机登录必须成功：${r.body.slice(0, 300)}`);
});

test('审计 P2：非回环反代下恶意 Origin 登录 POST 仍 403，不采纳 X-Forwarded-Host', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  const r = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    localAddress: '127.0.0.2',
    headers: {
      host: `127.0.0.1:${login.port}`,
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'https://evil.example',
      'x-forwarded-host': 'evil.example',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(r.status, 403, '非回环 peer 的伪造 X-Forwarded-Host 不得放行跨源登录');
});

test('审计 P2：POST /gateway/setup 拒绝跨源 Origin，且不消耗限速配额', async () => {
  const first = await call(setup.port, { method: 'GET', path: '/gateway/login' });
  const cookie = csrfCookieOf(first);
  const field = csrfFieldOf(first);
  // 连续 12 次（> SETUP_MAX_PER_WINDOW=10）：若 Origin 校验排在限速之后，
  // 第 11 次就会 429；全部 403 即证明校验先于限速，跨源请求打不满受害者配额。
  for (let i = 0; i < 12; i++) {
    const r = await call(setup.port, {
      method: 'POST',
      path: '/gateway/setup',
      headers: {
        cookie: `dsh_csrf=${cookie}`,
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://evil.example',
      },
      body: `csrf=${encodeURIComponent(field)}&setupKey=bad&username=x&password=y`,
    });
    assert.equal(r.status, 403, `第 ${i + 1} 次跨源 setup 必须 403（不得 429）`);
  }
});

// ── Secure Cookie：TLS 终止反向代理（网关自身 tls=null）──────────────
// nginx/caddy 在 80/443 终结 TLS 时，网关收到的是明文 HTTP（config.gateway.tls=null）。
// 受信回环反代转发的 X-Forwarded-Proto=https 必须让会话/CSRF Cookie 带 Secure；
// 公网直连伪造该头无效（trust proxy=loopback），明文直连则不得声明 Secure。
test('反向代理 TLS 终止：受信回环转发 X-Forwarded-Proto=https 时会话/CSRF Cookie 带 Secure', async () => {
  const first = await call(login.port, {
    method: 'GET',
    path: '/gateway/login',
    headers: { 'x-forwarded-proto': 'https' },
  });
  assert.equal(first.status, 200);
  const csrfCookie = first.setCookies.find((c) => c.startsWith('dsh_csrf=')) ?? '';
  assert.match(csrfCookie, /;\s*Secure/i, '反代 https 下 CSRF cookie 必须带 Secure');

  const submit = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    headers: {
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      'x-forwarded-proto': 'https',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(submit.status, 302, `反代 https 下登录必须成功：${submit.body.slice(0, 200)}`);
  const sessionCookie = submit.setCookies.find((c) => c.startsWith('dsh_gateway_token=')) ?? '';
  assert.match(sessionCookie, /;\s*Secure/i, '反代 https 下会话 cookie 必须带 Secure');
});

test('直连明文 HTTP：不带 X-Forwarded-Proto 时 Cookie 不得误加 Secure', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  assert.equal(first.status, 200);
  const csrfCookie = first.setCookies.find((c) => c.startsWith('dsh_csrf=')) ?? '';
  assert.doesNotMatch(csrfCookie, /;\s*Secure/i, '明文直连不得声明 Secure');
});

// ── 审计 P2：Referrer-Policy 必须 same-origin（no-referrer 会把真实同源表单 POST
//    降级为 Origin: null + Sec-Fetch-Site: same-origin，被同源校验误判 403）──────
test('审计 P2：登录 / 首次配置页 Referrer-Policy 必须为 same-origin', async () => {
  const loginPage = await call(login.port, { method: 'GET', path: '/gateway/login' });
  assert.equal(loginPage.status, 200);
  assert.equal(
    loginPage.headers['referrer-policy'],
    'same-origin',
    'no-referrer 会让同源表单 POST 变成 Origin: null',
  );
  const setupPage = await call(setup.port, { method: 'GET', path: '/gateway/login' });
  assert.equal(setupPage.status, 200);
  assert.equal(setupPage.headers['referrer-policy'], 'same-origin');
});

// 真实同源 HTML 表单在 Referrer-Policy 失效时的探针形态：Origin: null + same-origin。
// 修复 Referrer-Policy 后浏览器不应再发该形态，但服务端不得因此放宽：仍必须 403。
test('审计 P2：Origin: null + Sec-Fetch-Site: same-origin 登录 POST 仍 403', async () => {
  const first = await call(login.port, { method: 'GET', path: '/gateway/login' });
  const r = await call(login.port, {
    method: 'POST',
    path: '/gateway/login',
    headers: {
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'null',
      'sec-fetch-site': 'same-origin',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&username=admin&password=Admin123!`,
  });
  assert.equal(r.status, 403, 'Origin: null 不得因 Sec-Fetch-Site: same-origin 被放行');
  assert.equal(r.body, '403 Forbidden');
});

test('审计 P2：Origin: null + Sec-Fetch-Site: same-origin 首次配置 POST 仍 403', async () => {
  const first = await call(setup.port, { method: 'GET', path: '/gateway/login' });
  const r = await call(setup.port, {
    method: 'POST',
    path: '/gateway/setup',
    headers: {
      cookie: `dsh_csrf=${csrfCookieOf(first)}`,
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'null',
      'sec-fetch-site': 'same-origin',
    },
    body: `csrf=${encodeURIComponent(csrfFieldOf(first))}&setupKey=x&username=x&password=y`,
  });
  assert.equal(r.status, 403, 'Origin: null 不得绕过首次配置同源校验');
});

// ── 审计 P3：匿名自动探针路径共用一份精确 Set ─────────────────
test('审计 P3：未认证自动探针路径全部 204（不渲染、不重定向、不下发 cookie）', async () => {
  const probes = [
    '/favicon.ico',
    '/apple-touch-icon.png',
    '/apple-touch-icon-precomposed.png',
    '/manifest.json',
    '/manifest.webmanifest',
    '/browserconfig.xml',
    '/robots.txt',
    '/sitemap.xml',
  ];
  for (const target of probes) {
    const r = await call(login.port, { method: 'GET', path: target });
    assert.equal(r.status, 204, `${target} 匿名探针必须 204`);
    assert.equal(r.setCookies.length, 0, `${target} 不得下发 cookie`);
    assert.equal(r.location, '', `${target} 不得重定向`);
  }
});

test('审计 P3：非探针 / 近似路径仍 302，保持精确归一化边界', async () => {
  for (const target of ['/apple-touch-icon-120x120.png', '/ROBOTS.TXT', '/robots.txt/extra', '/manifest.json/extra']) {
    const r = await call(login.port, { method: 'GET', path: target });
    assert.equal(r.status, 302, `${target} 未认证必须仍重定向`);
  }
});

test('审计 P3：幽灵会话（用户行不存在）探针路径仍 204', async () => {
  // sub 与 username 不一致：sessionOf 现按 sub（getUserById）定位并比对 username，
  // 伪造的 sub=999999 无对应行 → 直接判未认证（不再产生“已解析出会话但路由二次
  // 查询为空”的幽灵会话分支）。无论走哪条分支，都必须与未认证分支共用同一探针 Set。
  const ghost = jwt.sign({ sub: '999999', username: 'admin', cv: 0 }, login.config.jwtSecret, {
    expiresIn: '12h',
  });
  const probe = await call(login.port, {
    method: 'GET',
    path: '/apple-touch-icon.png',
    headers: { cookie: `dsh_gateway_token=${ghost}` },
  });
  assert.equal(probe.status, 204, '幽灵会话探针路径必须 204');
  const other = await call(login.port, {
    method: 'GET',
    path: '/dashboard',
    headers: { cookie: `dsh_gateway_token=${ghost}` },
  });
  assert.equal(other.status, 302, '幽灵会话非探针路径必须重定向');
});
