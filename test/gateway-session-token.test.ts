// sessionOf() JWT 身份校验回归（对应 src/gateway.ts sessionOf 按 sub 定位 + 比对
// username 的修复）。锁定的对外契约：
//
//   1. 改名复活：用户 A 持旧 token（sub=A.id）→ A 改名 → 新建同名用户 B →
//      旧 token 请求受保护路径必须被拒（302），不得以 B 的身份/旧 sub 复活。
//   2. 删除用户：删除后其旧 token 立即失效（302）。
//   3. 凭据变更：主用户为子用户 changePassword（credential_version +1）后，
//      旧 token 失效（302）。
//   4. sub/username 错配：伪造 { sub: 999999, username: 'alice' }（username 指向
//      真实用户、sub 无对应行）视为未认证——探针路径 204、其它路径 302。
//   对照用例：有效会话 token 仍能放行到上游（200），确保上述断言不是“恒拒”。
//
// 这些用例都只发送一次目标 token、且发生在 DB 变更之后：gateway 的会话缓存
// （TTL 30s，按 token 缓存）不会命中变更前的旧状态，因此断言考察的是 sessionOf
// 的身份校验本身，而非缓存时序。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService, type AuthedUser } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import type { PlatformConfig } from '../src/config.js';

/** 匿名自动探针路径（未认证时 204）与常规受保护路径（未认证时 302）。 */
const PROBE_PATH = '/apple-touch-icon.png';
const PROTECTED_PATH = '/dashboard';
/** bcrypt 哈希占位：本文件只用 JWT 组合身份，不校验口令。 */
const DUMMY_HASH = '$2a$10$dummyhashdummyhashdummyhashdu';
/** 满足 PASSWORD_RE（大小写 + 数字 + 符号，12-128 字符）。 */
const NEW_PASSWORD = 'New-Strong-Passw0rd!';

let appDir: string;
let db: Database;
let auth: AuthService;
let config: PlatformConfig;
let gateway: http.Server;
let upstream: http.Server;
let gatewayPort = 0;
let admin: { id: number; username: string };

const adminCaller = (): AuthedUser => ({ userId: admin.id, username: admin.username, role: 'admin' });

/** 与 AuthService.login 相同形状的 JWT：sub 为字符串形式用户 ID。 */
function tokenCookie(payload: { sub: number; username: string; cv: number }): string {
  return `dsh_gateway_token=${jwt.sign(
    { sub: String(payload.sub), username: payload.username, cv: payload.cv },
    config.jwtSecret,
    { expiresIn: '12h' },
  )}`;
}

function get(pathname: string, cookie: string): Promise<{ status: number; location: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, method: 'GET', path: pathname, headers: { cookie, connection: 'close' } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode ?? 0,
          location: typeof res.headers.location === 'string' ? res.headers.location : '',
        }));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

before(async () => {
  appDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-session-token-'));
  const dbPath = path.join(appDir, 'test.db');
  db = new Database(dbPath, createFieldCrypto('testkey', 'testkey'));
  db.init();
  const adminRow = db.createUser('admin', DUMMY_HASH, 'admin');
  admin = { id: adminRow.id, username: adminRow.username };

  upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>upstream</body></html>');
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
  auth = new AuthService(config, db);
  gateway = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', resolve));
  gatewayPort = (gateway.address() as { port: number }).port;
});

after(async () => {
  gateway?.close();
  (gateway as http.Server & { closeAllConnections?: () => void })?.closeAllConnections?.();
  upstream?.close();
  (upstream as http.Server & { closeAllConnections?: () => void })?.closeAllConnections?.();
  db?.close();
  try { rmSync(appDir, { recursive: true, force: true }); } catch { /* Windows 文件占用：忽略 */ }
});

test('对照：有效会话 token 放行到上游（基线非恒拒）', async () => {
  const user = db.createUser('control_user', DUMMY_HASH, 'user');
  const cookie = tokenCookie({ sub: user.id, username: user.username, cv: user.credential_version });
  const res = await get(PROTECTED_PATH, cookie);
  assert.equal(res.status, 200, '有效会话必须放行到上游');
});

test('改名复活：A 旧 token 在 A 改名 + 新建同名用户后失效', async () => {
  const victim = db.createUser('rename_revive', DUMMY_HASH, 'user');
  // 持有旧 token（sub=victim.id，username='rename_revive'，cv 为迁移前版本）
  const stale = tokenCookie({ sub: victim.id, username: 'rename_revive', cv: victim.credential_version });
  await auth.renameUser(adminCaller(), 'rename_revive', 'rename_revive_v2');
  // 新建同名用户 B：sub 不同、cv=0，与旧 token 的 username/cv 恰好匹配
  db.createUser('rename_revive', DUMMY_HASH, 'user');

  const res = await get(PROTECTED_PATH, stale);
  assert.equal(res.status, 302, '旧 token 不得以同名新用户 B 的身份复活');
  assert.match(res.location, /\/gateway\/login/, '必须重定向回登录页');
});

test('删除用户：旧 token 立即失效', async () => {
  const victim = db.createUser('delete_victim', DUMMY_HASH, 'user');
  const stale = tokenCookie({ sub: victim.id, username: victim.username, cv: victim.credential_version });
  await auth.removeUser(adminCaller(), 'delete_victim');

  const res = await get(PROTECTED_PATH, stale);
  assert.equal(res.status, 302, '被删除用户的旧 token 必须失效');
});

test('凭据变更：changePassword 后旧 token 失效', async () => {
  const victim = db.createUser('pw_victim', DUMMY_HASH, 'user');
  const stale = tokenCookie({ sub: victim.id, username: victim.username, cv: victim.credential_version });
  await auth.changePassword(adminCaller(), 'pw_victim', NEW_PASSWORD);

  const res = await get(PROTECTED_PATH, stale);
  assert.equal(res.status, 302, '改密（credential_version +1）后旧 token 必须失效');
});

test('sub/username 错配：伪造 sub 指向真实 username 仍判未认证', async () => {
  // username 指向真实用户、sub 无对应行：修复后按 sub 定位 → 查无此用户 → 未认证
  db.createUser('alice', DUMMY_HASH, 'user');
  const forged = tokenCookie({ sub: 999999, username: 'alice', cv: 0 });

  const probe = await get(PROBE_PATH, forged);
  assert.equal(probe.status, 204, '错配身份的探针路径必须 204');
  assert.equal(probe.location, '', '探针路径不得重定向');

  const other = await get(PROTECTED_PATH, forged);
  assert.equal(other.status, 302, '错配身份的非探针路径必须 302');
});
