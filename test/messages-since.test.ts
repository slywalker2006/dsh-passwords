// 留言 ?since 增量拉取回归测试：
// 客户端轮询带 ?since=<lastId>，服务端只返回 id > lastId 的新消息（升序），
// 避免每 4 秒轮询都全量下载最近 300 条留言（长期挂机的无谓带宽/CPU 开销）。
// 同时覆盖：POST 留言 → 全量列表包含 → 增量列表只含新消息且升序。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { createGatewayServer } from '../src/gateway.js';
import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import type { PlatformConfig } from '../src/config.js';

let tempDir: string;
let db: Database;
let gateway: http.Server;
let upstream: http.Server;
let gatewayPort = 0;
let cookie = '';
let adminId = 0;

interface JsonResponse {
  status: number;
  body: { ok?: boolean; messages?: Array<{ id: number; content: string }>; message?: { id: number } };
}

function req(method: string, url: string, body?: unknown): Promise<JsonResponse> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const r = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        method,
        path: url,
        headers: {
          cookie,
          ...(payload !== undefined
            ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) }
            : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            body: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
          }),
        );
      },
    );
    r.on('error', reject);
    r.end(payload);
  });
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-msg-'));
  db = new Database(path.join(tempDir, 'test.db'), createFieldCrypto('testkey', 'testkey'));
  db.init();
  const user = db.createUser('admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  adminId = user.id;

  // 上游 mock：本测试只走网关自带 /gateway/* 路由，mock 仅兜底
  upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  await new Promise<void>((resolve) => upstream.listen(0, '127.0.0.1', () => resolve()));
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
      publicHost: '',
      domain: 'localhost',
      autoTls: false,
      acmeEmail: '',
      acmeStaging: false,
    },
    jwtSecret: 'test-secret',
    internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };

  const auth = new AuthService(config, db);
  gateway = createGatewayServer(config, auth, db);
  await new Promise<void>((resolve) => gateway.listen(0, '127.0.0.1', () => resolve()));
  gatewayPort = (gateway.address() as { port: number }).port;

  const token = jwt.sign({ sub: String(user.id), username: user.username, cv: 0 }, config.jwtSecret, {
    expiresIn: '12h',
  });
  cookie = `dsh_gateway_token=${token}`;
});

after(() => {
  gateway?.close();
  upstream?.close();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    /* 忽略：Windows 上 node:sqlite 文件句柄可能未释放 */
  }
});

test('留言：POST 三条 → since 增量拉取只返回新消息（升序）', async () => {
  const ids: number[] = [];
  for (const text of ['first', 'second', 'third']) {
    const r = await req('POST', '/gateway/api/messages', { content: text, broadcast: true });
    assert.equal(r.status, 200);
    assert.ok(r.body.message, 'POST 应返回新消息体');
    ids.push(r.body.message!.id);
  }
  assert.ok(ids[0] < ids[1] && ids[1] < ids[2], '消息 id 应递增');

  // 全量：应含全部三条（服务端 DESC 返回，客户端自己排序，这里只验证存在性）
  const all = await req('GET', '/gateway/api/messages');
  assert.equal(all.status, 200);
  const allIds = (all.body.messages ?? []).map((m) => m.id);
  for (const id of ids) assert.ok(allIds.includes(id), `全量列表应包含消息 ${id}`);

  // 增量：since=ids[0] 应只返回 ids[1]、ids[2]，且升序
  const inc = await req('GET', `/gateway/api/messages?since=${ids[0]}`);
  assert.equal(inc.status, 200);
  const incIds = (inc.body.messages ?? []).map((m) => m.id);
  assert.deepEqual(incIds, [ids[1], ids[2]], 'since 增量应只含新消息且升序');

  // since 越过最新消息：应返回空数组
  const empty = await req('GET', `/gateway/api/messages?since=${ids[2]}`);
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.body.messages ?? [], [], 'since 超出最新 id 时应为空');
});

// ── 聊天 SSE 的撤权窗口 ─────────────────────────────────────────
// 未登记到网关撤销表的长连接，在登出/封禁/删号/改密/权限变更后仍会继续推送。

test('留言 SSE：登出后服务端必须立即断开长连接（不留撤权窗口）', async () => {
  // 用本用例专属的 token，避免吊销影响模块级共享 cookie。
  const token = jwt.sign({ sub: String(adminId), username: 'admin', cv: 0 }, 'test-secret', { expiresIn: '12h' });
  const sseCookie = `dsh_gateway_token=${token}`;

  let sseReq: http.ClientRequest | null = null;
  let resolveClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => { resolveClosed = resolve; });
  await new Promise<void>((resolveOpen, reject) => {
    sseReq = http.request(
      { host: '127.0.0.1', port: gatewayPort, method: 'GET', path: '/gateway/api/messages/stream', headers: { cookie: sseCookie } },
      (res) => {
        res.on('data', () => { /* 消费，保持连接 */ });
        res.on('close', () => resolveClosed());
        res.on('end', () => resolveClosed());
        resolveOpen();
      },
    );
    sseReq.on('error', reject);
    sseReq.end();
  });

  try {
    const logoutStatus = await new Promise<number>((resolve, reject) => {
      const r = http.request(
        { host: '127.0.0.1', port: gatewayPort, method: 'POST', path: '/gateway/logout', headers: { cookie: sseCookie } },
        (res) => { res.on('data', () => { /* 丢弃 */ }); res.on('end', () => resolve(res.statusCode ?? 0)); },
      );
      r.on('error', reject);
      r.end();
    });
    assert.equal(logoutStatus, 302, '登出必须成功');

    const outcome = await Promise.race([
      closed.then(() => 'closed'),
      new Promise<string>((resolve) => setTimeout(() => resolve('still-open'), 2000)),
    ]);
    assert.equal(outcome, 'closed', '登出后聊天 SSE 必须被服务端立即断开');
  } finally {
    // 即使断言失败也要释放连接，否则 gateway.close() 会因未关闭的长连接挂住。
    sseReq?.destroy();
  }
});
