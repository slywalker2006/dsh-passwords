// 端点登记表热更新（改 .env 无需重启网关）回归测试：
//   1) 写入部署 .env 的登记表规则后，运行中的网关在轮询周期内自动生效；
//   2) 登记在 MCP_GATEWAY_SSH_ENDPOINTS 的 SSH/owner 路由：owner: 规则对子用户
//      始终拒绝；其余规则由子用户 allowSsh 开关控制（关闭拒绝、开启放行，HTTP 与
//      WS 共用一个开关），主用户正常；
//   3) 规则被清空后立即收紧，并断开已授权 WebSocket（撤销语义）；
//   4) 非法规则保留上一次有效快照（不静默放宽，也不打断已有授权）。
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import jwt from 'jsonwebtoken';

import { AuthService } from '../src/auth.js';
import { Database } from '../src/db.js';
import { createFieldCrypto } from '../src/encrypt.js';
import { createGatewayServer } from '../src/gateway.js';
import type { PlatformConfig } from '../src/config.js';

let tempDir = '';
let envFile = '';
let db: Database;
let upstream: http.Server;
let gateway: http.Server;
let port = 0;
let adminCookie = '';
let subCookie = '';
let subId = 0;
const RELOAD_MS = 25;
const SETTLE_MS = RELOAD_MS * 6;

function writeEnv(registry?: string): void {
  const lines = ['SETUP_KEY=test-setup-key'];
  if (registry !== undefined) lines.push(`MCP_GATEWAY_SSH_ENDPOINTS=${registry}`);
  lines.push('');
  writeFileSync(envFile, lines.join('\n'));
}

function setSubPermissions(allowSsh: boolean): void {
  db.setPermissions(subId, {
    allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
    allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false,
    banned: false, sandboxMode: null, disabledSessions: [], allowSsh,
  });
}

function request(pathname: string, cookie: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method: 'GET',
      headers: { cookie, 'content-type': 'application/json', 'content-length': '2', connection: 'close' },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    });
    req.on('error', reject);
    req.end('{}');
  });
}

/** 原始 WS 握手：被拒绝时按普通 HTTP 响应返回状态码，被放行时返回 101。 */
function wsHandshake(pathname: string, cookie: string): Promise<{ status: number; socket: http.IncomingMessage['socket'] | null }> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: pathname,
      headers: {
        // originHostMatches 要求 Origin.host 与请求 Host 精确相等（含端口），
        // 因此两者统一写成不带端口的 127.0.0.1（与既有 WS 测试一致）。
        host: '127.0.0.1',
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': Buffer.from(`reload-${Math.random()}`).toString('base64'),
        'sec-websocket-version': '13',
        cookie,
        origin: 'http://127.0.0.1',
      },
    });
    req.on('upgrade', (res, socket) => resolve({ status: res.statusCode ?? 0, socket }));
    req.on('response', (res) => { res.resume(); resolve({ status: res.statusCode ?? 0, socket: null }); });
    req.on('error', reject);
    req.end();
  });
}

/**
 * 本机 internal 路由（宿主运行时面）POST：用于「自建清单」授权普通 WS 路径。
 * 只回显状态码，测试只关心是否登记成功。
 */
function postInternal(pathname: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
        'x-internal-secret': 'test-internal',
        connection: 'close',
      },
    }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    });
    req.on('error', reject);
    req.end(body);
  });
}

/** 用宿主运行时动态清单给子用户授权一条普通（非 SSH）WS 路径，供撤销语义验证。 */
async function authorizePlainPluginWs(generation: string): Promise<void> {
  const status = await postInternal('/gateway/internal/plugin-manifest', JSON.stringify({
    generation,
    parentPid: process.pid,
    namespaces: ['pluginlive'],
    streamEndpoints: [],
    exactPaths: [],
    pathPrefixes: [],
  }));
  assert.equal(status, 200, '自建清单登记成功');
}

/** 清单授权的普通（非 SSH）WS 路径，供多处断言复用。 */
const PLAIN_WS_PATH = '/api/pluginlive/live';

/** 管理员概览：热更新后的当前登记表快照。 */
function overviewRules(): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: '/gateway/api/overview', method: 'GET',
      headers: { cookie: adminCookie, connection: 'close' },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        try { resolve((JSON.parse(Buffer.concat(chunks).toString('utf8')) as { endpoints: string[] }).endpoints); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

const wait = (ms: number): Promise<void> => new Promise((resolve) => { setTimeout(resolve, ms); });

let revocationSeq = 0;
/**
 * 触发一次「有效的」登记表变更，强制网关服务端断开已授权 WS（撤销语义）。
 * 用于测试清理：客户端主动 destroy() 不会拆掉网关↔上游的升级隧道，只有服务端
 * 撤销（登记表热更新）会一并断开两侧，避免测试进程被挂起的连接拖住。
 */
async function forceRegistryRevocation(): Promise<void> {
  writeEnv(`/api/plugin/cleanup-${revocationSeq++}`);
  await wait(SETTLE_MS);
}

before(async () => {
  tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-reload-'));
  envFile = path.join(tempDir, '.env');
  writeEnv();
  process.env.DSH_PASSWORDS_ENV_FILE = envFile;
  // 清单登记端点会校验父进程 pid；测试进程不依赖该变量，显式清掉保证确定性。
  delete process.env.DSH_GATEWAY_PARENT_PID;
  db = new Database(path.join(tempDir, 'test.db'), createFieldCrypto('test-key', 'test-key'));
  db.init();
  const admin = db.createUser('reload-admin', '$2a$10$dummyhashdummyhashdummyhashdu', 'admin');
  const sub = db.createUser('reload-sub', '$2a$10$dummyhashdummyhashdummyhashdu');
  subId = sub.id;
  setSubPermissions(true);
  upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  });
  upstream.on('upgrade', (_req, socket) => {
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });
  await new Promise<void>((resolve) => { upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamPort = (upstream.address() as { port: number }).port;
  const config: PlatformConfig = {
    setupKey: 'test-setup-key', dbPath: path.join(tempDir, 'test.db'), dbEncKey: 'test-key',
    gateway: {
      host: '127.0.0.1', port: 0, upstream: `http://127.0.0.1:${upstreamPort}`,
      tls: null, redirectPort: null, publicHost: '', domain: 'localhost', autoTls: false,
      acmeEmail: '', acmeStaging: false,
    },
    jwtSecret: 'test-secret', internalSecret: 'test-internal',
    patch: { dshRoot: '', restartService: '' },
    endpointRules: [],
  };
  adminCookie = `dsh_gateway_token=${jwt.sign({ sub: String(admin.id), username: admin.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  subCookie = `dsh_gateway_token=${jwt.sign({ sub: String(sub.id), username: sub.username, cv: 0 }, config.jwtSecret, { expiresIn: '12h' })}`;
  gateway = createGatewayServer(config, new AuthService(config, db), db, undefined, {
    envFile,
    endpointReloadIntervalMs: RELOAD_MS,
  });
  await new Promise<void>((resolve) => { gateway.listen(0, '127.0.0.1', resolve); });
  port = (gateway.address() as { port: number }).port;
});

after(() => {
  gateway?.close();
  upstream?.close();
  db?.close();
  delete process.env.DSH_PASSWORDS_ENV_FILE;
  try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* Windows 清理尽力而为 */ }
});

test('热更新：普通插件未登记直通，写入 SSH 表后子用户按 allowSsh 放行/拒绝', async () => {
  assert.equal(await request('/api/plugin/terminal', subCookie), 200, '普通插件未登记时直通');
  assert.equal(await request('/api/plugin/terminal', adminCookie), 200, '未登记：主用户不受登记表限制');

  writeEnv('/api/plugin/terminal');
  await wait(SETTLE_MS);
  assert.equal(await request('/api/plugin/terminal', adminCookie), 200, '已登记：主用户仍然正常');

  // 已登记 SSH 路由：未勾选 allowSsh 时拒绝，勾选后放行。
  setSubPermissions(false);
  assert.equal(await request('/api/plugin/terminal', subCookie), 403, '热更新生效：未勾选 SSH 时已登记路由拒绝');
  setSubPermissions(true);
  assert.equal(await request('/api/plugin/terminal', subCookie), 200, '勾选 allowSsh 后放行已登记路由');
  setSubPermissions(false);
});

test('热更新：owner: 规则始终拒绝；ws:/http: 规则由 allowSsh 按对应通道放行，主用户正常', async () => {
  try {
    // owner: 规则优先于 allowSsh：即使勾选 SSH，子用户两条通道仍一律拒绝。
    writeEnv('owner:/api/plugin/terminal');
    await wait(SETTLE_MS);
    setSubPermissions(true);
    assert.equal(await request('/api/plugin/terminal', subCookie), 403, 'owner: 规则 HTTP 拒绝（allowSsh=true 也不例外）');
    const ownerWs = await wsHandshake('/api/plugin/terminal', subCookie);
    try {
      assert.equal(ownerWs.status, 403, 'owner: 规则 WS 拒绝（allowSsh=true 也不例外）');
    } finally {
      ownerWs.socket?.destroy();
    }

    // ws: / http: 前缀只放开对应通道：未勾选 SSH 时该通道拒绝，勾选后放行。
    for (const { registry, channel } of [
      { registry: 'ws:/api/plugin/terminal', channel: 'ws' as const },
      { registry: 'http:/api/plugin/terminal', channel: 'http' as const },
    ]) {
      writeEnv(registry);
      await wait(SETTLE_MS);
      setSubPermissions(false);
      if (channel === 'http') {
        assert.equal(await request('/api/plugin/terminal', subCookie), 403, `${registry}：未勾选 SSH 时 HTTP 拒绝`);
      } else {
        const deniedWs = await wsHandshake('/api/plugin/terminal', subCookie);
        try {
          assert.equal(deniedWs.status, 403, `${registry}：未勾选 SSH 时 WS 拒绝`);
        } finally {
          deniedWs.socket?.destroy();
        }
      }

      setSubPermissions(true);
      if (channel === 'http') {
        assert.equal(await request('/api/plugin/terminal', subCookie), 200, `${registry}：勾选 SSH 后 HTTP 放行`);
      } else {
        const allowedWs = await wsHandshake('/api/plugin/terminal', subCookie);
        try {
          assert.equal(allowedWs.status, 101, `${registry}：勾选 SSH 后 WS 放行`);
        } finally {
          allowedWs.socket?.destroy();
        }
      }
      setSubPermissions(false);
    }

    assert.equal(await request('/api/plugin/terminal', adminCookie), 200, '主用户 HTTP 始终正常');
  } finally {
    setSubPermissions(false);
    // 放行过的 WS 需要一次登记表变更做服务端撤销，避免隧道挂在网关↔上游让进程无法退出。
    await forceRegistryRevocation();
  }
});

test('热更新：规则被清空后立即收紧，且已授权 WebSocket 被断开（撤销语义）', async () => {
  // 子用户已不可能在登记路由上建立 WS，因此用宿主运行时自建清单授权一条普通 WS；
  // 它同样进入网关的撤销集合，登记表热更新（此处清空）必须断开它。
  await authorizePlainPluginWs('reload-revocation');
  // 先落一个非空快照，确保随后的清空必然是一次变更（否则可能不触发撤销）。
  writeEnv('/api/plugin/terminal');
  await wait(SETTLE_MS);
  const allowed = await wsHandshake(PLAIN_WS_PATH, subCookie);
  try {
    assert.equal(allowed.status, 101, '清单授权的普通 WS 允许升级');

    let closed = false;
    allowed.socket?.once('close', () => { closed = true; });
    writeEnv(undefined);
    await wait(SETTLE_MS);
    assert.equal(closed, true, '规则清空后已授权 WS 必须被断开');
    assert.equal(await request('/api/plugin/terminal', subCookie), 200, '普通插件新 HTTP 请求仍直通，旧 WS 连接已撤销');
  } finally {
    await forceRegistryRevocation();
  }
});

test('热更新：非法规则保留上一次有效快照（不静默放宽、不打断已有授权）', async () => {
  writeEnv('/api/plugin/terminal');
  await wait(SETTLE_MS);
  assert.deepEqual(await overviewRules(), ['/api/plugin/terminal'], '有效规则生效');

  // 已授权的普通 WS（清单授权）在非法热更新期间必须保持连接。
  await authorizePlainPluginWs('reload-invalid-keep');
  const live = await wsHandshake(PLAIN_WS_PATH, subCookie);
  try {
    assert.equal(live.status, 101, '清单授权的普通 WS 允许升级');
    let closed = false;
    live.socket?.once('close', () => { closed = true; });

    writeEnv('ws:');
    await wait(SETTLE_MS);
    assert.deepEqual(await overviewRules(), ['/api/plugin/terminal'], '非法写法不生效，保持上一次有效规则');
    assert.equal(closed, false, '非法规则保留旧快照，不打断已有授权');

    writeEnv('/gateway/login');
    await wait(SETTLE_MS);
    assert.deepEqual(await overviewRules(), ['/api/plugin/terminal'], '网关自身路径同样不生效（保留旧快照）');
    assert.equal(closed, false, '非法的网关路径同样不打断已有授权');
  } finally {
    await forceRegistryRevocation();
  }
});

test('热更新：概览只反映登记表，插件兼容不存在专属开关', async () => {
  writeEnv('/api/plugin/status');
  await wait(SETTLE_MS);
  assert.deepEqual(await overviewRules(), ['/api/plugin/status'], '登记表同步可见');
  writeEnv(undefined);
  await wait(SETTLE_MS);
  assert.deepEqual(await overviewRules(), [], '清空登记表后立即收紧');
});
