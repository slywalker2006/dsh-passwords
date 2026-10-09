// 复审 R2/R4：internal/assignable-resources 探测的读取契约。
//
// R2 —— 截断响应必须在超时/连接结束前有界结束：探针 Promise 不能因连接提前关闭而
//       永不 settle，否则管理员保存权限的请求会一直挂起。
// R4 —— 该端点旧实现用固定 256 KiB 内联上限缓冲响应，会错误拒绝随规模增长的合法
//       清单；读取必须改用专用上限，且不得先于条目上限触发；条目/契约不符仍 fail-closed。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http, { type IncomingMessage } from 'node:http';
import { readFileSync } from 'node:fs';

import {
  ASSIGNABLE_RESOURCES_MAX_BYTES,
  parseAssignableResources,
  readBoundedResponseBody,
} from '../src/gateway.js';

type ProbeHand = { response: IncomingMessage; request: http.ClientRequest };

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('unexpected server address');
  return { server, port: address.port };
}

function probeOnce(port: number): Promise<ProbeHand> {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port, path: '/probe' }, (response) => {
      resolve({ response, request });
    });
    request.on('error', reject);
  });
}

function closeServer(server: http.Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

test('R2: 截断响应（声明长度未满足即断连）有界结束且不返回半截体', async () => {
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '1048576' });
    res.write('{"ok":true,"folders":["/workspaces/a"],"assignableSessions":["sess-1"]}');
    // 声明 1 MiB 只发几十字节便结束连接：客户端必须视作截断并立即 settle。
    res.socket?.end();
  });
  try {
    const { response, request } = await probeOnce(port);
    const started = Date.now();
    const body = await readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, 1_000);
    const elapsed = Date.now() - started;
    assert.equal(body, null, '截断响应不得返回半截缓冲体');
    assert.ok(elapsed < 2_000, `截断必须在探测超时前有界结束（实际 ${elapsed}ms）`);
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R2: 持续 trickle 响应达到墙钟期限后有界结束', async () => {
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    const timer = setInterval(() => res.write(' '), 20);
    res.on('close', () => clearInterval(timer));
  });
  try {
    const { response, request } = await probeOnce(port);
    const started = Date.now();
    const body = await readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, 150);
    const elapsed = Date.now() - started;
    assert.equal(body, null, '持续 trickle 不得绕过墙钟截止时间');
    assert.ok(elapsed < 1_000, `trickle 必须有界结束（实际 ${elapsed}ms）`);
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R2: 头部到达后连接静默关闭同样有界结束', async () => {
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': '4096' });
    res.flushHeaders();
    // 不发 body，稍后直接回收 socket：模拟上游卡死后连接被断开。
    setTimeout(() => res.socket?.destroy(), 30);
  });
  try {
    const { response, request } = await probeOnce(port);
    const body = await readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, 1_000);
    assert.equal(body, null, '连接结束但从未 end 时必须返回 null（fail-closed）');
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R2: 正常完整响应仍返回缓冲体并解析成功', async () => {
  const payload = JSON.stringify({
    ok: true,
    folders: ['/workspaces/a'],
    assignableSessions: ['sess-1'],
    retainedSessions: ['sess-0'],
  });
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) });
    res.end(payload);
  });
  try {
    const { response, request } = await probeOnce(port);
    const body = await readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, 1_000);
    assert.notEqual(body, null, '完整响应必须返回缓冲体');
    const parsed = parseAssignableResources(body as Buffer);
    assert.notEqual(parsed, null);
    assert.deepEqual([...parsed!.folders], ['/workspaces/a']);
    assert.deepEqual([...parsed!.assignableSessions], ['sess-1']);
    assert.deepEqual([...parsed!.retainedSessions], ['sess-0']);
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R4: 超过旧固定 256 KiB 上限的合法清单用专用上限读取成功', async () => {
  const folders = Array.from({ length: 8_000 }, (_, i) => `/workspaces/tenant-group-alpha/project-${String(i).padStart(5, '0')}`);
  const assignableSessions = Array.from({ length: 4_000 }, (_, i) => `session-${String(i).padStart(6, '0')}`);
  const payload = Buffer.from(JSON.stringify({ ok: true, folders, assignableSessions, retainedSessions: [] }));
  assert.ok(payload.length > 256 * 1024, `夹具必须超过旧固定 256 KiB 上限（实际 ${payload.length} 字节）`);

  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(payload.length) });
    res.end(payload);
  });
  try {
    // 旧实现的固定 256 KiB 上限会拒绝同一份合法清单：证明回归边界真实存在。
    const rejected = await probeOnce(port);
    const truncated = await readBoundedResponseBody(rejected.response, 256 * 1024, 5_000);
    assert.equal(truncated, null, '旧固定 256 KiB 上限必须拒绝这份合法清单');
    rejected.request.destroy();

    // 专用上限下同一清单可被完整读取并解析（不再按固定 256 KiB 拒绝）。
    const accepted = await probeOnce(port);
    const body = await readBoundedResponseBody(accepted.response, ASSIGNABLE_RESOURCES_MAX_BYTES, 5_000);
    assert.notEqual(body, null, '合法大清单必须被专用上限读取');
    const parsed = parseAssignableResources(body as Buffer);
    assert.notEqual(parsed, null);
    assert.equal(parsed!.folders.size, folders.length);
    assert.equal(parsed!.assignableSessions.size, assignableSessions.length);
    accepted.request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R4: 合法 Unicode 路径与会话 ID 不被过度拒绝', () => {
  const payload = Buffer.from(JSON.stringify({
    ok: true,
    folders: ['/工作区/项目一', '/workspaces/团队-α', '/ws/emoji-😀'],
    assignableSessions: ['会话-001', 'sess-ünïcode'],
    retainedSessions: ['归档-会话'],
  }));
  const parsed = parseAssignableResources(payload);
  assert.notEqual(parsed, null, '合法 Unicode 路径/ID 必须被接受');
  assert.deepEqual([...parsed!.folders], ['/工作区/项目一', '/workspaces/团队-α', '/ws/emoji-😀']);
  assert.deepEqual([...parsed!.assignableSessions], ['会话-001', 'sess-ünïcode']);
  assert.deepEqual([...parsed!.retainedSessions], ['归档-会话']);
  // 空串与 C0 控制字符仍 fail-closed——拒绝的是非法输入，不是 Unicode。
  assert.equal(parseAssignableResources(Buffer.from(JSON.stringify({ ok: true, folders: ['/a\u0000b'], assignableSessions: [], retainedSessions: [] }))), null);
  assert.equal(parseAssignableResources(Buffer.from(JSON.stringify({ ok: true, folders: [''], assignableSessions: [], retainedSessions: [] }))), null);
});

test('R4: 条目上限内的合法清单字节数落在专用上限内', () => {
  // 用代表性长度（而非最短占位）估算条目上限清单的字节数：旧固定 256 KiB 上限会拒绝它。
  const payload = Buffer.byteLength(JSON.stringify({
    ok: true,
    folders: Array.from({ length: 10_000 }, (_, i) => `/workspaces/tenant-group-alpha/project-${String(i).padStart(5, '0')}`),
    assignableSessions: Array.from({ length: 20_000 }, (_, i) => `session-${String(i).padStart(6, '0')}-0123456789abcdef`),
    retainedSessions: Array.from({ length: 20_000 }, (_, i) => `archived-${String(i).padStart(6, '0')}-0123456789abcdef`),
  }));
  assert.ok(ASSIGNABLE_RESOURCES_MAX_BYTES > 256 * 1024, '专用上限必须高于旧固定 256 KiB 上限');
  assert.ok(payload > 256 * 1024, `条目上限清单必须超过旧固定 256 KiB 上限（实际 ${payload} 字节）`);
  assert.ok(payload < ASSIGNABLE_RESOURCES_MAX_BYTES, `条目上限清单必须能被专用上限读取（${payload} bytes）`);
});

test('R4: 超出读取上限的响应被拒绝（有界内存）', async () => {
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('x'.repeat(4096));
  });
  try {
    const { response, request } = await probeOnce(port);
    const body = await readBoundedResponseBody(response, 1024);
    assert.equal(body, null, '超过 maxBytes 必须返回 null 并停止缓冲');
    // 迟到的 socket error 不得变成 uncaughtException（监听器留到流结束）。
    await new Promise((resolve) => setTimeout(resolve, 20));
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R4: 契约与条目上限不符时解析 fail-closed', () => {
  const ok = (value: unknown): Buffer => Buffer.from(JSON.stringify(value));
  assert.equal(parseAssignableResources(ok({ ok: false, folders: [], assignableSessions: [] })), null);
  assert.equal(parseAssignableResources(ok({ ok: true, folders: 'nope', assignableSessions: [] })), null);
  assert.equal(parseAssignableResources(ok({ ok: true, folders: [], assignableSessions: 'nope', retainedSessions: [] })), null);
  assert.equal(parseAssignableResources(ok({ ok: true, folders: ['/a', 5], assignableSessions: [] })), null, '非字符串条目 fail-closed');
  assert.equal(parseAssignableResources(Buffer.from('not-json')), null);
  assert.equal(
    parseAssignableResources(ok({ ok: true, folders: Array.from({ length: 10_001 }, (_, i) => `/w/${i}`), assignableSessions: [] })),
    null,
    'folders 超上限 fail-closed',
  );
  assert.equal(
    parseAssignableResources(ok({ ok: true, folders: [], assignableSessions: Array.from({ length: 20_001 }, (_, i) => `s${i}`) })),
    null,
    'assignableSessions 超上限 fail-closed',
  );
  // canonical 字段存在但畸形时不得回退到合法 legacy 字段。
  for (const invalid of [null, 'bad', {}, 5, true]) {
    assert.equal(
      parseAssignableResources(ok({ ok: true, folders: ['/a'], assignableSessions: invalid, sessions: ['s1'], retainedSessions: [] })),
      null,
      '畸形 canonical 字段必须 fail-closed',
    );
  }
  assert.equal(
    parseAssignableResources(ok({ ok: true, folders: ['/a'], assignableSessions: ['s1'], sessions: ['s2'], retainedSessions: [] })),
    null,
    'canonical 与 legacy 冲突必须 fail-closed',
  );
  const equivalent = parseAssignableResources(ok({ ok: true, folders: ['/a'], assignableSessions: ['s1', 's2'], sessions: ['s2', 's1'], retainedSessions: [] }));
  assert.notEqual(equivalent, null, '等集的 canonical/legacy 字段可兼容');

  // 旧字段 sessions 回退仍被接受。
  const fallback = parseAssignableResources(ok({ ok: true, folders: ['/a'], sessions: ['s1'], retainedSessions: [] }));
  assert.notEqual(fallback, null);
  assert.deepEqual([...fallback!.assignableSessions], ['s1']);
  assert.equal(parseAssignableResources(ok({ ok: true, folders: ['/a'], sessions: ['s1'] })), null, 'retainedSessions 缺失必须拒绝');
  assert.equal(parseAssignableResources(ok({ ok: true, folders: ['/a'], sessions: ['s1'], retainedSessions: 'bad' })), null, 'retainedSessions 非数组必须拒绝');
});

test('R4: 兼容旧 sessions 字段的 mock 需一并提供 retainedSessions 才被接受', async () => {
  // 兼容上游可能仍用旧字段名 sessions；该 mock 必须补上 retainedSessions 字段，
  // 否则解析会对缺失字段 fail-closed（见下一条 unit 断言）。
  const compatible = JSON.stringify({ ok: true, folders: ['/workspaces/a'], sessions: ['sess-legacy'], retainedSessions: [] });
  const { server, port } = await listen((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(compatible)) });
    res.end(compatible);
  });
  try {
    const { response, request } = await probeOnce(port);
    const body = await readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, 1_000);
    assert.notEqual(body, null);
    const parsed = parseAssignableResources(body as Buffer);
    assert.notEqual(parsed, null, 'sessions 回退字段 + retainedSessions 必须被接受');
    assert.deepEqual([...parsed!.assignableSessions], ['sess-legacy']);
    assert.equal(parseAssignableResources(Buffer.from(JSON.stringify({ ok: true, folders: ['/a'], sessions: ['sess-legacy'] }))), null, '缺 retainedSessions 的旧兼容 mock 必须被拒绝');
    request.destroy();
  } finally {
    await closeServer(server);
  }
});

test('R4: 生产探针用专用上限与 internalProbeTimeoutMs 读取（源码契约）', () => {
  const source = readFileSync(new URL('../src/gateway.ts', import.meta.url), 'utf8');
  const start = source.indexOf('const fetchAssignableResources');
  const end = source.indexOf('// workspaceId → 规范路径映射', start);
  assert.ok(start >= 0 && end > start, '必须能定位 fetchAssignableResources');
  const probe = source.slice(start, end);
  assert.ok(probe.includes('const deadline = Date.now() + timeoutMs'), '探针必须从请求开始锚定单一总截止时间');
  assert.ok(
    probe.includes('readBoundedResponseBody(response, ASSIGNABLE_RESOURCES_MAX_BYTES, remainingMs)'),
    '响应体读取必须使用总截止时间的剩余预算',
  );
  assert.ok(!probe.includes('256 * 1024'), '不得残留旧实现的固定 256 KiB 上限');
});

test('R2: readBoundedResponseBody 用墙钟 maxMs 并在 settle 时清理 timer（源码契约）', () => {
  const source = readFileSync(new URL('../src/gateway.ts', import.meta.url), 'utf8');
  const start = source.indexOf('export function readBoundedResponseBody');
  const end = source.indexOf('const WebSocket = require', start);
  assert.ok(start >= 0 && end > start, '必须能定位 readBoundedResponseBody');
  const fn = source.slice(start, end);
  assert.ok(/setTimeout\(\(\) => \{[\s\S]*?\}, maxMs\)/.test(fn), '必须有以 maxMs 为期限的墙钟 setTimeout');
  assert.ok(fn.includes('clearTimeout(timer)'), 'settle 必须清理 timer');
  assert.ok(fn.includes("response.on('close'") && fn.includes("response.on('aborted'"), '连接中断/关闭形态必须有界 settle');
});
