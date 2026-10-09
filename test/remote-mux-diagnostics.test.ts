import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  REMOTE_MUX_CLOSE_CODES,
  REMOTE_MUX_CLOSE_SOURCES,
  REMOTE_MUX_DIRECTIONS,
  REMOTE_MUX_PROBE_STATES,
  REMOTE_MUX_STALL_KINDS,
  createRemoteMuxDiagnostics,
  createRemoteMuxDiagnosticsSession,
  normalizeRemoteMuxCarrierId,
  normalizeRemoteMuxCloseCode,
  normalizeRemoteMuxCloseSource,
  normalizeRemoteMuxCounter,
  normalizeRemoteMuxDirection,
  normalizeRemoteMuxProbeState,
  normalizeRemoteMuxStallKind,
  observeRemoteMuxCarrier,
  recordRemoteMuxClose,
  remoteMuxCloseLogRecord,
} from '../src/remote-mux-diagnostics.js';

/** Keys the terminal record is allowed to expose; nothing else may appear. */
const ALLOWED_RECORD_KEYS = [
  'bufferedBytes',
  'carrier',
  'clientSender',
  'code',
  'direction',
  'pendingBytes',
  'probe',
  'probeElapsedMs',
  'reject',
  'source',
  'stall',
  'stallElapsedMs',
  'streams',
  'upstreamSender',
].sort();

test('remote-mux-diagnostics：默认状态全部为保留枚举/零，且未记录关闭', () => {
  const state = createRemoteMuxDiagnostics('remote.mux#1');
  assert.equal(state.carrier, 'remote.mux#1');
  assert.equal(state.bufferedBytes, 0);
  assert.equal(state.pendingBytes, 0);
  assert.equal(state.streams, 0);
  assert.equal(state.probe, 'idle');
  assert.equal(state.stall, 'none');
  assert.equal(state.close, null);
  assert.equal(remoteMuxCloseLogRecord(state), null);
});

test('remote-mux-diagnostics：source 只接受保留枚举或已知 reason 文案，其余归 unknown', () => {
  // 保留枚举值原样通过。
  for (const source of REMOTE_MUX_CLOSE_SOURCES) {
    assert.equal(normalizeRemoteMuxCloseSource(source), source);
  }
  // 网关既有的 reason 文案映射到受限分类，原始字符串不进入结果。
  assert.equal(normalizeRemoteMuxCloseSource('Remote stream heartbeat timed out'), 'heartbeat');
  assert.equal(normalizeRemoteMuxCloseSource('Remote stream backpressure limit exceeded'), 'backpressure');
  assert.equal(normalizeRemoteMuxCloseSource('Permissions changed'), 'permission-revoked');
  assert.equal(normalizeRemoteMuxCloseSource('upstream closed'), 'upstream-close');
  // 未知文本（可能含敏感内容）一律归 unknown。
  assert.equal(normalizeRemoteMuxCloseSource('cookie=session=SECRET'), 'unknown');
  assert.equal(normalizeRemoteMuxCloseSource('https://evil.example/api?token=SECRET'), 'unknown');
  assert.equal(normalizeRemoteMuxCloseSource(42), 'unknown');
  assert.equal(normalizeRemoteMuxCloseSource(null), 'unknown');
  assert.equal(normalizeRemoteMuxCloseSource(undefined), 'unknown');
});

test('remote-mux-diagnostics：direction/code/probe/stall 走受限白名单', () => {
  for (const direction of REMOTE_MUX_DIRECTIONS) {
    assert.equal(normalizeRemoteMuxDirection(direction), direction);
  }
  assert.equal(normalizeRemoteMuxDirection('sideways'), 'both');

  for (const code of REMOTE_MUX_CLOSE_CODES) {
    assert.equal(normalizeRemoteMuxCloseCode(code), code);
  }
  assert.equal(normalizeRemoteMuxCloseCode(4999), 0);
  assert.equal(normalizeRemoteMuxCloseCode('1011'), 0);
  assert.equal(normalizeRemoteMuxCloseCode(NaN), 0);

  for (const probe of REMOTE_MUX_PROBE_STATES) {
    assert.equal(normalizeRemoteMuxProbeState(probe), probe);
  }
  assert.equal(normalizeRemoteMuxProbeState('mid-flight'), 'idle');

  for (const stall of REMOTE_MUX_STALL_KINDS) {
    assert.equal(normalizeRemoteMuxStallKind(stall), stall);
  }
  assert.equal(normalizeRemoteMuxStallKind('frozen'), 'none');
});

test('remote-mux-diagnostics：计数器拒绝 NaN/Infinity/负数并截断超大值', () => {
  assert.equal(normalizeRemoteMuxCounter(0), 0);
  assert.equal(normalizeRemoteMuxCounter(2048), 2048);
  assert.equal(normalizeRemoteMuxCounter(2048.9), 2048);
  assert.equal(normalizeRemoteMuxCounter(-1), 0);
  assert.equal(normalizeRemoteMuxCounter(NaN), 0);
  assert.equal(normalizeRemoteMuxCounter(Infinity), 0);
  assert.equal(normalizeRemoteMuxCounter(Number.MAX_VALUE), Number.MAX_SAFE_INTEGER);
  assert.equal(normalizeRemoteMuxCounter('4096'), 0);
});

test('remote-mux-diagnostics：carrier id 只放行短不透明 id，拒绝 URL 与超长 token', () => {
  assert.equal(normalizeRemoteMuxCarrierId('remote.mux#12'), 'remote.mux#12');
  assert.equal(normalizeRemoteMuxCarrierId('carrier_ab-3'), 'carrier_ab-3');
  // URL 形状（scheme/query/host 分隔符）被拒。
  assert.equal(normalizeRemoteMuxCarrierId('https://evil.example/api?token=SECRET'), 'remote.mux');
  // 真实长度的 JWT 超过 64 字符上限，被长度约束拒绝。
  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  assert.ok(jwt.length > 64);
  assert.equal(normalizeRemoteMuxCarrierId(jwt), 'remote.mux');
  assert.equal(normalizeRemoteMuxCarrierId('x'.repeat(65)), 'remote.mux');
  // 约束是字符集+长度，不做 JWT 指纹识别：短不透明 id 即使含点也放行。
  assert.equal(normalizeRemoteMuxCarrierId('carrier.1.2'), 'carrier.1.2');
  assert.equal(normalizeRemoteMuxCarrierId({}), 'remote.mux');
});

test('remote-mux-diagnostics：拒绝类别保留 queue-count，显式 null 可清除陈旧拒绝', () => {
  const initial = createRemoteMuxDiagnostics('remote.mux#reject');
  const rejected = observeRemoteMuxCarrier(initial, { reject: { direction: 'upstream', kind: 'queue-count', messageBytes: 300 } });
  assert.equal(rejected.reject?.kind, 'queue-count');
  const cleared = observeRemoteMuxCarrier(rejected, { reject: null });
  assert.equal(cleared.reject, null);
});

test('remote-mux-diagnostics：observe 只更新出现过的键，返回新对象且不改入参', () => {
  const state = createRemoteMuxDiagnostics('remote.mux#2');
  const next = observeRemoteMuxCarrier(state, { bufferedBytes: 1024, pendingBytes: 2048, streams: 3 });
  assert.notEqual(next, state);
  assert.equal(state.bufferedBytes, 0, '原状态对象必须保持不变');
  assert.equal(next.bufferedBytes, 1024);
  assert.equal(next.pendingBytes, 2048);
  assert.equal(next.streams, 3);
  assert.equal(next.probe, 'idle', '未提供的键沿用旧值');
  assert.equal(next.stall, 'none');

  const probed = observeRemoteMuxCarrier(next, { probe: 'pending', probeElapsedMs: 1500, stall: 'write', stallElapsedMs: 4200 });
  assert.equal(probed.bufferedBytes, 1024, '未提供的缓冲沿用旧值');
  assert.equal(probed.probe, 'pending');
  assert.equal(probed.probeElapsedMs, 1500);
  assert.equal(probed.stall, 'write');
  assert.equal(probed.stallElapsedMs, 4200);
});

test('remote-mux-diagnostics：每条 carrier 只记录一次终止事件，先到者胜', () => {
  const live = createRemoteMuxDiagnostics('remote.mux#3');
  const observed = observeRemoteMuxCarrier(live, { bufferedBytes: 4096, pendingBytes: 64, streams: 2, probe: 'timeout' });
  const first = recordRemoteMuxClose(observed, { source: 'heartbeat', direction: 'client', code: 1011 });
  assert.notEqual(first.close, null);

  // 第二次关闭（不同来源/代码/方向）被忽略，返回同一个状态对象。
  const second = recordRemoteMuxClose(first, { source: 'backpressure', direction: 'upstream', code: 1013, bufferedBytes: 999 });
  assert.equal(second, first, '已记录后必须原样返回同一状态对象');
  assert.equal(second.close?.source, 'heartbeat');
  assert.equal(second.close?.code, 1011);
  assert.equal(second.close?.direction, 'client');
  assert.equal(second.close?.bufferedBytes, 4096, '忽略的第二次关闭不得改动已记录的值');
});

test('remote-mux-diagnostics：终止记录只含白名单标量字段，且不泄漏敏感串', () => {
  const secretBody = 'MESSAGE_BODY_SECRET_9f2c';
  const secretCookie = 'cookie=dsh_gateway_token=COOKIE_SECRET_abc';
  const secretJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJTRUNSRVQifQ.signature';
  const secretUrl = 'https://host.example/api/remote.mux?token=URL_SECRET';

  const state = createRemoteMuxDiagnostics(secretUrl);
  const closed = recordRemoteMuxClose(state, {
    source: secretCookie,
    direction: secretJwt,
    code: 1011,
    bufferedBytes: 8192,
    pendingBytes: 128,
    streams: 1,
    probe: 'responded',
    probeElapsedMs: 90,
    stall: 'write',
    stallElapsedMs: 3000,
  });
  const record = remoteMuxCloseLogRecord(closed);
  assert.ok(record);

  assert.deepEqual(Object.keys(record).sort(), ALLOWED_RECORD_KEYS);
  assert.deepEqual(record.clientSender, { queuedMessages: 0, queuedBytes: 0, acceptedBytes: 0, inFlight: false, bufferedAmount: 0 });
  assert.deepEqual(record.upstreamSender, { queuedMessages: 0, queuedBytes: 0, acceptedBytes: 0, inFlight: false, bufferedAmount: 0 });
  assert.equal(record.reject, null);
  for (const sender of [record.clientSender, record.upstreamSender]) {
    for (const value of Object.values(sender)) assert.ok(typeof value === 'number' || typeof value === 'boolean');
  }

  const serialized = JSON.stringify(record);
  for (const secret of [secretBody, 'COOKIE_SECRET_abc', 'eyJhbGciOiJIUzI1NiJ9', 'URL_SECRET', 'MESSAGE_BODY_SECRET_9f2c']) {
    assert.equal(serialized.includes(secret), false, `终止记录不得包含敏感串 ${secret}`);
  }
  // carrier/source/direction 都被兜底为保留值。
  assert.equal(record.carrier, 'remote.mux');
  assert.equal(record.source, 'unknown');
  assert.equal(record.direction, 'both');
});

test('remote-mux-diagnostics：session 句柄 observe 后 close，第二次 close 返回 null', () => {
  const session = createRemoteMuxDiagnosticsSession('remote.mux#9');
  assert.equal(session.carrier, 'remote.mux#9');
  assert.equal(session.snapshot(), null);

  session.observe({ bufferedBytes: 2048, pendingBytes: 0, streams: 4, probe: 'pending', probeElapsedMs: 250, stall: 'write', stallElapsedMs: 6000 });
  const first = session.close({ source: 'backpressure', direction: 'client', code: 1013 });
  assert.ok(first);
  assert.equal(first?.source, 'backpressure');
  assert.equal(first?.direction, 'client');
  assert.equal(first?.code, 1013);
  assert.equal(first?.bufferedBytes, 2048);
  assert.equal(first?.streams, 4);
  assert.equal(first?.probe, 'pending');
  assert.equal(first?.stall, 'write');
  assert.equal(session.snapshot(), first);

  // 之后任何关闭都被忽略。
  assert.equal(session.close({ source: 'shutdown', direction: 'both', code: 1001 }), null);
  assert.equal(session.snapshot()?.source, 'backpressure');
});

test('remote-mux-diagnostics：session close 可携带现场观测覆盖旧样本', () => {
  const session = createRemoteMuxDiagnosticsSession('remote.mux#10');
  session.observe({ bufferedBytes: 10, pendingBytes: 20, streams: 1 });
  const record = session.close({ source: 'send-failed', direction: 'upstream', code: 1011, bufferedBytes: 7000, pendingBytes: 40 });
  assert.ok(record);
  assert.equal(record?.bufferedBytes, 7000, 'close 携带的现场观测优先');
  assert.equal(record?.pendingBytes, 40);
  assert.equal(record?.streams, 1, '未覆盖的键沿用此前观测');
});
