// Remote mux 背压回归（helper 侧）：/api/remote.mux 两个方向的总积压最多为
// 2 MiB 的正常余量 + 一个最大合法帧（100 MiB）。真实慢 socket 的 bufferedAmount
// 取决于内核窗口，无法稳定制造；stub socket 确定性验证大快照后的续帧和总上限。
// 网关真实转发大历史快照的用例见 gateway-proxy-headers.test.ts。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sendMuxFrameBounded, type MuxBufferedSocket } from '../src/proxy.js';

const LIMIT = 2 * 1024 * 1024;
const MAX_FRAME_BYTES = 100 * 1024 * 1024;

/** 模仿 ws 的行为：send 同步入队并累加 bufferedAmount（drain 代表内核冲出）。 */
class StubSocket implements MuxBufferedSocket {
  readyState = 1;
  bufferedAmount = 0;
  readonly sent: string[] = [];
  send(data: string): void {
    this.sent.push(data);
    this.bufferedAmount += Buffer.byteLength(data);
  }
  drain(): void {
    this.bufferedAmount = 0;
  }
}

test('Remote mux 有界发送：预算内按原顺序写出', () => {
  const socket = new StubSocket();
  const frames = ['a', 'bb', 'ccc'];
  for (const frame of frames) {
    assert.equal(sendMuxFrameBounded(socket, frame, LIMIT, MAX_FRAME_BYTES), 'sent');
  }
  assert.deepEqual(socket.sent, frames);
});

test('Remote mux 有界发送：单个大帧（超过 pending 预算）在未积压时仍放行', () => {
  const socket = new StubSocket();
  const snapshot = 'x'.repeat(3 * 1024 * 1024);
  assert.equal(sendMuxFrameBounded(socket, snapshot, LIMIT, MAX_FRAME_BYTES), 'sent');
  assert.equal(sendMuxFrameBounded(socket, 'follow-up-event', LIMIT, MAX_FRAME_BYTES), 'sent');
  assert.deepEqual(socket.sent, [snapshot, 'follow-up-event']);
});

test('Remote mux 有界发送：超最大帧和总积压预算时拒绝且不写出', () => {
  const socket = new StubSocket();
  assert.equal(sendMuxFrameBounded(socket, 'x'.repeat(MAX_FRAME_BYTES + 1), LIMIT, MAX_FRAME_BYTES), 'oversized');
  socket.bufferedAmount = LIMIT + MAX_FRAME_BYTES;
  assert.equal(sendMuxFrameBounded(socket, 'x', LIMIT, MAX_FRAME_BYTES), 'backpressure');
  assert.deepEqual(socket.sent, []);
});

test('Remote mux 有界发送：pending 余量边界内可继续发送', () => {
  const socket = new StubSocket();
  socket.bufferedAmount = LIMIT;
  assert.equal(sendMuxFrameBounded(socket, 'abc', LIMIT, MAX_FRAME_BYTES), 'sent');
  assert.deepEqual(socket.sent, ['abc']);
});

test('Remote mux 有界发送：socket 非 OPEN 时 skipped，不写出也不收尾', () => {
  const socket = new StubSocket();
  socket.readyState = 0; // CONNECTING
  assert.equal(sendMuxFrameBounded(socket, 'x', LIMIT, MAX_FRAME_BYTES), 'skipped');
  assert.deepEqual(socket.sent, []);
});

test('Remote mux 有界发送：send 抛异常时 failed，交由调用方按 1011 收尾', () => {
  const socket = new StubSocket();
  socket.send = () => { throw new Error('socket closing'); };
  assert.equal(sendMuxFrameBounded(socket, 'x', LIMIT, MAX_FRAME_BYTES), 'failed');
});

test('Remote mux 有界发送：慢对端逐帧积压，超过预算后停止并关闭', () => {
  const socket = new StubSocket();
  const chunk = 'x'.repeat(Math.floor(LIMIT / 2) + 1);
  assert.equal(sendMuxFrameBounded(socket, chunk, LIMIT, MAX_FRAME_BYTES), 'sent');
  assert.equal(sendMuxFrameBounded(socket, chunk, LIMIT, MAX_FRAME_BYTES), 'sent');
  // 越过 2 MiB 余量仍允许最后一个合法帧；余量+帧总上限后拒绝后续帧。
  socket.bufferedAmount = LIMIT + MAX_FRAME_BYTES - 1;
  assert.equal(sendMuxFrameBounded(socket, 'xy', LIMIT, MAX_FRAME_BYTES), 'backpressure');
  assert.deepEqual(socket.sent, [chunk, chunk]);
  // 对端恢复消费后即可继续发送，顺序不受影响。
  socket.drain();
  assert.equal(sendMuxFrameBounded(socket, 'after-drain', LIMIT, MAX_FRAME_BYTES), 'sent');
  assert.deepEqual(socket.sent, [chunk, chunk, 'after-drain']);
});
