// 聊天 SSE 写路径的有界性回归：慢客户端（写持续背压）必须在超过上限后被断开，
// 而不是让服务端响应缓冲无界增长。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CHAT_SSE_MAX_PENDING_BYTES, pushChatSseFrame } from '../src/messages.js';

/** 构造一个可控的假响应：write 返回指定的背压状态，记录 destroy。 */
function fakeClient(writeReturns: boolean) {
  let destroyed = false;
  const client: any = {
    res: {
      write: () => writeReturns,
      writableEnded: false,
      destroyed: false,
      destroy: () => { destroyed = true; },
    },
    pendingBytes: 0,
  };
  return { client, isDestroyed: () => destroyed };
}

test('聊天 SSE 慢客户端：写缓冲超过上限后断开（有界），不无界增长', () => {
  const { client, isDestroyed } = fakeClient(false);
  const payload = 'x'.repeat(64 * 1024);
  let kept = true;
  let writes = 0;
  while (kept && writes < 1000) {
    kept = pushChatSseFrame(client, payload);
    writes += 1;
  }
  assert.equal(kept, false, '累计背压字节超过上限后必须返回 false（移除该订阅者）');
  assert.equal(isDestroyed(), true, '超限必须 destroy 响应以释放缓冲');
  assert.ok(writes * payload.length > CHAT_SSE_MAX_PENDING_BYTES, '确实达到过上限');
});

test('聊天 SSE 健康客户端：写成功即视为缓冲已排空，永不因累积被误断', () => {
  const { client, isDestroyed } = fakeClient(true);
  const payload = 'y'.repeat(64 * 1024);
  for (let i = 0; i < 1000; i += 1) {
    assert.equal(pushChatSseFrame(client, payload), true, '写成功不得断开');
  }
  assert.equal(client.pendingBytes, 0, '写成功后累计字节必须归零');
  assert.equal(isDestroyed(), false);
});

test('聊天 SSE 已结束的响应：直接返回 false（不写入、不抛错）', () => {
  const { client } = fakeClient(true);
  client.res.writableEnded = true;
  assert.equal(pushChatSseFrame(client, 'data: x\n\n'), false);
});
