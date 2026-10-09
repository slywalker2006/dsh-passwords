// R1 回归：沙盒失败回收 grant 后，HTTP prompt 仍使用旧访问快照。
//
// 根因：权限保存的「DB 提交后、沙盒 await 前」立即撤回窗口会清空内存快照，
// 但 applySandboxToSessions 的 await 期间 carrier 已重连，DSH 会凭“grant 仍在
// DB”重建一份 workspace baseline，把即将被回收的会话重新写进 userSessionAccess。
// 沙盒随后失败并 db.deleteUserSessionGrants 删除权威 grant，却没有再次失效该
// 快照；而 HTTP 会话归属校验（proxy.ts）只信内存快照、不复查 DB grant，于是
// prompt 继续用旧快照转发已撤销会话。
//
// 修复：删除权威 grant 后必须再次失效快照并关闭 carrier，令 control baseline、
// prompt 与列表投影统一从删除后的权威权限集合重建。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const source = readFileSync(path.join(import.meta.dirname, '..', 'src', 'admin.ts'), 'utf8');
// proxy.ts：受限子用户 prompt 在沙盒确认 await 之后的权威回查。
const proxySource = readFileSync(path.join(import.meta.dirname, '..', 'src', 'proxy.ts'), 'utf8');

const REVOKE_GUARD = 'if (sandboxRevokedSessionIds.length > 0) {';
const DELETE_GRANTS = 'db.deleteUserSessionGrants(userId, sandboxRevokedSessionIds)';
const INVALIDATE = 'invalidateUserSessionAccess(userId)';
const CLOSE_REMOTE = 'closeUserRemoteMuxClients(userId)';
const CLOSE_WS = 'closeUserWebSocketClients(userId)';

test('R1：沙盒删除权威 grant 后必须重新失效快照并关闭 carrier', () => {
  const guardIdx = source.indexOf(REVOKE_GUARD);
  assert.ok(guardIdx >= 0, '沙盒回收分支必须存在，且仅在确有回收时触发');

  const deleteIdx = source.indexOf(DELETE_GRANTS, guardIdx);
  assert.ok(deleteIdx > guardIdx, '回收分支必须删除权威 grant');

  // 删除 grant 之后、进入后续配额/审计收尾之前，是本分支删除后的处理尾部。
  const blockEnd = source.indexOf('只有显式提交会话集合时', deleteIdx);
  assert.ok(blockEnd > deleteIdx, '删除 grant 之后必须还有沙盒分支收尾代码');
  const afterDelete = source.slice(deleteIdx, blockEnd);

  const invalidateIdx = afterDelete.indexOf(INVALIDATE);
  assert.ok(invalidateIdx >= 0, '删除权威 grant 后必须重新失效内存访问快照（否则 rebuilt baseline 仍是旧快照）');
  assert.ok(
    afterDelete.indexOf(CLOSE_REMOTE, invalidateIdx) > invalidateIdx,
    '失效快照后必须关闭 Remote carrier，令 DSH 重连并按权威 grant 重建 baseline',
  );
  assert.ok(
    afterDelete.indexOf(CLOSE_WS, invalidateIdx) > invalidateIdx,
    '失效快照后必须关闭 legacy WebSocket carrier',
  );
});

test('R1：撤回同时覆盖 await 前窗口与删除后窗口，且不误伤同值保存', () => {
  // 立即撤回窗口（DB 提交后、沙盒 await 前）仍须存在，否则在途 carrier 继续发送已撤回帧。
  const fence = source.indexOf('if (accessChanged || sshChanged || otherPermissionChanged) {');
  const sandboxAwait = source.indexOf('sandboxRevokedSessionIds = await applySandboxToSessions', fence);
  assert.ok(fence >= 0 && sandboxAwait > fence, 'await 前立即撤回窗口必须保留');
  const immediate = source.slice(fence, sandboxAwait);
  assert.ok(immediate.includes(INVALIDATE), 'await 前窗口必须清空旧授权快照');

  // 两个窗口都必须推进 epoch（重新失效内部会 bump），确保在途 baseline 不能回写旧集合。
  const invalidateCalls = source.split(INVALIDATE).length - 1;
  assert.ok(invalidateCalls >= 2, 'await 前与删除后两个窗口都要重新失效快照');

  // 删除后的重新失效必须严格嵌在“确有回收”守卫内：同值保存仍是 no-op，不撕裂 carrier。
  const deleteIdx = source.indexOf(DELETE_GRANTS);
  const guardIdx = source.lastIndexOf(REVOKE_GUARD, deleteIdx);
  const reinvalidateIdx = source.indexOf(INVALIDATE, deleteIdx);
  assert.ok(guardIdx >= 0 && guardIdx < reinvalidateIdx, '删除后重新失效必须位于 sandboxRevokedSessionIds.length > 0 守卫内');
});

// R1 的 await 窗口在 HTTP prompt 路径上另有一条独立实现：受限子用户 prompt 在转发前
// 必须真实 await 沙盒确认（applySandboxToSession），await 之后必须重读权威权限再决定
// 是否转发旧请求——不能只用请求开始时的旧快照放行。grant/disabled 两条可用真实延迟
// 观测的路径由 r1-http-await-behavior.test.ts 覆盖；此处用源码契约固定 epoch 栅栏：
// 触发真实 epoch 推进需要走依赖上游资源核验的 /gateway/api/permissions，本文件的
// harness 不具备该依赖，故不伪造通过，只断言实现结构。
test('R1：沙盒确认 await 后必须重读 epoch 与权威 grant/disabled 再决定是否转发', () => {
  const runCheck = proxySource.indexOf('if (needsSandboxRunCheck) {');
  assert.ok(runCheck >= 0, '受限子用户 prompt 的沙盒确认分支必须存在');
  const awaitSandbox = proxySource.indexOf('await applySandboxToSession(runSessionId, runSandboxMode)', runCheck);
  assert.ok(awaitSandbox > runCheck, '沙盒确认必须在转发前真实 await');

  const postMarker = proxySource.indexOf('Sandbox enforcement awaits an internal confirmation', awaitSandbox);
  assert.ok(postMarker > awaitSandbox, 'await 之后必须存在权威回查窗口');
  const blockStart = proxySource.indexOf('if (needsSandboxRunCheck && reqAs.dshpwUser !== undefined) {', postMarker);
  assert.ok(blockStart > postMarker, 'await 后回查必须仍挂在 needsSandboxRunCheck 上');
  const blockEnd = proxySource.indexOf('// The alpha client may publish', blockStart);
  assert.ok(blockEnd > blockStart, 'await 后回查块必须有界');
  const block = proxySource.slice(blockStart, blockEnd);

  for (const needed of [
    'db.getPermissions(userId)',
    'userSessionAccessFor(userId)',
    'userAccessEpochFor(userId)',
    'currentEpoch !== sessionAccessRequestEpoch',
    '!currentPerms.disabled_sessions.includes(sessionId)',
    'db.hasUserSessionGrant(userId, sessionId)',
    '!allowedAfterSandbox(sessionId)',
  ]) {
    assert.ok(block.includes(needed), `await 后回查必须包含：${needed}`);
  }

  // 回查失败必须销毁在途上游请求再 403：await 期间权限变化后绝不放行旧 prompt。
  const denyIdx = block.indexOf('upstreamReq.destroy();');
  assert.ok(denyIdx >= 0, 'await 后回查失败必须销毁在途上游请求');
  const forbiddenIdx = block.indexOf('res.status(403)', denyIdx);
  assert.ok(forbiddenIdx > denyIdx, '回查失败必须先销毁上游请求再 403');
});
