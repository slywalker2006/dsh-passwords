import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const source = readFileSync(path.join(import.meta.dirname, '..', 'src', 'admin.ts'), 'utf8');

test('权限提交后在沙盒 await 前立即撤销旧订阅', () => {
  const fence = source.indexOf('if (accessChanged || sshChanged || otherPermissionChanged) {');
  const sandbox = source.indexOf('sandboxRevokedSessionIds = await applySandboxToSessions', fence);
  assert.ok(fence >= 0, '权限提交后必须存在立即撤回分支');
  assert.ok(sandbox > fence, '沙盒应用必须发生在立即撤回之后');
  const immediate = source.slice(fence, sandbox);
  assert.ok(immediate.includes('fenceUserAccessEpoch(userId)'), '撤回窗口必须推进权限 epoch');
  assert.ok(immediate.includes('invalidateUserSessionAccess(userId)'), '撤回窗口必须清空旧授权快照');
  assert.ok(immediate.includes('closeUserRemoteMuxClients(userId)'), '撤回窗口必须关闭 Remote carrier');
  assert.ok(immediate.includes('closeUserWebSocketClients(userId)'), '撤回窗口必须关闭 legacy WebSocket');
});
