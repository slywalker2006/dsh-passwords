// 敏感路径判定回归：
//   - 基列表命中（相等与段边界子树包含）与相似前缀不误命中；
//   - Windows 文件系统大小写不敏感：大小写变体必须仍命中敏感基（否则敏感基静默失效）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';

import { createSensitivePathChecker } from '../src/sensitive-paths.js';

/** 部署布局：数据库在 <部署根>/data/ 下；dshRoot 显式给一个已存在目录以避免探测子进程。 */
function makeChecker(tempDir: string) {
  return createSensitivePathChecker({
    dbPath: path.join(tempDir, 'data', 'platform.db'),
    dshRoot: tempDir,
    gatewayRoot: tempDir,
    configuredRoot: tempDir,
  });
}

test('敏感路径基：部署根、数据库父级与其子树命中；相似前缀不误命中', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-sens-'));
  try {
    const checker = makeChecker(tempDir);
    assert.equal(checker.isSensitivePath(tempDir), true, '部署根自身必须命中');
    assert.equal(checker.isSensitivePath(path.join(tempDir, 'data', 'platform.db')), true, '数据库文件必须命中');
    assert.equal(checker.isSensitivePath(path.join(tempDir, 'dist', 'cli.js')), true, '部署根子树必须命中');
    assert.equal(checker.isSensitivePath(path.join(tempDir, 'data')), true, '数据库父级必须命中');
    // 段边界：仅前缀相同（没有分隔符边界）的目录不得命中。
    assert.equal(checker.isSensitivePath(`${tempDir}-sibling/x`), false, '相似前缀不得越界命中');
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

test('配置根的真实路径别名仍命中敏感基', () => {
  const parent = mkdtempSync(path.join(os.tmpdir(), 'dshpw-sens-link-'));
  const realRoot = path.join(parent, 'real');
  const aliasRoot = path.join(parent, 'alias');
  try {
    const checker = createSensitivePathChecker({
      dbPath: path.join(parent, 'data', 'platform.db'),
      dshRoot: realRoot,
      gatewayRoot: aliasRoot,
      configuredRoot: aliasRoot,
    });
    // Windows junction 与 POSIX symlink 都由 realpathSync 解析；测试只验证路径边界，
    // 不读取任何敏感文件。symlink 在 Windows 无权限时跳过该变体。
    try {
      mkdirSync(realRoot, { recursive: true });
      symlinkSync(realRoot, aliasRoot, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      return;
    }
    assert.equal(checker.isSensitivePath(realRoot), true);
    assert.equal(checker.isSensitivePath(path.join(realRoot, 'secret.txt')), true);
    assert.equal(checker.isSensitivePath(path.join(aliasRoot, 'secret.txt')), true);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('Windows 敏感路径大小写：win32 下大小写变体仍命中，POSIX 保持大小写敏感', () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dshpw-sens-case-'));
  try {
    const checker = makeChecker(tempDir);
    // 全大写变体：Windows 上指向同一目录；POSIX 上是不同路径。
    const upper = tempDir.replace(/[a-z]/g, (ch) => ch.toUpperCase());

    if (process.platform === 'win32') {
      assert.equal(checker.isSensitivePath(upper), true, 'win32 下大小写变体必须仍命中敏感基');
      assert.equal(
        checker.isSensitivePath(path.join(upper, 'DATA', 'PLATFORM.DB')),
        true,
        'win32 下大小写混合的子树必须仍命中敏感基',
      );
    } else {
      assert.equal(checker.isSensitivePath(tempDir), true);
      assert.equal(checker.isSensitivePath(upper), false, 'POSIX 大小写敏感：变体不是同一路径');
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
