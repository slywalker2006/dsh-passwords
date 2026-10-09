// R7 回归：~/.ssh 的真实链接目标必须落入敏感基。
// 调用方（gateway / admin）传入的是 canonical(realpath) 路径；若只登记词法 ~/.ssh，
// 当 SSH 目录被软链到其它位置时，规范化后的凭据路径不会命中任何基，敏感基静默漏放。
// 这里同时验证词法侧仍命中、canonical 目标子树命中、且未扩大到链接目标的无关父目录。
// 另有一条缓存回归：realpath 基不得在首次调用后永久固化，链接晚于首调建立/改指也必须生效。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';

import { createSensitivePathChecker } from '../src/sensitive-paths.js';

test('R7 缓存：~/.ssh 链接晚于 checker 首次调用建立/改指，realpath 基仍实时生效', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'dshpw-r7-late-ssh-'));
  const home = path.join(base, 'home');
  const deploy = path.join(base, 'deploy');
  const targetA = path.join(base, 'creds-a');
  const targetB = path.join(base, 'creds-b');
  const sshLink = path.join(home, '.ssh');
  const originalHomedir = os.homedir;
  try {
    // deploy 与两个凭据目录分离：部署基（gatewayRoot/configuredRoot/dshRoot/dbPath 父级）
    // 不含 base 本身，targetA/targetB 因此不会因落在部署基内而误命中。
    mkdirSync(deploy, { recursive: true });
    mkdirSync(home, { recursive: true });
    mkdirSync(targetA, { recursive: true });
    mkdirSync(targetB, { recursive: true });
    os.homedir = () => home;

    const checker = createSensitivePathChecker({
      dbPath: path.join(deploy, 'data', 'platform.db'),
      dshRoot: deploy,
      gatewayRoot: deploy,
      configuredRoot: deploy,
    });

    // 首次调用发生在 ~/.ssh 尚不存在时：此刻 realpath(~/.ssh) 只能退回词法，目标不应命中。
    assert.equal(checker.isSensitivePath(path.join(targetA, 'id_rsa')), false, '未建链接前目标不应命中');

    try {
      // Windows junction 与 POSIX symlink 都由 realpathSync 解析；无权限创建链接时跳过该变体。
      symlinkSync(targetA, sshLink, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      return;
    }
    // 同一个 checker 必须实时解析出链接目标，而不是沿用首次调用时的 realpath 缓存。
    assert.equal(checker.isSensitivePath(path.join(sshLink, 'id_rsa')), true, '词法 ~/.ssh 子树仍命中');
    assert.equal(checker.isSensitivePath(path.join(targetA, 'id_rsa')), true, '首调之后建立的链接目标必须命中');

    // 改指：旧目标不再命中、新目标命中，证明首次 realpath 没有被永久固化。
    rmSync(sshLink, { recursive: true, force: true });
    symlinkSync(targetB, sshLink, process.platform === 'win32' ? 'junction' : 'dir');
    assert.equal(checker.isSensitivePath(path.join(targetB, 'id_rsa')), true, '改指后的新目标必须命中');
    assert.equal(checker.isSensitivePath(path.join(targetA, 'id_rsa')), false, '改指后的旧目标不再命中');
  } finally {
    os.homedir = originalHomedir;
    rmSync(base, { recursive: true, force: true });
  }
});

test('~/.ssh 的 realpath 链接目标及其子树命中敏感基，未扩大到无关父目录', () => {
  const base = mkdtempSync(path.join(os.tmpdir(), 'dshpw-r7-ssh-'));
  const home = path.join(base, 'home');
  const deploy = path.join(base, 'deploy');
  const sshTarget = path.join(base, 'elsewhere', 'ssh-real');
  const sshLink = path.join(home, '.ssh');
  const originalHomedir = os.homedir;
  try {
    // 部署基（gatewayRoot/configuredRoot/dshRoot/dbPath 父级）与 SSH 链接目标完全分离，
    // 否则目标会因落在部署基内而命中，无法隔离 R7 的缺口。
    mkdirSync(deploy, { recursive: true });
    mkdirSync(sshTarget, { recursive: true });
    mkdirSync(home, { recursive: true });
    try {
      // Windows junction 与 POSIX symlink 都由 realpathSync 解析；测试只验证路径边界，
      // 不读取任何敏感文件。无权限创建链接时跳过该变体（与既有敏感路径测试一致）。
      symlinkSync(sshTarget, sshLink, process.platform === 'win32' ? 'junction' : 'dir');
    } catch {
      return;
    }
    os.homedir = () => home;

    const checker = createSensitivePathChecker({
      dbPath: path.join(deploy, 'data', 'platform.db'),
      dshRoot: deploy,
      gatewayRoot: deploy,
      configuredRoot: deploy,
    });

    // 词法侧不回退：~/.ssh 子树仍命中。
    assert.equal(checker.isSensitivePath(path.join(sshLink, 'id_rsa')), true, '词法 ~/.ssh 子树必须命中');
    // canonical 侧：链接目标自身与其子树必须命中（R7 修复点）。
    assert.equal(checker.isSensitivePath(sshTarget), true, '~/.ssh 链接目标自身必须命中');
    assert.equal(checker.isSensitivePath(path.join(sshTarget, 'id_rsa')), true, '~/.ssh 链接目标子树必须命中');
    // fail-closed 但不越界：链接目标的无关父目录不得命中。
    assert.equal(checker.isSensitivePath(path.join(base, 'elsewhere')), false, '不得扩大到无关父目录');
  } finally {
    os.homedir = originalHomedir;
    rmSync(base, { recursive: true, force: true });
  }
});
