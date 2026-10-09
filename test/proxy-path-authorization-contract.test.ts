// 路径授权契约回归：open-in-app 启动路径 / workspace 登记分支的 canonical + 敏感复核，
// 以及 Windows/POSIX 路径 helper 的口径。
//
// 1. proxy.ts 源码契约：这些分支需要完整 Express 请求上下文（权限行、realpath、上游记账）
//    才能端到端构造，行为回归见 test/unified-directory-authorization.test.ts；本文件只固定
//    读者可核对的顶层结构/符号，避免绑定实现细节。
// 2. 路径 helper 契约：normalizePath / isAbsoluteLikePath / isFullyQualifiedPath /
//    isFilesystemRootPath / pathWithin / folderAllowed / samePathForMatch 的平台口径。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  folderAllowed,
  isAbsoluteLikePath,
  isFilesystemRootPath,
  isFullyQualifiedPath,
  normalizePath,
  pathWithin,
} from '../src/permissions.js';
import { samePathForMatch } from '../src/db.js';

const isWindows = process.platform === 'win32';
const proxySource = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'proxy.ts'),
  'utf8',
);

// ── 1. proxy.ts 源码契约 ────────────────────────────────────────────

test('proxy.ts 契约：open-in-app 启动路径做 canonical + 敏感 + 大小写折叠绑定', () => {
  assert.match(
    proxySource,
    /const canonicalRequestedPath = normalizedRequestedPath === null/,
    'open-in-app 必须解析 canonical 请求路径（realpath 后复核）',
  );
  assert.match(
    proxySource,
    /samePathForMatch\(workspacePath, normalizedRequestedPath\)/,
    '词法绑定必须走 samePathForMatch（canonical + win32 大小写折叠），不能裸 normalizePath 相等',
  );
  assert.match(
    proxySource,
    /samePathForMatch\(workspacePath, canonicalRequestedPath\)/,
    'canonical 绑定必须走 samePathForMatch',
  );
  assert.match(
    proxySource,
    /!isSensitivePath\(normalizedRequestedPath\) && !isSensitivePath\(canonicalRequestedPath\)/,
    'open-in-app 词法 + canonical 两腿都必须拒绝敏感基',
  );
});

test('proxy.ts 契约：workspace/create 登记分支复核敏感路径（请求门禁 + 迟到回包）', () => {
  assert.match(
    proxySource,
    /isSensitivePath\(targetPath\) \|\| isSensitivePath\(canonicalTarget\)\) \{/,
    '登记请求门禁必须复核词法 + canonical 敏感基',
  );
  assert.match(
    proxySource,
    /!isSensitivePath\(grantPath\) && !isSensitivePath\(canonicalizePathBestEffort\(grantPath\)\)/,
    '迟到登记回包必须复核词法 + canonical 敏感基',
  );
  assert.match(proxySource, /'sensitive_path'/, '审计必须能区分敏感路径拒绝');
});

// ── 2. Windows/POSIX 路径 helper 契约 ───────────────────────────────

test('normalizePath：反斜杠归一、点段解析、盘符小写、UNC 归为单斜杠 rooted', () => {
  assert.equal(normalizePath('C:\\Users\\Sky'), 'c:/Users/Sky');
  assert.equal(normalizePath('C:/'), 'c:/');
  assert.equal(normalizePath('/a/./b/../c'), '/a/c');
  // 盘符相对路径保持相对语义（不补根），完全限定判定必须另经 isFullyQualifiedPath。
  assert.equal(normalizePath('C:foo'), 'c:foo');
  // UNC 被归一成单斜杠 rooted 形态：调用方必须用 isFullyQualifiedPath 拒绝它。
  assert.equal(normalizePath('\\\\server\\share\\x'), '/server/share/x');
  assert.equal(isFullyQualifiedPath('\\\\server\\share\\x'), false, 'UNC 不是完全限定路径');
});

test('isAbsoluteLikePath（宽松）与 isFullyQualifiedPath（严格）的 Windows 口径', () => {
  if (isWindows) {
    assert.equal(isAbsoluteLikePath('/x'), true);
    assert.equal(isAbsoluteLikePath('C:/x'), true);
    assert.equal(isAbsoluteLikePath('C:x'), true, '盘符相对属“绝对类”宽松口径');
    assert.equal(isAbsoluteLikePath('x'), false);

    assert.equal(isFullyQualifiedPath('C:/x'), true);
    assert.equal(isFullyQualifiedPath('C:\\x'), true);
    assert.equal(isFullyQualifiedPath('C:x'), false, '盘符相对不是完全限定');
    assert.equal(isFullyQualifiedPath('/x'), false, '无盘符 rooted 不是完全限定');
  } else {
    assert.equal(isAbsoluteLikePath('/x'), true);
    assert.equal(isAbsoluteLikePath('x'), false);
    assert.equal(isAbsoluteLikePath('C:/x'), false);

    assert.equal(isFullyQualifiedPath('/x'), true);
    assert.equal(isFullyQualifiedPath('x'), false);
    assert.equal(isFullyQualifiedPath('C:/x'), false);
  }
});

test('isFilesystemRootPath：识别 / 与盘符根，不误判普通目录', () => {
  assert.equal(isFilesystemRootPath('/'), true);
  assert.equal(isFilesystemRootPath('C:/'), true);
  assert.equal(isFilesystemRootPath('C:\\'), true);
  assert.equal(isFilesystemRootPath('/a'), false);
  assert.equal(isFilesystemRootPath('c:/x'), false);
  assert.equal(isFilesystemRootPath('C:'), false, '盘符相对不是文件系统根');
});

test('samePathForMatch：canonical + win32 大小写折叠的等值判定', () => {
  assert.equal(samePathForMatch('/a/b', '/a/b'), true);
  assert.equal(samePathForMatch('/a/b', '/a/b/c'), false, '包含不是等值');
  if (isWindows) {
    assert.equal(samePathForMatch('C:/Users/Sky/a', 'c:/users/sky/a'), true, 'win32 折叠大小写');
    assert.equal(samePathForMatch('C:/Users/Sky/a', 'C:/Users/Sky/b'), false);
  } else {
    assert.equal(samePathForMatch('C:/Users/Sky/a', 'c:/users/sky/a'), false, 'POSIX 段大小写敏感');
  }
});

test('folderAllowed/pathWithin：段边界判定（仅盘符小写，非盘符段不做大小写折叠）', () => {
  assert.equal(pathWithin('/home/sky/work', '/home/sky'), true);
  assert.equal(pathWithin('/home/sky', '/home/sky'), true);
  assert.equal(pathWithin('/home/skyler', '/home/sky'), false, '相似前缀不得越段命中');
  assert.equal(folderAllowed('/home/sky/work', ['/home/sky']), true);
  assert.equal(folderAllowed('/home/skyler', ['/home/sky']), false);
  if (isWindows) {
    // 记录既有口径：folderAllowed 只统一盘符大小写，其余段保持大小写敏感（误配时 fail-closed）。
    assert.equal(folderAllowed('C:/Users/Sky', ['c:/users/sky']), false);
  }
});
