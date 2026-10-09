// 目录创建/会话 cwd 路径硬化回归（统一目录授权）。
//
// 覆盖两个可验证契约：
//   1. directoryPicker/createDirectory 在当前 live 权限行下以 allowed_folders 为唯一范围：
//      父目录与新目标的词法 + canonical 两腿都必须命中，且拒绝文件系统根与敏感基；不存在
//      独立创建根、旧规则（configuredRoots === null）或家目录短路。
//   2. session/create 的 cwd 对子用户补 canonical path 白名单 + 敏感基复核，阻止授权目录内
//      symlink 指向敏感/白名单外。
//
// 1、2 的分支需要完整 Express 请求上下文（权限行、realpath、上游记账），纯函数测试无法构造，
// 因此以 proxy.ts 源码契约断言表达：只固定能被读者核对的结构/符号，不绑定实现细节。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const proxySource = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'proxy.ts'),
  'utf8',
);

// ── 1. directoryPicker/createDirectory：allowed_folders 唯一范围 ─────────────

test('proxy.ts 契约：createDirectory 的 targetAllowed 以 validName + 双口径白名单 + 敏感校验为顶层合取', () => {
  const match = proxySource.match(/const targetAllowed = (validName &&[\s\S]*?);/);
  assert.ok(match, '未找到 createDirectory 的 targetAllowed 表达式');
  const expr = match![1].replace(/\s+/g, ' ').trim();
  // 顶层首项必须是 validName。旧实现存在 `configuredRoots === null || (...)` 的旧规则分支，
  // 会把名称校验与敏感校验整体短路跳过——统一目录授权后不得再存在该分支。
  assert.match(expr, /^validName && /, expr);
  assert.doesNotMatch(expr, /configuredRoots/, '不得保留旧创建根/旧规则分支');
  // 词法 + canonical 两腿都必须命中当前 live allowed_folders。
  assert.match(expr, /folderAllowed\(targetLexical, folders\) && folderAllowed\(targetCanonical, folders\)/, expr);
  // 非文件系统根与非敏感基是组外顶层合取项：任一不通过即拒绝。
  assert.match(expr, /!isFilesystemRootPath\(targetLexical\) && !isFilesystemRootPath\(targetCanonical\)/, expr);
  assert.match(expr, /!isSensitivePath\(targetLexical\) && !isSensitivePath\(targetCanonical\)/, expr);
});

test('proxy.ts 契约：createDirectory 的父目录双口径校验与 allow_workspace_create 前置开关', () => {
  assert.match(
    proxySource,
    /const parentAllowed = folderAllowed\(targetPath, folders\) && folderAllowed\(canonicalParent, folders\)/,
    '父目录必须同时通过词法与 canonical 白名单',
  );
  assert.match(
    proxySource,
    /if \(!currentPerms\.allow_workspace_create \|\| !parentAllowed \|\| !targetAllowed \|\|/,
    'allow_workspace_create 必须是创建门禁的前置合取项',
  );
});

// ── 2. session/create：cwd 追加 canonical 白名单 + 敏感复核 ──────────────

test('proxy.ts 契约：session/create 的 cwd 追加 canonical 白名单与敏感复核', () => {
  assert.match(
    proxySource,
    /const canonicalTarget = WORKSPACE_ENDPOINT_RE\.test\(proxyPath\)\s*\?\s*canonicalizePathBestEffort\(targetPath\)\s*:\s*null/,
    '缺少 session/create 的 canonical 目标解析（须以 WORKSPACE_ENDPOINT_RE 圈定 create）',
  );
  assert.match(
    proxySource,
    /!folderAllowed\(canonicalTarget, folders\)\s*\|\|\s*isSensitivePath\(canonicalTarget\)/,
    'canonical cwd 必须同时复核白名单与敏感基，阻止授权目录内 symlink 逃逸',
  );
});
