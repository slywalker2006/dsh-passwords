// 管理员目录选择器 browse roots 回归：
//   · 纯路径判定：段边界包含、相似前缀不误命中、win32 大小写口径、祖先直连子路径；
//   · scope 分类：root / inside / ancestor / outside，嵌套 root 取最具体、符号链接逃逸拒绝；
//   · roots 解析：逗号/换行分隔、去重、丢弃相对路径与全盘根，未配置回退家目录；
//   · roots 校验：丢弃不存在/非目录/敏感候选、记录 canonical（realpath 链接目标）；
//   · 源码契约：选择器不再从盘符根枚举、必须走 browse roots 配置、保持主用户门控。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  classifyDirectoryPickerTarget,
  directoryPickerChildToward,
  directoryPickerEntryName,
  directoryPickerPathWithin,
  resolveDirectoryPickerBrowseRoots,
  type DirectoryPickerRootRef,
} from '../src/admin.js';
import { parseDirectoryPickerRootList, resolveDirectoryPickerRoots } from '../src/config.js';
import { normalizePath } from '../src/permissions.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isWindows = process.platform === 'win32';

function root(lexical: string, real: string = lexical): DirectoryPickerRootRef {
  return { lexical, real };
}

// ── 纯路径判定 ────────────────────────────────────────────────────

test('directoryPickerPathWithin：段边界包含，相似前缀不误命中', () => {
  assert.equal(directoryPickerPathWithin('/home/sky', '/home/sky/work'), true);
  assert.equal(directoryPickerPathWithin('/home/sky', '/home/sky'), true);
  assert.equal(directoryPickerPathWithin('/home/sky', '/home/skyler'), false, '相似前缀不得越段命中');
  assert.equal(directoryPickerPathWithin('/home/sky', '/home'), false, '父目录不在子树内');
  assert.equal(directoryPickerPathWithin('/', '/home/sky'), true, '文件系统根包含全部绝对路径');
  assert.equal(directoryPickerPathWithin('C:/', 'C:/Users/Sky'), true, 'Windows 盘符根同理');
});

test('directoryPickerChildToward：返回通往目标 root 的直接子路径', () => {
  assert.equal(directoryPickerChildToward('/home', '/home/sky/work'), '/home/sky');
  assert.equal(directoryPickerChildToward('/', '/home/sky'), '/home');
  assert.equal(directoryPickerChildToward('/home/sky', '/home/sky/work'), '/home/sky/work');
  assert.equal(directoryPickerChildToward('C:/', 'C:/Users/Sky'), 'c:/Users');
  assert.equal(directoryPickerChildToward('/home/sky', '/home/sky'), null, '相等不是严格祖先');
  assert.equal(directoryPickerChildToward('/home', '/etc'), null, '无关路径返回 null');
});

test('directoryPickerEntryName：取归一化路径最后一段', () => {
  assert.equal(directoryPickerEntryName('/home/sky'), 'sky');
  assert.equal(directoryPickerEntryName('/data/'), 'data');
  assert.equal(directoryPickerEntryName('C:/Users/Sky'), 'Sky');
});

// ── scope 分类 ───────────────────────────────────────────────────

test('classifyDirectoryPickerTarget：root/inside/ancestor/outside 判定', () => {
  // 词法与 canonical 不同（root 经符号链接登记）时，两者都必须命中同一 root。
  const roots = [root('/srv/projects', '/mnt/projects')];
  assert.equal(classifyDirectoryPickerTarget(root('/srv/projects', '/mnt/projects'), roots).kind, 'root');
  assert.equal(classifyDirectoryPickerTarget(root('/srv/projects/app', '/mnt/projects/app'), roots).kind, 'inside');
  assert.equal(classifyDirectoryPickerTarget(root('/srv', '/mnt'), roots).kind, 'ancestor', 'root 的祖先是 ancestor');
  assert.equal(classifyDirectoryPickerTarget(root('/', '/'), roots).kind, 'ancestor', '文件系统根只通往 root');
  assert.equal(classifyDirectoryPickerTarget(root('/srv/other', '/mnt/other'), roots).kind, 'outside');
  // 符号链接逃逸：词法落在 root 内，canonical 落到 root 外。
  assert.equal(classifyDirectoryPickerTarget(root('/srv/projects/app', '/etc'), roots).kind, 'outside');
  // 用户传入等价于 root 但 canonical 不符的路径不得当成 root。
  assert.equal(classifyDirectoryPickerTarget(root('/srv/projects', '/tmp/elsewhere'), roots).kind, 'outside');
});

test('classifyDirectoryPickerTarget：嵌套 root 取最具体者，ancestor 只回通往 root 的条目', () => {
  const roots = [root('/data'), root('/data/team/app')];
  const nested = classifyDirectoryPickerTarget(root('/data/team/app'), roots);
  assert.equal(nested.kind, 'root', '精确等于内层 root 时 parentPath 应为 null');
  assert.equal(nested.rootIndex, 1);
  const descendant = classifyDirectoryPickerTarget(root('/data/team/app/sub'), roots);
  assert.equal(descendant.kind, 'inside');
  assert.equal(descendant.rootIndex, 1, '取最具体的 root');
  // /data/team 落在 root /data 子树内，因此是 inside 而非 ancestor。
  assert.equal(classifyDirectoryPickerTarget(root('/data/team'), roots).kind, 'inside');

  // 真正的祖先（不在任何 root 内）：只回通往各 root 的直接子条目，且不可作为落点。
  const aboveRoots = [root('/srv/a'), root('/srv/b')];
  const ancestor = classifyDirectoryPickerTarget(root('/srv'), aboveRoots);
  assert.equal(ancestor.kind, 'ancestor');
  assert.deepEqual(ancestor.ancestorEntries, ['/srv/a', '/srv/b']);
  assert.equal(classifyDirectoryPickerTarget(root('/srv/other'), aboveRoots).kind, 'outside', '兄弟目录不出现');
});

// ── roots 解析（纯字符串）──────────────────────────────────────────

test('parseDirectoryPickerRootList：逗号/换行分隔、去重、丢弃相对路径与全盘根', () => {
  const absA = isWindows ? 'C:\\data\\a' : '/data/a';
  const absB = isWindows ? 'D:/data/b' : '/data/b';
  const fsRoot = isWindows ? 'C:\\' : '/';
  const parsed = parseDirectoryPickerRootList(`${absA}, ${absB}\n${absA}\r\nrelative/path\n`);
  assert.deepEqual(parsed, [absA, absB], '保留合规绝对路径、去重、丢弃相对路径');
  assert.deepEqual(parseDirectoryPickerRootList(fsRoot), [], '全盘根一律丢弃');
  assert.deepEqual(parseDirectoryPickerRootList('  ,\n , '), [], '纯空白/分隔符得到空列表');
});

test('resolveDirectoryPickerRoots：未配置回退家目录，配置时解析候选', () => {
  assert.deepEqual(resolveDirectoryPickerRoots({}), [os.homedir()], '未配置时唯一安全起点是家目录');
  assert.deepEqual(resolveDirectoryPickerRoots({ MCP_GATEWAY_DIRECTORY_PICKER_ROOTS: '   ' }), [os.homedir()]);
  const abs = isWindows ? 'C:\\data\\a' : '/data/a';
  assert.deepEqual(resolveDirectoryPickerRoots({ MCP_GATEWAY_DIRECTORY_PICKER_ROOTS: abs }), [abs]);
});

// ── roots 校验（按文件系统状态）──────────────────────────────────

test('resolveDirectoryPickerBrowseRoots：丢弃全盘根/不存在/敏感候选，记录 canonical', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'dshpw-picker-'));
  try {
    const real = path.join(temp, 'real');
    mkdirSync(real, { recursive: true });
    const roots = resolveDirectoryPickerBrowseRoots([real, real, path.join(temp, 'missing')], () => false);
    assert.equal(roots.length, 1, '去重并丢弃不存在候选');
    assert.equal(roots[0].lexical, normalizePath(real));
    assert.equal(roots[0].real, normalizePath(real));

    const alias = path.join(temp, 'alias');
    let aliasOk = true;
    try {
      symlinkSync(real, alias, isWindows ? 'junction' : 'dir');
    } catch {
      aliasOk = false;
    }
    if (aliasOk) {
      const linked = resolveDirectoryPickerBrowseRoots([alias], () => false);
      assert.equal(linked.length, 1);
      assert.equal(linked[0].real, normalizePath(real), 'canonical 必须解析链接目标');
    }

    assert.deepEqual(resolveDirectoryPickerBrowseRoots([real], () => true), [], '敏感候选整体丢弃（fail-closed）');
    const fsRoot = isWindows ? 'C:\\' : '/';
    assert.deepEqual(resolveDirectoryPickerBrowseRoots([fsRoot], () => false), [], '全盘根丢弃');
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

// ── 源码契约 ──────────────────────────────────────────────────────

test('源码契约：选择器不再从盘符/文件系统根枚举，必须走 browse roots 配置', () => {
  const adminSource = readFileSync(path.join(projectRoot, 'src', 'admin.ts'), 'utf8');
  assert.ok(!/String\.fromCharCode/.test(adminSource), '不得再有盘符（0x41..0x5a）枚举');
  assert.ok(!/collectSubdirectories\(['"]\/['"]\)/.test(adminSource), '不得再从文件系统根直接列举');
  assert.match(adminSource, /\/gateway\/api\/directory-picker\/list/, '目录选择器路由必须存在');
  assert.match(adminSource, /config\.directoryPickerRoots/, '必须通过 browse roots 配置收窄浏览范围');
  assert.match(adminSource, /apiAuth\(req, res, true\)/, '目录选择器必须保持主用户门控');

  const configSource = readFileSync(path.join(projectRoot, 'src', 'config.ts'), 'utf8');
  assert.match(configSource, /'MCP_GATEWAY_DIRECTORY_PICKER_ROOTS'/, '新键必须纳入托管环境键');
});
