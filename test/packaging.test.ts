import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '..');
const cleanDistScript = path.join(projectRoot, 'scripts', 'clean-dist.mjs');

type PackageJson = {
  scripts?: Record<string, string>;
  files?: string[];
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};
const readPackageJson = (): PackageJson =>
  JSON.parse(readFileSync(path.join(projectRoot, 'package.json'), 'utf8')) as PackageJson;

// 与 scripts/clean-dist.mjs 相同的判定：只有同时存在 .js 与 .d.ts 的成对产物，
// 且 src/ 下已无同名 .ts，才算陈旧编译产物（client.js 之类无 .d.ts 的打包产物保留）。
function obsoleteCompiledOutputs(distDir: string, srcDir: string): string[] {
  const sourceBases = new Set(
    readdirSync(srcDir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
      .map((entry) => entry.name.slice(0, -'.ts'.length)),
  );
  const distFiles = readdirSync(distDir, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
  const distSet = new Set(distFiles);
  return distFiles
    .filter((name) => name.endsWith('.d.ts'))
    .map((name) => name.slice(0, -'.d.ts'.length))
    .filter((base) => distSet.has(`${base}.js`) && !sourceBases.has(base))
    .sort();
}

test('prepack cleans obsolete dist outputs before the build', () => {
  const prepack = readPackageJson().scripts?.prepack ?? '';
  assert.match(prepack, /clean-dist/, 'prepack must invoke the clean-dist script');
  assert.ok(
    prepack.indexOf('clean-dist') < prepack.indexOf('build'),
    'prepack must clean stale outputs before building',
  );
});

test('clean-dist removes orphaned compiled outputs and keeps live artifacts', () => {
  const fixture = mkdtempSync(path.join(tmpdir(), 'dshpw-clean-dist-'));
  try {
    const srcDir = path.join(fixture, 'src');
    const distDir = path.join(fixture, 'dist');
    mkdirSync(srcDir, { recursive: true });
    mkdirSync(distDir, { recursive: true });
    // 仍有源码的编译产物：必须保留
    writeFileSync(path.join(srcDir, 'gateway.ts'), 'export const gateway = 1;\n');
    writeFileSync(path.join(srcDir, 'index.ts'), 'export const index = 1;\n');
    writeFileSync(path.join(distDir, 'gateway.js'), 'live\n');
    writeFileSync(path.join(distDir, 'gateway.d.ts'), 'live\n');
    writeFileSync(path.join(distDir, 'index.js'), 'live\n');
    writeFileSync(path.join(distDir, 'index.d.ts'), 'live\n');
    // 无 .d.ts 的 esbuild 打包产物（dist/client.js）：必须保留
    writeFileSync(path.join(distDir, 'client.js'), 'bundle\n');
    // 旧构建残留：必须删除
    const staleBases = ['gateway-admin', 'gateway-media', 'gateway-messages', 'gateway-proxy', 'plugin-compat'];
    for (const base of staleBases) {
      writeFileSync(path.join(distDir, `${base}.js`), 'stale\n');
      writeFileSync(path.join(distDir, `${base}.d.ts`), 'stale\n');
    }

    const result = spawnSync(process.execPath, [cleanDistScript], { cwd: fixture, encoding: 'utf8' });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

    assert.deepEqual(obsoleteCompiledOutputs(distDir, srcDir), []);
    for (const kept of ['gateway.js', 'gateway.d.ts', 'index.js', 'index.d.ts', 'client.js']) {
      assert.equal(existsSync(path.join(distDir, kept)), true, `${kept} must be preserved`);
    }
    for (const base of staleBases) {
      assert.equal(existsSync(path.join(distDir, `${base}.js`)), false, `${base}.js must be removed`);
      assert.equal(existsSync(path.join(distDir, `${base}.d.ts`)), false, `${base}.d.ts must be removed`);
    }
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test('npm package declares runtime modules as production dependencies and ships installer files', () => {
  const pkg = readPackageJson();
  for (const name of ['bcryptjs', 'dotenv', 'express', 'jsonwebtoken', 'ws']) {
    assert.equal(typeof pkg.dependencies?.[name], 'string', `${name} must be installed for production use`);
    assert.equal(pkg.devDependencies?.[name], undefined, `${name} must not be development-only`);
  }
  for (const file of ['dist/', 'scripts/', '.env.example', 'cordis.yml', 'npm-shrinkwrap.json', 'README.md', 'README_en.md', 'docs/']) {
    assert.ok(pkg.files?.includes(file), `${file} must be published`);
  }
});

test('source installer ignores dependency scripts and builds from the checked-out source', () => {
  const installer = readFileSync(path.join(projectRoot, 'scripts', 'install.mjs'), 'utf8');
  assert.match(installer, /\['ci', '--include=optional', '--include=dev', '--ignore-scripts'/);
  assert.match(installer, /\['install', '--ignore-scripts'/);
  assert.match(installer, /const hasSource = existsSync/);
  assert.match(installer, /if \(prebuilt && !hasSource\)/);
  assert.doesNotMatch(installer, /DSH_PASSWORDS_INSTALL_ROOT/, '测试根目录不得成为生产安装器环境变量');
  assert.match(installer, /\['run', 'build'\]/);
});

test('published package omits source-only build inputs', () => {
  const pkg = readPackageJson();
  assert.equal(pkg.files?.includes('src/'), false);
  assert.equal(pkg.files?.includes('tsconfig.json'), false);
});

test('the npm package includes README-linked documentation', () => {
  const pkg = readPackageJson();
  assert.ok(pkg.files?.includes('docs/'), 'docs/ must be published because README links into it');
  const docsDir = path.join(projectRoot, 'docs');
  assert.equal(existsSync(docsDir), true, 'docs/ must exist in the source tree');
  assert.ok(readdirSync(docsDir).length > 0, 'docs/ must contain publishable documentation');
  for (const linked of ['advanced-tuning.md', 'community-checklist.md', 'endpoint-registration.md', 'banner.jpg']) {
    assert.equal(
      existsSync(path.join(docsDir, linked)),
      true,
      `README links to docs/${linked}, so it must stay in the tree`,
    );
  }
});

test('docs/.npmignore trims internal artifacts from the published docs/', () => {
  const ignorePath = path.join(projectRoot, 'docs', '.npmignore');
  assert.equal(existsSync(ignorePath), true, 'docs/.npmignore is required to trim the docs/ whitelist');
  const ignore = readFileSync(ignorePath, 'utf8');
  for (const rule of [
    'plans/',
    'screenshots/',
    'dsh-better-sidebar-conflict-investigation.md',
    'issue-29-remote-mux-proxy-audit.md',
    'loading-timeline-observation.md',
    'testing-gaps-docker-installer.md',
  ]) {
    assert.ok(ignore.includes(rule), `docs/.npmignore must exclude ${rule}`);
  }
});

test('published READMEs only link relatively to files that ship in the package', () => {
  // docs/.npmignore trims docs/screenshots/, docs/plans/ and the internal
  // investigation notes from the published docs/; .github/ and the source-only
  // build inputs are outside the "files" whitelist. A relative link to any of
  // those breaks for npm consumers, so the READMEs must use absolute GitHub URLs.
  const excluded = [
    '.github/',
    'docs/screenshots/',
    'docs/plans/',
    'docs/dsh-better-sidebar-conflict-investigation.md',
    'docs/issue-29-remote-mux-proxy-audit.md',
    'docs/loading-timeline-observation.md',
    'docs/testing-gaps-docker-installer.md',
    'src/',
    'test/',
    'tsconfig.json',
  ];
  const relativeReferences = (markdown: string): string[] => {
    const refs: string[] = [];
    for (const match of markdown.matchAll(/<img[^>]*\bsrc="([^"]+)"/g)) refs.push(match[1]);
    for (const match of markdown.matchAll(/\]\(([^)\s]+)\)/g)) refs.push(match[1]);
    return refs.filter((ref) => !/^(?:[a-z][a-z0-9+.-]*:|\/|#)/i.test(ref));
  };
  for (const readme of ['README.md', 'README_en.md']) {
    const refs = relativeReferences(readFileSync(path.join(projectRoot, readme), 'utf8'));
    for (const ref of refs) {
      for (const bad of excluded) {
        assert.equal(
          ref.startsWith(bad),
          false,
          `${readme} links ${ref} relatively, but npm excludes ${bad}; use an absolute GitHub URL instead`,
        );
      }
    }
  }
});

test('packaging does not rely on an unverified prepare script', () => {
  const scripts = readPackageJson().scripts ?? {};
  assert.equal(scripts.prepare, undefined, 'do not add a prepare script that runs on consumer installs');
  assert.ok(scripts.prepack, 'prepack must remain the verified pre-publish build');
});

test('the packed dist tree carries no obsolete compiled outputs', () => {
  const distDir = path.join(projectRoot, 'dist');
  // 统一门禁先 `npm run build` 再 `node --import tsx --test "test/**/*.test.ts"`；
  // dist 缺失说明没有先构建，这里必须显式失败而不是静默通过，否则打包回归会被漏掉。
  assert.equal(
    existsSync(distDir),
    true,
    'dist/ 不存在：请先运行 `npm run build`（统一门禁：`npm run build && node --import tsx --test "test/**/*.test.ts"`）',
  );
  assert.deepEqual(
    obsoleteCompiledOutputs(distDir, path.join(projectRoot, 'src')),
    [],
    'run `node scripts/clean-dist.mjs` and rebuild; stale dist outputs would be packed',
  );
});
