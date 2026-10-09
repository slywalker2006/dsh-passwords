import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '..');
const read = (...parts: string[]) => readFileSync(path.join(projectRoot, ...parts), 'utf8');

// The DSH 0.2.1 patch line is the current compatibility target, expressed as the
// declared dev range `>=0.2.1-alpha.1 <0.2.2-0`. The resolved development /
// bundled-Docker pin is `0.2.1-alpha.2`: the npm `alpha` dist-tag and the only DSH tree
// the shrinkwrap resolves. Accepting the later 0.2.1 prereleases and the stable release
// is a declared-range fact, not a machine-verified runtime: no 0.2.1 build has been run
// through full gateway acceptance. Bump these constants together with package.json, the
// lockfile, the installers, and Docker defaults.
const DSH_PIN = '0.2.1-alpha.2';
// The declared dev range is the single patch line `>=0.2.1-alpha.1 <0.2.2-0`: the
// reviewed 0.2.1 prereleases from alpha.1 up (alpha.2, beta, rc) plus the stable 0.2.1
// release. It excludes the retired 0.2.0 line and 0.1.x head, the pre-pin
// `0.2.1-alpha.0`, and every 0.2.2+ identity. node-semver admits the `0.2.1-alpha.1`
// prereleases because the lower comparator carries the same `[0, 2, 1]` tuple with a
// prerelease; a bare `^0.2.1` would admit none.
const DSH_DEV_RANGE = '>=0.2.1-alpha.1 <0.2.2-0';
// Pinned target shipped and validated by the last dsh-passwords release (v2.7.5). It
// survives only as history (CHANGELOG release notes, release/verification prose) and
// must never reappear as a current source pin.
const RELEASED_PIN = '0.1.7-rc.2';
// Exact-match detector for the released pin: the `(?!\d)` guard keeps a future
// alpha.20 / alpha.21 from being misread as alpha.2, and `-{1,2}` also matches the
// shields.io badge double-hyphen spelling.
const RELEASED_PIN_RE = new RegExp(`0\\.1\\.7-{1,2}rc\\.2(?!\\d)`);

type LockEntry = { version?: string; resolved?: string; [key: string]: unknown };
type Lockfile = { name: string; version: string; lockfileVersion: number; packages: Record<string, LockEntry> };
type ParsedVersion = { major: number; minor: number; patch: number; prerelease: string[] };

const lockPackageName = (key: string) => key.split('node_modules/').pop() ?? '';
const isDshPackage = (name: string) => name === '@deepseek-ai/dsh' || name.startsWith('@deepseek-ai/dsh-');

/** SemVer 2.0.0 identity; build metadata is dropped because it never changes precedence. */
function parseSemver(version: string): ParsedVersion {
  const withoutBuild = version.split('+', 1)[0];
  const dash = withoutBuild.indexOf('-');
  const core = dash === -1 ? withoutBuild : withoutBuild.slice(0, dash);
  const prerelease = dash === -1 ? '' : withoutBuild.slice(dash + 1);
  const [major, minor, patch] = core.split('.').map(Number);
  return { major, minor, patch, prerelease: prerelease === '' ? [] : prerelease.split('.') };
}

function comparePrereleaseIdentifiers(a: string, b: string): number {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) return Number(a) - Number(b);
  if (aNumeric) return -1; // numeric identifiers sort before alphanumeric ones
  if (bNumeric) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** SemVer 2.0.0 precedence; a release outranks any of its prereleases. */
function compareSemver(a: string, b: string): number {
  const left = parseSemver(a);
  const right = parseSemver(b);
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (left[key] !== right[key]) return left[key] - right[key];
  }
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;
  const length = Math.max(left.prerelease.length, right.prerelease.length);
  for (let i = 0; i < length; i += 1) {
    const aId = left.prerelease[i];
    const bId = right.prerelease[i];
    if (aId === undefined) return -1; // fewer identifiers ranks lower
    if (bId === undefined) return 1;
    const order = comparePrereleaseIdentifiers(aId, bId);
    if (order !== 0) return order;
  }
  return 0;
}

/**
 * Evaluate the declared DSH dev range, a `||`-separated union of `>=<lower> <upper>`
 * comparator sets. Reproduces node-semver's prerelease-admission rule: a prerelease
 * candidate is admitted only when a comparator in the matched set shares its
 * `[major, minor, patch]` tuple with a prerelease. A plain interval check would wrongly
 * accept `0.2.2-alpha.1` under `>=0.2.1-alpha.1 <0.2.2-0`, which node-semver rejects
 * because the lower comparator carries the 0.2.1 tuple, not 0.2.2.
 */
function satisfiesPinnedRange(version: string, range: string): boolean {
  const candidate = parseSemver(version);
  for (const set of range.split('||').map((part) => part.trim())) {
    const match = /^>=(\S+)\s+<(\S+)$/.exec(set);
    if (match === null) throw new Error(`unexpected DSH dev range shape: ${range}`);
    const lower = match[1];
    const upper = match[2];
    if (compareSemver(version, lower) < 0) continue;
    if (compareSemver(version, upper) >= 0) continue;
    if (candidate.prerelease.length > 0) {
      const admitsPrerelease = [lower, upper].some((bound) => {
        const parsed = parseSemver(bound);
        return (
          parsed.prerelease.length > 0 &&
          parsed.major === candidate.major &&
          parsed.minor === candidate.minor &&
          parsed.patch === candidate.patch
        );
      });
      if (!admitsPrerelease) continue;
    }
    return true;
  }
  return false;
}

test('the released-pin detector matches the previous pin exactly and never a longer number', () => {
  assert.match(`@deepseek-ai/dsh@${RELEASED_PIN}`, RELEASED_PIN_RE);
  assert.match(`"${RELEASED_PIN}"`, RELEASED_PIN_RE);
  assert.match(`^${RELEASED_PIN}`, RELEASED_PIN_RE);
  assert.doesNotMatch('0.1.7-alpha.20', RELEASED_PIN_RE);
  assert.doesNotMatch('0.1.7-alpha.21', RELEASED_PIN_RE);
  assert.doesNotMatch('0.1.7-alpha.200', RELEASED_PIN_RE);
  assert.doesNotMatch(DSH_PIN, RELEASED_PIN_RE, 'the current pin must not be mistaken for the released pin');
  assert.match('DSH-0.1.7--rc.2', RELEASED_PIN_RE, 'the shields.io double-hyphen spelling must also be detected');
});

test('the declared dev range is the 0.2.1 patch line and rejects 0.1.x, 0.2.0, 0.2.1-alpha.0, and 0.2.2+', () => {
  // Accepted: the resolved 0.2.1-alpha.2 pin, later 0.2.1 prereleases, stable 0.2.1, and
  // build metadata. Cross-checked against node_modules/semver@7.8.5, which agrees on
  // every identity below.
  for (const version of ['0.2.1-alpha.1', '0.2.1-alpha.2', '0.2.1-alpha.20', '0.2.1-beta.1', '0.2.1-rc.1', '0.2.1-rc.10', '0.2.1', '0.2.1+build.7', '0.2.1-alpha.1+build.3', '0.2.1-alpha.3.1']) {
    assert.ok(satisfiesPinnedRange(version, DSH_DEV_RANGE), `${version} must satisfy ${DSH_DEV_RANGE}`);
  }
  // Rejected: the retired 0.1.x head and 0.2.0 line (stable and prerelease), the pre-pin
  // `0.2.1-alpha.0` and bare `0.2.1-alpha` (both below the floor), numeric-only 0.2.1
  // prereleases (they sort below alphanumeric identifiers), later 0.2.x patches including
  // their prereleases, and the next minor.
  for (const version of ['0.1.7', '0.1.7-rc.2', '0.2.0', '0.2.0-rc.2', '0.2.0-alpha.1', '0.2.1-alpha', '0.2.1-alpha.0', '0.2.1-0', '0.2.1-1', '0.2.2', '0.2.2-alpha.1', '0.3.0']) {
    assert.ok(!satisfiesPinnedRange(version, DSH_DEV_RANGE), `${version} must not satisfy ${DSH_DEV_RANGE}`);
  }
  // The resolved pin must always sit inside the range that declares it.
  assert.ok(satisfiesPinnedRange(DSH_PIN, DSH_DEV_RANGE), `${DSH_PIN} must satisfy ${DSH_DEV_RANGE}`);
});

test('package.json and npm-shrinkwrap use the released 2.7.8 package version', () => {
  const pkg = JSON.parse(read('package.json')) as { version: string };
  const lock = JSON.parse(read('npm-shrinkwrap.json')) as Lockfile;
  assert.equal(pkg.version, '2.7.8');
  assert.equal(lock.version, '2.7.8');
  assert.equal(lock.packages['']?.version, '2.7.8');
});

test('package.json declares every @deepseek-ai/dsh* dev dependency with the pinned dev range', () => {
  const pkg = JSON.parse(read('package.json')) as { devDependencies: Record<string, string> };
  const dshPackages = Object.entries(pkg.devDependencies).filter(([name]) => isDshPackage(name));
  assert.ok(dshPackages.length >= 9, `expected the @deepseek-ai/dsh* dev dependency set, found ${dshPackages.length}`);
  for (const [name, spec] of dshPackages) {
    assert.equal(spec, DSH_DEV_RANGE, `${name} must be exactly ${DSH_DEV_RANGE}`);
  }
});

test('npm-shrinkwrap.json root mirrors the package.json dependency graph', () => {
  const pkg = JSON.parse(read('package.json')) as {
    version: string;
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
    engines: Record<string, string>;
    overrides?: Record<string, unknown>;
  };
  const lock = JSON.parse(read('npm-shrinkwrap.json')) as Lockfile;
  const root = lock.packages[''];
  assert.ok(root !== undefined, 'npm v3 lockfiles must carry the root "" package entry');
  assert.equal(root.version, pkg.version, 'lock root version must match package.json');
  assert.deepEqual(root.dependencies, pkg.dependencies, 'lock root dependencies must match package.json');
  assert.deepEqual(root.devDependencies, pkg.devDependencies, 'lock root devDependencies must match package.json');
  assert.deepEqual(root.engines, pkg.engines, 'lock root engines must match package.json');

  // npm does not persist `overrides` in the lock root, so consistency is enforced
  // where it matters: every locked copy of an overridden package must satisfy the
  // range. A stale lockfile after an override bump fails here.
  const satisfiesOverride = (version: string, range: string): boolean => {
    const caret = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range.trim());
    if (caret === null) return version === range.trim();
    const [major, minor, patch] = version.split('-')[0].split('.').map(Number);
    const [wantMajor, wantMinor, wantPatch] = caret.slice(1).map(Number);
    return major === wantMajor && (minor > wantMinor || (minor === wantMinor && patch >= wantPatch));
  };
  for (const [name, range] of Object.entries(pkg.overrides ?? {})) {
    if (typeof range !== 'string') continue; // 条件/嵌套覆盖当前未使用；出现时应显式扩展本测试
    const locked = Object.entries(lock.packages).filter(([key]) => lockPackageName(key) === name);
    assert.ok(locked.length > 0, `override target ${name} must exist in the lock`);
    for (const [key, entry] of locked) {
      assert.ok(
        typeof entry.version === 'string' && satisfiesOverride(entry.version, range),
        `${key}@${String(entry.version)} must satisfy override ${range}`,
      );
    }
  }
});

test('npm-shrinkwrap.json locks the whole @deepseek-ai/dsh* tree to the resolved pinned target on the official registry', () => {
  const raw = read('npm-shrinkwrap.json');
  const lock = JSON.parse(raw) as Lockfile;
  assert.equal(lock.lockfileVersion, 3);

  const entries = Object.entries(lock.packages);
  const dshEntries = entries.filter(([key]) => isDshPackage(lockPackageName(key)));
  // Keep a conservative lower bound so a truncated or regenerated lockfile cannot silently
  // lose a substantial part of the DSH closure without tying the test to a stale count.
  assert.ok(dshEntries.length >= 250, `expected a populated @deepseek-ai/dsh* lock tree, found ${dshEntries.length}`);
  for (const [key, entry] of dshEntries) {
    assert.equal(entry.version, DSH_PIN, `${key} must lock ${DSH_PIN}`);
  }

  for (const [key, entry] of entries) {
    if (entry.resolved === undefined) continue;
    assert.ok(
      entry.resolved.startsWith('https://registry.npmjs.org/'),
      `${key} must resolve from the official registry, got ${entry.resolved}`,
    );
  }

  // Catches both resolved versions and leftover specifier ranges. CHANGELOG.md is
  // intentionally not scanned here: as a published record it keeps the released-pin
  // history, which this lock-tree check must not misread as current source residue.
  assert.doesNotMatch(raw, RELEASED_PIN_RE, 'no previous 0.1.7-rc.2 entry or specifier may remain in the locked tree');
});

test('installers and bundled Docker default to the current pinned target', () => {
  for (const file of ['install.sh', 'install.bat', 'scripts/install.mjs']) {
    const source = read(file);
    assert.match(source, /@deepseek-ai\/dsh@0\.2\.1-alpha\.2/, `${file} must install @deepseek-ai/dsh@${DSH_PIN}`);
    assert.doesNotMatch(source, /@deepseek-ai\/dsh@0\.1\.7-alpha\.2(?!\d)/, `${file} must not prescribe the released alpha.2 install command`);
  }
  assert.match(read('docker', 'Dockerfile.bundled'), /ARG DSH_VERSION=0\.2\.1-alpha\.2/);
  assert.match(read('docker', 'docker-compose.yml'), /DSH_VERSION:-0\.2\.1-alpha\.2/);
  assert.match(read('docker', '.env.example'), /#DSH_VERSION=0\.2\.1-alpha\.2/);
});

test('dsh-passwords bundle pins the official workspace picker to browse on every host platform', () => {
  const patch = read('cordis.yml');
  assert.match(patch, /- id: directory-picker\s+name: '@deepseek-ai\/dsh-host-directory-picker-browse'/);
  assert.match(patch, /- id: directory-picker-client\s+name: '@deepseek-ai\/dsh-client-ui-directory-picker-browse'/);
  assert.doesNotMatch(patch, /dsh-host-directory-picker-auto|dsh-host-directory-picker-native|dsh-client-ui-directory-picker-native/);
});

test('the deprecated third-party plugin compat switch is gone from every env template', () => {
  // `src/plugin-compat.ts` was removed; the `MCP_GATEWAY_PLUGIN_COMPAT` switch has no
  // implementation left, so neither the host nor the Docker template may advertise it.
  assert.doesNotMatch(read('.env.example'), /MCP_GATEWAY_PLUGIN_COMPAT/);
  assert.doesNotMatch(read('docker', '.env.example'), /MCP_GATEWAY_PLUGIN_COMPAT/);
});

// CHANGELOG.md is a published historical record: released sections keep the compatibility
// pin they shipped with and must not be rewritten to a later pin. These are history guards,
// not current-source-pin assertions.
test('CHANGELOG.md keeps the released 2.7.6 / 2.7.4 / 2.7.3 compatibility history', () => {
  const changelog = read('CHANGELOG.md');

  assert.match(changelog, /## 2\.7\.6 - 2026-09-29/, 'CHANGELOG.md must carry the released 2.7.6 section');
  const released276Match = /## 2\.7\.6[^\r\n]*\r?\n([\s\S]*?)(?:\r?\n## |$)/.exec(changelog);
  assert.ok(released276Match !== null, 'CHANGELOG.md must carry the 2.7.6 section body');
  assert.match(released276Match[1], /兼容 DSH `0\.2\.0-rc\.1`|Compatible with DSH `0\.2\.0-rc\.1`/, 'the 2.7.6 section must describe the rc.1 compatibility');
  assert.match(released276Match[1], /修复 Issue #33|Fixed Issue #33/);
  assert.match(released276Match[1], /普通插件|ordinary plugins/i);
  assert.match(released276Match[1], /649\/649/);

  const released274Match = /## 2\.7\.4[^\r\n]*\r?\n([\s\S]*?)(?:\r?\n## |$)/.exec(changelog);
  assert.ok(released274Match !== null, 'CHANGELOG.md must carry the 2.7.4 release section');
  assert.match(released274Match[1], /DSH `0\.1\.7-alpha\.2`/, 'CHANGELOG.md 2.7.4 must keep its released alpha.2 pin');
  assert.match(released274Match[1], /测试服务器 2\.7\.4 \/ DSH 0\.1\.7-alpha\.2 health\/ready 与 patch status 正常/);
  assert.match(released274Match[1], /MEDIA_QUOTA/);
  assert.match(released274Match[1], /Destructive purge was not run/);
  assert.doesNotMatch(released274Match[1], /审查模型|Review model:/);
  assert.doesNotMatch(released274Match[1], /0\.1\.6-alpha\.2(?!\d)/, 'the 2.7.4 section must not prescribe the previous DSH line');

  const released273Match = /## 2\.7\.3[^\r\n]*\r?\n([\s\S]*?)(?:\r?\n## |$)/.exec(changelog);
  assert.ok(released273Match !== null, 'CHANGELOG.md must keep the released 2.7.3 section');
  assert.match(released273Match[1], /0\.1\.6-alpha\.2/, 'the released 2.7.3 section must keep its historical alpha.2 pin');
});

// The 2.7.7 section is a released historical record: it keeps the 0.2.1-alpha.1 pin it
// shipped with (2.7.7 predates the alpha.2 bump) plus the Issue #35 and hardening fixes,
// and it declares the same single 0.2.1 patch line that package.json still keeps.
test('CHANGELOG.md 2.7.7 records the Issue #35 and hardening fixes', () => {
  const changelog = read('CHANGELOG.md');
  const released277Match = /## 2\.7\.7[^\r\n]*\r?\n([\s\S]*?)(?:\r?\n## |$)/.exec(changelog);
  assert.ok(released277Match !== null, 'CHANGELOG.md must carry the 2.7.7 release section');
  const section = released277Match[1];
  assert.match(section, /Issue #35/, 'the 2.7.7 section must record the Issue #35 fix');
  assert.match(section, /favicon/, 'the 2.7.7 section must describe the favicon/CSRF fix');
  assert.match(section, /csrfMatches/, 'the 2.7.7 section must record the P0 CSRF signature hardening');
  assert.match(section, /clean-dist/, 'the 2.7.7 section must record the dist packaging cleanup');
  assert.match(section, /subtree|workspace ownership/i, 'the 2.7.7 section must record cross-workspace authorization hardening');
  assert.match(section, /SSE|Unicode/i, 'the 2.7.7 section must record SSE filtering hardening');
  assert.match(section, /Remote mux|backpressure/i, 'the 2.7.7 section must record bounded mux buffering');
  assert.match(section, /plugin disposal|lifecycle/i, 'the 2.7.7 section must record plugin lifecycle fixes');
  assert.match(section, /0\.2\.1-alpha\.1/, 'the 2.7.7 section must keep the 0.2.1-alpha.1 pin it shipped with');
  assert.ok(section.includes(DSH_DEV_RANGE), `the 2.7.7 section must state the declared range ${DSH_DEV_RANGE}`);
  assert.doesNotMatch(section, /0\.2\.0-rc\.[0-9]/, 'the 2.7.7 section must not present a retired 0.2.0 rc as current');
});

// Public prose docs (README/README_en/CONTRIBUTING/docs) track the same single patch-line
// contract as package.json: the pin is `0.2.1-alpha.2`, the declared range is DSH_DEV_RANGE,
// and the retired 0.2.0 / 0.1.x baselines must no longer be presented as current.
// CHANGELOG.md keeps its released history, so it is checked separately above.
test('public docs describe the current 0.2.1-alpha.2 patch line, not the retired rc.2 baseline', () => {
  const docs = ['README.md', 'README_en.md', 'CONTRIBUTING.md', 'docs/compatibility-matrix.md'];
  for (const file of docs) {
    const source = read(...file.split('/'));
    assert.ok(source.includes(DSH_PIN), `${file} must carry the current ${DSH_PIN} pin`);
    assert.ok(source.includes(DSH_DEV_RANGE), `${file} must state the declared range ${DSH_DEV_RANGE}`);
    assert.doesNotMatch(source, /0\.2\.0-rc\.[0-9]/, `${file} must not present a retired 0.2.0 rc as current`);
    assert.doesNotMatch(source, /0\.1\.7/, `${file} must not present the retired 0.1.7 line as supported`);
    assert.doesNotMatch(source, /2\.7\.8-pre/, `${file} must not advertise the retired prerelease spelling`);
  }
});
