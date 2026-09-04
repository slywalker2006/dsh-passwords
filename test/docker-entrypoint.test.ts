import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '..');
const bundledEntrypoint = path.join(projectRoot, 'docker', 'docker-entrypoint.bundled.sh');
const bundledDockerfile = path.join(projectRoot, 'docker', 'Dockerfile.bundled');

test('bundled entrypoint leaves gateway startup to the authenticated DSH plugin lifecycle', () => {
  const script = readFileSync(bundledEntrypoint, 'utf8');
  assert.match(script, /node \/opt\/dsh-passwords\/dist\/cli\.js patch/);
  assert.match(script, /exec dsh web --no-open/);
  assert.doesNotMatch(script, /serve-gateway/);
  assert.doesNotMatch(script, /DSH_UPSTREAM_AUTH_COOKIE/);
});

test('bundled Dockerfile allows rc.1 runtime postinstall dependencies', () => {
  const dockerfile = readFileSync(bundledDockerfile, 'utf8');
  assert.match(dockerfile, /'allowBuilds:'/);
  for (const dependency of ['@deepseek-ai/dsh-subprocess-local', '@google/genai', 'koffi', 'node-pty', 'protobufjs']) {
    const escaped = dependency.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
    assert.match(dockerfile, new RegExp(`(?:"${escaped}"|${escaped}): true`));
  }
});
