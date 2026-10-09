import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const projectRoot = path.resolve(import.meta.dirname, '..');
const bundledEntrypoint = path.join(projectRoot, 'docker', 'docker-entrypoint.bundled.sh');
const bundledDockerfile = path.join(projectRoot, 'docker', 'Dockerfile.bundled');
const plainDockerfile = path.join(projectRoot, 'docker', 'Dockerfile');
const composeFile = path.join(projectRoot, 'docker', 'docker-compose.yml');
const dockerEnvExample = path.join(projectRoot, 'docker', '.env.example');

test('bundled entrypoint leaves gateway startup to the authenticated DSH plugin lifecycle', () => {
  const script = readFileSync(bundledEntrypoint, 'utf8');
  assert.match(script, /node \/opt\/dsh-passwords\/dist\/cli\.js patch/);
  assert.match(script, /exec dsh web --no-open/);
  assert.doesNotMatch(script, /serve-gateway/);
  assert.doesNotMatch(script, /DSH_UPSTREAM_AUTH_COOKIE/);
});

test('bundled Dockerfile allows DSH runtime postinstall dependencies', () => {
  const dockerfile = readFileSync(bundledDockerfile, 'utf8');
  assert.match(dockerfile, /'allowBuilds:'/);
  for (const dependency of ['@deepseek-ai/dsh-subprocess-local', '@google/genai', 'koffi', 'node-pty', 'protobufjs']) {
    const escaped = dependency.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(dockerfile, new RegExp(`(?:"${escaped}"|${escaped}): true`));
  }
});

test('Dockerfiles expose a /gateway/readyz HEALTHCHECK so container health reflects readiness', () => {
  for (const file of [bundledDockerfile, plainDockerfile]) {
    const dockerfile = readFileSync(file, 'utf8');
    const name = path.basename(file);
    assert.match(dockerfile, /^HEALTHCHECK\b/m, `${name} must declare a HEALTHCHECK`);
    assert.match(dockerfile, /\/gateway\/readyz/, `${name} HEALTHCHECK must probe /gateway/readyz`);
  }
});

test('Dockerfiles assert the dsh-passwords build version; bundled keeps the DSH pin guard', () => {
  for (const file of [bundledDockerfile, plainDockerfile]) {
    const dockerfile = readFileSync(file, 'utf8');
    const name = path.basename(file);
    assert.match(dockerfile, /dsh-passwords version mismatch/, `${name} must fail the build on a dsh-passwords version mismatch`);
    assert.match(dockerfile, /dist\/cli\.js/, `${name} must cross-check the built dist/cli.js version`);
  }
  const bundled = readFileSync(bundledDockerfile, 'utf8');
  assert.match(bundled, /bundled DSH mismatch/, 'the bundled DSH version guard must stay');
  assert.match(bundled, /ARG DSH_VERSION=0\.2\.1-alpha\.2/, 'the alpha.2 pin must not change');
});

test('Compose 与 docker/.env.example 透传目录选择器与自更新环境变量', () => {
  const compose = readFileSync(composeFile, 'utf8');
  const envExample = readFileSync(dockerEnvExample, 'utf8');
  const keys = [
    'MCP_GATEWAY_DIRECTORY_PICKER_ROOTS',
    'MCP_DSH_AUTO_UPDATE',
    'MCP_DSH_UPDATE_MAX_BPS',
    'MCP_DSH_DOCKER_SELF_UPDATE',
    'MCP_DSH_DOCKER_COMPOSE_DIR',
    'MCP_DSH_DOCKER_COMPOSE_FILE',
    'MCP_DSH_DOCKER_IMAGE',
    'MCP_DSH_DOCKER_SOCKET',
  ];
  for (const key of keys) {
    assert.match(compose, new RegExp(`${key}: \\$\\{${key}:-\\}`), `${key} 必须在 Compose 显式透传（空值回退默认）`);
    assert.match(envExample, new RegExp(key), `${key} 必须在 docker/.env.example 列出`);
  }
});
