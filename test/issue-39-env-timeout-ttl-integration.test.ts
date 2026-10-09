// Issue #39 的集成缺口：`.env` 里的 timeout/TTL 必须最终改变网关进程的行为，
// 而不是只停留在 deploymentGatewayEnv 的快照里。
//
// 真实链路：dsh 常驻进程启动插件 → plugin.apply() 用 deploymentGatewayEnv() 把部署
// .env 覆盖进网关子进程环境（src/plugin.ts startGateway 的 runtime.spawn env）→ 网关
// 进程内 upstreamResponseHeaderTimeoutMs() / internalProbeTimeoutMs() 读它自己的
// process.env，inventory TTL 由 resolveInventoryTtlMs() 决定。
//
// 这里不启动真实网关，而是把「网关子进程会拿到的环境」原样喂给三个消费点，
// 证明 .env 的值一路到达判定函数，并驱动缓存行为。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deploymentGatewayEnv } from '../src/config.js';
import { internalProbeTimeoutMs } from '../src/gateway.js';
import { upstreamResponseHeaderTimeoutMs } from '../src/proxy.js';
import { createAssignableInventoryLoader, resolveInventoryTtlMs } from '../src/plugin.js';

function writeEnv(dir: string, lines: string[]): string {
  const file = path.join(dir, '.env');
  writeFileSync(file, [...lines, ''].join('\n'));
  return file;
}

/** 模拟 dsh 常驻进程继承给网关子进程的陈旧默认值。 */
function staleInherited(envFile: string): NodeJS.ProcessEnv {
  return {
    DSH_PASSWORDS_ENV_FILE: envFile,
    MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS: '60000',
    MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS: '10000',
    MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '0',
  };
}

test('Issue #39：.env 的 header timeout / 内部探测 timeout / inventory TTL 到达网关消费点', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-issue39-env-'));
  try {
    const file = writeEnv(dir, [
      'SETUP_KEY=file-key',
      'MCP_GATEWAY_AUTO_TLS=0',
      'MCP_GATEWAY_UPSTREAM_HEADER_TIMEOUT_MS=180000',
      'MCP_GATEWAY_INTERNAL_PROBE_TIMEOUT_MS=120000',
      'MCP_DSH_PASSWORDS_INVENTORY_TTL_MS=60000',
    ]);
    const gatewayEnv = deploymentGatewayEnv(file, staleInherited(file));

    assert.equal(upstreamResponseHeaderTimeoutMs(gatewayEnv), 180_000, 'display 路由的 504 预算必须来自 .env');
    assert.equal(internalProbeTimeoutMs(gatewayEnv), 120_000, 'internal probe 的 502 预算必须来自 .env');
    assert.equal(resolveInventoryTtlMs(gatewayEnv), 60_000, 'inventory TTL 必须来自 .env');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Issue #39：.env 未设置这些键时网关保持上游默认（不因继承值漂移）', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-issue39-default-'));
  try {
    const file = writeEnv(dir, ['SETUP_KEY=file-key', 'MCP_GATEWAY_AUTO_TLS=0']);
    // 常驻进程没有固化过这些键（真实缺省场景）。
    const gatewayEnv = deploymentGatewayEnv(file, { DSH_PASSWORDS_ENV_FILE: file });

    assert.equal(upstreamResponseHeaderTimeoutMs(gatewayEnv), 60_000);
    assert.equal(internalProbeTimeoutMs(gatewayEnv), 10_000);
    assert.equal(resolveInventoryTtlMs(gatewayEnv), 0, '缺省 TTL=0：不缓存，保持上游逐请求重算');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveInventoryTtlMs 有界：仅 (0, 600000] 内的整数启用缓存', () => {
  assert.equal(resolveInventoryTtlMs({}), 0);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '' }), 0);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '0' }), 0);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '-1' }), 0);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '1' }), 1);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '600000' }), 600_000);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: '600001' }), 0);
  assert.equal(resolveInventoryTtlMs({ MCP_DSH_PASSWORDS_INVENTORY_TTL_MS: 'invalid' }), 0);
});

type Query = {
  readTitle: (id: string) => Promise<{ title: string }>;
  readSurface: (id: string) => Promise<{ events: Array<{ type: string }> }>;
};

function inventoryFixtures(query: Query) {
  const registry = {
    list: () => [{
      path: '/workspaces/project',
      title: 'Project',
      sessionIds: ['session-a'],
      status: async () => 'ok' as const,
    }],
    archivedSessionIds: [] as readonly string[],
  };
  return { registry, sessions: { get: () => undefined }, query };
}

test('Issue #39：从 .env 解析出的 TTL 真正驱动 loader 的缓存开关', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'dshpw-issue39-loader-'));
  try {
    let reads = 0;
    const query: Query = {
      readTitle: async () => { reads += 1; return { title: 'cached' }; },
      readSurface: async () => ({ events: [{ type: 'user/message' }] }),
    };
    const { registry, sessions } = inventoryFixtures(query);

    // TTL 来自 .env：冷启动后紧接着的第二次读取命中内存缓存。
    const cachedFile = writeEnv(dir, ['SETUP_KEY=file-key', 'MCP_DSH_PASSWORDS_INVENTORY_TTL_MS=60000']);
    const cachedEnv = deploymentGatewayEnv(cachedFile, { DSH_PASSWORDS_ENV_FILE: cachedFile });
    const cachedLoader = createAssignableInventoryLoader(resolveInventoryTtlMs(cachedEnv));
    await cachedLoader(registry, sessions, undefined, query);
    await cachedLoader(registry, sessions, undefined, query);
    assert.equal(reads, 1, 'TTL>0 时第二次读取不应重新枚举');

    // .env 未开启 TTL：每次读取都重算（上游默认行为）。
    let uncachedReads = 0;
    const uncachedQuery: Query = {
      readTitle: async () => { uncachedReads += 1; return { title: 'fresh' }; },
      readSurface: query.readSurface,
    };
    const plainFile = writeEnv(dir, ['SETUP_KEY=file-key']);
    const plainEnv = deploymentGatewayEnv(plainFile, { DSH_PASSWORDS_ENV_FILE: plainFile });
    const uncachedLoader = createAssignableInventoryLoader(resolveInventoryTtlMs(plainEnv));
    await uncachedLoader(registry, sessions, undefined, uncachedQuery);
    await uncachedLoader(registry, sessions, undefined, uncachedQuery);
    assert.equal(uncachedReads, 2, 'TTL=0 时每次读取都重新枚举');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
