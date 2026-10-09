import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { Component, createElement, type ComponentProps, type ReactNode } from 'react';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import { DshPasswordsCard, readModelCatalogResponse, type UpdateInfo } from '../src/client/card.tsx';

type CardProps = { t: (key: string, params?: Record<string, unknown>) => string };

class CardBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    return this.state.failed ? 'card-crashed' : this.props.children;
  }
}

const updateStatus: UpdateInfo = {
  env: 'npm-prefix', currentVersion: '2.6.4', latestVersion: null,
  updateAvailable: false, phase: 'idle', downloadPercent: null,
  downloadMode: null, downloadedBytes: 0, totalBytes: null,
  pendingVersion: null, installConfirmationRequired: false,
  lastNotificationAt: null, idleRemainingMs: null, autoUpdateEnabled: false,
  autoInstallSupported: true, checking: false, manualCommand: '',
  lastCheckedAt: null, lastError: null, applyCooldownRemainingMs: 0,
};

function loginResponse() {
  const response = new Response('<!doctype html><title>Login</title>', {
    headers: { 'content-type': 'text/html' },
  });
  Object.defineProperties(response, {
    redirected: { value: true },
    url: { value: 'https://example.test/gateway/login' },
  });
  return response;
}

async function mountCard(t: TestContext, overrides: Record<string, () => Response | Promise<Response>> = {}, payloadOverrides: Record<string, unknown> = {}) {
  const intervals = new Map<number, { callback: () => void; delay: number }>();
  let nextTimer = 0;
  let renderer: ReactTestRenderer | undefined;
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      setInterval(callback: () => void, delay: number) {
        intervals.set(++nextTimer, { callback, delay });
        return nextTimer;
      },
      clearInterval(id: number) { intervals.delete(id); },
      setTimeout,
    },
  });
  t.after(async () => {
    try {
      await act(async () => { renderer?.unmount(); });
    } finally {
      if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow);
      else Reflect.deleteProperty(globalThis, 'window');
    }
    assert.equal(intervals.size, 0);
  });
  t.mock.method(console, 'error', () => {});
  const me = { id: 1, username: 'test-admin', role: 'admin' };
  const payloads: Record<string, unknown> = {
    '/api/dsh-passwords/state': { me, users: [] },
    '/gateway/api/overview': { me, users: [], },
    '/api/session/modelCatalog': {
      type: 'server-response', rpcId: 'rpc-model-catalog', result: {
        ok: true, value: {
          default: { provider: 'openai', model: 'gpt-5' },
          routableProviders: ['openai'],
          groups: [{ id: 'openai', name: 'OpenAI', models: [{ id: 'gpt-5', name: 'GPT-5' }] }],
          failures: [],
        },
      },
    },
    '/api/dsh-passwords/workspaces': { workspaces: [] },
    '/api/dsh-passwords/patch/status': {
      status: { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'patched' },
    },
    '/api/dsh-passwords/update/status': { status: updateStatus },
    '/api/dsh-passwords/agent-presets': { presets: [] },
    ...payloadOverrides,
  };
  const requests: Array<{ input: string; init?: RequestInit }> = [];
  t.mock.method(globalThis, 'fetch', async (input: string, init?: RequestInit) => {
    requests.push({ input, init });
    if (overrides[input]) return overrides[input]();
    assert.ok(input in payloads, `Unexpected request: ${input}`);
    // payload 可以是函数，让 mock 能反映保存后的服务端新状态（静态对象无法表达）；
    // 工厂可直接返回 Response（走 overrides 同一路径），否则按 JSON 序列化。
    const payload = typeof payloads[input] === 'function'
      ? (payloads[input] as () => unknown)()
      : payloads[input];
    return payload instanceof Response ? payload : Response.json(payload);
  });
  const translate: CardProps['t'] = (key) => key === 'err.NOT_AUTHENTICATED'
    ? 'Session expired' : key;
  await act(async () => {
    renderer = create(createElement(CardBoundary, {
      children: createElement(DshPasswordsCard, { t: translate } satisfies CardProps),
    }));
  });
  return {
    renderer: renderer!,
    text: () => JSON.stringify(renderer!.toJSON()),
    requests,
    async refresh() {
      const timer = [...intervals.values()].find(({ delay }) => delay === 30_000);
      assert.ok(timer, 'Card must retain its refresh timer');
      await act(async () => { timer.callback(); });
    },
  };
}

test('modelCatalog response parser accepts the alpha.2 client-request response envelope', () => {
  const catalog = readModelCatalogResponse({
    type: 'server-response',
    rpcId: 'rpc-model-catalog',
    result: {
      ok: true,
      value: {
        default: { provider: 'openai', model: 'gpt-5' },
        routableProviders: ['openai'],
        groups: [{ id: 'openai', name: 'OpenAI', models: [{ id: 'gpt-5', name: 'GPT-5' }] }],
        failures: [],
      },
    },
  });
  assert.equal(catalog.status, 'ready');
  assert.deepEqual(catalog.entries.map((entry) => entry.id), ['openai/gpt-5']);
});

test('settings card renders account and patch controls for a healthy response', async (t) => {
  const card = await mountCard(t);
  assert.match(card.text(), /test-admin/);
  assert.match(card.text(), /patchOk/);
  assert.doesNotMatch(card.text(), /card-crashed/);
});

test('settings card offers the SSH/terminal toggle, reflects the saved value, and omits it when untouched', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      users: [{
        id: 2,
        username: 'subuser',
        role: 'user',
        permissions: {
          allowedFolders: [],
          hourlyTokenLimit: null,
          dailyMinutesLimit: null,
          allowUpload: false,
          allowGitDownload: false,
          allowWorkspaceCreate: false,
          allowSsh: false,
          allowedAgentPresets: [],
          banned: false,
          sandboxMode: null,
          disabledSessions: [],
          allowedSessionIds: [],
        },
        usage: null,
      }],
    },
  });
  const sshLabel = card.renderer.root.findAllByType('label').find((label) => label.children.includes('permsSsh'));
  assert.ok(sshLabel, 'SSH 和终端使用开关必须可见');
  const sshInputs = card.renderer.root.findAllByProps({ 'aria-label': 'permsSsh' });
  assert.equal(sshInputs.length, 1, 'SSH 开关必须唯一');
  assert.equal(sshInputs[0].props.checked, false, '未授权时 SSH 开关必须默认 false');

  // 未触碰开关直接保存：不得提交 allowSsh（仅 touched 时提交）。
  await savePermissions(card);
  const [untouched] = permissionBodies(card);
  assert.ok(untouched);
  assert.equal('allowSsh' in untouched, false);
  assert.equal('expectedDisabledSessions' in untouched, false, '未修改会话时不得提交禁用会话 CAS 基线');

  // 触碰开关并保存：必须提交 allowSsh=true。
  await act(async () => { sshInputs[0].props.onChange({ target: { checked: true } }); });
  await savePermissions(card);
  const bodies = permissionBodies(card);
  const toggled = bodies[bodies.length - 1];
  assert.ok(toggled);
  assert.equal(toggled.allowSsh, true, '触碰后保存必须提交 allowSsh=true');
});

test('settings card synchronizes an explicitly changed session permission with its CAS baseline', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true, allowedSessionIds: [], disabledSessions: ['session-visible'] }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      users: [{
        id: 2, username: 'subuser', role: 'user',
        permissions: {
          allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null,
          allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false, allowSsh: false,
          allowedAgentPresets: [], banned: false, sandboxMode: null,
          disabledSessions: ['session-visible'], allowedSessionIds: ['session-visible'],
        }, usage: null,
      }],
    },
    '/api/dsh-passwords/workspaces': {
      workspaces: [{
        path: '/work/visible',
        title: 'Visible workspace',
        sessions: [{ id: 'session-visible', title: 'Visible session' }],
      }],
    },
  });
  const sessionLabel = card.renderer.root.findAllByProps({ className: 'dshpw-session-check' })
    .find((label) => label.findAllByType('input').length === 1);
  assert.ok(sessionLabel, '会话授权开关必须可见');
  await act(async () => { sessionLabel!.findByType('input').props.onChange({ target: { checked: false } }); });
  const saveButton = card.renderer.root.findAllByType('button').find((button) => button.children.some((child) => child === 'permsSave'));
  assert.ok(saveButton);
  await act(async () => { saveButton!.props.onClick(); });
  const permissionRequest = card.requests.find((request) => request.input === '/gateway/api/permissions');
  assert.ok(permissionRequest);
  const permissionBody = JSON.parse(String(permissionRequest!.init?.body)) as Record<string, unknown>;
  assert.deepEqual(permissionBody.expectedDisabledSessions, ['session-visible']);
  assert.deepEqual(permissionBody.allowedSessionIds, []);
});

test('settings card synchronizes the large request body permission to the visible checkbox and save API', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      users: [{
        id: 2,
        username: 'subuser',
        role: 'user',
        permissions: {
          allowedFolders: [],
          hourlyTokenLimit: null,
          dailyMinutesLimit: null,
          allowUpload: false,
          allowGitDownload: false,
          allowWorkspaceCreate: false,
          allowSsh: false,
          allowedAgentPresets: [],
          banned: false,
          sandboxMode: null,
          disabledSessions: [],
          allowedSessionIds: [],
        },
        usage: null,
      }],
    },
  });
  const uploadLabel = card.renderer.root.findAllByType('label').find((label) => label.children.some((child) => child === 'permsUpload'));
  assert.ok(uploadLabel, '大请求体权限开关必须出现在子用户权限卡片');
  const checkbox = uploadLabel!.findByType('input');
  assert.equal(checkbox.props.checked, false, '前端必须反映后端 allowUpload=false（64 MiB 档位）');
  await act(async () => { checkbox.props.onChange({ target: { checked: true } }); });
  const saveButton = card.renderer.root.findAllByType('button').find((button) => button.children.some((child) => child === 'permsSave'));
  assert.ok(saveButton, '子用户权限卡片必须存在保存按钮');
  await act(async () => { saveButton!.props.onClick(); });
  const permissionRequest = card.requests.find((request) => request.input === '/gateway/api/permissions');
  assert.ok(permissionRequest, '保存必须调用权限 API');
  assert.equal(JSON.parse(String(permissionRequest!.init?.body)).allowUpload, true, '保存必须提交 allowUpload');
});

test('settings card shows Agent preset registry failure instead of hiding the permission section', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/agent-presets': () => new Response(JSON.stringify({ ok: false, code: 'PRESETS_UNAVAILABLE' }), { status: 502, headers: { 'content-type': 'application/json' } }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      users: [{ id: 2, username: 'subuser', role: 'user', permissions: { allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null, allowUpload: true, allowGitDownload: false, allowWorkspaceCreate: false, allowedAgentPresets: [], banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [] }, usage: null }],
    },
  });
  assert.match(card.text(), /permsAgentPresetsUnavailable/);
});

test('settings card exposes independent workspace loading state', async (t) => {
  let release!: (response: Response) => void;
  const gate = new Promise<Response>((resolve) => { release = resolve; });
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': () => gate,
  }, {
    '/gateway/api/overview': { me: { id: 1, username: 'test-admin', role: 'admin' }, users: [{ id: 2, username: 'sub', role: 'user', permissions: { allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null, allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false, allowSsh: false, allowedAgentPresets: null, banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [] }, usage: null }] },
  });
  assert.match(card.text(), /permsWorkspacesLoading/);
  release(Response.json({ workspaces: [] }));
});

test('settings card preserves workspace error state instead of showing an empty inventory', async (t) => {
  const card = await mountCard(t, {
    '/api/dsh-passwords/workspaces': () => Response.json({ ok: false, code: 'WORKSPACES_UNAVAILABLE', error: 'down' }, { status: 502 }),
  }, {
    '/gateway/api/overview': { me: { id: 1, username: 'test-admin', role: 'admin' }, users: [{ id: 2, username: 'sub', role: 'user', permissions: { allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null, allowUpload: false, allowGitDownload: false, allowWorkspaceCreate: false, allowSsh: false, allowedAgentPresets: null, banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [] }, usage: null }] },
  });
  assert.match(card.text(), /permsWorkspacesUnavailable|down/);
});

test('settings card stays mounted when login expires during refresh', async (t) => {
  const responses: Record<string, () => Response> = {};
  const card = await mountCard(t, responses);
  responses['/api/dsh-passwords/state'] = loginResponse;
  responses['/api/dsh-passwords/patch/status'] = loginResponse;
  responses['/api/dsh-passwords/update/status'] = loginResponse;
  await card.refresh();
  assert.doesNotMatch(card.text(), /card-crashed/);
  assert.match(card.text(), /Session expired/);
  assert.match(card.text(), /patchUnknown/);
  assert.match(card.text(), /test-admin/);
});

for (const [label, payload] of [
  ['missing', {}],
  ['null', { status: null }],
  ['malformed', { status: { settingsHostMode: 'true', workspaceSearch: true, bindAll: true, connectionCookieBridge: 'patched' } }],
] as const) {
  test(`settings card shows unknown for ${label} patch status`, async (t) => {
    const card = await mountCard(t, {
      '/api/dsh-passwords/patch/status': () => Response.json(payload),
    });
    assert.doesNotMatch(card.text(), /card-crashed/);
    assert.match(card.text(), /patchUnknown/);
    assert.match(card.text(), /test-admin/);
  });
}

type MountedCard = Awaited<ReturnType<typeof mountCard>>;

/** 一个含单个会话的工作区：allowedFolders=[] 时默认全部工作区开启，会话开关可见。 */
const permissionWorkspaces = {
  workspaces: [{
    path: '/work/alpha',
    title: 'Alpha',
    sessions: [{ id: 'sess-1', title: 'Session 1' }],
  }],
};

function subuserOverview(allowedSessionIds: string[], allowedFolders: string[] = []) {
  return {
    me: { id: 1, username: 'test-admin', role: 'admin' },
    users: [{
      id: 2,
      username: 'subuser',
      role: 'user',
      permissions: {
        allowedFolders,
        hourlyTokenLimit: null,
        dailyMinutesLimit: null,
        allowUpload: false,
        allowGitDownload: false,
        allowWorkspaceCreate: false,
        allowSsh: false,
        allowedAgentPresets: [],
        banned: false,
        sandboxMode: null,
        disabledSessions: [],
        allowedSessionIds,
      },
      usage: null,
    }],
  };
}

const DIRECTORY_LIST = '/gateway/api/directory-picker/list';

function dirEntry(path: string, selectable = true, name?: string) {
  return {
    name: name ?? path.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? path,
    path,
    selectable,
  };
}

/** 真实后端统一响应体：{ ok, currentPath, parentPath, selectable, entries, truncated }。 */
function directoryListing(currentPath: string | null, options: {
  parentPath?: string | null;
  selectable?: boolean;
  entries?: Array<Record<string, unknown>>;
  truncated?: boolean;
} = {}) {
  return {
    ok: true,
    currentPath,
    parentPath: options.parentPath ?? null,
    selectable: options.selectable ?? false,
    entries: options.entries ?? [],
    truncated: options.truncated ?? false,
  };
}

/** 带 path query 的目录列表 URL（同时校验 URL 编码）。 */
function directoryUrl(path: string): string {
  return `${DIRECTORY_LIST}?path=${encodeURIComponent(path)}`;
}

function classTokens(className: unknown): string[] {
  return typeof className === 'string' ? className.split(/\s+/).filter((token) => token !== '') : [];
}

function byClass(card: MountedCard, className: string) {
  return card.renderer.root.findAll((node) => classTokens(node.props.className).includes(className));
}

type TestInstance = ReturnType<typeof byClass>[number];

/** 在某个子树（如目录行）内按 class 找节点。 */
function scopedByClass(instance: TestInstance, className: string): TestInstance[] {
  return instance.findAll((node) => classTokens(node.props.className).includes(className));
}

function oneByClass(card: MountedCard, className: string) {
  const nodes = byClass(card, className);
  assert.equal(nodes.length, 1, `必须唯一渲染 ${className}`);
  return nodes[0];
}

function pickerRow(card: MountedCard, name: string) {
  return byClass(card, 'dshpw-dir-picker-row')
    .find((row) => row.findAll((node) => classTokens(node.props.className).includes('dshpw-dir-picker-name'))
      .some((span) => span.children.join('') === name));
}

function chipPaths(card: MountedCard): string[] {
  return card.renderer.root.findAll((node) => classTokens(node.props.className).includes('dshpw-read-path'))
    .map((span) => span.children.join(''));
}

function chipFor(card: MountedCard, path: string) {
  return byClass(card, 'dshpw-read-chip')
    .find((chip) => chip.findAll((node) => classTokens(node.props.className).includes('dshpw-read-path'))
      .some((span) => span.children.join('') === path));
}

async function toggleWorkspaceCreate(card: MountedCard) {
  const label = card.renderer.root.findAllByProps({ className: 'dshpw-check' })
    .find((node) => node.findAllByType('input').length === 1
      && node.children.some((child) => child === 'permsWorkspaceCreate'));
  assert.ok(label, '可创建工作区开关必须渲染');
  const input = label!.findByType('input');
  const next = !input.props.checked;
  await act(async () => { input.props.onChange({ target: { checked: next } }); });
  return next;
}

function saveButton(card: MountedCard) {
  return card.renderer.root.findAllByType('button')
    .find((button) => button.children.some((child) => child === 'permsSave'));
}

function sessionCheckbox(card: MountedCard) {
  const label = card.renderer.root
    .findAllByProps({ className: 'dshpw-session-check' })
    .find((node) => node.findAllByType('input').length === 1);
  assert.ok(label, '已启用工作区必须渲染会话授权开关');
  return label!.findByType('input');
}

function permissionBodies(card: MountedCard): Array<Record<string, unknown>> {
  return card.requests
    .filter((request) => request.input === '/gateway/api/permissions')
    .map((request) => JSON.parse(String(request.init?.body)) as Record<string, unknown>);
}

async function savePermissions(card: MountedCard) {
  const save = saveButton(card);
  assert.ok(save, '子用户权限卡片必须存在保存按钮');
  await act(async () => { save!.props.onClick(); });
}

test('saving a workspace-only change omits allowedSessionIds so server grants survive', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const workspaceSwitch = card.renderer.root
    .findAllByProps({ className: 'dshpw-switch dshpw-workspace-switch' })
    .find((node) => node.findAllByType('input').length === 1);
  assert.ok(workspaceSwitch, '工作区开关必须渲染');
  await act(async () => {
    workspaceSwitch!.findByType('input').props.onChange({ target: { checked: false } });
  });
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.ok(body, '保存必须调用权限 API');
  assert.equal('allowedSessionIds' in body!, false, '未编辑会话时不得提交 allowedSessionIds');
  assert.equal('disabledSessions' in body!, false, '未编辑会话时不得覆盖并发更新的禁用集合');
});

test('SSH grant reflects the saved value and saving unrelated permissions preserves session grants', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': {
      ...subuserOverview(['sess-1']),
      users: [{ ...subuserOverview(['sess-1']).users[0], permissions: {
        ...subuserOverview(['sess-1']).users[0].permissions, allowSsh: true,
      } }],
    },
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const sshInputs = card.renderer.root.findAllByProps({ 'aria-label': 'permsSsh' });
  assert.equal(sshInputs.length, 1, 'SSH 和终端使用开关必须可见');
  assert.equal(sshInputs[0].props.checked, true, '必须反映已保存的 allowSsh=true');
  const workspaceSwitch = card.renderer.root.findAllByProps({ className: 'dshpw-switch dshpw-workspace-switch' })
    .find((node) => node.findAllByType('input').length === 1);
  assert.ok(workspaceSwitch);
  await act(async () => { workspaceSwitch.findByType('input').props.onChange({ target: { checked: false } }); });
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.ok(body);
  assert.equal('allowSsh' in body, false, '未触碰 SSH 开关时不得提交 allowSsh');
  assert.equal('allowedSessionIds' in body, false, '未编辑会话时不得提交 allowedSessionIds');
  assert.equal('disabledSessions' in body, false, '未编辑会话时不得覆盖禁用集合');
});

test('saving after toggling a session submits the session allowlist', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const checkbox = sessionCheckbox(card);
  assert.equal(checkbox.props.checked, false);
  await act(async () => {
    checkbox.props.onChange({ target: { checked: true } });
  });
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.ok(body);
  assert.deepEqual(body!.allowedSessionIds, ['sess-1']);
});

for (const [code, notice] of [
  ['SESSION_GRANTS_CONFLICT', 'permsSessionConflict'],
  ['PERMISSIONS_CONFLICT', 'permsStateConflict'],
] as const) {
  test(`${code} rebases the current grant and the next save omits session fields`, async (t) => {
    let saves = 0;
    const card = await mountCard(t, {
      '/gateway/api/permissions': () => {
        saves += 1;
        return saves === 1
          ? Response.json({ ok: false, code, error: 'conflict', allowedSessionIds: ['sess-1'] }, { status: 409 })
          : Response.json({ ok: true, allowedSessionIds: ['sess-1'], disabledSessions: [] });
      },
    }, {
      '/gateway/api/overview': subuserOverview(['sess-1']),
      '/api/dsh-passwords/workspaces': permissionWorkspaces,
    });
    const checkbox = sessionCheckbox(card);
    await act(async () => { checkbox.props.onChange({ target: { checked: false } }); });
    await savePermissions(card);
    assert.match(card.text(), new RegExp(notice));
    assert.equal(sessionCheckbox(card).props.checked, true, '最新服务端 grant 应恢复为已勾选');
    await savePermissions(card);
    const bodies = permissionBodies(card);
    assert.equal('allowedSessionIds' in bodies[1]!, false);
    assert.equal('disabledSessions' in bodies[1]!, false);
  });
}

test('sandbox-revoked session grants are removed from the draft and reported inline', async (t) => {
  let overviewCalls = 0;
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({
      ok: true,
      allowedSessionIds: [],
      disabledSessions: [],
      sandboxRevokedSessionIds: ['sess-1'],
    }),
    '/gateway/api/overview': () => Response.json(subuserOverview(overviewCalls++ === 0 ? ['sess-1'] : [])),
  }, {
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await savePermissions(card);
  await act(async () => { await new Promise((resolve) => setImmediate(resolve)); });
  assert.equal(sessionCheckbox(card).props.checked, false);
  assert.match(card.text(), /permsSandboxRevoked/);
});

test('saving after revoking every session still submits an explicit empty allowlist', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview(['sess-1']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const checkbox = sessionCheckbox(card);
  assert.equal(checkbox.props.checked, true);
  await act(async () => {
    checkbox.props.onChange({ target: { checked: false } });
  });
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.ok(body);
  assert.deepEqual(body!.allowedSessionIds, [], '显式取消全部会话仍须提交 []（fail-closed）');
});

test('the session touch marker resets after a successful save', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const checkbox = sessionCheckbox(card);
  await act(async () => {
    checkbox.props.onChange({ target: { checked: true } });
  });
  await savePermissions(card);

  const workspaceSwitch = card.renderer.root.findAllByProps({ className: 'dshpw-switch dshpw-workspace-switch' })
    .find((node) => node.findAllByType('input').length === 1);
  assert.ok(workspaceSwitch);
  await act(async () => { workspaceSwitch.findByType('input').props.onChange({ target: { checked: false } }); });
  await savePermissions(card);

  const bodies = permissionBodies(card);
  assert.equal(bodies.length, 2, '两次保存都必须调用权限 API');
  assert.deepEqual(bodies[0].allowedSessionIds, ['sess-1']);
  assert.equal('allowedSessionIds' in bodies[1], false, '保存成功后未再编辑会话则不再提交集合');
});

test('refresh during a dirty draft preserves local session edits', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const checkbox = sessionCheckbox(card);
  await act(async () => {
    checkbox.props.onChange({ target: { checked: true } });
  });
  await card.refresh();
  assert.equal(sessionCheckbox(card).props.checked, true, '刷新不得覆盖未保存的会话编辑');
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.ok(body);
  assert.deepEqual(body!.allowedSessionIds, ['sess-1']);
});

test('目录浏览器逐级导航、盘根不可选、去重后保存为 string[]', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/', {
      selectable: false,
      entries: [dirEntry('/srv', true)],
    })),
    [directoryUrl('/srv')]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true,
      entries: [dirEntry('/srv/work', true), dirEntry('/srv/lab', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });

  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  assert.ok(card.requests.some((request) => request.input === DIRECTORY_LIST), '打开面板请求默认起点（不带 path query）');
  assert.equal(oneByClass(card, 'dshpw-dir-picker-select-current').props.disabled, true, 'selectable=false 的目录不可选择');
  assert.ok(pickerRow(card, 'srv'), '必须渲染直接子目录');

  await act(async () => { scopedByClass(pickerRow(card, 'srv')!, 'dshpw-dir-picker-enter')[0].props.onClick(); });
  assert.ok(card.requests.some((request) => request.input === directoryUrl('/srv')), '进入请求的 path 必须 URL 编码');
  assert.equal(oneByClass(card, 'dshpw-dir-picker-select-current').props.disabled, false, 'selectable=true 的目录可选');

  await act(async () => { oneByClass(card, 'dshpw-dir-picker-select-current').props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/srv']);

  const selectWork = () => scopedByClass(pickerRow(card, 'work')!, 'dshpw-dir-picker-select')[0];
  await act(async () => { selectWork().props.onClick(); });
  await act(async () => { selectWork().props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/srv', '/srv/work'], '重复选择必须去重');

  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.deepEqual(body!.allowedFolders, ['/srv', '/srv/work'], '保存提交 string[]');
});

test('Windows 盘符根只可进入不可选择', async (t) => {
  const card = await mountCard(t, {
    [DIRECTORY_LIST]: () => Response.json(directoryListing(null, {
      selectable: false,
      entries: [dirEntry('C:\\', false, 'C:')],
    })),
    [directoryUrl('C:\\')]: () => Response.json(directoryListing('C:\\', {
      parentPath: null, selectable: false,
      entries: [dirEntry('C:\\Users', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  const driveRow = pickerRow(card, 'C:');
  assert.ok(driveRow, '起点必须列出盘符根');
  assert.equal(scopedByClass(driveRow!, 'dshpw-dir-picker-select')[0].props.disabled, true, '盘符根只可进入不可选择');
  assert.equal(scopedByClass(driveRow!, 'dshpw-dir-picker-enter')[0].props.disabled, false);

  await act(async () => { scopedByClass(driveRow!, 'dshpw-dir-picker-enter')[0].props.onClick(); });
  assert.ok(card.requests.some((request) => request.input === directoryUrl('C:\\')), '盘符进入必须 URL 编码');
  assert.equal(oneByClass(card, 'dshpw-dir-picker-select-current').props.disabled, true, '盘符根不可选为当前目录');
  assert.match(card.text(), /C:/, '面包屑显示盘符');

  await act(async () => { scopedByClass(pickerRow(card, 'Users')!, 'dshpw-dir-picker-select')[0].props.onClick(); });
  assert.deepEqual(chipPaths(card), ['C:\\Users']);
});

test('30s 刷新不覆盖未保存的目录选择', async (t) => {
  const card = await mountCard(t, {
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true, entries: [dirEntry('/srv/work', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { scopedByClass(pickerRow(card, 'work')!, 'dshpw-dir-picker-select')[0].props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/srv/work']);
  await card.refresh();
  assert.deepEqual(chipPaths(card), ['/srv/work'], '30s 刷新不得覆盖未保存的目录选择');
});

test('目录面板：按钮 aria-expanded/controls、面板可聚焦并支持 Escape 关闭', async (t) => {
  const card = await mountCard(t, {
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true, entries: [dirEntry('/srv/work', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  const addBefore = oneByClass(card, 'dshpw-read-add');
  assert.equal(addBefore.props['aria-expanded'], false, '未打开时 aria-expanded=false');
  const panelId = addBefore.props['aria-controls'];
  assert.equal(panelId, 'dshpw-dir-picker-2', 'aria-controls 必须指向该子用户的面板');

  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  assert.equal(oneByClass(card, 'dshpw-read-add').props['aria-expanded'], true, '打开后 aria-expanded=true');
  const panel = oneByClass(card, 'dshpw-dir-picker');
  assert.equal(panel.props.id, panelId, '面板 id 必须等于按钮的 aria-controls');
  assert.equal(panel.props.tabIndex, -1, '面板必须可聚焦（tabIndex=-1），打开后不丢焦点');

  await act(async () => { panel.props.onKeyDown({ key: 'Escape' }); });
  assert.equal(byClass(card, 'dshpw-dir-picker').length, 0, 'Escape 必须关闭面板');
  assert.equal(oneByClass(card, 'dshpw-read-add').props['aria-expanded'], false, '关闭后 aria-expanded 复位');

  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  assert.equal(byClass(card, 'dshpw-dir-picker').length, 1, '再次点击添加目录按钮重新打开面板');
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  assert.equal(byClass(card, 'dshpw-dir-picker').length, 0, '再次点击添加目录按钮应收起面板');
});

test('目录请求超时会中止并转错误态，迟到响应不覆盖', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let releaseHang: (() => void) | undefined;
  const hang = new Promise<Response>((resolve) => {
    releaseHang = () => resolve(Response.json(directoryListing('/', { selectable: true, entries: [dirEntry('/late', true)] })));
  });
  const card = await mountCard(t, {
    [DIRECTORY_LIST]: () => hang,
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { t.mock.timers.tick(30_000); });
  assert.match(card.text(), /permsDirTimeout/, '超时必须转错误态');
  const signal = card.requests.find((request) => request.input === DIRECTORY_LIST)?.init?.signal;
  assert.equal(signal?.aborted, true, '超时必须中止在飞请求');
  await act(async () => { releaseHang!(); });
  assert.equal(byClass(card, 'dshpw-dir-picker-list').length, 0, '迟到响应不得覆盖错误态');
});

test('可读取目录：[] 显示“所有目录”，未触碰不提交 allowedFolders', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  assert.match(card.text(), /permsReadUnrestricted/, '[] 必须显示为“所有目录”');
  assert.deepEqual(chipPaths(card), [], '[] 不转换，不渲染具体 chips');
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.equal('allowedFolders' in body!, false, '未触碰 allowedFolders 不得提交');
});

test('可读取目录：添加目录从“所有目录”切到具体 array 并去重保存', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true, allowedFolders: ['/work/alpha', '/srv/read'] }),
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true, entries: [dirEntry('/srv/read', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([]),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { scopedByClass(pickerRow(card, 'read')!, 'dshpw-dir-picker-select')[0].props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/work/alpha', '/srv/read'], '从全部工作区集合切入并去重');
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.deepEqual(body!.allowedFolders, ['/work/alpha', '/srv/read']);
});

test('可读取目录：__deny__ 显示禁止读取，添加后恢复为具体目录', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true, allowedFolders: ['/srv/read'] }),
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true, entries: [dirEntry('/srv/read', true)],
    })),
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  assert.match(card.text(), /permsReadEmpty/, '__deny__ 必须显示为禁止读取');
  assert.deepEqual(chipPaths(card), []);
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { scopedByClass(pickerRow(card, 'read')!, 'dshpw-dir-picker-select')[0].props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/srv/read']);
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.deepEqual(body!.allowedFolders, ['/srv/read']);
});

test('可读取目录：移除最后一个提交 ["__deny__"]', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true, allowedFolders: ['__deny__'] }),
  }, {
    '/gateway/api/overview': subuserOverview([], ['/srv/read']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  assert.deepEqual(chipPaths(card), ['/srv/read']);
  await act(async () => { chipFor(card, '/srv/read')!.findByType('button').props.onClick(); });
  assert.deepEqual(chipPaths(card), []);
  assert.match(card.text(), /permsReadEmpty/);
  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.deepEqual(body!.allowedFolders, ['__deny__'], '移除最后一个必须提交 __deny__');
});

test('可读取目录：关闭面板中止在飞请求，旧响应不覆盖新路径', async (t) => {
  let releaseStale: (() => void) | undefined;
  const staleResponse = new Promise<Response>((resolve) => {
    releaseStale = () => resolve(Response.json(directoryListing('/stale', { selectable: true })));
  });
  let calls = 0;
  const card = await mountCard(t, {
    [DIRECTORY_LIST]: () => {
      calls += 1;
      return calls === 1 ? staleResponse : Response.json(directoryListing('/fresh', { selectable: true }));
    },
  }, {
    '/gateway/api/overview': subuserOverview([], ['__deny__']),
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { oneByClass(card, 'dshpw-dir-picker-close').props.onClick(); });
  const staleSignal = card.requests.find((request) => request.input === DIRECTORY_LIST)?.init?.signal;
  assert.equal(staleSignal?.aborted, true);
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  await act(async () => { releaseStale!(); });
  await act(async () => { oneByClass(card, 'dshpw-dir-picker-select-current').props.onClick(); });
  assert.deepEqual(chipPaths(card), ['/fresh'], '旧响应不得覆盖新路径');
});

test('新建工作区开关与目录选择共用同一 picker：关开不改目录且不提交 workspaceCreationRoots', async (t) => {
  const base = subuserOverview([], ['/srv/read']);
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true, allowedFolders: ['/srv/read'] }),
    [DIRECTORY_LIST]: () => Response.json(directoryListing('/srv', {
      parentPath: '/', selectable: true, entries: [dirEntry('/srv/read', true)],
    })),
  }, {
    '/gateway/api/overview': {
      ...base,
      users: [{ ...base.users[0], permissions: { ...base.users[0].permissions, allowWorkspaceCreate: true } }],
    },
    '/api/dsh-passwords/workspaces': permissionWorkspaces,
  });

  // 单一 picker：只有可读取目录入口，不再有独立创建根 UI。
  assert.equal(byClass(card, 'dshpw-creation-root-add').length, 0, '不得再渲染独立创建根入口');
  assert.equal(byClass(card, 'dshpw-read-add').length, 1, '只有单一目录 picker 入口');
  assert.deepEqual(chipPaths(card), ['/srv/read']);

  // 关闭新建工作区开关：目录选择不变，read picker 仍可用。
  await toggleWorkspaceCreate(card);
  assert.deepEqual(chipPaths(card), ['/srv/read'], '关闭开关不得改动目录选择');
  await act(async () => { oneByClass(card, 'dshpw-read-add').props.onClick(); });
  assert.equal(byClass(card, 'dshpw-dir-picker').length, 1, '关闭开关后 read picker 仍可打开');
  await act(async () => { oneByClass(card, 'dshpw-dir-picker-close').props.onClick(); });

  // 重新开启开关同样不改动目录选择。
  await toggleWorkspaceCreate(card);
  assert.deepEqual(chipPaths(card), ['/srv/read'], '重新开启开关不得改动目录选择');

  await savePermissions(card);
  const [body] = permissionBodies(card);
  assert.equal('workspaceCreationRoots' in body!, false, '不得提交已退役的 workspaceCreationRoots');
  assert.equal('allowedFolders' in body!, false, '仅切换开关不得提交 allowedFolders');
});

for (const code of ['DOWNLOAD_IN_PROGRESS', 'INSTALL_IN_PROGRESS']) {
  test(`settings card preserves the ${code} update notice`, async (t) => {
    const card = await mountCard(t, {
      '/api/dsh-passwords/update/apply': () => Response.json({
        ok: false, code, message: 'Update already in progress',
      }),
    });
    const button = card.renderer.root.findByProps({ className: 'dshpw-btn dshpw-update-apply' });
    assert.equal(button.props.disabled, false);
    await act(async () => { await button.props.onClick(); });
    assert.match(card.text(), /Update already in progress/);
    assert.equal(card.renderer.root.findAllByProps({ className: 'dshpw-error' }).length, 0);
    assert.doesNotMatch(card.text(), /card-crashed/);
  });
}
