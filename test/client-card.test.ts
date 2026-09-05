import assert from 'node:assert/strict';
import { test, type TestContext } from 'node:test';
import { Component, createElement, type ComponentProps, type ReactNode } from 'react';
import { act, create, type ReactTestRenderer } from 'react-test-renderer';
import { DshPasswordsCard, type UpdateInfo } from '../src/client/card.tsx';

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

async function mountCard(t: TestContext, overrides: Record<string, () => Response> = {}, payloadOverrides: Record<string, unknown> = {}) {
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
    '/gateway/api/overview': { me, users: [], availableWebSocketPaths: [] },
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
    return Response.json(payloads[input]);
  });
  const translate = ((key: string) => key === 'err.NOT_AUTHENTICATED'
    ? 'Session expired' : key) as ComponentProps<typeof DshPasswordsCard>['t'];
  await act(async () => {
    renderer = create(createElement(CardBoundary, {
      children: createElement(DshPasswordsCard, { t: translate }),
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

test('settings card renders account and patch controls for a healthy response', async (t) => {
  const card = await mountCard(t);
  assert.match(card.text(), /test-admin/);
  assert.match(card.text(), /patchOk/);
  assert.doesNotMatch(card.text(), /card-crashed/);
});

test('settings card synchronizes the SSH permission beside upload and save API', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      availableWebSocketPaths: [],
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
          allowedWebSocketPaths: [],
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
  const sshLabel = card.renderer.root.findAllByType('label').find((label) => label.children.some((child) => child === 'permsSsh'));
  assert.ok(sshLabel, 'SSH 权限开关必须出现在上传权限附近');
  const checkbox = sshLabel!.findByType('input');
  assert.equal(checkbox.props.checked, false);
  await act(async () => { checkbox.props.onChange({ target: { checked: true } }); });
  const saveButton = card.renderer.root.findAllByType('button').find((button) => button.children.some((child) => child === 'permsSave'));
  assert.ok(saveButton);
  await act(async () => { saveButton!.props.onClick(); });
  const permissionRequest = card.requests.find((request) => request.input === '/gateway/api/permissions');
  assert.ok(permissionRequest);
  assert.equal(JSON.parse(String(permissionRequest!.init?.body)).allowSsh, true);
});

test('settings card synchronizes the large request body permission to the visible checkbox and save API', async (t) => {
  const card = await mountCard(t, {
    '/gateway/api/permissions': () => Response.json({ ok: true }),
  }, {
    '/gateway/api/overview': {
      me: { id: 1, username: 'test-admin', role: 'admin' },
      availableWebSocketPaths: [],
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
          allowedWebSocketPaths: [],
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
      availableWebSocketPaths: [],
      users: [{ id: 2, username: 'subuser', role: 'user', permissions: { allowedFolders: [], hourlyTokenLimit: null, dailyMinutesLimit: null, allowUpload: true, allowGitDownload: false, allowWorkspaceCreate: false, allowedWebSocketPaths: [], allowedAgentPresets: [], banned: false, sandboxMode: null, disabledSessions: [], allowedSessionIds: [] }, usage: null }],
    },
  });
  assert.match(card.text(), /permsAgentPresetsUnavailable/);
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
