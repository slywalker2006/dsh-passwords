import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api } from '../src/client/api.ts';
import { readPatchState } from '../src/client/card.tsx';

test('api preserves JSON payloads and GET/POST request options', async (t) => {
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json({ value: 1 }));
  assert.deepEqual(await api('/test'), { value: 1 });
  assert.deepEqual(fetch.mock.calls[0].arguments, ['/test', {
    method: 'GET', headers: undefined, body: undefined,
  }]);
  await api('/test', { enabled: false });
  assert.deepEqual(fetch.mock.calls[1].arguments, ['/test', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"enabled":false}',
  }]);
});

test('api maps a followed login redirect to the existing authentication error code', async (t) => {
  const response = new Response('<!doctype html><title>Login</title>');
  Object.defineProperties(response, {
    redirected: { value: true },
    url: { value: 'https://example.test/gateway/login?next=%2F' },
  });
  t.mock.method(globalThis, 'fetch', async () => response);
  await assert.rejects(api('/test'), { code: 'NOT_AUTHENTICATED' });
});

test('api permits non-login redirects returning JSON', async (t) => {
  const response = Response.json({ value: 1 });
  Object.defineProperties(response, {
    redirected: { value: true },
    url: { value: 'https://example.test/canonical/test' },
  });
  t.mock.method(globalThis, 'fetch', async () => response);
  assert.deepEqual(await api('/test'), { value: 1 });
});

test('api rejects HTTP 200 HTML instead of silently returning an empty object', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('<!doctype html><title>Login</title>'));
  await assert.rejects(api('/test'), /Expected a JSON response/);
});

test('api does not crash on malformed final redirect URL', async (t) => {
  const response = new Response('<html>login</html>');
  Object.defineProperties(response, {
    redirected: { value: true },
    url: { value: '' },
  });

  t.mock.method(globalThis, 'fetch', async () => response);

  await assert.rejects(
    api('/test'),
    /Expected a JSON response/,
  );
});

test('api does not treat a nested gateway path as the login redirect', async (t) => {
  const response = new Response('<html>login</html>');
  Object.defineProperties(response, {
    redirected: { value: true },
    url: { value: 'https://example.test/gateway/login/extra' },
  });

  t.mock.method(globalThis, 'fetch', async () => response);

  await assert.rejects(
    api('/test'),
    /Expected a JSON response/,
  );
});

test('api preserves structured HTTP errors for localized messages', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => Response.json({
    error: 'Authentication required', code: 'NOT_AUTHENTICATED',
  }, { status: 401 }));
  await assert.rejects(api('/test'), {
    message: 'Authentication required', code: 'NOT_AUTHENTICATED',
  });
});

test('api preserves HTTP status for non-JSON proxy errors', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('<title>Bad Gateway</title>', { status: 502 }));
  await assert.rejects(api('/test'), { message: 'HTTP 502' });
});

for (const payload of [null, [], 'unexpected', 1]) {
  test(`api rejects non-object JSON: ${JSON.stringify(payload)}`, async (t) => {
    t.mock.method(globalThis, 'fetch', async () => Response.json(payload));
    await assert.rejects(api('/test'), /Expected a JSON object/);
  });
}

for (const code of ['DOWNLOAD_IN_PROGRESS', 'INSTALL_IN_PROGRESS']) {
  test(`api leaves HTTP 200 ${code} business results to the caller`, async (t) => {
    const result = { ok: false, code, message: 'Update already in progress' };
    t.mock.method(globalThis, 'fetch', async () => Response.json(result));
    assert.deepEqual(await api('/api/dsh-passwords/update/apply', {}), result);
  });
}

test('patch status normalization rejects missing and malformed flags', () => {
  for (const payload of [
    undefined, null, [], {}, { status: null }, { status: [] }, { status: {} },
    { status: { settingsHostMode: true } },
    { status: { settingsHostMode: 'true', workspaceSearch: true, bindAll: true, connectionCookieBridge: 'patched' } },
    { status: { settingsHostMode: true, workspaceSearch: 'false', bindAll: true, connectionCookieBridge: 'patched' } },
    { status: { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'invalid' } },
  ]) assert.equal(readPatchState(payload), null);
});

test('patch status normalization preserves valid true and false flags', () => {
  for (const status of [
    { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'patched' },
    { settingsHostMode: false, workspaceSearch: false, bindAll: false, connectionCookieBridge: 'missing' },
    { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'native' },
    { settingsHostMode: true, workspaceSearch: true, bindAll: true, connectionCookieBridge: 'unsupported' },
  ]) assert.deepEqual(readPatchState({ status }), status);
});
