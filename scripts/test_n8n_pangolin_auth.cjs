const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { createMiddleware } = require('../ansible/roles/n8n/files/pangolin-auth.js');

const id = '33333333-3333-4333-8333-333333333333';
function setup({ headers = {}, peer = '10.42.0.202', method = 'GET', path = '/', token, user = {}, validSession = id, failure = false } = {}) {
  const account = { id, password: 'existing-hash', disabled: false, role: { slug: 'global:owner' }, ...user };
  const req = { headers: { 'x-n8n-user': id, ...headers }, socket: { remoteAddress: peer }, method, path, cookies: token ? { 'n8n-auth': token } : {} };
  const result = { next: 0, issued: 0, cleared: 0 };
  const res = {
    status(code) { result.status = code; return this; },
    json(body) { result.body = body; return this; },
    cookie(name, value, options) { result.cookie = { name, value, options }; return this; },
    redirect(code, target) { result.redirect = { code, target }; },
  };
  const middleware = createMiddleware({
    config: { allowedUserIds: [id], trustedSources: ['10.42.0.202'], header: 'x-n8n-user', origin: 'https://n8n.homelab.example' },
    cookieName: 'n8n-auth', logger: { info() {}, error() {} },
    userRepository: { async findOne(query) { assert.equal(query.where.id, id); if (failure) throw new Error('database unavailable'); return account; } },
    authService: {
      async validateCookieToken() { if (!validSession) throw new Error('revoked'); return { id: validSession }; },
      clearCookie() { result.cleared++; },
      issueCookie(response, user, usedMfa, browserId) {
        result.issued++; assert.equal(user.id, id); assert.equal(usedMfa, false);
        result.browserId = browserId;
        response.cookie('n8n-auth', 'native-signed-token', { secure: true, httpOnly: true });
      },
    },
  });
  return { req, result, run: () => middleware(req, res, () => { result.next++; }) };
}

test('trusted binding establishes the existing account with a native cookie', async () => {
  const s = setup({ headers: { 'browser-id': 'browser-123' } }); await s.run();
  assert.equal(s.result.issued, 1); assert.equal(s.result.next, 1);
  assert.equal(s.req.cookies['n8n-auth'], 'native-signed-token');
  assert.equal(s.result.browserId, 'browser-123');
  assert.equal(s.result.cookie.options.httpOnly, true);
});
test('forged header from LAN or direct backend cannot authenticate', async () => {
  for (const peer of ['10.42.0.51', '10.42.0.210', '127.0.0.1']) {
    const s = setup({ peer }); await s.run(); assert.equal(s.result.status, 403); assert.equal(s.result.issued, 0);
  }
});
test('unknown, empty and duplicate identities fail even with an existing owner cookie', async () => {
  for (const value of ['unmapped', '', ['one', 'two'], 'another-id']) {
    const s = setup({ headers: { 'x-n8n-user': value }, token: 'owner-cookie' });
    await s.run(); assert.equal(s.result.status, 403); assert.equal(s.result.next, 0);
  }
});
test('LAN recovery and API/webhook authentication retain native handling', async () => {
  const cases = [{ headers: { 'x-n8n-user': undefined } }, ...['/healthz/readiness', '/webhook/abc', '/webhook-test/abc', '/api/v1/workflows', '/assets/app.js', '/rest/oauth2-credential/callback'].map(path => ({ path, peer: 'untrusted' }))];
  for (const options of cases) { const s = setup(options); await s.run(); assert.equal(s.result.next, 1); assert.equal(s.result.issued, 0); }
});
test('a valid bound session is reused', async () => {
  const s = setup({ token: 'valid' }); await s.run(); assert.equal(s.result.issued, 0); assert.equal(s.result.next, 1);
});
test('expired, revoked and other-account cookies are replaced on navigation', async () => {
  for (const validSession of [null, 'different-user']) {
    const s = setup({ token: 'old', validSession }); await s.run(); assert.equal(s.result.issued, 1); assert.equal(s.result.cleared, 1);
  }
});
test('unsafe requests cannot bootstrap or switch accounts', async () => {
  const s = setup({ method: 'POST', path: '/rest/workflows', token: 'other', validSession: 'different-user' });
  await s.run(); assert.equal(s.result.status, 401); assert.equal(s.result.issued, 0); assert.equal(s.req.cookies['n8n-auth'], undefined);
});
test('foreign origins cannot bootstrap sessions', async () => {
  const s = setup({ headers: { origin: 'https://attacker.example.com' } }); await s.run(); assert.equal(s.result.status, 403); assert.equal(s.result.issued, 0);
});
test('disabled and incomplete accounts fail closed', async () => {
  for (const user of [{ disabled: true }, { role: null }, { password: '' }]) {
    const s = setup({ user }); await s.run(); assert.equal(s.result.status, 403); assert.equal(s.result.issued, 0);
  }
});
test('local MFA is not marked as satisfied by the gateway', async () => {
  const s = setup({ user: { mfaEnabled: true } }); await s.run(); assert.equal(s.result.issued, 0); assert.equal(s.result.next, 1);
});
test('signin navigation returns to the editor', async () => {
  const s = setup({ path: '/signin' }); await s.run(); assert.deepEqual(s.result.redirect, { code: 303, target: '/' });
});
test('database failures do not fall through to an unrelated session', async () => {
  const s = setup({ failure: true }); await s.run(); assert.equal(s.result.status, 503); assert.equal(s.result.next, 0);
});

function startupFixture(installedVersion, configuredVersion = installedVersion) {
  const module = { exports: {} };
  const AuthService = class {};
  const Logger = class {};
  const config = { version: configuredVersion, allowedUserIds: [id], trustedSources: ['192.0.2.10'] };
  const nativeRequire = (name) => {
    if (name === './package.json') return { version: installedVersion };
    if (name === '@n8n/di') return { Container: { get: () => ({ info() {} }) } };
    if (name === './dist/auth/auth.service.js') return { AuthService };
    if (name === './dist/constants.js') return { AUTH_COOKIE_NAME: 'n8n-auth' };
    if (name === '@n8n/backend-common') return { Logger };
    throw new Error(`Unexpected n8n import: ${name}`);
  };
  vm.runInNewContext(readFileSync(require.resolve('../ansible/roles/n8n/files/pangolin-auth.js'), 'utf8'), {
    module, require(name) {
      if (name === 'node:module') return { createRequire: () => nativeRequire };
      if (name === 'node:fs') return { readFileSync: () => JSON.stringify(config) };
      throw new Error(`Unexpected hook import: ${name}`);
    },
  });
  const app = {
    router: { stack: [{ name: 'cookieParser' }, { name: 'nativeAuth' }] },
    use(handle) { this.router.stack.push({ name: handle.name, handle }); },
  };
  return { app, hook: module.exports,
    run: () => module.exports.n8n.ready[0].call({ dbCollections: { User: {} } }, { app }) };
}

test('only reviewed exact versions install between cookie parsing and native auth', async () => {
  for (const version of ['2.42.6', '2.43.7', '2.43.8']) {
    const s = startupFixture(version);
    await s.run();
    assert.deepEqual(s.app.router.stack.map(layer => layer.name),
      ['cookieParser', 'pangolinSession', 'nativeAuth']);
    assert.deepEqual(Object.keys(s.hook), ['n8n']);
  }
});
test('unreviewed releases and mismatched binding versions fail closed', async () => {
  for (const [installed, configured] of [['2.43.9', '2.43.9'], ['2.43.7-beta.1', '2.43.7-beta.1'],
    ['2.42.6', '2.43.7'], ['2.43.7', '2.42.6']]) {
    const s = startupFixture(installed, configured);
    await assert.rejects(s.run(), /Review Pangolin session hook/);
    assert.equal(s.app.router.stack.length, 2);
  }
});
test('missing native cookie parser prevents hook installation', async () => {
  const s = startupFixture('2.42.6');
  s.app.router.stack.shift();
  await assert.rejects(s.run(), /n8n cookie parser was not found/);
  assert.equal(s.app.router.stack.length, 1);
});
