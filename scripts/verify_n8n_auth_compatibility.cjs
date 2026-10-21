#!/usr/bin/env node
'use strict';

// Run with a separately installed release. This imports its real authentication
// classes but uses synthetic accounts and keys; it never opens an n8n database,
// reads service configuration, starts a listener, or executes a workflow.
const assert = require('node:assert/strict');
const { randomBytes, createHash } = require('node:crypto');
const { readFileSync, realpathSync } = require('node:fs');
const { createRequire } = require('node:module');
const { resolve } = require('node:path');
const vm = require('node:vm');

async function main() {
  if (!process.argv[2]) throw new Error('Usage: verify_n8n_auth_compatibility.cjs RELEASE_DIR [HOOK_FILE]');
  const release = realpathSync(process.argv[2]);
  const hookFile = resolve(process.argv[3] || `${__dirname}/../ansible/roles/n8n/files/pangolin-auth.js`);
  const hookSource = readFileSync(hookFile, 'utf8');
  const n8nRequire = createRequire(`${release}/node_modules/n8n/package.json`);
  const version = n8nRequire('./package.json').version;
  assert.ok(['2.42.6', '2.43.7', '2.43.8'].includes(version), 'release requires an explicit compatibility review');
  const purposeBoundSessions = ['2.43.7', '2.43.8'].includes(version);
  const { AuthService } = n8nRequire('./dist/auth/auth.service.js');
  const { JwtService } = n8nRequire('./dist/services/jwt.service.js');
  const { ExternalHooks } = n8nRequire('./dist/external-hooks.js');
  const { AUTH_COOKIE_NAME } = n8nRequire('./dist/constants.js');
  const { Logger } = n8nRequire('@n8n/backend-common');
  const express = n8nRequire('express');
  const cookieParser = n8nRequire('cookie-parser');
  const jwt = n8nRequire('jsonwebtoken');
  const id = '11111111-1111-4111-8111-111111111111';
  const otherId = '22222222-2222-4222-8222-222222222222';
  const logger = { debug() {}, info() {}, warn() {}, error() {} };
  const config = {
    endpoints: { rest: 'rest' }, auth: { cookie: { samesite: 'lax', secure: true } },
    userManagement: { jwtSecret: randomBytes(32).toString('hex'), jwtSessionDurationHours: 1, jwtRefreshTimeoutHours: 0 },
  };
  const original = { id, email: 'synthetic@example.invalid', password: 'synthetic-password-hash',
    disabled: false, mfaEnabled: false, role: { slug: 'global:owner' } };
  let user = { ...original };
  let mfaEnforced = false;
  const revoked = new Set();
  const repository = { async findOne(query) {
    assert.deepEqual(JSON.parse(JSON.stringify(query.relations)), ['role']);
    return query.where.id === id ? user : query.where.id === otherId ? { ...user, id: otherId } : null;
  } };
  const jwtService = new JwtService({ encryptionKey: randomBytes(32).toString('hex') }, config, logger);
  const authService = new AuthService(config, logger, { isWithinUsersLimit: () => true },
    jwtService, {}, repository, { existsBy: async ({ token }) => revoked.has(token) },
    { isMFAEnforced: async () => mfaEnforced });
  const binding = { version, allowedUserIds: [id], trustedSources: ['192.0.2.10'],
    header: 'x-n8n-user', origin: 'https://n8n.example.invalid' };

  function loadHook(bindingVersion = version, installedVersion = version) {
    const module = { exports: {} };
    const boundRequire = (name) => {
      if (name === './package.json') return { version: installedVersion };
      if (name === '@n8n/di') return { Container: { get(type) {
        if (type === AuthService) return authService;
        if (type === Logger) return logger;
        throw new Error('Unexpected dependency injection lookup');
      } } };
      return n8nRequire(name);
    };
    vm.runInNewContext(hookSource, { module, require(name) {
      if (name === 'node:module') return { createRequire(path) {
        assert.equal(path, '/opt/n8n/current/node_modules/n8n/package.json');
        return boundRequire;
      } };
      if (name === 'node:fs') return { readFileSync(path, encoding) {
        assert.equal(path, '/etc/n8n/pangolin-auth.json');
        assert.equal(encoding, 'utf8');
        return JSON.stringify({ ...binding, version: bindingVersion });
      } };
      throw new Error(`Unexpected hook import: ${name}`);
    } }, { filename: hookFile });
    return module.exports;
  }

  const hook = loadHook();
  const app = express();
  app.use(cookieParser());
  app.use(function nativeBrowserId(req, _, next) { req.browserId = req.headers['browser-id']; next(); });
  const nativeAuth = authService.createAuthMiddleware({ allowSkipMFA: false });
  app.use(nativeAuth);
  const externalHooks = new ExternalHooks(logger, { error() {} }, {}, repository, {}, {}, {});
  externalHooks.loadHooks(hook);
  await externalHooks.run('n8n.ready', [{ app }]);
  assert.deepEqual(app.router.stack.slice(0, 3).map((layer) => layer.name),
    ['cookieParser', 'pangolinSession', 'nativeBrowserId']);
  assert.equal(app.router.stack[3].handle, nativeAuth);
  const middleware = app.router.stack[1].handle;
  const passed = ['ready-hook-before-native-auth'];
  const check = async (name, run) => { await run(); passed.push(name); };
  function response() {
    const result = { cookies: [], cleared: [], statusCode: 200 };
    return Object.assign(result, {
      cookie(name, value, options) { this.cookies.push({ name, value, options }); return this; },
      clearCookie(name) { this.cleared.push(name); return this; },
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; },
      redirect(code, target) { this.statusCode = code; this.location = target; return this; },
    });
  }
  async function request({ path = '/rest/workflows', method = 'GET', headers = {},
    peer = '192.0.2.10', token, native = true } = {}) {
    const req = { path, method, headers: { 'x-n8n-user': id, 'browser-id': 'synthetic-browser', ...headers },
      socket: { remoteAddress: peer },
      baseUrl: '', route: { path } };
    if (token) req.headers.cookie = `${AUTH_COOKIE_NAME}=${encodeURIComponent(token)}`;
    const res = response();
    let parsed = false;
    app.router.stack[0].handle(req, res, () => { parsed = true; });
    assert.equal(parsed, true);
    assert.equal(typeof req.cookies, 'object');
    let passedHook = false;
    let authorized = false;
    await middleware(req, res, () => { passedHook = true; });
    if (passedHook && native) {
      req.browserId = req.headers['browser-id'];
      await nativeAuth(req, res, () => { authorized = true; });
    }
    return { req, res, passedHook, authorized };
  }
  function nativeToken(account = user, usedMfa = false, browserId = 'synthetic-browser') {
    const res = response();
    authService.issueCookie(res, account, usedMfa, browserId);
    return res.cookies[0].value;
  }

  await check('native-cookie-issuer-validator-and-auth-middleware', async () => {
    const result = await request();
    assert.equal(result.authorized, true);
    assert.equal(result.req.user.id, id);
    assert.equal(result.req.authInfo.usedMfa, false);
    const cookie = result.res.cookies[0];
    assert.equal(cookie.name, AUTH_COOKIE_NAME);
    assert.equal(cookie.options.secure, true);
    assert.equal(cookie.options.httpOnly, true);
    assert.equal(cookie.options.sameSite, 'lax');
    assert.equal((await authService.validateCookieToken(cookie.value)).id, id);
    if (purposeBoundSessions) assert.equal(jwt.decode(cookie.value).aud, 'n8n:session');
  });
  await check('native-session-reuse', async () => {
    const result = await request({ token: nativeToken() });
    assert.equal(result.authorized, true);
    assert.equal(result.res.cookies.length, 0);
  });
  await check('native-browser-binding-still-enforced', async () => {
    const result = await request({ token: nativeToken(), headers: { 'browser-id': 'other-browser' } });
    assert.equal(result.authorized, false);
    assert.equal(result.res.statusCode, 401);
  });
  await check('revoked-and-other-account-sessions-rejected-on-post', async () => {
    const revokedToken = nativeToken();
    revoked.add(revokedToken);
    for (const token of [revokedToken, nativeToken({ ...user, id: otherId })]) {
      const result = await request({ method: 'POST', token });
      assert.equal(result.authorized, false);
      assert.equal(result.res.statusCode, 401);
      assert.equal(result.req.cookies[AUTH_COOKIE_NAME], undefined);
    }
    revoked.clear();
  });
  await check('mapped-header-and-source-required', async () => {
    for (const options of [{ peer: '192.0.2.99' }, { headers: { 'x-n8n-user': otherId } },
      { headers: { 'x-n8n-user': [id, otherId] } }]) {
      const result = await request(options);
      assert.equal(result.res.statusCode, 403);
      assert.equal(result.authorized, false);
      assert.equal(result.res.cookies.length, 0);
    }
  });
  await check('native-login-without-gateway-header', async () => {
    const result = await request({ method: 'POST', path: '/rest/login',
      headers: { 'x-n8n-user': undefined }, peer: '192.0.2.99', native: false });
    assert.equal(result.passedHook, true);
    assert.equal(result.res.cookies.length, 0);
  });
  await check('webhook-and-api-retain-native-handling', async () => {
    for (const path of ['/webhook/example', '/webhook-test/example', '/webhook-waiting/example',
      '/api/v1/workflows', '/rest/oauth2-credential/callback']) {
      const result = await request({ path, method: 'POST', peer: '192.0.2.99', native: false });
      assert.equal(result.passedHook, true);
      assert.equal(result.res.cookies.length, 0);
    }
  });
  await check('mfa-account-requires-native-login', async () => {
    user = { ...original, mfaEnabled: true, mfaSecret: 'synthetic-secret' };
    const result = await request();
    assert.equal(result.res.statusCode, 401);
    assert.equal(result.authorized, false);
    assert.equal(result.res.cookies.length, 0);
    const login = await request({ path: '/rest/login', method: 'POST', native: false });
    assert.equal(login.passedHook, true);
    const completed = await request({ token: nativeToken(user, true) });
    assert.equal(completed.authorized, true);
    assert.equal(completed.req.authInfo.usedMfa, true);
    user = { ...original };
  });
  await check('native-enforced-mfa-is-not-bypassed', async () => {
    mfaEnforced = true;
    const result = await request();
    assert.equal(result.authorized, false);
    assert.equal(result.res.statusCode, 401);
    assert.equal(result.res.body.mfaRequired, true);
    mfaEnforced = false;
  });
  await check('mismatched-and-unreviewed-versions-fail-closed', async () => {
    for (const candidate of [loadHook('0.0.0'), loadHook('99.0.0', '99.0.0')]) {
      await assert.rejects(candidate.n8n.ready[0].call({ dbCollections: { User: repository } },
        { app: express() }), /Review Pangolin session hook/);
    }
  });
  if (purposeBoundSessions) {
    await check('wrong-purpose-and-legacy-tokens-cannot-authorize-writes', async () => {
      const claims = { id, hash: authService.createJWTHash(user), usedMfa: false };
      const wrongPurpose = jwtService.sign('passwordReset', claims, { expiresIn: 3600 });
      const legacy = jwt.sign(claims, config.userManagement.jwtSecret, { expiresIn: 3600 });
      for (const token of [wrongPurpose, legacy]) {
        await assert.rejects(authService.validateCookieToken(token));
        const result = await request({ token, method: 'POST' });
        assert.equal(result.res.statusCode, 401);
        assert.equal(result.authorized, false);
        assert.equal(result.res.cookies.length, 0);
      }
      const navigation = await request({ token: legacy });
      assert.equal(navigation.authorized, true);
      assert.equal(jwt.decode(navigation.res.cookies[0].value).aud, 'n8n:session');
    });
    await check('legacy-mfa-session-requires-native-reauthentication', async () => {
      user = { ...original, mfaEnabled: true, mfaSecret: 'synthetic-secret' };
      const legacy = jwt.sign({ id, hash: authService.createJWTHash(user), usedMfa: true },
        config.userManagement.jwtSecret, { expiresIn: 3600 });
      const result = await request({ token: legacy });
      assert.equal(result.authorized, false);
      assert.equal(result.res.statusCode, 401);
      assert.equal(result.res.cookies.length, 0);
      user = { ...original };
    });
  }
  await check('installed-workflow-node-versions-remain-loadable', async () => {
    const nodesRequire = createRequire(n8nRequire.resolve('n8n-nodes-base/package.json'));
    for (const [name, requiredVersion] of [['Webhook', 2.1], ['If', 2.2], ['Matrix', 1]]) {
      const node = new (nodesRequire(`./dist/nodes/${name}/${name}.node.js`)[name])();
      const available = node.nodeVersions ? Object.keys(node.nodeVersions).map(Number) :
        [node.description.version].flat();
      assert.ok(available.includes(requiredVersion), `${name} v${requiredVersion} is unavailable`);
    }
  });
  const nativeSha256 = Object.fromEntries(['auth/auth.service.js', 'services/jwt.service.js',
    'external-hooks.js', 'abstract-server.js', 'server.js'].map(name => [name,
    createHash('sha256').update(readFileSync(n8nRequire.resolve(`./dist/${name}`))).digest('hex')]));
  console.log(JSON.stringify({ version, release, hookSha256: createHash('sha256').update(hookSource).digest('hex'),
    lockSha256: createHash('sha256').update(readFileSync(`${release}/package-lock.json`)).digest('hex'),
    nativeSha256, checks: passed, count: passed.length, syntheticAccounts: true, liveDatabaseAccess: false,
    workflowExecution: false }, null, 2));
}
main().catch((error) => { console.error(error.stack); process.exitCode = 1; });
