'use strict';
// Run only in an isolated network namespace with a disposable HOME.
// Loads installed consumers; never reads n8n configuration or executes workflows.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {createRequire} = require('node:module');
const release = fs.realpathSync(process.argv[2]);
const req = createRequire(path.join(release, 'package.json'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'n8n-dependency-probe-'));
process.env.SNOWFLAKE_HOME = tmp;
process.env.SNOWFLAKE_DEFAULT_CONNECTION_NAME = 'default';
process.env.N8N_DISABLED_MODULES = 'source-control,promotions';
const checks = [];
const record = (name) => checks.push(name);
const packageVersion = name => req(`${name}/package.json`).version;
const plain = value => JSON.parse(JSON.stringify(value));

async function main() {
  req('sqlite3');
  req('isolated-vm');
  record('native SQLite and isolated-vm bindings load');
  const nodemailer = req('nodemailer');
  const {simpleParser} = req('mailparser');
  assert.equal(packageVersion('nodemailer'), '10.1.7');
  assert.equal(packageVersion('snowflake-sdk'), '3.4.0');
  assert.equal(packageVersion('toml'), '5.0.1');
  for (const name of ['n8n', 'n8n-nodes-base', 'mailparser']) {
    const consumer = createRequire(req.resolve(`${name}/package.json`));
    assert.equal(consumer('nodemailer/package.json').version, '10.1.7');
  }
  record('all three installed Nodemailer consumers resolve the patched package');
  const addressParser = req('nodemailer/lib/addressparser');
  assert.equal(typeof addressParser, 'function');
  assert.deepEqual(plain(addressParser('Example <alice@example.invalid>')),
    [{address: 'alice@example.invalid', name: 'Example'}]);
  record('mailparser CommonJS addressparser subpath remains callable');

  for (const [index, message] of [
    {text: 'Hello plain text'},
    {html: '<p>Hello <b>HTML</b></p>', text: 'Hello HTML'},
    {text: 'Unicode árvíztűrő tükörfúrógép'},
    {text: 'Attachment', attachments: [{filename: 'test.txt', content: Buffer.from('safe-fixture')}]},
    {html: '<img src="cid:fixture">', attachments: [{filename: 'inline.txt', cid: 'fixture', content: Buffer.from('inline-fixture')}]},
  ].entries()) {
    const transport = nodemailer.createTransport({streamTransport: true, buffer: true});
    const result = await transport.sendMail({
      from: 'Fixture <from@example.invalid>', to: 'Reader <to@example.invalid>',
      subject: `Fixture ${index}`, ...message,
    });
    const parsed = await simpleParser(result.message);
    assert.equal(parsed.subject, `Fixture ${index}`);
    assert.equal(parsed.from.value[0].address, 'from@example.invalid');
    assert.equal(parsed.to.value[0].address, 'to@example.invalid');
    if (message.text) assert.equal(parsed.text.trim(), message.text);
    if (message.html) assert.equal(parsed.html, message.html);
    if (message.attachments) assert.equal(parsed.attachments[0].content.toString(), message.attachments[0].content.toString());
    transport.close();
  }
  record('five real MIME compositions round-trip through the installed mailparser');

  req('reflect-metadata');
  const {NodeMailer} = req(path.join(release, 'node_modules/n8n/dist/user-management/email/node-mailer.js'));
  const logger = {debug() {}, error() {}};
  const mailer = new NodeMailer({userManagement: {emails: {smtp: {
    host: 'unused.example.invalid', port: 2525, secure: false, startTLS: true,
    sender: 'n8n@example.invalid', auth: {user: '', pass: ''},
  }}}}, logger, {error() {}});
  mailer.transport.close();
  const stream = nodemailer.createTransport({streamTransport: true, buffer: true});
  let nativeMail;
  const originalSend = stream.sendMail.bind(stream);
  stream.sendMail = async (...args) => { nativeMail = await originalSend(...args); return nativeMail; };
  mailer.transport = stream;
  assert.deepEqual(await mailer.sendMail({emailRecipients: ['user@example.invalid'],
    subject: 'Native invitation fixture', body: '<p>Invitation fixture</p>'}), {emailSent: true});
  const parsedNative = await simpleParser(nativeMail.message);
  assert.equal(parsedNative.subject, 'Native invitation fixture');
  assert.equal(parsedNative.text.trim(), 'Invitation fixture');
  assert.ok(parsedNative.attachments.some(x => x.cid === 'n8n-logo'));
  stream.close();
  record('real n8n NodeMailer composes text, HTML, and packaged inline logo');

  const {configureTransport} = req(path.join(release, 'node_modules/n8n-nodes-base/dist/nodes/EmailSend/v2/utils.js'));
  const nodeTransport = configureTransport({host: 'unused.example.invalid', port: 2525,
    secure: false, disableStartTls: false, user: '', password: ''}, {});
  assert.equal(nodeTransport.options.ignoreTLS, false);
  // Keep the real EmailSend defaults and Mail processing, replacing only delivery
  // with Nodemailer's native in-memory stream transport.
  const StreamTransport = req('nodemailer/lib/stream-transport');
  nodeTransport.transporter = new StreamTransport({buffer: true});
  nodeTransport.transporter.mailer = nodeTransport;
  const sentinel = path.join(tmp, 'benign.txt');
  fs.writeFileSync(sentinel, 'Subject: harmless\r\n\r\nfixture-only\r\n', {mode: 0o600});
  await assert.rejects(nodeTransport.sendMail({raw: {path: sentinel}}), e => e.code === 'EFILEACCESS');
  await assert.rejects(nodeTransport.sendMail({raw: {href: 'http://127.0.0.1:9/unused'}}), e => e.code === 'EURLACCESS');
  const normal = await nodeTransport.sendMail({from: 'from@example.invalid', to: 'to@example.invalid', text: 'Normal EmailSend fixture'});
  assert.equal((await simpleParser(normal.message)).text.trim(), 'Normal EmailSend fixture');
  nodeTransport.close();
  record('real EmailSend policy rejects raw file/URL access and accepts ordinary mail');

  const snowflake = req('snowflake-sdk');
  snowflake.configure({logLevel: 'OFF', logFilePath: 'STDOUT'});
  const toml = req('toml');
  const configFixture = '[default]\naccount = "example-account"\nuser = "fixture"\npassword = "synthetic-not-a-secret"\nwarehouse = "TEST"\nclient_session_keep_alive = false\n';
  fs.writeFileSync(path.join(tmp, 'connections.toml'), configFixture, {mode: 0o600});
  const snowflakeRoot = path.dirname(req.resolve('snowflake-sdk/package.json'));
  const {loadConnectionConfiguration} = req(path.join(snowflakeRoot, 'dist/lib/configuration/connection_configuration.js'));
  const config = loadConnectionConfiguration();
  assert.equal(config.account, 'example-account');
  assert.equal(config.username, 'fixture');
  assert.equal(config.clientSessionKeepAlive, false);
  const connection = snowflake.createConnection(config);
  assert.equal(typeof connection.connect, 'function');
  assert.equal(typeof connection.execute, 'function');
  assert.equal(typeof connection.destroy, 'function');
  record('real Snowflake TOML configuration and disconnected connection factory remain compatible');
  const {Snowflake} = req(path.join(release, 'node_modules/n8n-nodes-base/dist/nodes/Snowflake/Snowflake.node.js'));
  assert.ok(new Snowflake().description.version.includes(1.1));
  record('real n8n Snowflake node still loads');
  assert.throws(() => toml.parse('[a.b]\ny=1\n[a.b.y.__proto__.__proto__]\nhomelabAuditSentinel="safe"\n'));
  assert.equal(Object.prototype.homelabAuditSentinel, undefined);
  assert.throws(() => toml.parse('x=' + '['.repeat(600) + '0' + ']'.repeat(600)),
    e => !(e instanceof RangeError));
  record('TOML rejects prototype traversal and bounded excessive nesting without RangeError');
  const {LazyPackageDirectoryLoader} = req(path.join(release, 'node_modules/n8n-core/dist/nodes-loader/lazy-package-directory-loader.js'));
  const excluded = ['n8n-nodes-base.executeCommand', 'n8n-nodes-base.localFileTrigger', 'n8n-nodes-base.git'];
  const loader = new LazyPackageDirectoryLoader(path.join(release, 'node_modules/n8n-nodes-base'), excluded);
  await loader.loadAll();
  assert.equal(loader.known.nodes.git, undefined);
  assert.throws(() => loader.getNode('git'), /Unrecognized node/);
  for (const name of ['webhook', 'if', 'matrix']) assert.ok(loader.getNode(name));
  const backendRoot = path.dirname(req.resolve('@n8n/backend-common/package.json'));
  const {ModulesConfig} = req(path.join(backendRoot, 'dist/modules/modules.config.js'));
  const {ModuleRegistry} = req(path.join(backendRoot, 'dist/modules/module-registry.js'));
  const moduleConfig = req('@n8n/di').Container.get(ModulesConfig);
  assert.deepEqual([...moduleConfig.disabledModules], ['source-control', 'promotions']);
  const registry = new ModuleRegistry({}, {}, logger, moduleConfig, {});
  assert.ok(!registry.eligibleModules.includes('source-control'));
  assert.ok(!registry.eligibleModules.includes('promotions'));
  record('native loader denies Git and enterprise Git modules while retaining all active workflow node types');
  const {globWithDeadline} = req(path.join(release, 'node_modules/n8n-nodes-base/dist/nodes/Files/ReadWriteFile/helpers/utils.js'));
  const started = performance.now();
  await assert.rejects(globWithDeadline({name: 'Synthetic file selector', type: 'n8n-nodes-base.readWriteFile'},
    '{'.repeat(6000) + 'fixture' + '}'.repeat(6000), {cwd: tmp}, 0, 250));
  assert.ok(performance.now() - started < 3000);
  record('native file selector isolates and bounds a deeply nested braces input');
  process.stdout.write(JSON.stringify({status: 'passed', release,
    lock_sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(release, 'package-lock.json'))).digest('hex'),
    node: process.version, versions: Object.fromEntries(['n8n', 'nodemailer', 'snowflake-sdk', 'toml'].map(n => [n, packageVersion(n)])),
    checks, external_network: false, production_config_read: false}, null, 2) + '\n');
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; })
  .finally(() => fs.rmSync(tmp, {recursive: true, force: true}));
