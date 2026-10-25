process.env.NODE_ENV = 'test';

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const app = require('../server');

let server;
let base;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

async function run(mode, command) {
  const res = await fetch(`${base}/api/${mode}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }),
  });
  return { status: res.status, body: await res.json() };
}

const PAYLOADS = [
  'ping 127.0.0.1; whoami',
  'ping 127.0.0.1 && cat ../private/secrets.txt',
  'ping 127.0.0.1 || id',
  'ping 127.0.0.1 | id',
  'echo $(whoami)',
  'echo `whoami`',
  'ping 127.0.0.1\nwhoami',
  'ping 127.0.0.1 > /tmp/pwned',
  'cat ${HOME}/.ssh/id_rsa',
  "ping '127.0.0.1'",
];

test('vulnerable mode: chained command executes (proves the vulnerability)', async () => {
  const { body } = await run('vulnerable', 'echo hello; cat ../private/secrets.txt');
  assert.match(body.output, /DB_PASSWORD=SuperSecret123!/);
});

for (const payload of PAYLOADS) {
  test(`secure mode blocks: ${JSON.stringify(payload)}`, async () => {
    const { status, body } = await run('secure', payload);
    assert.strictEqual(status, 400);
    assert.strictEqual(body.blocked, true);
    assert.doesNotMatch(body.output, /SuperSecret|uid=/);
  });
}

test('secure mode blocks commands not in the allowlist', async () => {
  const { body } = await run('secure', 'rm sandbox');
  assert.strictEqual(body.blocked, true);
  assert.match(body.output, /not allowed/);
});

test('secure mode blocks prototype keys as command names', async () => {
  const { body } = await run('secure', 'constructor');
  assert.strictEqual(body.blocked, true);
});

test('secure mode blocks argument injection (flags)', async () => {
  const { body } = await run('secure', 'ping -c 1000 127.0.0.1');
  assert.strictEqual(body.blocked, true);
  assert.match(body.output, /flags are not allowed/);
});

test('secure mode blocks path traversal in cat', async () => {
  const { body } = await run('secure', 'cat ../private/secrets.txt');
  assert.strictEqual(body.blocked, true);
});

test('secure mode blocks invalid hostnames', async () => {
  const { body } = await run('secure', 'nslookup exa_mple..com');
  assert.strictEqual(body.blocked, true);
});

test('secure mode blocks overly long input', async () => {
  const { body } = await run('secure', 'echo ' + 'a'.repeat(200));
  assert.strictEqual(body.blocked, true);
});

test('secure mode blocks non-ASCII / unicode tricks', async () => {
  const { body } = await run('secure', 'ping 127.0.0.1；whoami'); // fullwidth semicolon
  assert.strictEqual(body.blocked, true);
});

test('secure mode still allows legitimate commands', async () => {
  const help = await run('secure', 'help');
  assert.match(help.body.output, /Available commands/);

  const cat = await run('secure', 'cat welcome.txt');
  assert.strictEqual(cat.body.ok, true);
  assert.match(cat.body.output, /Welcome to the WEB404 Web CLI/);

  const echo = await run('secure', 'echo hello world');
  assert.strictEqual(echo.body.output, 'hello world');

  const ping = await run('secure', 'ping 127.0.0.1');
  assert.strictEqual(ping.body.ok, true);
  assert.match(ping.body.output, /127\.0\.0\.1/);
});

test('secure mode never leaks stack traces', async () => {
  const { body } = await run('secure', 'cat missing.txt');
  assert.doesNotMatch(body.output, /at \w+ \(|node:internal|Error:/);
});
