// ⚠️  INTENTIONALLY VULNERABLE — for demonstration only. Never deploy this.
//
// This is the "classic mistake": the developer checks that the first word is a
// known command, then glues the user's input into a string and hands it to
// child_process.exec(), which runs it through /bin/sh. The shell interprets
// metacharacters such as ; && || | ` $() and newlines, so an attacker can
// chain any command they like after a legitimate one.

const { exec } = require('child_process');
const path = require('path');

const SANDBOX = path.join(__dirname, '..', 'sandbox');

// Command name -> shell template. The user-controlled part is concatenated in.
const TEMPLATES = {
  ping: (args) => `ping -c 2 ${args}`,
  nslookup: (args) => `nslookup ${args}`,
  ls: (args) => `ls -la ${args}`,
  cat: (args) => `cat ${args}`,
  echo: (args) => `echo ${args}`,
  whoami: () => 'whoami',
  date: () => 'date',
  uptime: () => 'uptime',
};

function runVulnerable(input) {
  return new Promise((resolve) => {
    const trimmed = String(input || '').trim();
    const name = trimmed.split(' ')[0];
    const args = trimmed.slice(name.length).trim();

    // "Validation" that only looks at the first word — easily bypassed.
    if (!TEMPLATES[name]) {
      return resolve({ ok: false, output: `Unknown command: ${name}` });
    }

    const shellCommand = TEMPLATES[name](args);

    // VULNERABLE SINK: exec() spawns a shell and parses the whole string.
    exec(shellCommand, { cwd: SANDBOX, timeout: 10000 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        executed: shellCommand, // leaks the exact command line (information disclosure)
        output: stdout + stderr + (err ? `\n${err.stack}` : ''), // leaks stack traces
      });
    });
  });
}

module.exports = { runVulnerable };
