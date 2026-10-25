// Secure command runner. Defence in depth — every layer below would stop
// command injection on its own, but they are combined so that a mistake in
// one layer does not become a vulnerability.
//
//  1. Input length limit + printable-ASCII-only (blocks unicode/encoding tricks)
//  2. Shell metacharacter detection (blocks and logs ; & | ` $ ( ) < > etc.)
//  3. Strict allowlist of commands — the user never names a binary directly
//  4. Per-argument validation with allowlist regexes (hostnames, file names)
//  5. Argument-injection protection (arguments may not start with "-")
//  6. Path confinement to the sandbox directory (blocks ../ traversal)
//  7. execFile() with shell:false — arguments are passed as an array straight
//     to the program, so there is no shell to interpret metacharacters
//  8. Absolute binary paths, minimal environment, timeout, output size limit
//  9. Generic error messages (no stack traces) + audit logging

const { execFile } = require('child_process');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { audit } = require('./logger');

const SANDBOX = path.join(__dirname, '..', 'sandbox');
const MAX_INPUT_LENGTH = 100;
const MAX_ARGS = 1;
const EXEC_OPTIONS = {
  cwd: SANDBOX,
  timeout: 10000,
  maxBuffer: 64 * 1024,
  shell: false,
  env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
};

const SHELL_METACHARACTERS = /[;&|`$(){}\[\]<>\\'"!*?~#\n\r\t]/;
const PRINTABLE_ASCII = /^[\x20-\x7E]*$/;
const HOSTNAME = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const SAFE_FILENAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const SAFE_TEXT = /^[a-zA-Z0-9 .,:_-]{0,80}$/;

function findBinary(name) {
  const candidates = [`/sbin/${name}`, `/bin/${name}`, `/usr/bin/${name}`, `/usr/sbin/${name}`];
  return candidates.find((p) => fs.existsSync(p));
}

class ValidationError extends Error {}

function validateHost(host) {
  if (net.isIP(host) || HOSTNAME.test(host)) return host;
  throw new ValidationError('Invalid hostname or IP address.');
}

function validateSandboxFile(name, { allowDirectory }) {
  if (name === undefined) {
    if (allowDirectory) return '.';
    throw new ValidationError('A file name is required.');
  }
  if (!SAFE_FILENAME.test(name)) {
    throw new ValidationError('Invalid file name. Use letters, numbers, ".", "_" or "-".');
  }
  const resolved = path.resolve(SANDBOX, name);
  if (path.dirname(resolved) !== SANDBOX) {
    throw new ValidationError('Access outside the sandbox is not allowed.');
  }
  if (!fs.existsSync(resolved)) {
    throw new ValidationError('File not found.');
  }
  const stat = fs.lstatSync(resolved);
  if (stat.isSymbolicLink()) throw new ValidationError('Symbolic links are not allowed.');
  if (!allowDirectory && !stat.isFile()) throw new ValidationError('Not a regular file.');
  return path.basename(resolved);
}

// The allowlist. Each entry maps a user-facing command to a fixed binary and
// builds the argument array itself — user input only ever fills validated slots.
const COMMANDS = {
  help: {
    usage: 'help',
    description: 'Show available commands',
    maxArgs: 0,
    run: () => Promise.resolve(helpText()),
  },
  ping: {
    usage: 'ping <host>',
    description: 'Send 2 ICMP echo requests to a host',
    maxArgs: 1,
    minArgs: 1,
    binary: 'ping',
    buildArgs: ([host]) => ['-c', '2', validateHost(host)],
  },
  nslookup: {
    usage: 'nslookup <domain>',
    description: 'DNS lookup for a domain',
    maxArgs: 1,
    minArgs: 1,
    binary: 'nslookup',
    buildArgs: ([host]) => [validateHost(host)],
  },
  ls: {
    usage: 'ls',
    description: 'List files in the sandbox directory',
    maxArgs: 0,
    binary: 'ls',
    buildArgs: () => ['-l', '.'],
  },
  cat: {
    usage: 'cat <file>',
    description: 'Show a file from the sandbox directory',
    maxArgs: 1,
    minArgs: 1,
    binary: 'cat',
    buildArgs: ([file]) => ['--', validateSandboxFile(file, { allowDirectory: false })],
  },
  whoami: { usage: 'whoami', description: 'Show the server user', maxArgs: 0, binary: 'whoami', buildArgs: () => [] },
  date: { usage: 'date', description: 'Show server date and time', maxArgs: 0, binary: 'date', buildArgs: () => [] },
  uptime: { usage: 'uptime', description: 'Show server uptime', maxArgs: 0, binary: 'uptime', buildArgs: () => [] },
  echo: {
    usage: 'echo <text>',
    description: 'Echo text back (handled in JavaScript, no OS process)',
    maxArgs: Infinity,
    // Best prevention of all: don't call the OS when the language can do it.
    run: (args) => {
      const text = args.join(' ');
      if (!SAFE_TEXT.test(text)) throw new ValidationError('Text contains disallowed characters.');
      return Promise.resolve(text);
    },
  },
};

function helpText() {
  const rows = Object.values(COMMANDS).map((c) => `  ${c.usage.padEnd(20)} ${c.description}`);
  return ['Available commands (secure mode):', ...rows, '  clear                Clear the screen'].join('\n');
}

function execAllowed(binaryName, args) {
  const binary = findBinary(binaryName);
  if (!binary) return Promise.reject(new ValidationError(`'${binaryName}' is not available on this server.`));
  return new Promise((resolve) => {
    execFile(binary, args, EXEC_OPTIONS, (err, stdout, stderr) => {
      if (err && err.killed) return resolve({ ok: false, output: 'Command timed out.' });
      // stdout/stderr of an allowlisted program are fine to show; the raw error object is not.
      resolve({ ok: !err, output: (stdout + stderr).trimEnd() || (err ? 'Command failed.' : '') });
    });
  });
}

async function runSecure(input, meta = {}) {
  const raw = typeof input === 'string' ? input : '';
  const reject = (reason, message) => {
    audit({ event: 'BLOCKED', reason, input: raw.slice(0, 200), ip: meta.ip });
    return { ok: false, blocked: true, output: message };
  };

  // Layer 1: size and character set
  if (raw.length === 0) return { ok: false, output: '' };
  if (raw.length > MAX_INPUT_LENGTH) return reject('TOO_LONG', `Input too long (max ${MAX_INPUT_LENGTH} characters).`);
  if (!PRINTABLE_ASCII.test(raw)) return reject('NON_PRINTABLE', 'Only printable ASCII characters are allowed.');

  // Layer 2: shell metacharacters — never legitimate for this CLI, so treat as an attack
  if (SHELL_METACHARACTERS.test(raw)) {
    return reject('INJECTION_ATTEMPT', 'Blocked: input contains shell metacharacters. This attempt has been logged.');
  }

  // Tokenise ourselves; the shell never sees the input
  const [name, ...args] = raw.trim().split(/ +/);

  // Layer 3: allowlist (hasOwnProperty avoids prototype keys like "constructor")
  if (!Object.prototype.hasOwnProperty.call(COMMANDS, name)) {
    return reject('NOT_ALLOWLISTED', `Command not allowed: '${name}'. Type 'help' for the list.`);
  }
  const cmd = COMMANDS[name];

  // Layer 5: argument injection (e.g. "ping -f host", "cat --help")
  if (args.some((a) => a.startsWith('-'))) {
    return reject('ARGUMENT_INJECTION', 'Options/flags are not allowed in arguments.');
  }
  if (args.length > (cmd.maxArgs ?? MAX_ARGS) || args.length < (cmd.minArgs ?? 0)) {
    return reject('BAD_ARG_COUNT', `Usage: ${cmd.usage}`);
  }

  try {
    let result;
    if (cmd.run) {
      result = { ok: true, output: await cmd.run(args) };
    } else {
      // Layer 4 + 6 happen inside buildArgs; layer 7 + 8 inside execAllowed
      result = await execAllowed(cmd.binary, cmd.buildArgs(args));
    }
    audit({ event: 'EXECUTED', command: name, args, ip: meta.ip, ok: result.ok });
    return result;
  } catch (err) {
    if (err instanceof ValidationError) return reject('INVALID_ARGUMENT', err.message);
    audit({ event: 'ERROR', command: name, error: err.message, ip: meta.ip });
    return { ok: false, output: 'An internal error occurred.' }; // Layer 9: no stack trace
  }
}

module.exports = { runSecure, COMMANDS, SHELL_METACHARACTERS };
