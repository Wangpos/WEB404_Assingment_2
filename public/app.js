// Front-end for the web CLI. All output is written with textContent (never
// innerHTML) so command output can't inject HTML/JS into the page (XSS).
(function () {
  const output = document.getElementById('output');
  const form = document.getElementById('prompt-form');
  const input = document.getElementById('cmd');
  const promptLabel = document.getElementById('prompt-label');
  const banner = document.getElementById('banner');
  const terminal = document.getElementById('terminal');

  const history = [];
  let historyIndex = 0;
  let mode = 'secure';

  const BANNERS = {
    secure: 'SECURE MODE: allowlisted commands, validated arguments, execFile() with no shell.',
    vulnerable: 'VULNERABLE MODE: input is concatenated into a shell string and run with exec(). Demo only!',
  };

  function print(text, cls) {
    const div = document.createElement('div');
    div.className = 'line ' + (cls || 'ok');
    div.textContent = text;
    output.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
  }

  function setMode(next) {
    mode = next;
    banner.textContent = BANNERS[mode];
    banner.className = 'banner ' + mode;
    promptLabel.textContent = mode + '@web-cli:~$';
    promptLabel.className = 'prompt ' + mode;
    print('--- switched to ' + mode.toUpperCase() + ' mode ---', 'meta');
    input.focus();
  }

  async function run(command) {
    print(promptLabel.textContent + ' ' + command, 'cmd');
    if (command.trim() === 'clear') {
      output.textContent = '';
      return;
    }
    input.disabled = true;
    try {
      const res = await fetch('/api/' + mode + '/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: command }),
      });
      const data = await res.json();
      if (data.executed) print('[server ran] ' + data.executed, 'meta');
      if (data.output) print(data.output, data.blocked ? 'blocked' : data.ok ? 'ok' : 'err');
    } catch (e) {
      print('Request failed: ' + e.message, 'err');
    } finally {
      input.disabled = false;
      input.focus();
    }
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    const command = input.value;
    if (!command.trim()) return;
    history.push(command);
    historyIndex = history.length;
    input.value = '';
    run(command);
  });

  input.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowUp' && historyIndex > 0) {
      input.value = history[--historyIndex];
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      historyIndex = Math.min(historyIndex + 1, history.length);
      input.value = history[historyIndex] || '';
      e.preventDefault();
    }
  });

  document.querySelectorAll('input[name="mode"]').forEach(function (radio) {
    radio.addEventListener('change', function () { setMode(radio.value); });
  });

  document.querySelectorAll('.hints button').forEach(function (btn) {
    btn.addEventListener('click', function () {
      input.value = btn.dataset.cmd;
      input.focus();
    });
  });

  terminal.addEventListener('click', function () { input.focus(); });

  print("Welcome to the WEB404 Web CLI. Type 'help' to see available commands.", 'meta');
})();
