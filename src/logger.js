// Append-only JSON-lines audit log, so blocked injection attempts can be reviewed.
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'audit.log');

function audit(entry) {
  const line = JSON.stringify({ time: new Date().toISOString(), ...entry });
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch {
    // Logging must never break the request
  }
  if (entry.event === 'BLOCKED' && process.env.NODE_ENV !== 'test') {
    console.warn(`[SECURITY] ${entry.reason}: ${JSON.stringify(entry.input)}`);
  }
}

module.exports = { audit, LOG_FILE };
