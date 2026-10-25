const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { runSecure } = require('./src/secure');
const { runVulnerable } = require('./src/vulnerable');

const HOST = '127.0.0.1'; // bind to localhost only — the vulnerable endpoint must never be reachable remotely
const PORT = Number(process.env.PORT) || 3000;

const app = express();
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        upgradeInsecureRequests: null, // the demo runs over plain http on localhost
      },
    },
  })
);
app.use(express.json({ limit: '1kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const secureLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, output: 'Too many requests. Please slow down.' },
});

app.post('/api/secure/run', secureLimiter, async (req, res) => {
  const result = await runSecure(req.body && req.body.command, { ip: req.ip });
  res.status(result.blocked ? 400 : 200).json(result);
});

if (process.env.DISABLE_VULNERABLE !== 'true') {
  app.post('/api/vulnerable/run', async (req, res) => {
    res.json(await runVulnerable(req.body && req.body.command));
  });
}

// Generic error handler — no stack traces to the client
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({ ok: false, output: 'Bad request.' });
});

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`Web CLI running at http://${HOST}:${PORT}`);
    console.log('  Secure endpoint:     POST /api/secure/run');
    if (process.env.DISABLE_VULNERABLE !== 'true') {
      console.log('  Vulnerable endpoint: POST /api/vulnerable/run  (demo only!)');
    }
  });
}

module.exports = app;
