'use strict';

// Umami SSO bridge.
//
// Purpose: Umami has no SSO/SAML/OIDC support and stores its session as a
// JWT in the browser's localStorage (not a cookie), so putting Umami behind
// Caddy's forward_auth alone is not enough to get a logged-in dashboard --
// Authelia can gate access to the page, but it can't populate Umami's own
// session storage.
//
// This service closes that gap. It is only ever reached for requests that
// Caddy has ALREADY sent through Authelia's forward_auth (see docker-compose
// labels), and it is additionally gated by a shared secret that only Caddy
// knows, so that no other container on the shared "caddy" network can call
// it directly and impersonate a user.
//
// Flow:
//   1. Caddy's forward_auth verifies the Authelia session and injects the
//      Remote-User (and Remote-Groups/Remote-Email) headers.
//   2. Caddy forwards the request here only if the visitor doesn't yet have
//      the local "umami_sso" marker cookie.
//   3. This service looks up the matching Umami account (by username --
//      accounts are provisioned manually, never auto-created) and, if found,
//      mints a Umami session token using the same algorithm Umami's own
//      login endpoint uses (see crypto.js). No password -- Authelia's or
//      Umami's -- is ever needed or stored here.
//   4. It returns a minimal HTML page that writes the token into
//      localStorage, sets the marker cookie, and redirects back to the
//      originally requested URL. From then on the browser looks exactly
//      like it logged into Umami directly.

const crypto = require('node:crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const { encrypt, hash, secretFromAppSecret } = require('./crypto');

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const APP_SECRET = requiredEnv('APP_SECRET');
const SHARED_SECRET = requiredEnv('SSO_BRIDGE_SHARED_SECRET');
const DATABASE_URL = requiredEnv('DATABASE_URL');

const TRUSTED_USER_HEADER = (process.env.SSO_TRUSTED_USER_HEADER || 'Remote-User').toLowerCase();
const SHARED_SECRET_HEADER = (
  process.env.SSO_SHARED_SECRET_HEADER || 'X-Internal-Bridge-Secret'
).toLowerCase();
const COOKIE_NAME = process.env.SSO_COOKIE_NAME || 'umami_sso';
const COOKIE_MAX_AGE = parseInt(process.env.SSO_COOKIE_MAX_AGE || '600', 10);

const USERNAME_RE = /^[A-Za-z0-9_.\-@]{1,255}$/;

const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

async function fetchUser(username) {
  const { rows } = await pool.query(
    'SELECT user_id, role, password FROM "user" WHERE username = $1 AND deleted_at IS NULL',
    [username],
  );
  return rows[0] || null;
}

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function safeRedirectTarget(req) {
  // Only ever redirect to a same-origin relative path we generated.
  const queryIndex = req.originalUrl.indexOf('?');
  const target = queryIndex === -1 ? req.path : req.path + req.originalUrl.slice(queryIndex);
  if (!target.startsWith('/') || target.startsWith('//')) {
    return '/';
  }
  return target;
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function sendErrorPage(res, statusCode, message) {
  const body = `<!doctype html>
<html lang="it"><head><meta charset="utf-8"><title>Accesso non riuscito</title></head>
<body style="font-family: sans-serif; max-width: 40em; margin: 4em auto; line-height: 1.5;">
<h1>Accesso non riuscito</h1>
<p>${escapeHtml(message)}</p>
</body></html>`;
  res
    .status(statusCode)
    .set('Cache-Control', 'no-store')
    .set('X-Content-Type-Options', 'nosniff')
    .type('html')
    .send(body);
}

function sendBootstrapPage(res, token, redirectTarget, nonce) {
  const body = `<!doctype html>
<html lang="it"><head><meta charset="utf-8"><title>Accesso in corso&hellip;</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 4em;">
<p>Accesso in corso&hellip;</p>
<noscript>Devi abilitare JavaScript per accedere a Umami.</noscript>
<script nonce="${nonce}">
// Umami's own storage helper JSON-encodes values before writing them
// (src/lib/storage.ts: localStorage.setItem(key, JSON.stringify(data))),
// so the token must be JSON-stringified at runtime here too, not just
// safely embedded as a JS literal -- otherwise Umami's getItem() calls
// JSON.parse() on a raw, unquoted string, fails, and silently treats the
// session as absent.
var token = ${JSON.stringify(token)};
localStorage.setItem("umami.auth", JSON.stringify(token));
window.location.replace(${JSON.stringify(redirectTarget)});
</script>
</body></html>`;
  res
    .status(200)
    .set('Cache-Control', 'no-store')
    .set('X-Content-Type-Options', 'nosniff')
    .set(
      'Content-Security-Policy',
      `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'`,
    )
    .set(
      'Set-Cookie',
      `${COOKIE_NAME}=1; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
    )
    .type('html')
    .send(body);
}

const app = express();
app.disable('x-powered-by');

app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.type('text/plain').send('ok');
  } catch (err) {
    console.error('healthz failed:', err.message);
    res.status(503).type('text/plain').send('db unreachable');
  }
});

app.get(/.*/, async (req, res) => {
  const providedSecret = req.headers[SHARED_SECRET_HEADER];
  if (!safeCompare(providedSecret, SHARED_SECRET)) {
    console.warn(`rejected request without a valid bridge secret (path=${req.path})`);
    return sendErrorPage(res, 403, 'Richiesta non autorizzata.');
  }

  const username = req.headers[TRUSTED_USER_HEADER];
  if (!username || !USERNAME_RE.test(username)) {
    console.warn(`missing/invalid ${TRUSTED_USER_HEADER} header`);
    return sendErrorPage(res, 400, 'Identità non trasmessa correttamente da Authelia.');
  }

  let user;
  try {
    user = await fetchUser(username);
  } catch (err) {
    console.error('user lookup failed:', err.message);
    return sendErrorPage(res, 500, "Errore interno durante la verifica dell'account.");
  }

  if (!user) {
    console.warn(`authenticated user '${username}' has no matching Umami account`);
    return sendErrorPage(
      res,
      403,
      'Il tuo account è autenticato ma non esiste un utente Umami ' +
        'corrispondente. Contatta un amministratore per farlo creare.',
    );
  }

  const secret = secretFromAppSecret(APP_SECRET);
  const payload = {
    userId: String(user.user_id),
    role: user.role,
    pwd: hash(user.password),
  };
  const token = encrypt(jwt.sign(payload, secret), secret);

  console.log(`minted Umami session for user '${username}'`);
  const nonce = crypto.randomBytes(16).toString('hex');
  sendBootstrapPage(res, token, safeRedirectTarget(req), nonce);
});

const port = 8000;
app.listen(port, '0.0.0.0', () => {
  console.log(`sso-bridge listening on 0.0.0.0:${port}`);
});
