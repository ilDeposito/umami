"""
Umami SSO bridge.

Purpose: Umami has no SSO/SAML/OIDC support and stores its session as a
JWT in the browser's localStorage (not a cookie), so putting Umami behind
Caddy's forward_auth alone is not enough to get a logged-in dashboard --
Authelia can gate access to the page, but it can't populate Umami's own
session storage.

This service closes that gap. It is only ever reached for requests that
Caddy has ALREADY sent through Authelia's forward_auth (see docker-compose
labels), and it is additionally gated by a shared secret that only Caddy
knows, so that no other container on the shared "caddy" network can call
it directly and impersonate a user.

Flow:
  1. Caddy's forward_auth verifies the Authelia session and injects the
     Remote-User (and Remote-Groups/Remote-Email) headers.
  2. Caddy forwards the request here only if the visitor doesn't yet have
     the local "umami_sso" marker cookie.
  3. This service looks up the matching Umami account (by username --
     accounts are provisioned manually, never auto-created) and, if found,
     mints a Umami session token using the same algorithm Umami's own
     login endpoint uses (see crypto.py). No password -- Authelia's or
     Umami's -- is ever needed or stored here.
  4. It returns a minimal HTML page that writes the token into
     localStorage, sets the marker cookie, and redirects back to the
     originally requested URL. From then on the browser looks exactly
     like it logged into Umami directly.
"""

import html
import json
import logging
import os
import re
import secrets
from contextlib import contextmanager

import psycopg2
import psycopg2.pool
from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

import crypto

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("umami-sso-bridge")


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


APP_SECRET = _required_env("APP_SECRET")
SHARED_SECRET = _required_env("SSO_BRIDGE_SHARED_SECRET")
DATABASE_URL = _required_env("DATABASE_URL")

TRUSTED_USER_HEADER = os.environ.get("SSO_TRUSTED_USER_HEADER", "Remote-User")
SHARED_SECRET_HEADER = os.environ.get("SSO_SHARED_SECRET_HEADER", "X-Internal-Bridge-Secret")
COOKIE_NAME = os.environ.get("SSO_COOKIE_NAME", "umami_sso")
COOKIE_MAX_AGE = int(os.environ.get("SSO_COOKIE_MAX_AGE", "600"))

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-@]{1,255}$")

_pool = psycopg2.pool.ThreadedConnectionPool(minconn=1, maxconn=5, dsn=DATABASE_URL)

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)


@contextmanager
def _connection():
    conn = _pool.getconn()
    try:
        yield conn
    finally:
        _pool.putconn(conn)


def _fetch_user(username: str):
    with _connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id, role, password
            FROM "user"
            WHERE username = %s AND deleted_at IS NULL
            """,
            (username,),
        )
        return cur.fetchone()


def _safe_redirect_target(request: Request) -> str:
    """Only ever redirect to a same-origin relative path we generated."""
    target = request.url.path or "/"
    if request.url.query:
        target += "?" + request.url.query
    if not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


def _error_page(status_code: int, message: str) -> HTMLResponse:
    safe_message = html.escape(message)
    body = f"""<!doctype html>
<html lang="it"><head><meta charset="utf-8"><title>Accesso non riuscito</title></head>
<body style="font-family: sans-serif; max-width: 40em; margin: 4em auto; line-height: 1.5;">
<h1>Accesso non riuscito</h1>
<p>{safe_message}</p>
</body></html>"""
    return HTMLResponse(
        body,
        status_code=status_code,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def _bootstrap_page(token: str, redirect_target: str, nonce: str) -> HTMLResponse:
    token_json = json.dumps(token)
    target_json = json.dumps(redirect_target)
    body = f"""<!doctype html>
<html lang="it"><head><meta charset="utf-8"><title>Accesso in corso&hellip;</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 4em;">
<p>Accesso in corso&hellip;</p>
<noscript>Devi abilitare JavaScript per accedere a Umami.</noscript>
<script nonce="{nonce}">
localStorage.setItem("umami.auth", {token_json});
window.location.replace({target_json});
</script>
</body></html>"""
    nonce_csp = f"default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'"
    return HTMLResponse(
        body,
        status_code=200,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": nonce_csp,
            "Set-Cookie": (
                f"{COOKIE_NAME}=1; Path=/; Max-Age={COOKIE_MAX_AGE}; "
                "HttpOnly; Secure; SameSite=Lax"
            ),
        },
    )


@app.get("/healthz")
def healthz():
    try:
        with _connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        log.error("healthz failed: %s", exc)
        return PlainTextResponse("db unreachable", status_code=503)
    return PlainTextResponse("ok")


@app.api_route("/{full_path:path}", methods=["GET", "HEAD"])
def bootstrap(
    request: Request,
    full_path: str,
    x_internal_bridge_secret: str | None = Header(default=None, alias=SHARED_SECRET_HEADER),
):
    if not x_internal_bridge_secret or not secrets.compare_digest(
        x_internal_bridge_secret, SHARED_SECRET
    ):
        log.warning("rejected request without a valid bridge secret (path=%s)", full_path)
        return _error_page(403, "Richiesta non autorizzata.")

    username = request.headers.get(TRUSTED_USER_HEADER)
    if not username or not _USERNAME_RE.match(username):
        log.warning("missing/invalid %s header", TRUSTED_USER_HEADER)
        return _error_page(400, "Identità non trasmessa correttamente da Authelia.")

    row = _fetch_user(username)
    if not row:
        log.warning("authenticated user %r has no matching Umami account", username)
        return _error_page(
            403,
            "Il tuo account è autenticato ma non esiste un utente Umami "
            "corrispondente. Contatta un amministratore per farlo creare.",
        )

    user_id, role, password_hash = row
    token = crypto.create_secure_token(
        {
            "userId": str(user_id),
            "role": role,
            "pwd": crypto.password_fingerprint(password_hash),
        },
        APP_SECRET,
    )

    log.info("minted Umami session for user %r", username)
    nonce = secrets.token_hex(16)
    return _bootstrap_page(token, _safe_redirect_target(request), nonce)
