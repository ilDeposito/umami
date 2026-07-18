# umami

Self-hosted Umami analytics behind Caddy (caddy-docker-proxy), with SSO via
Authelia.

## SSO architecture

Umami has no SSO/SAML/OIDC support of its own, and its browser session is
not a cookie — it's a JWT kept in `localStorage`. So Authelia/forward_auth
alone can gate *access to the page*, but can't make Umami itself think the
visitor is logged in. This stack adds a small internal service,
`sso-bridge` (`sso-bridge/`), that closes that gap:

1. Anonymous visit to `stats.ildeposito.org` → Caddy's `forward_auth` sends
   it to Authelia (`auth.ildeposito.org`) → user logs in under whatever
   rules you configure there → Authelia redirects back with the identity
   injected via the `Remote-User` / `Remote-Groups` / `Remote-Email`
   headers.
2. If the browser doesn't yet have the local `umami_sso` marker cookie,
   Caddy routes that first request to `sso-bridge` instead of Umami.
3. `sso-bridge` looks up the Umami account with that exact username
   (accounts are **not** auto-provisioned — see below), and mints a Umami
   session token using the same algorithm Umami's own `/api/auth/login`
   uses (`sso-bridge/crypto.js`, ported directly from Umami's own
   `src/lib/crypto.ts`). It never needs, sees, or stores any password —
   Authelia's or Umami's.
4. It returns a tiny HTML page that writes that token into
   `localStorage`, sets the `umami_sso` cookie, and redirects to the
   originally requested URL. From then on the browser looks exactly like
   it logged into Umami directly, and normal navigation goes straight to
   Umami (step 2 is skipped while the marker cookie is valid).

Everything else is unauthenticated by design, matching how Umami is meant
to be embedded/used:

- `/script.js` and `/api/send*` — the tracking snippet and the collection
  endpoint, used by anonymous visitors on any site embedding Umami.
- `/api/*` (except `/api/auth/login`) — the REST API enforces its own
  Bearer/API-key auth already; gating it with Authelia too would break
  legitimate external API-key consumers.
- `/login` and `/api/auth/login` — Umami's own credential login is
  disabled (`/login` redirects home, `/api/auth/login` 404s). Authelia is
  the only front door.

Caddy routing lives entirely in `docker-compose.yml` labels on the `umami`
service (`caddy_0.*`), as a single explicit `route` block so execution
order doesn't depend on Caddy's automatic directive sorting.

### Security properties

- **No password duplication.** `sso-bridge` mints tokens by reading the
  user's *existing* bcrypt password hash from Postgres and re-hashing it
  (`sha512`) the same way Umami's login route does — it doesn't need
  plaintext credentials from either system. Changing a user's Umami
  password immediately invalidates their old tokens, same as with normal
  login.
- **Least-privilege DB access.** `sso-bridge` connects as `umami_sso_bridge`,
  a role that can only `SELECT` the `user_id, username, password, role,
  deleted_at` columns of the `user` table (see `db-init/`). It cannot read
  analytics data or write anything.
- **Shared-secret gate.** The `caddy` Docker network is shared with other
  services, so `sso-bridge` also requires a secret header
  (`X-Internal-Bridge-Secret`, from `SSO_BRIDGE_SHARED_SECRET`) that only
  Caddy sets — any incoming copy of that header is stripped before
  `forward_auth` runs, so nothing upstream of Caddy can forge it, and no
  other container on the network can call the bridge directly and
  impersonate a user.
- **No auto-provisioning.** An Authelia-authenticated user with no
  matching Umami account gets a clear 403, not a freshly created account
  with unknown permissions. Create Umami accounts by hand, with the exact
  same username used in Authelia.
- **Umami's own auth stays defused.** `/login` and `/api/auth/login` are
  blocked at Caddy, so there's no second, weaker credential-guessing
  surface sitting next to SSO.

### First-time / one-time setup

1. Generate secrets and fill in `.env` (see `.env.example`):
   `APP_SECRET`, `POSTGRES_PASSWORD`, `SSO_BRIDGE_DB_PASSWORD`,
   `SSO_BRIDGE_SHARED_SECRET` (`openssl rand -hex 32` for each).
2. In Authelia's own configuration (outside this repo), add an
   `access_control` rule for `stats.ildeposito.org` with whatever
   subjects/groups you want to allow.
3. `docker compose up -d`.
4. Grant the bridge role read access to the `user` table — this can't be
   done automatically at DB-init time because Umami's schema doesn't
   exist yet at that point (Umami creates it via Prisma migrations on its
   own first startup, after Postgres init scripts have already run):
   ```
   docker exec ildeposito_stats_postgres psql -U umami -d umami -c \
     'GRANT SELECT (user_id, username, password, role, deleted_at) ON public."user" TO umami_sso_bridge;'
   ```
   Needed once, whether this is a brand-new deployment or an existing one.
5. Create a Umami user (Umami admin UI, using a temporary/throwaway
   password since it will never actually be used to log in) whose
   username exactly matches the Authelia username for each person who
   should have access.

### Known limitation

The `umami_sso` marker cookie (`SSO_COOKIE_MAX_AGE`, default 10 minutes)
is what avoids re-minting a token on every single page load. If someone
clears Umami's `localStorage` (or opens a different browser) while that
cookie is still valid, they'll see Umami's own "not logged in" state until
the cookie expires and the bridge re-runs. Lower `SSO_COOKIE_MAX_AGE` if
that's not an acceptable tradeoff for your use.
