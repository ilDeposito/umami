#!/bin/sh
# Dedicated, least-privilege Postgres role for the SSO bridge.
#
# This only creates the role and lets it connect/see the schema. It
# deliberately does NOT grant SELECT on the "user" table here: at first
# initialization this script runs before Umami has created its schema
# (Umami's own container runs the Prisma migrations on startup, not
# Postgres' initdb), so that grant would fail on a brand-new volume.
#
# Run the grant once, after the stack has come up at least once (fresh
# install or existing one, same command either way):
#
#   docker exec ildeposito_stats_postgres psql -U umami -d umami -c \
#     'GRANT SELECT (user_id, username, password, role, deleted_at) ON public."user" TO umami_sso_bridge;'
#
# This script itself only runs automatically on a brand-new database
# volume (docker-entrypoint-initdb.d scripts run once, at first
# initialization). If umami-db-data already existed before this file was
# added, Postgres never ran it -- run it by hand once (safe to re-run,
# e.g. after rotating SSO_BRIDGE_DB_PASSWORD). It's already present inside
# the container via the read-only bind mount, so no copying needed:
#
#   docker exec -e SSO_BRIDGE_DB_PASSWORD="$(grep -oP '(?<=^SSO_BRIDGE_DB_PASSWORD=).*' .env)" \
#     ildeposito_stats_postgres sh /docker-entrypoint-initdb.d/01-sso-bridge-role.sh

set -eu

: "${SSO_BRIDGE_DB_PASSWORD:?SSO_BRIDGE_DB_PASSWORD must be set on the db service}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
    DO \$\$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'umami_sso_bridge') THEN
        CREATE ROLE umami_sso_bridge LOGIN PASSWORD '${SSO_BRIDGE_DB_PASSWORD}';
      ELSE
        ALTER ROLE umami_sso_bridge WITH PASSWORD '${SSO_BRIDGE_DB_PASSWORD}';
      END IF;
    END
    \$\$;

    GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO umami_sso_bridge;
    GRANT USAGE ON SCHEMA public TO umami_sso_bridge;
SQL
