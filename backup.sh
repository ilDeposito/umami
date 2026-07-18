#!/usr/bin/env bash
#
# Backup del database Postgres di Umami (self-hosted, via docker compose).
# Crea un dump compresso bz2 con timestamp in BACKUP_DIR e applica la
# retention (mantiene solo gli ultimi RETENTION file).
#
# Destinazione finale prevista: /home/ubuntu/sergej/websites/umami/backup/
# Installazione in crontab (esempio: ogni notte alle 03:00):
#   0 3 * * * /home/ubuntu/sergej/websites/umami/backup/umami-backup.sh >> /home/ubuntu/sergej/websites/umami/backup/backup.log 2>&1
#
set -euo pipefail

# ---- Config ----
CONTAINER_DB="ildeposito_stats_postgres"
BACKUP_DIR="/home/ubuntu/sergej/websites/umami/backup"
RETENTION=30
LOCK_FILE="/tmp/umami-backup.lock"

# ---- Lock: evita esecuzioni sovrapposte se il dump precedente è ancora in corso ----
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "[$(date '+%F %T')] Backup già in esecuzione, esco." >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# ---- Verifica che il container sia up ----
if ! docker inspect -f '{{.State.Running}}' "$CONTAINER_DB" 2>/dev/null | grep -q true; then
    echo "[$(date '+%F %T')] ERRORE: container ${CONTAINER_DB} non in esecuzione." >&2
    exit 1
fi

# ---- Credenziali DB lette dall'ambiente del container (niente hardcoding) ----
DB_USER=$(docker exec "$CONTAINER_DB" printenv POSTGRES_USER)
DB_NAME=$(docker exec "$CONTAINER_DB" printenv POSTGRES_DB)

if [[ -z "$DB_USER" || -z "$DB_NAME" ]]; then
    echo "[$(date '+%F %T')] ERRORE: impossibile leggere POSTGRES_USER/POSTGRES_DB dal container ${CONTAINER_DB}." >&2
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DUMP_FILE="${BACKUP_DIR}/umami-${TIMESTAMP}.sql.bz2"
TMP_FILE="${DUMP_FILE}.tmp"

echo "[$(date '+%F %T')] Avvio backup di ${DB_NAME}@${CONTAINER_DB} -> ${DUMP_FILE}"

if docker exec "$CONTAINER_DB" pg_dump -U "$DB_USER" "$DB_NAME" | bzip2 -9 > "$TMP_FILE"; then
    mv "$TMP_FILE" "$DUMP_FILE"
    echo "[$(date '+%F %T')] Backup completato ($(du -h "$DUMP_FILE" | cut -f1))"
else
    echo "[$(date '+%F %T')] ERRORE durante pg_dump/compressione." >&2
    rm -f "$TMP_FILE"
    exit 1
fi

# ---- Retention: mantiene solo gli ultimi RETENTION dump ----
cd "$BACKUP_DIR"
BACKUP_COUNT=$(ls -1 umami-*.sql.bz2 2>/dev/null | wc -l | tr -d ' ')
if [[ "$BACKUP_COUNT" -gt "$RETENTION" ]]; then
    ls -1t umami-*.sql.bz2 | tail -n +"$((RETENTION + 1))" | while read -r old; do
        rm -f -- "$old"
        echo "[$(date '+%F %T')] Rimosso backup obsoleto: ${old}"
    done
fi

echo "[$(date '+%F %T')] Fine. Backup presenti: $(ls -1 umami-*.sql.bz2 2>/dev/null | wc -l | tr -d ' ')/${RETENTION}"