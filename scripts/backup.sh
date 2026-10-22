#!/usr/bin/env bash
set -euo pipefail
umask 077

PROJECT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo 'Invalid retention days' >&2; exit 1; }
mkdir -p -- "$BACKUP_DIR"
TIMESTAMP=$(date -u +'%Y%m%dT%H%M%SZ')
TEMPORARY=$(mktemp "$BACKUP_DIR/.aiops-postgres-${TIMESTAMP}-XXXXXX")
trap 'rm -f -- "$TEMPORARY"' EXIT
NAME="${TEMPORARY##*/}"
BACKUP_FILE="$BACKUP_DIR/${NAME#.}.sql.gz"

docker compose --project-directory "$PROJECT_ROOT" -f "$PROJECT_ROOT/docker-compose.yml" \
  exec -T postgres sh -c 'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  | gzip > "$TEMPORARY"
gzip -t -- "$TEMPORARY"
[[ $(gzip -dc -- "$TEMPORARY" | wc -c) -gt 0 ]] || { echo 'Empty database dump' >&2; exit 1; }
mv -- "$TEMPORARY" "$BACKUP_FILE"
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'aiops-postgres-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
printf 'Backup saved: %s\n' "$BACKUP_FILE"
