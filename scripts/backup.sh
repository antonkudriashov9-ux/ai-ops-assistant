#!/usr/bin/env bash
# ==============================================================================
# Automated PostgreSQL Backup Script with 7-Day Retention
# ==============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/aiops}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CONTAINER_NAME="aiops_postgres"
DB_NAME="${POSTGRES_DB:-aiops}"
DB_USER="${POSTGRES_USER:-postgres}"
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[INFO] Starting database backup: ${DB_NAME} at ${TIMESTAMP}"

# Dump and compress on the fly
docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" "${DB_NAME}" | gzip > "${BACKUP_FILE}"

# Verify backup size > 0
if [[ -s "${BACKUP_FILE}" ]]; then
    echo "[SUCCESS] Backup created successfully: ${BACKUP_FILE} ($(du -h "${BACKUP_FILE}" | cut -f1))"
else
    echo "[ERROR] Backup file is empty!" >&2
    exit 1
fi

# Rotate backups older than 7 days
echo "[INFO] Removing backups older than 7 days..."
find "${BACKUP_DIR}" -type f -name "*.sql.gz" -mtime +7 -delete

echo "[INFO] Backup process completed."
