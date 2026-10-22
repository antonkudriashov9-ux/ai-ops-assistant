#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sandbox=$(mktemp -d "${TMPDIR:-/tmp}/aiops-backup-test.XXXXXX")
case "$sandbox" in */aiops-backup-test.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$sandbox"' EXIT
mkdir -p "$sandbox/bin" "$sandbox/backups"
cat > "$sandbox/bin/docker" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ " $* " == *" exec -T postgres "* ]] || exit 5
if [[ ${FAKE_DOCKER_FAIL:-0} == 1 ]]; then
  printf 'partial dump'
  exit 1
fi
printf '%s\n' '-- PostgreSQL database dump' 'SELECT 1;'
FAKE
chmod +x "$sandbox/bin/docker"
export PATH="$sandbox/bin:$PATH" BACKUP_DIR="$sandbox/backups"
touch "$BACKUP_DIR/unrelated.sql.gz" "$BACKUP_DIR/aiops-postgres-old.sql.gz"
touch -t 200001010000 "$BACKUP_DIR/unrelated.sql.gz" "$BACKUP_DIR/aiops-postgres-old.sql.gz"
bash "$project_root/scripts/backup.sh"
[[ -f "$BACKUP_DIR/unrelated.sql.gz" ]]
[[ ! -f "$BACKUP_DIR/aiops-postgres-old.sql.gz" ]]
mapfile -t backups < <(find "$BACKUP_DIR" -name 'aiops-postgres-*.sql.gz')
[[ ${#backups[@]} == 1 ]]
gzip -t "${backups[0]}"
gzip -dc "${backups[0]}" | grep -q 'SELECT 1;'
if FAKE_DOCKER_FAIL=1 bash "$project_root/scripts/backup.sh"; then
  echo 'failed dump must not report success' >&2
  exit 1
fi
[[ $(find "$BACKUP_DIR" -name 'aiops-postgres-*.sql.gz' | wc -l) == 1 ]]
[[ $(find "$BACKUP_DIR" -name '.aiops-postgres-*' | wc -l) == 0 ]]
printf '%s\n' 'Backup regression tests passed'
