#!/bin/sh
set -eu
export LC_ALL=C

for task_file in /db/migrations/[0-9][0-9][0-9]_*.sql; do
  [ -f "$task_file" ] || { echo 'No hay migraciones SQL' >&2; exit 1; }
  export MIGRATION_NAME="${task_file##*/}"
  case "$MIGRATION_NAME" in
    *[!0-9A-Za-z_.-]*) echo 'Nombre de migración inválido' >&2; exit 1 ;;
  esac
  export MIGRATION_PATH="$task_file"
  MIGRATION_CHECKSUM=$(sha256sum "$task_file")
  export MIGRATION_CHECKSUM="${MIGRATION_CHECKSUM%% *}"
  psql -X --no-password --set ON_ERROR_STOP=1 --file /db/migrate.sql
done
