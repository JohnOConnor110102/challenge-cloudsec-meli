#!/bin/sh
set -eu
umask 077

task_password=$(cat "$DB_PASSWORD_FILE")
case "$task_password" in
  *[!0-9a-f]*|'') echo 'Secreto PostgreSQL inválido' >&2; exit 1 ;;
esac
[ "${#task_password}" -eq 64 ] || { echo 'Secreto PostgreSQL inválido' >&2; exit 1; }
task_pgpass=$(mktemp)
trap 'rm -f "$task_pgpass"' EXIT HUP INT TERM
printf '%s:%s:%s:%s:%s\n' "$PGHOST" "$PGPORT" "$PGDATABASE" "$PGUSER" "$task_password" > "$task_pgpass"
unset task_password
export PGPASSFILE="$task_pgpass"
"$@"
