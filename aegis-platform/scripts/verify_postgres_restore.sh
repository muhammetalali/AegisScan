#!/bin/sh
set -eu

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:=5432}"
: "${PGUSER:?PGUSER is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"

backup="${1:?usage: verify_postgres_restore.sh BACKUP.dump}"
test -f "$backup"
test -f "${backup}.sha256"
(cd "$(dirname "$backup")" && sha256sum -c "$(basename "$backup").sha256")

restore_db="aegis_restore_verify_$(date -u +%Y%m%d%H%M%S)_$$"
case "$restore_db" in (*[!a-zA-Z0-9_]*) echo 'unsafe restore database name' >&2; exit 2;; esac
cleanup() { dropdb --if-exists "$restore_db" >/dev/null 2>&1 || true; }
trap cleanup EXIT HUP INT TERM

createdb "$restore_db"
pg_restore --exit-on-error --no-owner --no-acl --dbname="$restore_db" "$backup"

required="${AEGIS_RESTORE_REQUIRED_TABLES:-django_migrations,users_user}"
old_ifs="$IFS"; IFS=','
for table in $required; do
  IFS="$old_ifs"
  case "$table" in (*[!a-zA-Z0-9_]*) echo "unsafe required table: $table" >&2; exit 2;; esac
  exists="$(psql --dbname="$restore_db" --tuples-only --no-align --command="SELECT to_regclass('public.$table') IS NOT NULL")"
  test "$exists" = "t" || { echo "required restored table is missing: $table" >&2; exit 1; }
  IFS=','
done
IFS="$old_ifs"
printf 'RESTORE_VERIFICATION=PASS database=%s\n' "$restore_db"
