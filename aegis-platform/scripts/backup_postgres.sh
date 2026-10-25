#!/bin/sh
set -eu

: "${PGHOST:?PGHOST is required}"
: "${PGPORT:=5432}"
: "${PGUSER:?PGUSER is required}"
: "${PGDATABASE:?PGDATABASE is required}"
: "${PGPASSWORD:?PGPASSWORD is required}"
: "${AEGIS_BACKUP_DIR:?AEGIS_BACKUP_DIR is required}"

umask 077
mkdir -p "$AEGIS_BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$AEGIS_BACKUP_DIR/aegisscan-${PGDATABASE}-${stamp}.dump"
temporary="${final}.partial"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

# The backup service can be created alongside PostgreSQL during a release.
# Wait briefly for the local DB socket instead of treating boot ordering as
# a failed daily backup; its existing scheduler handles longer outages.
attempt=0
until pg_isready -q -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE"; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 6 ]; then
    printf '%s\n' 'BACKUP_PG_PREFLIGHT=not_ready' >&2
    exit 1
  fi
  sleep 2
done

pg_dump --format=custom --compress=9 --no-owner --no-acl --file="$temporary" "$PGDATABASE"
pg_restore --list "$temporary" >/dev/null
mv "$temporary" "$final"
sha256sum "$final" >"${final}.sha256"
chmod 0600 "$final" "${final}.sha256"

if [ "${AEGIS_BACKUP_RETENTION_DAYS:-0}" -gt 0 ]; then
  find "$AEGIS_BACKUP_DIR" -type f \( -name 'aegisscan-*.dump' -o -name 'aegisscan-*.dump.sha256' \) \
    -mtime "+${AEGIS_BACKUP_RETENTION_DAYS}" -delete
fi
printf '%s\n' "$final"
