#!/bin/sh
set -eu

COMMAND="${1:-}"
if [ "$COMMAND" != "issue" ] && [ "$COMMAND" != "renew" ]; then
  echo "usage: production_tls_acme.sh issue|renew" >&2
  exit 2
fi

: "${AEGIS_PUBLIC_DOMAIN:?AEGIS_PUBLIC_DOMAIN is required}"
: "${AEGIS_ACME_EMAIL:?AEGIS_ACME_EMAIL is required}"
: "${AEGIS_PRODUCTION_ENV_FILE:?AEGIS_PRODUCTION_ENV_FILE is required}"

case "$AEGIS_PUBLIC_DOMAIN" in
  *[!A-Za-z0-9.-]*|.*|*..*|*.) echo "invalid AEGIS_PUBLIC_DOMAIN" >&2; exit 2 ;;
esac
case "$AEGIS_ACME_EMAIL" in
  *@*.*) ;;
  *) echo "invalid AEGIS_ACME_EMAIL" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "TLS issuance must run as root" >&2
  exit 1
fi
if [ ! -r "$AEGIS_PRODUCTION_ENV_FILE" ]; then
  echo "production env file is missing or unreadable" >&2
  exit 1
fi
mode="$(stat -c '%a' "$AEGIS_PRODUCTION_ENV_FILE")"
group_other="$((8#$mode & 077))"
if [ "$group_other" -ne 0 ]; then
  echo "production env file must not be accessible by group or others" >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PLATFORM_DIR="$(dirname "$SCRIPT_DIR")"
SSL_DIR="$PLATFORM_DIR/docker/ssl"
LIVE_DIR="/etc/letsencrypt/live/$AEGIS_PUBLIC_DOMAIN"

compose() {
  docker compose --env-file "$AEGIS_PRODUCTION_ENV_FILE" \
    -f "$PLATFORM_DIR/docker-compose.yml" \
    -f "$PLATFORM_DIR/docker-compose.prod.yml" \
    -f "$PLATFORM_DIR/docker-compose.monitoring.yml" \
    -f "$PLATFORM_DIR/docker-compose.backup.yml" "$@"
}

nginx_was_running=0
if compose ps --status running --services 2>/dev/null | grep -qx nginx; then
  nginx_was_running=1
  compose stop nginx
fi

restart_nginx() {
  if [ "$nginx_was_running" -eq 1 ]; then
    compose start nginx >/dev/null 2>&1 || true
  fi
}
trap restart_nginx EXIT HUP INT TERM

if [ "$COMMAND" = "issue" ]; then
  certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --no-eff-email \
    --email "$AEGIS_ACME_EMAIL" \
    --cert-name "$AEGIS_PUBLIC_DOMAIN" \
    --key-type ecdsa \
    -d "$AEGIS_PUBLIC_DOMAIN"
else
  certbot renew \
    --non-interactive \
    --cert-name "$AEGIS_PUBLIC_DOMAIN"
fi

test -s "$LIVE_DIR/fullchain.pem"
test -s "$LIVE_DIR/privkey.pem"
openssl x509 -checkend 604800 -noout -in "$LIVE_DIR/fullchain.pem"
cert_pub="$(openssl x509 -in "$LIVE_DIR/fullchain.pem" -pubkey -noout)"
key_pub="$(openssl pkey -in "$LIVE_DIR/privkey.pem" -pubout)"
test "$cert_pub" = "$key_pub"

install -d -m 0700 "$SSL_DIR"
install -m 0644 "$LIVE_DIR/fullchain.pem" "$SSL_DIR/fullchain.pem"
install -m 0600 "$LIVE_DIR/privkey.pem" "$SSL_DIR/privkey.pem"

trap - EXIT HUP INT TERM
if [ "$nginx_was_running" -eq 1 ]; then
  compose start nginx
fi

openssl x509 -subject -issuer -dates -noout -in "$SSL_DIR/fullchain.pem"
printf '%s\n' "AEGISSCAN_TLS_ACME=PASS domain=$AEGIS_PUBLIC_DOMAIN command=$COMMAND"
