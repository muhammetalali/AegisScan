#!/bin/sh
set -eu

TABLE='aegis_egress'
CHAIN='egress'
IFACE="${SCANNER_EGRESS_INTERFACE:-eth0}"
CONTROL_ENDPOINTS="${SCANNER_CONTROL_ENDPOINTS:-postgres:5432/tcp,redis:6379/tcp,django:8000/tcp}"
PRIVATE_TARGETS="${SCANNER_EGRESS_PRIVATE_TARGETS:-}"

log() {
  printf '[scanner-egress] %s\n' "$*"
}

fail() {
  printf '[scanner-egress] ERROR: %s\n' "$*" >&2
  exit 1
}

validate_token() {
  value="$1"
  printf '%s' "$value" | grep -Eq '^[A-Za-z0-9._:/-]+$' || fail "unsafe policy token: $value"
}

resolve_host() {
  host="$1"
  validate_token "$host"
  attempt=1
  while [ "$attempt" -le 30 ]; do
    addresses="$(getent hosts "$host" 2>/dev/null | awk '{print $1}' | sort -u || true)"
    if [ -n "$addresses" ]; then
      printf '%s\n' "$addresses"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  fail "unable to resolve required policy host: $host"
}

add_allow_address() {
  address="$1"
  port="${2:-}"
  proto="${3:-tcp}"
  validate_token "$address"
  if printf '%s' "$address" | grep -q ':'; then
    family='ip6'
  else
    family='ip'
  fi
  if [ -n "$port" ]; then
    validate_token "$port"
    nft add rule netdev "$TABLE" "$CHAIN" "$family" daddr "$address" "$proto" dport "$port" accept
  else
    nft add rule netdev "$TABLE" "$CHAIN" "$family" daddr "$address" accept
  fi
}

add_allow_target() {
  target="$1"
  [ -n "$target" ] || return 0
  validate_token "$target"
  case "$target" in
    */*)
      add_allow_address "$target"
      ;;
    *:*)
      add_allow_address "$target"
      ;;
    *[!0-9.]* )
      resolve_host "$target" | while IFS= read -r resolved; do
        [ -n "$resolved" ] && add_allow_address "$resolved"
      done
      ;;
    *)
      add_allow_address "$target"
      ;;
  esac
}

command -v nft >/dev/null 2>&1 || fail 'nft command is unavailable'
ip link show "$IFACE" >/dev/null 2>&1 || fail "egress interface does not exist: $IFACE"

nft delete table netdev "$TABLE" >/dev/null 2>&1 || true
nft add table netdev "$TABLE"
nft "add chain netdev $TABLE $CHAIN { type filter hook egress device \"$IFACE\" priority 0; policy accept; }"

# Permit only the exact private control-plane endpoints required by the scanner
# worker. Public destinations remain reachable unless blocked by the explicit
# special/private ranges below.
old_ifs="$IFS"
IFS=','
for endpoint in $CONTROL_ENDPOINTS; do
  [ -n "$endpoint" ] || continue
  validate_token "$endpoint"
  host="${endpoint%%:*}"
  rest="${endpoint#*:}"
  port="${rest%%/*}"
  proto="${rest#*/}"
  [ "$host" != "$endpoint" ] || fail "control endpoint lacks port: $endpoint"
  [ "$proto" != "$rest" ] || proto='tcp'
  resolve_host "$host" | while IFS= read -r resolved; do
    [ -n "$resolved" ] && add_allow_address "$resolved" "$port" "$proto"
  done
done
IFS="$old_ifs"

# Private scan targets are a second, independent operator decision. They do not
# come from the application authorization ledger and must be explicit here.
old_ifs="$IFS"
IFS=','
for target in $PRIVATE_TARGETS; do
  [ -n "$target" ] || continue
  add_allow_target "$target"
done
IFS="$old_ifs"

# Block non-global and special IPv4 ranges at the network-device egress hook.
# This hook sees traffic emitted through raw/packet sockets as well as normal
# TCP/UDP sockets, so scanner binaries cannot bypass it by changing socket type.
for cidr in \
  0.0.0.0/8 \
  10.0.0.0/8 \
  100.64.0.0/10 \
  127.0.0.0/8 \
  169.254.0.0/16 \
  172.16.0.0/12 \
  192.0.0.0/24 \
  192.0.2.0/24 \
  192.168.0.0/16 \
  198.18.0.0/15 \
  198.51.100.0/24 \
  203.0.113.0/24 \
  224.0.0.0/4 \
  240.0.0.0/4; do
  nft add rule netdev "$TABLE" "$CHAIN" ip daddr "$cidr" counter drop
done

for cidr in \
  ::/128 \
  ::1/128 \
  100::/64 \
  2001:db8::/32 \
  fc00::/7 \
  fe80::/10 \
  ff00::/8; do
  nft add rule netdev "$TABLE" "$CHAIN" ip6 daddr "$cidr" counter drop
done

log "kernel egress policy installed on $IFACE"
log "control endpoints: $CONTROL_ENDPOINTS"
log "private scan targets: ${PRIVATE_TARGETS:-<none>}"
nft list table netdev "$TABLE"

exec tail -f /dev/null
