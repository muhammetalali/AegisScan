#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "internal DNS bootstrap must run as root" >&2
  exit 1
fi

PLATFORM_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
INTERFACE="${AEGIS_DDNS_INTERFACE:-ens33}"
INTERNAL_CIDR="${AEGIS_DDNS_NETWORK:-192.168.49.0/24}"
DNS_SERVICE_IP="${AEGIS_DNS_SERVICE_IP:-192.168.49.53}"
FQDN="${AEGIS_DDNS_FQDN:-aegis-prod.aegis.internal.}"
ZONE="${AEGIS_DDNS_ZONE:-aegis.internal.}"
TSIG_NAME="${AEGIS_DDNS_TSIG_NAME:-aegis-prod-ddns}"
NETPLAN_FILE="${AEGIS_DNS_NETPLAN_FILE:-/etc/netplan/90-aegisscan-dns-service.yaml}"
BIND_KEY_FILE="${AEGIS_BIND_DDNS_KEY:-/etc/bind/keys/aegis-prod-ddns.key}"
RUNTIME_KEY_FILE="${AEGIS_DDNS_KEY:-/etc/aegisscan/ddns.key}"
ZONE_FILE="${AEGIS_DNS_ZONE_FILE:-/var/lib/bind/db.aegis.internal}"
BIND_INCLUDE="${AEGIS_BIND_INCLUDE:-/etc/bind/named.conf.aegisscan}"
APPLY_NETWORK="${AEGIS_NETPLAN_APPLY:-0}"
BACKUP_ROOT="${AEGIS_DNS_BACKUP_DIR:-/var/lib/aegisscan/backups/dns-config}"

case "$APPLY_NETWORK" in
  0|1) ;;
  *)
    echo "AEGIS_NETPLAN_APPLY must be 0 or 1" >&2
    exit 1
    ;;
esac

for command in python3 ip netplan systemctl systemd-analyze named-checkconf named-checkzone tsig-keygen dig nsupdate cmp grep awk date cp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is missing: $command" >&2
    exit 1
  fi
done

APP_IP="$(
  ip -4 -o addr show dev "$INTERFACE" scope global dynamic |
    awk '$3 == "inet" {split($4, value, "/"); print value[1]}'
)"

APP_COUNT="$(printf '%s\n' "$APP_IP" | awk 'NF {count++} END {print count+0}')"
if [ "$APP_COUNT" -ne 1 ]; then
  echo "expected exactly one dynamic IPv4 on $INTERFACE; found $APP_COUNT" >&2
  exit 1
fi

python3 - "$APP_IP" "$DNS_SERVICE_IP" "$INTERNAL_CIDR" <<'PY'
import ipaddress
import sys

app = ipaddress.ip_address(sys.argv[1])
dns = ipaddress.ip_address(sys.argv[2])
network = ipaddress.ip_network(sys.argv[3])

if app.version != 4 or dns.version != 4:
    raise SystemExit("AegisScan internal production DNS requires IPv4")
if app not in network:
    raise SystemExit(f"dynamic application IP {app} is outside {network}")
if dns not in network:
    raise SystemExit(f"DNS service IP {dns} is outside {network}")
if app == dns:
    raise SystemExit("dynamic application IP must differ from DNS service IP")
if not app.is_private or not dns.is_private:
    raise SystemExit("internal production addresses must be private")
PY

install -d -m 0750 /etc/bind/keys
install -d -m 0700 /etc/aegisscan
install -d -o bind -g bind -m 0775 /var/lib/bind
install -d -m 0700 /var/lib/aegisscan
install -d -m 0700 /var/lib/aegisscan/backups
install -d -m 0700 "$BACKUP_ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
for candidate in /etc/bind/named.conf.options /etc/bind/named.conf.local "$NETPLAN_FILE"; do
  if [ -f "$candidate" ]; then
    safe_name="$(printf '%s' "$candidate" | tr '/' '_')"
    cp -a "$candidate" "$BACKUP_ROOT/$safe_name.$STAMP"
  fi
done

if [ ! -f "$BIND_KEY_FILE" ] && [ -f "$RUNTIME_KEY_FILE" ]; then
  install -o root -g bind -m 0640 "$RUNTIME_KEY_FILE" "$BIND_KEY_FILE"
fi

if [ ! -f "$BIND_KEY_FILE" ] && [ ! -f "$RUNTIME_KEY_FILE" ]; then
  umask 077
  tsig-keygen -a hmac-sha256 "$TSIG_NAME" >"$BIND_KEY_FILE"
fi

if [ -f "$BIND_KEY_FILE" ]; then
  chown root:bind "$BIND_KEY_FILE"
  chmod 0640 "$BIND_KEY_FILE"
fi

if [ ! -f "$RUNTIME_KEY_FILE" ]; then
  if [ ! -f "$BIND_KEY_FILE" ]; then
    echo "TSIG key material is unavailable" >&2
    exit 1
  fi
  install -o root -g root -m 0600 "$BIND_KEY_FILE" "$RUNTIME_KEY_FILE"
else
  chown root:root "$RUNTIME_KEY_FILE"
  chmod 0600 "$RUNTIME_KEY_FILE"
fi

if ! cmp -s "$BIND_KEY_FILE" "$RUNTIME_KEY_FILE"; then
  echo "BIND and runtime TSIG key material differ; refusing split-brain DDNS configuration" >&2
  exit 1
fi

cat >/etc/bind/named.conf.options <<EOF
acl "aegis_lan" {
    127.0.0.1;
    $INTERNAL_CIDR;
};

options {
    directory "/var/cache/bind";

    listen-on {
        127.0.0.1;
        $DNS_SERVICE_IP;
    };

    listen-on-v6 { none; };
    query-source-v6 address none;

    recursion yes;

    allow-query { aegis_lan; };
    allow-recursion { aegis_lan; };
    allow-query-cache { aegis_lan; };

    allow-transfer { none; };

    dnssec-validation auto;

    minimal-responses yes;
    max-cache-size 256m;
};
EOF

cat >"$BIND_INCLUDE" <<EOF
include "$BIND_KEY_FILE";

zone "${ZONE%.}" {
    type primary;
    file "$ZONE_FILE";
    allow-query { aegis_lan; };
    allow-transfer { none; };
    update-policy {
        grant $TSIG_NAME name $FQDN A;
    };
};
EOF

if ! grep -Eq '^[[:space:]]*zone[[:space:]]+"aegis\.internal"' /etc/bind/named.conf.local; then
  if ! grep -Fq "include \"$BIND_INCLUDE\";" /etc/bind/named.conf.local; then
    printf '\ninclude "%s";\n' "$BIND_INCLUDE" >>/etc/bind/named.conf.local
  fi
else
  echo "existing aegis.internal zone declaration preserved in /etc/bind/named.conf.local"
fi

if [ ! -f "$ZONE_FILE" ]; then
  cat >"$ZONE_FILE" <<EOF
\$TTL 300
@   IN  SOA ns1.aegis.internal. hostmaster.aegis.internal. (
        2026091901
        300
        120
        604800
        300
)
    IN  NS  ns1.aegis.internal.
ns1         IN  A   $DNS_SERVICE_IP
aegis-prod  IN  A   $APP_IP
EOF
  chown bind:bind "$ZONE_FILE"
  chmod 0640 "$ZONE_FILE"
fi

named-checkconf
named-checkzone "${ZONE%.}" "$ZONE_FILE"

cat >"$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    $INTERFACE:
      addresses:
        - $DNS_SERVICE_IP/32
      nameservers:
        addresses:
          - $DNS_SERVICE_IP
      dhcp4-overrides:
        use-dns: false
      dhcp6-overrides:
        use-dns: false
EOF
chmod 0600 "$NETPLAN_FILE"
netplan generate

install -o root -g root -m 0750 \
  "$PLATFORM_DIR/scripts/production_ddns_reconcile.py" \
  /usr/local/sbin/aegisscan-ddns-reconcile
install -o root -g root -m 0644 \
  "$PLATFORM_DIR/systemd/aegisscan-ddns-reconcile.service" \
  /etc/systemd/system/aegisscan-ddns-reconcile.service
install -o root -g root -m 0644 \
  "$PLATFORM_DIR/systemd/aegisscan-ddns-reconcile.timer" \
  /etc/systemd/system/aegisscan-ddns-reconcile.timer

systemd-analyze verify \
  /etc/systemd/system/aegisscan-ddns-reconcile.service \
  /etc/systemd/system/aegisscan-ddns-reconcile.timer

systemctl daemon-reload

if [ "$APPLY_NETWORK" -eq 1 ]; then
  netplan apply
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches
  fi
fi

if ! ip -4 -o addr show dev "$INTERFACE" |
  awk '$3 == "inet" {split($4, value, "/"); print value[1]}' |
  grep -Fxq "$DNS_SERVICE_IP"
then
  echo "DNS service IP $DNS_SERVICE_IP is not active on $INTERFACE" >&2
  echo "review the generated Netplan and rerun with AEGIS_NETPLAN_APPLY=1 from a console-safe session" >&2
  exit 1
fi

systemctl enable named
systemctl restart named
systemctl enable --now aegisscan-ddns-reconcile.timer
systemctl start aegisscan-ddns-reconcile.service

dig @"$DNS_SERVICE_IP" "$FQDN" A +short
dig +tcp @"$DNS_SERVICE_IP" "$FQDN" A +short
systemctl is-active named
systemctl is-active aegisscan-ddns-reconcile.timer

printf '%s\n' 'AEGISSCAN_INTERNAL_DNS_BOOTSTRAP=PASS'
