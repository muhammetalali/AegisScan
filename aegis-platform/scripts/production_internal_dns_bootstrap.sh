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
EXPLICIT_DNS_FORWARDER="${AEGIS_DNS_UPSTREAM:-}"
FQDN="${AEGIS_DDNS_FQDN:-aegis-prod.aegis.internal.}"
ZONE="${AEGIS_DDNS_ZONE:-aegis.internal.}"
TSIG_NAME="${AEGIS_DDNS_TSIG_NAME:-aegis-prod-ddns}"
NETPLAN_FILE="${AEGIS_DNS_NETPLAN_FILE:-/etc/netplan/90-aegisscan-dns-service.yaml}"
INSTALLER_NETPLAN_FILE="${AEGIS_INSTALLER_NETPLAN_FILE:-/etc/netplan/00-installer-config.yaml}"
BIND_KEY_FILE="${AEGIS_BIND_DDNS_KEY:-/etc/bind/keys/aegis-prod-ddns.key}"
RUNTIME_KEY_FILE="${AEGIS_DDNS_KEY:-/etc/aegisscan/ddns.key}"
RUNTIME_ENV_FILE="/etc/aegisscan/ddns-reconcile.env"
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

for command in python3 ip netplan systemctl systemd-analyze named-checkconf named-checkzone tsig-keygen dig nsupdate cmp grep awk date cp tr sed; do
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

# Preserve the DHCP-provided resolver for public internet names.
# BIND remains authoritative for aegis.internal, with DNSSEC validation
# enabled, and systemd-resolved routes only that zone to local BIND.
# A working DHCP gateway DNS is required before changing network profiles.
GATEWAY_DNS="$(
  ip -4 route show default dev "$INTERFACE" |
    awk '$1 == "default" && $2 == "via" { print $3 }'
)"
GATEWAY_COUNT="$(printf '%s\n' "$GATEWAY_DNS" | awk 'NF { count++ } END { print count+0 }')"
if [ "$GATEWAY_COUNT" -ne 1 ]; then
  echo "expected one DHCP gateway on $INTERFACE, found $GATEWAY_COUNT" >&2
  exit 1
fi
python3 - "$GATEWAY_DNS" "$DNS_SERVICE_IP" "$APP_IP" "$INTERNAL_CIDR" <<'PYGATEWAY'
import ipaddress
import sys
gateway, service, app = map(ipaddress.ip_address, sys.argv[1:4])
network = ipaddress.ip_network(sys.argv[4])
if not all(isinstance(x, ipaddress.IPv4Address) and x in network for x in (gateway, service, app)):
    raise SystemExit("gateway, service, and DHCP application address must be IPv4 in approved LAN")
if gateway in (service, app):
    raise SystemExit("invalid self-referential DHCP gateway")
PYGATEWAY
GATEWAY_READY=0
for ATTEMPT in 1 2 3 4 5; do
  GATEWAY_ANSWER="$(dig @"$GATEWAY_DNS" github.com. A +short +time=4 +tries=2 2>&1)" && GATEWAY_RC=0 || GATEWAY_RC=$?
  if [ "$GATEWAY_RC" -eq 0 ] &&
     printf '%s\n' "$GATEWAY_ANSWER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    GATEWAY_READY=1
    break
  fi
  echo "DHCP DNS preflight retry $ATTEMPT/5 via $GATEWAY_DNS (exit $GATEWAY_RC)" >&2
  sleep 2
done
if [ "$GATEWAY_READY" -ne 1 ]; then
  echo "DHCP gateway DNS cannot resolve public A records; refusing network change" >&2
  exit 1
fi

HOST_LABEL="$(
  python3 - "$APP_IP" "$DNS_SERVICE_IP" "$INTERNAL_CIDR" "$FQDN" "$ZONE" "$TSIG_NAME" <<'PY'
import ipaddress
import re
import sys

app = ipaddress.ip_address(sys.argv[1])
dns = ipaddress.ip_address(sys.argv[2])
network = ipaddress.ip_network(sys.argv[3])
fqdn = sys.argv[4].rstrip(".")
zone = sys.argv[5].rstrip(".")
tsig_name = sys.argv[6]

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

label_re = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

def validate_name(value: str, label: str) -> None:
    if not value or len(value) > 253:
        raise SystemExit(f"{label} is empty or too long")
    parts = value.split(".")
    if any(not label_re.fullmatch(part) for part in parts):
        raise SystemExit(f"{label} contains an invalid DNS label: {value}")

validate_name(fqdn, "FQDN")
validate_name(zone, "zone")

if fqdn == zone or not fqdn.endswith("." + zone):
    raise SystemExit(f"FQDN {fqdn} is not a host inside zone {zone}")

if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", tsig_name):
    raise SystemExit("TSIG key name contains unsupported characters")

print(fqdn[: -(len(zone) + 1)])
PY
)"

ZONE_NAME="${ZONE%.}"
FQDN_ABS="${FQDN%.}."

install -d -m 0700 /etc/aegisscan
install -d -m 0700 /var/lib/aegisscan
install -d -m 0700 /var/lib/aegisscan/backups
install -d -m 0700 "$BACKUP_ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

backup_file() {
  candidate="$1"
  if [ -f "$candidate" ]; then
    safe_name="$(printf '%s' "$candidate" | tr '/' '_')"
    cp -a "$candidate" "$BACKUP_ROOT/$safe_name.$STAMP"
  fi
}

backup_file "$NETPLAN_FILE"

# Netplan's older installer profile may still pin an obsolete VMware MAC.
# Then systemd-networkd silently uses dracut's generic DHCP profile instead,
# leaving the dedicated DNS service address inactive after every reboot.
# Preserve DHCP and the interface name, remove only that stale matching pin.
if [ -f "$INSTALLER_NETPLAN_FILE" ]; then
  backup_file "$INSTALLER_NETPLAN_FILE"
  if [ ! -r "/sys/class/net/$INTERFACE/address" ]; then
    echo "production interface MAC is unavailable: $INTERFACE" >&2
    exit 1
  fi
  IFS= read -r HOST_MAC <"/sys/class/net/$INTERFACE/address"
  python3 - "$INSTALLER_NETPLAN_FILE" "$INTERFACE" "$HOST_MAC" <<'PYMAC'
import os
import re
import sys
import tempfile
from pathlib import Path

import yaml

path, interface, host_mac = Path(sys.argv[1]), sys.argv[2], sys.argv[3].lower()
if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", host_mac):
    raise SystemExit("interface MAC is not valid")
config = yaml.safe_load(path.read_text())
if not isinstance(config, dict):
    raise SystemExit("installer Netplan config is invalid")
network = config.get("network")
ethernets = network.get("ethernets") if isinstance(network, dict) else None
settings = ethernets.get(interface) if isinstance(ethernets, dict) else None
if not isinstance(settings, dict) or settings.get("dhcp4") is not True:
    raise SystemExit("installer profile does not preserve DHCPv4 on the approved interface")

match = settings.get("match")
if match is None:
    print("NETPLAN_DHCP_MAC_MATCH=already-independent")
    raise SystemExit(0)
if not isinstance(match, dict) or set(match) != {"macaddress"}:
    raise SystemExit("unrecognized Netplan interface matcher: no change")
pinned = str(match["macaddress"]).lower()
if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", pinned):
    raise SystemExit("invalid installer MAC matcher: no change")
if settings.get("set-name", interface) != interface:
    raise SystemExit("unexpected installer interface renaming: no change")
settings.pop("match")
settings.pop("set-name", None)

stat = path.stat()
payload = yaml.safe_dump(config, sort_keys=False)
fd, staged = tempfile.mkstemp(prefix=".aegisscan-netplan-", dir=path.parent)
try:
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), stat.st_mode & 0o777)
        os.fchown(stream.fileno(), stat.st_uid, stat.st_gid)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(staged, path)
finally:
    if os.path.exists(staged):
        os.unlink(staged)
print("NETPLAN_DHCP_MAC_MATCH=removed-for-mac-independent-boot")
PYMAC
fi

cat >"$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    $INTERFACE:
      addresses:
        - $DNS_SERVICE_IP/32
      dhcp4-overrides:
        use-dns: true
      dhcp6-overrides:
        use-dns: true
    lo:
      match:
        name: lo
      dhcp4: false
      dhcp6: false
      nameservers:
        addresses:
          - 127.0.0.1
        search:
          - ~$ZONE_NAME
EOF
chmod 0600 "$NETPLAN_FILE"
netplan generate

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
  echo "generated Netplan was not activated; review it and rerun with AEGIS_NETPLAN_APPLY=1 from a console-safe session" >&2
  echo "AEGISSCAN_INTERNAL_DNS_BOOTSTRAP=PENDING_NETWORK_APPLY" >&2
  exit 1
fi

install -d -m 0750 /etc/bind/keys
install -d -o bind -g bind -m 0775 /var/lib/bind

backup_file /etc/bind/named.conf.options
backup_file /etc/bind/named.conf.local
backup_file "$BIND_INCLUDE"
backup_file "$RUNTIME_ENV_FILE"

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

cat >"$RUNTIME_ENV_FILE" <<EOF
AEGIS_DDNS_INTERFACE=$INTERFACE
AEGIS_DDNS_SERVER=127.0.0.1
AEGIS_DNS_SERVICE_IP=$DNS_SERVICE_IP
AEGIS_DDNS_NETWORK=$INTERNAL_CIDR
AEGIS_DDNS_FQDN=$FQDN_ABS
AEGIS_DDNS_ZONE=$ZONE_NAME.
AEGIS_DDNS_KEY=$RUNTIME_KEY_FILE
EOF
chown root:root "$RUNTIME_ENV_FILE"
chmod 0600 "$RUNTIME_ENV_FILE"

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

    # No public forwarding: DNSSEC validation remains enabled.
    # Host routes only the private zone to this authoritative instance.

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

zone "$ZONE_NAME" {
    type primary;
    file "$ZONE_FILE";
    allow-query { aegis_lan; };
    allow-transfer { none; };
    update-policy {
        grant $TSIG_NAME name $FQDN_ABS A;
    };
};
EOF

if ! grep -Fq "zone \"$ZONE_NAME\"" /etc/bind/named.conf.local; then
  if ! grep -Fq "include \"$BIND_INCLUDE\";" /etc/bind/named.conf.local; then
    printf '\ninclude "%s";\n' "$BIND_INCLUDE" >>/etc/bind/named.conf.local
  fi
else
  echo "existing $ZONE_NAME zone declaration preserved in /etc/bind/named.conf.local"
fi

if [ ! -f "$ZONE_FILE" ]; then
  cat >"$ZONE_FILE" <<EOF
\$TTL 300
@   IN  SOA ns1.$ZONE_NAME. hostmaster.$ZONE_NAME. (
        2026091901
        300
        120
        604800
        300
)
    IN  NS  ns1.$ZONE_NAME.
ns1         IN  A   $DNS_SERVICE_IP
$HOST_LABEL IN  A   $APP_IP
EOF
  chown bind:bind "$ZONE_FILE"
  chmod 0640 "$ZONE_FILE"
fi

named-checkconf
named-checkzone "$ZONE_NAME" "$ZONE_FILE"

# Both the signed DDNS reconciler and the existing DHCP identity detector
# must be installed together. Do not create a second network-discovery path.
install -o root -g root -m 0755 \
  "$PLATFORM_DIR/scripts/production_network_identity.py" \
  /usr/local/sbin/production_network_identity.py
install -o root -g root -m 0750 \
  "$PLATFORM_DIR/scripts/production_ddns_reconcile.py" \
  /usr/local/sbin/aegisscan-ddns-reconcile
# The DDNS updater is never permitted outbound network access: its signed
# update and its consistency query use local BIND, independently of DHCP.
install -o root -g root -m 0644 \
  "$PLATFORM_DIR/systemd/aegisscan-ddns-reconcile.service" \
  /etc/systemd/system/aegisscan-ddns-reconcile.service
chown root:root /etc/systemd/system/aegisscan-ddns-reconcile.service
chmod 0644 /etc/systemd/system/aegisscan-ddns-reconcile.service
install -o root -g root -m 0644 \
  "$PLATFORM_DIR/systemd/aegisscan-ddns-reconcile.timer" \
  /etc/systemd/system/aegisscan-ddns-reconcile.timer

systemd-analyze verify \
  /etc/systemd/system/aegisscan-ddns-reconcile.service \
  /etc/systemd/system/aegisscan-ddns-reconcile.timer

# Ensure BIND binds the DHCP-independent DNS service address after Netplan
# has configured ens33. Keep the existing named.service; no extra daemon.
BIND_NETWORK_ORDER_FILE=/etc/systemd/system/named.service.d/10-aegisscan-network-online.conf
install -d -m 0755 /etc/systemd/system/named.service.d
backup_file "$BIND_NETWORK_ORDER_FILE"
cat >"$BIND_NETWORK_ORDER_FILE" <<'EOFBINDNETWORK'
[Unit]
Wants=network-online.target
After=network-online.target
EOFBINDNETWORK
chmod 0644 "$BIND_NETWORK_ORDER_FILE"

systemctl daemon-reload
systemctl enable named
systemctl restart named
systemctl enable --now aegisscan-ddns-reconcile.timer
systemctl start aegisscan-ddns-reconcile.service

dig @"$DNS_SERVICE_IP" "$FQDN_ABS" A +short
dig +tcp @"$DNS_SERVICE_IP" "$FQDN_ABS" A +short
systemctl is-active named
systemctl is-active aegisscan-ddns-reconcile.timer

printf '%s\n' 'AEGISSCAN_INTERNAL_DNS_BOOTSTRAP=PASS'
