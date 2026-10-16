#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "production host bootstrap must run as root" >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "unsupported Linux distribution: /etc/os-release missing" >&2
  exit 1
fi
. /etc/os-release

case "${ID:-}" in
  ubuntu|debian) ;;
  *)
    echo "supported distributions are Ubuntu and Debian; got: ${ID:-unknown}" >&2
    exit 1
    ;;
esac

ARCH="$(dpkg --print-architecture)"
if [ "$ARCH" != "amd64" ]; then
  echo "AegisScan production host currently requires amd64; got: $ARCH" >&2
  exit 1
fi

SSH_PORT="${AEGIS_SSH_PORT:-22}"
CONFIGURE_INTERNAL_DNS="${AEGIS_CONFIGURE_INTERNAL_DNS:-0}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# Minimal Debian/Ubuntu machines may not ship Python or iproute2 yet.
# Bootstrap only these read-only discovery prerequisites before detecting DHCP.
if ! command -v python3 >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 iproute2
fi
if [ -n "${AEGIS_PRODUCTION_INTERFACE:-}" ]; then
  DISCOVERED_NETWORK="$(python3 "$SCRIPT_DIR/production_network_identity.py" --format tsv --interface "$AEGIS_PRODUCTION_INTERFACE")"
else
  DISCOVERED_NETWORK="$(python3 "$SCRIPT_DIR/production_network_identity.py" --format tsv)"
fi
IFS="$(printf '\t')" read -r DISCOVERED_INTERFACE DISCOVERED_CIDR DISCOVERED_IP DISCOVERED_GATEWAY <<EOFNETWORK
$DISCOVERED_NETWORK
EOFNETWORK
INTERFACE="$DISCOVERED_INTERFACE"
INTERNAL_CIDR="${AEGIS_INTERNAL_CIDR:-$DISCOVERED_CIDR}"
DNS_SERVICE_IP="${AEGIS_DNS_SERVICE_IP:-}"
# Never assume a local office subnet. Explicit cross-VLAN access must be an
# approved enterprise ingress scope; by default use only the DHCP subnet.
python3 - "$INTERNAL_CIDR" "$DISCOVERED_CIDR" "$DISCOVERED_IP" <<'PYNETWORK'
import ipaddress, sys
scope, active = (ipaddress.ip_network(x) for x in sys.argv[1:3])
address = ipaddress.ip_address(sys.argv[3])
allowed = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
if scope.version != 4 or not any(scope.subnet_of(x) for x in allowed):
    raise SystemExit("ingress must be an approved private corporate network")
if not active.subnet_of(scope) or address not in scope:
    raise SystemExit("ingress excludes the DHCP subnet")
PYNETWORK

case "$SSH_PORT" in
  ''|*[!0-9]*) echo "AEGIS_SSH_PORT must be numeric" >&2; exit 1 ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "AEGIS_SSH_PORT must be between 1 and 65535" >&2
  exit 1
fi

case "$CONFIGURE_INTERNAL_DNS" in
  0|1) ;;
  *)
    echo "AEGIS_CONFIGURE_INTERNAL_DNS must be 0 or 1" >&2
    exit 1
    ;;
esac

if [ "$CONFIGURE_INTERNAL_DNS" = 1 ] && [ -z "$DNS_SERVICE_IP" ]; then
  echo "legacy internal DNS requires an explicitly provisioned DNS service IP" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg git openssl ufw fail2ban jq sudo python3 \
  postgresql-client certbot dnsutils
if [ "$CONFIGURE_INTERNAL_DNS" = 1 ]; then
  apt-get install -y --no-install-recommends bind9 bind9-utils
fi

install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" \
    -o /etc/apt/keyrings/docker.asc
fi
chmod a+r /etc/apt/keyrings/docker.asc

CODENAME="${VERSION_CODENAME:-}"
if [ -z "$CODENAME" ]; then
  echo "VERSION_CODENAME is required for Docker repository setup" >&2
  exit 1
fi
cat >/etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $CODENAME
Components: stable
Architectures: $ARCH
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt-get update
apt-get install -y --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
systemctl enable --now fail2ban
if [ "$CONFIGURE_INTERNAL_DNS" = 1 ]; then
  systemctl enable named
fi

cat >/etc/sysctl.d/99-aegisscan-production.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_fifos=2
fs.protected_regular=2
EOF
sysctl --system >/dev/null

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow in on "$INTERFACE" from "$INTERNAL_CIDR" to any port "$SSH_PORT" proto tcp \
  comment 'Aegis internal SSH'
if [ "$CONFIGURE_INTERNAL_DNS" = 1 ]; then
  ufw allow in on "$INTERFACE" from "$INTERNAL_CIDR" to "$DNS_SERVICE_IP" port 53 proto udp \
    comment 'Aegis legacy internal DNS UDP'
  ufw allow in on "$INTERFACE" from "$INTERNAL_CIDR" to "$DNS_SERVICE_IP" port 53 proto tcp \
    comment 'Aegis legacy internal DNS TCP'
fi
ufw allow in on "$INTERFACE" from "$INTERNAL_CIDR" to any port 80 proto tcp \
  comment 'Aegis internal HTTP'
ufw allow in on "$INTERFACE" from "$INTERNAL_CIDR" to any port 443 proto tcp \
  comment 'Aegis internal HTTPS'
ufw --force enable
printf 'AEGISSCAN_DHCP_DISCOVERY=PASS uplink=%s subnet=%s\n' "$INTERFACE" "$DISCOVERED_CIDR"

install -d -m 0750 /opt/aegisscan
install -d -m 0700 /etc/aegisscan
install -d -m 0700 /etc/aegisscan/secrets
install -d -m 0700 /var/lib/aegisscan
install -d -m 0700 /var/lib/aegisscan/backups

DEPLOY_USER="aegisdeploy"
if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then
  useradd --create-home --user-group --shell /bin/bash "$DEPLOY_USER"
fi
DEPLOY_HOME="$(getent passwd "$DEPLOY_USER" | awk -F: '{print $6}')"
DEPLOY_SHELL="$(getent passwd "$DEPLOY_USER" | awk -F: '{print $7}')"
if [ -z "$DEPLOY_HOME" ] || [ ! -d "$DEPLOY_HOME" ]; then
  echo "production deploy user home is unavailable: $DEPLOY_USER" >&2
  exit 1
fi
case "$DEPLOY_SHELL" in
  */false|*/nologin|'')
    echo "production deploy user requires an interactive SSH-capable shell: $DEPLOY_USER" >&2
    exit 1
    ;;
esac
DEPLOY_GROUP="$(id -gn "$DEPLOY_USER")"
install -d -m 0700 -o "$DEPLOY_USER" -g "$DEPLOY_GROUP" "$DEPLOY_HOME/.ssh"
touch "$DEPLOY_HOME/.ssh/authorized_keys"
chown "$DEPLOY_USER:$DEPLOY_GROUP" "$DEPLOY_HOME/.ssh/authorized_keys"
chmod 0600 "$DEPLOY_HOME/.ssh/authorized_keys"

install -o root -g root -m 0755 \
  "$SCRIPT_DIR/production_privileged_gate.py" \
  /usr/local/sbin/aegisscan-production-gate
cat >/etc/sudoers.d/aegisscan-production-gate <<'EOF'
aegisdeploy ALL=(root) NOPASSWD: /usr/local/sbin/aegisscan-production-gate
EOF
chown root:root /etc/sudoers.d/aegisscan-production-gate
chmod 0440 /etc/sudoers.d/aegisscan-production-gate
visudo -cf /etc/sudoers.d/aegisscan-production-gate >/dev/null
/usr/local/sbin/aegisscan-production-gate --help | grep -q 'cleanup-e2e-scope'
/usr/local/sbin/aegisscan-production-gate --help | grep -q 'repair-checkout'
/usr/local/sbin/aegisscan-production-gate --help | grep -q 'recover-services'

if [ "$CONFIGURE_INTERNAL_DNS" -eq 1 ]; then
  AEGIS_DDNS_INTERFACE="$INTERFACE" \
  AEGIS_DDNS_NETWORK="$INTERNAL_CIDR" \
  AEGIS_DNS_SERVICE_IP="$DNS_SERVICE_IP" \
    sh "$SCRIPT_DIR/production_internal_dns_bootstrap.sh"
fi

docker --version
docker compose version
git --version
openssl version
certbot --version
if [ "$CONFIGURE_INTERNAL_DNS" = 1 ]; then
  named -V | head -n 1
fi
ufw status verbose
sysctl net.ipv4.ip_forward

printf '%s\n' 'AEGISSCAN_HOST_BOOTSTRAP=PASS'
