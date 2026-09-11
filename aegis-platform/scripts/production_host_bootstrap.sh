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
case "$SSH_PORT" in
  ''|*[!0-9]*) echo "AEGIS_SSH_PORT must be numeric" >&2; exit 1 ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
  echo "AEGIS_SSH_PORT must be between 1 and 65535" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg git openssl ufw fail2ban jq \
  postgresql-client certbot

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
ufw allow "$SSH_PORT/tcp" comment 'AegisScan SSH'
ufw allow 80/tcp comment 'AegisScan HTTP ACME redirect'
ufw allow 443/tcp comment 'AegisScan HTTPS'
ufw --force enable

install -d -m 0750 /opt/aegisscan
install -d -m 0700 /etc/aegisscan
install -d -m 0700 /etc/aegisscan/secrets
install -d -m 0700 /var/lib/aegisscan
install -d -m 0700 /var/lib/aegisscan/backups

docker --version
docker compose version
git --version
openssl version
certbot --version
ufw status verbose
sysctl net.ipv4.ip_forward

printf '%s\n' 'AEGISSCAN_HOST_BOOTSTRAP=PASS'
