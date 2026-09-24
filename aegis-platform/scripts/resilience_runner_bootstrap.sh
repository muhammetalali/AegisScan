#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "resilience runner bootstrap must run as root" >&2
  exit 1
fi

: "${AEGIS_GITHUB_RUNNER_URL:?AEGIS_GITHUB_RUNNER_URL is required}"
: "${AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256:?AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256 is required}"

RUNNER_USER="${AEGIS_GITHUB_RUNNER_USER:-aegisrunner}"
RUNNER_NAME="${AEGIS_GITHUB_RUNNER_NAME:-aegisscan-resilience-01}"
RUNNER_DIR="${AEGIS_GITHUB_RUNNER_DIR:-/opt/aegis-resilience-runner}"
RUNNER_WORK="${AEGIS_GITHUB_RUNNER_WORK:-/var/lib/aegisscan/resilience-runner-work}"
RUNNER_LABELS="aegisscan-resilience"
RUNNER_MARKER="/etc/aegisscan/resilience-runner.env"

case "$AEGIS_GITHUB_RUNNER_URL" in
  https://github.com/*) ;;
  *) echo "AEGIS_GITHUB_RUNNER_URL must be an HTTPS github.com repository or organization URL" >&2; exit 1 ;;
esac
case "$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" in
  *[!0-9a-f]*|'') echo "runner archive SHA256 must be lowercase hexadecimal" >&2; exit 1 ;;
esac
[ "${#AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256}" -eq 64 ]

for name in "$RUNNER_USER" "$RUNNER_NAME"; do
  case "$name" in
    ''|*[!A-Za-z0-9._-]*) echo "invalid runner identity: $name" >&2; exit 1 ;;
  esac
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl tar gzip libicu-dev git gh openssh-client postgresql-client

command -v docker >/dev/null
docker info >/dev/null
getent group docker >/dev/null

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/bash "$RUNNER_USER"
fi
usermod -aG docker "$RUNNER_USER"

install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_WORK"
install -d -m 0750 -o root -g root /etc/aegisscan

marker_matches() {
  [ -f "$RUNNER_MARKER" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$RUNNER_MARKER" 2>/dev/null || true)" = "root:root:640" ] || return 1
  grep -Fqx "schema=aegisscan.resilience-runner.v1" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_url=$AEGIS_GITHUB_RUNNER_URL" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_name=$RUNNER_NAME" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_labels=$RUNNER_LABELS" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" "$RUNNER_MARKER" || return 1
}

if [ -x "$RUNNER_DIR/config.sh" ]; then
  if ! marker_matches; then
    echo "existing resilience runner is not bound to the approved AegisScan resilience marker" >&2
    exit 1
  fi
  service_name="$(cd "$RUNNER_DIR" && ./svc.sh status 2>/dev/null | sed -n 's/.*\(actions.runner[^ ]*\.service\).*/\1/p' | head -n 1 || true)"
  if [ -z "$service_name" ]; then
    echo "approved resilience runner marker exists but the installed service cannot be resolved" >&2
    exit 1
  fi
  if systemctl is-active --quiet "$service_name"; then
    echo "existing approved resilience runner service is active: $service_name"
    exit 0
  fi
  echo "approved resilience runner service is inactive; attempting bounded service recovery: $service_name"
  systemctl is-enabled --quiet "$service_name" || systemctl enable "$service_name"
  (cd "$RUNNER_DIR" && ./svc.sh start)
  systemctl is-enabled --quiet "$service_name"
  systemctl is-active --quiet "$service_name"
  marker_matches
  echo "AEGISSCAN_RESILIENCE_RUNNER_RECOVERY=PASS"
  echo "runner_service=$service_name"
  exit 0
fi


: "${AEGIS_GITHUB_RUNNER_ARCHIVE_URL:?AEGIS_GITHUB_RUNNER_ARCHIVE_URL is required for fresh runner installation}"
: "${AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN:?AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN is required for fresh runner installation}"
case "$AEGIS_GITHUB_RUNNER_ARCHIVE_URL" in
  https://github.com/actions/runner/releases/download/*/actions-runner-linux-x64-*.tar.gz) ;;
  *) echo "AEGIS_GITHUB_RUNNER_ARCHIVE_URL must be a pinned official actions/runner linux-x64 release archive" >&2; exit 1 ;;
esac

tmp_archive="$(mktemp /tmp/aegis-resilience-runner.XXXXXX.tar.gz)"
trap 'rm -f "$tmp_archive"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$AEGIS_GITHUB_RUNNER_ARCHIVE_URL" -o "$tmp_archive"
printf '%s  %s\n' "$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" "$tmp_archive" | sha256sum -c -
tar -xzf "$tmp_archive" -C "$RUNNER_DIR"
if [ ! -x "$RUNNER_DIR/bin/installdependencies.sh" ]; then
  echo "verified runner archive is missing bin/installdependencies.sh" >&2
  exit 1
fi
"$RUNNER_DIR/bin/installdependencies.sh"
chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR" "$RUNNER_WORK"

runuser -u "$RUNNER_USER" -- "$RUNNER_DIR/config.sh" \
  --unattended \
  --disableupdate \
  --url "$AEGIS_GITHUB_RUNNER_URL" \
  --token "$AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN" \
  --name "$RUNNER_NAME" \
  --labels "$RUNNER_LABELS" \
  --work "$RUNNER_WORK"

cd "$RUNNER_DIR"
./svc.sh install "$RUNNER_USER"
./svc.sh start
service_name="$(./svc.sh status | sed -n 's/.*\(actions.runner[^ ]*\.service\).*/\1/p' | head -n 1)"
[ -n "$service_name" ]
systemctl is-enabled --quiet "$service_name"
systemctl is-active --quiet "$service_name"

marker_tmp="$(mktemp /etc/aegisscan/resilience-runner.env.XXXXXX)"
{
  echo "schema=aegisscan.resilience-runner.v1"
  echo "runner_url=$AEGIS_GITHUB_RUNNER_URL"
  echo "runner_name=$RUNNER_NAME"
  echo "runner_labels=$RUNNER_LABELS"
  echo "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256"
} > "$marker_tmp"
chmod 0640 "$marker_tmp"
chown root:root "$marker_tmp"
mv -f "$marker_tmp" "$RUNNER_MARKER"
marker_matches

echo "AEGISSCAN_RESILIENCE_RUNNER_BOOTSTRAP=PASS"
echo "runner_name=$RUNNER_NAME"
echo "runner_label=$RUNNER_LABELS"
echo "runner_service=$service_name"
