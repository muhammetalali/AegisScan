#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "production runner bootstrap must run as root" >&2
  exit 1
fi

: "${AEGIS_GITHUB_RUNNER_URL:?AEGIS_GITHUB_RUNNER_URL is required}"
: "${AEGIS_GITHUB_RUNNER_ARCHIVE_URL:?AEGIS_GITHUB_RUNNER_ARCHIVE_URL is required}"
: "${AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256:?AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256 is required}"
: "${AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN:?AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN is required}"

RUNNER_USER="${AEGIS_GITHUB_RUNNER_USER:-aegisrunner}"
RUNNER_NAME="${AEGIS_GITHUB_RUNNER_NAME:-aegisscan-production}"
RUNNER_DIR="${AEGIS_GITHUB_RUNNER_DIR:-/opt/actions-runner}"
RUNNER_WORK="${AEGIS_GITHUB_RUNNER_WORK:-/var/lib/aegisscan/actions-runner-work}"
RUNNER_LABELS="aegisscan-production"
RUNNER_MARKER="/etc/aegisscan/production-runner.env"

case "$AEGIS_GITHUB_RUNNER_URL" in
  https://github.com/*) ;;
  *) echo "AEGIS_GITHUB_RUNNER_URL must be an HTTPS github.com repository or organization URL" >&2; exit 1 ;;
esac

case "$AEGIS_GITHUB_RUNNER_ARCHIVE_URL" in
  https://github.com/actions/runner/releases/download/*/actions-runner-linux-x64-*.tar.gz) ;;
  *) echo "AEGIS_GITHUB_RUNNER_ARCHIVE_URL must be a pinned official actions/runner linux-x64 release archive" >&2; exit 1 ;;
esac

case "$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" in
  *[!0-9a-f]*|'') echo "AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256 must be lowercase hexadecimal" >&2; exit 1 ;;
esac
if [ "${#AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256}" -ne 64 ]; then
  echo "AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256 must be exactly 64 hexadecimal characters" >&2
  exit 1
fi

case "$RUNNER_USER" in
  ''|*[!A-Za-z0-9_-]*) echo "AEGIS_GITHUB_RUNNER_USER is invalid" >&2; exit 1 ;;
esac
case "$RUNNER_NAME" in
  ''|*[!A-Za-z0-9._-]*) echo "AEGIS_GITHUB_RUNNER_NAME is invalid" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl tar gzip libicu-dev git gh openssh-client

if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/bash "$RUNNER_USER"
fi

install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_DIR"
install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_WORK"

tmp_archive="$(mktemp /tmp/aegis-actions-runner.XXXXXX.tar.gz)"
cleanup() {
  rm -f "$tmp_archive"
}
trap cleanup EXIT HUP INT TERM

curl --fail --silent --show-error --location   --proto '=https' --tlsv1.2   "$AEGIS_GITHUB_RUNNER_ARCHIVE_URL"   -o "$tmp_archive"

printf '%s  %s
' "$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" "$tmp_archive" | sha256sum -c -

marker_matches() {
  [ -f "$RUNNER_MARKER" ] || return 1
  [ "$(stat -c '%U:%G:%a' "$RUNNER_MARKER" 2>/dev/null || true)" = "root:root:640" ] || return 1
  grep -Fqx "schema=aegisscan.production-runner.v1" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_url=$AEGIS_GITHUB_RUNNER_URL" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_name=$RUNNER_NAME" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_labels=$RUNNER_LABELS" "$RUNNER_MARKER" || return 1
  grep -Fqx "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" "$RUNNER_MARKER" || return 1
}

if [ -x "$RUNNER_DIR/config.sh" ]; then
  service_name="$(cd "$RUNNER_DIR" && ./svc.sh status 2>/dev/null | sed -n 's/.*\(actions.runner[^ ]*\.service\).*/\1/p' | head -n 1 || true)"
  if [ -n "$service_name" ] && systemctl is-active --quiet "$service_name"; then
    if ! marker_matches; then
      echo "existing active runner is not bound to the approved AegisScan production runner marker" >&2
      exit 1
    fi
    echo "existing approved production runner service is active: $service_name"
    exit 0
  fi
  echo "existing runner installation is not active; refusing destructive replacement" >&2
  exit 1
fi

tar -xzf "$tmp_archive" -C "$RUNNER_DIR"

if [ ! -x "$RUNNER_DIR/bin/installdependencies.sh" ]; then
  echo "verified runner archive is missing bin/installdependencies.sh" >&2
  exit 1
fi
"$RUNNER_DIR/bin/installdependencies.sh"

for command_name in git gh ssh ssh-keygen curl tar; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "production runner dependency is unavailable: $command_name" >&2
    exit 1
  fi
done

chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR" "$RUNNER_WORK"

runuser -u "$RUNNER_USER" -- "$RUNNER_DIR/config.sh"   --unattended   --url "$AEGIS_GITHUB_RUNNER_URL"   --token "$AEGIS_GITHUB_RUNNER_REGISTRATION_TOKEN"   --name "$RUNNER_NAME"   --labels "$RUNNER_LABELS"   --work "$RUNNER_WORK"

cd "$RUNNER_DIR"
./svc.sh install "$RUNNER_USER"
./svc.sh start

service_name="$(./svc.sh status | sed -n 's/.*\(actions.runner[^ ]*\.service\).*/\1/p' | head -n 1 || true)"
if [ -z "$service_name" ]; then
  echo "unable to resolve installed GitHub Actions runner service" >&2
  exit 1
fi
systemctl is-enabled --quiet "$service_name"
systemctl is-active --quiet "$service_name"

install -d -m 0750 -o root -g root /etc/aegisscan
marker_tmp="$(mktemp /etc/aegisscan/production-runner.env.XXXXXX)"
{
  printf '%s\n' "schema=aegisscan.production-runner.v1"
  printf '%s\n' "runner_url=$AEGIS_GITHUB_RUNNER_URL"
  printf '%s\n' "runner_name=$RUNNER_NAME"
  printf '%s\n' "runner_labels=$RUNNER_LABELS"
  printf '%s\n' "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256"
} > "$marker_tmp"
chmod 0640 "$marker_tmp"
chown root:root "$marker_tmp"
mv -f "$marker_tmp" "$RUNNER_MARKER"
marker_matches

printf '%s
' "AEGISSCAN_PRODUCTION_RUNNER_BOOTSTRAP=PASS"
printf '%s
' "runner_name=$RUNNER_NAME"
printf '%s
' "runner_label=$RUNNER_LABELS"
printf '%s
' "runner_service=$service_name"
