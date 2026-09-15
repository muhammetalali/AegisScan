#!/bin/sh
set -eu

COSIGN_VERSION='v2.6.1'
COSIGN_LINUX_AMD64_SHA256='064954c5d8c7e3b28188eee5b1727b31c411550bc5fefd41aa672d3c761d103a'
INSTALL_PATH="${1:-${HOME}/.local/bin/cosign}"
INSTALL_DIR="$(dirname "$INSTALL_PATH")"
TMP="$(mktemp)"
VERSION_OUT="$(mktemp)"
cleanup() {
  rm -f "$TMP" "$VERSION_OUT"
}
trap cleanup EXIT HUP INT TERM

URL="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"

mkdir -p "$INSTALL_DIR"
curl --fail --location --silent --show-error \
  --connect-timeout 15 --max-time 240 \
  --retry 5 --retry-all-errors --retry-delay 2 --retry-max-time 180 \
  "$URL" --output "$TMP"

printf '%s  %s\n' "$COSIGN_LINUX_AMD64_SHA256" "$TMP" | sha256sum --check --strict -
install -m 0755 "$TMP" "$INSTALL_PATH"

"$INSTALL_PATH" version >"$VERSION_OUT" 2>&1
grep -F "$COSIGN_VERSION" "$VERSION_OUT" >/dev/null
cat "$VERSION_OUT"
