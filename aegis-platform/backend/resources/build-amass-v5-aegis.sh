#!/bin/sh
set -eu

AMASS_REPOSITORY="https://github.com/owasp-amass/amass.git"
AMASS_COMMIT="79299dce87b0085db0f2f4ef3e9c52cccb49f514"
PATCH_PATH="${1:?patch path is required}"
OUTPUT_PATH="${2:?output path is required}"
SOURCE_ROOT="$(mktemp -d /tmp/aegis-amass-source.XXXXXX)"

cleanup() {
    rm -rf "$SOURCE_ROOT"
}
trap cleanup EXIT HUP INT TERM

git -C "$SOURCE_ROOT" init -q
git -C "$SOURCE_ROOT" remote add origin "$AMASS_REPOSITORY"
git -C "$SOURCE_ROOT" fetch -q --depth 1 origin "$AMASS_COMMIT"
git -C "$SOURCE_ROOT" checkout -q --detach FETCH_HEAD
test "$(git -C "$SOURCE_ROOT" rev-parse HEAD)" = "$AMASS_COMMIT"

git -C "$SOURCE_ROOT" apply --check "$PATCH_PATH"
git -C "$SOURCE_ROOT" apply "$PATCH_PATH"
gofmt -w \
    "$SOURCE_ROOT/engine/api/client/v1/client.go" \
    "$SOURCE_ROOT/engine/api/server/server.go"

mkdir -p "$(dirname "$OUTPUT_PATH")"
(
    cd "$SOURCE_ROOT"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -buildvcs=false -o "$OUTPUT_PATH" ./cmd/amass
)
chmod 0755 "$OUTPUT_PATH"
"$OUTPUT_PATH" -version 2>&1 | grep -q '5.1.1'

# The security patch is part of the executable contract, not documentation.
grep -q 'AEGIS_AMASS_ENGINE_TOKEN' "$SOURCE_ROOT/engine/api/client/v1/client.go"
grep -q 'X-Aegis-Amass-Token' "$SOURCE_ROOT/engine/api/server/server.go"
