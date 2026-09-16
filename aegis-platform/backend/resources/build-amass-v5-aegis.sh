#!/bin/sh
set -eu

AMASS_REPOSITORY="https://github.com/owasp-amass/amass.git"
AMASS_COMMIT="79299dce87b0085db0f2f4ef3e9c52cccb49f514"
PATCH_PATH="${1:?patch path is required}"
OUTPUT_PATH="${2:?output path is required}"
SOURCE_ROOT="$(mktemp -d /tmp/aegis-amass-source.XXXXXX)"

cleanup() { rm -rf "$SOURCE_ROOT"; }
trap cleanup EXIT HUP INT TERM

retry() {
    max_attempts="$1"
    shift
    attempt=1
    while ! "$@"; do
        if [ "$attempt" -ge "$max_attempts" ]; then
            echo "command failed after ${attempt} attempts: $*" >&2
            return 1
        fi
        sleep_seconds=$((attempt * 10))
        echo "retrying in ${sleep_seconds}s: $*" >&2
        sleep "$sleep_seconds"
        attempt=$((attempt + 1))
    done
}

git -C "$SOURCE_ROOT" init -q
git -C "$SOURCE_ROOT" remote add origin "$AMASS_REPOSITORY"
retry 5 git -C "$SOURCE_ROOT" fetch -q --depth 1 origin "$AMASS_COMMIT"
git -C "$SOURCE_ROOT" checkout -q --detach FETCH_HEAD
test "$(git -C "$SOURCE_ROOT" rev-parse HEAD)" = "$AMASS_COMMIT"

git -C "$SOURCE_ROOT" apply --unidiff-zero --check "$PATCH_PATH"
git -C "$SOURCE_ROOT" apply --unidiff-zero "$PATCH_PATH"
gofmt -w \
    "$SOURCE_ROOT/engine/api/client/v1/client.go" \
    "$SOURCE_ROOT/engine/api/server/server.go" \
    "$SOURCE_ROOT/engine/api/server/v1/handlers.go"

mkdir -p "$(dirname "$OUTPUT_PATH")"
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
export GODEBUG=http2client=0
(
    cd "$SOURCE_ROOT"
    retry 5 env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -buildvcs=false -o "$OUTPUT_PATH" ./cmd/amass
)
chmod 0755 "$OUTPUT_PATH"
"$OUTPUT_PATH" -version 2>&1 | grep -q '5.1.1'
grep -q 'AEGIS_AMASS_ENGINE_TOKEN' "$SOURCE_ROOT/engine/api/client/v1/client.go"
grep -q 'X-Aegis-Amass-Token' "$SOURCE_ROOT/engine/api/server/server.go"
