#!/usr/bin/env bash
set -euo pipefail

: "${AEGIS_EXACT_HEAD:?AEGIS_EXACT_HEAD is required}"
test "$(git rev-parse HEAD)" = "${AEGIS_EXACT_HEAD}"

ROOT="$(pwd)"
ARTIFACTS="$ROOT/artifacts"
SOURCE_DIR="$ROOT/parity-source"
RULE_DIR="$ROOT/parity-rules"
WORKSPACE_DIR="$ROOT/semgrep-workspace"
AUTH_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

cleanup() {
  docker rm -f aegis-semgrep-m5-provider aegis-semgrep-m5-scanner >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$ARTIFACTS" "$SOURCE_DIR" "$RULE_DIR" "$WORKSPACE_DIR"
chmod 0777 "$ARTIFACTS" "$WORKSPACE_DIR"
cp aegis-platform/e2e/fixtures/semgrep-parity-source/app.py "$SOURCE_DIR/app.py"
cp aegis-platform/e2e/fixtures/semgrep-parity.yml "$RULE_DIR/semgrep-parity.yml"
sha256sum "$SOURCE_DIR/app.py" "$RULE_DIR/semgrep-parity.yml" > "$ARTIFACTS/fixture-sha256s.txt"

docker build --no-cache   --build-arg AEGIS_RETIRE_NMAP=1   --build-arg AEGIS_RETIRE_NUCLEI=1   --target production-no-legacy-recon   -t aegis-semgrep-m5:scanner   -f aegis-platform/backend/Dockerfile.django   aegis-platform/backend

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
docker build --no-cache   --build-arg BUILD_COMMIT="$AEGIS_EXACT_HEAD"   --build-arg AEGIS_RUNNER_VERSION=0.1.0   --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"   -t aegis-kali:base   -f aegis-platform/kali/Dockerfile.base   aegis-platform/kali

docker build --no-cache   --build-arg AEGIS_BASE_IMAGE=aegis-kali:base   --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"   --target profile-code   -t aegis-kali:code   -f aegis-platform/kali/Dockerfile.profiles   .

docker build --no-cache   --build-arg AEGIS_CODE_BASE_IMAGE=aegis-kali:code   -t aegis-kali:code-provider   -f aegis-platform/kali/Dockerfile.code-provider   aegis-platform/kali

docker run --rm --entrypoint sh aegis-semgrep-m5:scanner -c   'semgrep --version 2>&1 | grep -q "1.177.0" && ! command -v nmap && ! command -v nuclei'
docker run --rm --entrypoint sh aegis-kali:code-provider -c   'semgrep --version 2>&1 | grep -q "1.177.0"'

IMAGE_ID="$(docker image inspect aegis-kali:code-provider --format '{{.Id}}')"
case "$IMAGE_ID" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "unexpected code provider image ID: $IMAGE_ID" >&2; exit 1 ;;
esac

docker run --rm --entrypoint cat "$IMAGE_ID"   /opt/aegis-runner/runtime-manifest.json > "$ARTIFACTS/runtime-manifest.json"

eval "$(
python - <<'PY'
import hashlib, json, shlex
raw=open('artifacts/runtime-manifest.json','rb').read()
runtime=json.loads(raw)
assert runtime['profile']=='code', runtime
assert runtime['dispatch_enabled'] is True, runtime
assert runtime['dispatch_state']=='semantic-code-provider', runtime
assert runtime['dispatch_capabilities']==['code.semgrep'], runtime
assert runtime['profile_tools']['semgrep']['version']=='1.177.0', runtime
values={
    'RUNNER_VERSION':runtime['runner_version'],
    'BUILD_COMMIT':runtime['build_commit'],
    'BASE_IMAGE_DIGEST':runtime['base_image_digest'],
    'TOOL_MANIFEST_DIGEST':runtime['tool_manifest_digest'],
    'RUNTIME_MANIFEST_DIGEST':'sha256:'+hashlib.sha256(raw).hexdigest(),
}
for key,value in values.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"

docker run -d --name aegis-semgrep-m5-scanner   --network none   --user 10001:10001   --cap-drop ALL --security-opt no-new-privileges:true   --read-only   --tmpfs /tmp:rw,noexec,nosuid,nodev,size=192m   -e AEGIS_SEMGREP_PROVIDER=default-kali   -e AEGIS_KALI_SEMGREP_CANARY_BPS=0   -e AEGIS_KALI_CODE_URL=http://127.0.0.1:18771   -e AEGIS_KALI_CODE_AUTH_TOKEN="$AUTH_TOKEN"   -e AEGIS_KALI_CODE_EXPECTED_RUNNER_VERSION="$RUNNER_VERSION"   -e AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT="$BUILD_COMMIT"   -e AEGIS_KALI_CODE_EXPECTED_BASE_IMAGE_DIGEST="$BASE_IMAGE_DIGEST"   -e AEGIS_KALI_CODE_EXPECTED_TOOL_MANIFEST_DIGEST="$TOOL_MANIFEST_DIGEST"   -e AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST="$IMAGE_ID"   -e AEGIS_KALI_CODE_EXPECTED_RUNTIME_MANIFEST_DIGEST="$RUNTIME_MANIFEST_DIGEST"   -e AEGIS_SEMGREP_WORKSPACE_ROOT=/var/lib/aegis-semgrep   -e SEMGREP_CONFIG=/opt/aegis-semgrep-rules/semgrep-parity.yml   -e SEMGREP_SEND_METRICS=off   -e SEMGREP_ENABLE_VERSION_CHECK=0   -e HOME=/tmp/home   -e XDG_CONFIG_HOME=/tmp/config   -e XDG_CACHE_HOME=/tmp/cache   -e TMPDIR=/tmp   -e DJANGO_SETTINGS_MODULE=django_project.settings   -e SECRET_KEY=aegisscan-semgrep-default-kali-ci-secret-key-not-for-production   -e JWT_SECRET_KEY=aegisscan-semgrep-default-kali-ci-jwt-key-not-for-production   -v "$SOURCE_DIR:/workspace/source:ro"   -v "$RULE_DIR:/opt/aegis-semgrep-rules:ro"   -v "$WORKSPACE_DIR:/var/lib/aegis-semgrep"   -v "$ARTIFACTS:/artifacts"   -v "$ROOT/aegis-platform/e2e/semgrep_default_kali_reality.py:/semgrep_default_kali_reality.py:ro"   --entrypoint sleep aegis-semgrep-m5:scanner infinity

docker run -d --name aegis-semgrep-m5-provider   --network container:aegis-semgrep-m5-scanner   --user 10001:10001   --read-only --cap-drop ALL --security-opt no-new-privileges:true   --pids-limit 128 --memory 768m --cpus 1   --tmpfs /tmp:rw,noexec,nosuid,nodev,size=192m   -e AEGIS_CODE_LISTEN_HOST=127.0.0.1   -e AEGIS_CODE_LISTEN_PORT=18771   -e AEGIS_KALI_CODE_AUTH_TOKEN="$AUTH_TOKEN"   -e AEGIS_CODE_WORKSPACE_ROOT=/var/lib/aegis-semgrep   -e AEGIS_CODE_SEMGREP_CONFIG=/opt/aegis-semgrep-rules/semgrep-parity.yml   -v "$RULE_DIR:/opt/aegis-semgrep-rules:ro"   -v "$WORKSPACE_DIR:/var/lib/aegis-semgrep:ro"   "$IMAGE_ID"

docker exec -i aegis-semgrep-m5-provider python3 - <<'PY'
import os
from pathlib import Path
values={}
for line in Path('/proc/1/status').read_text().splitlines():
    if ':' in line:
        k,v=line.split(':',1)
        values[k]=v.strip()
assert os.geteuid()==10001,os.geteuid()
for key in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb'):
    assert values[key]=='0000000000000000',(key,values[key])
assert values['NoNewPrivs']=='1',values['NoNewPrivs']
PY

docker exec aegis-semgrep-m5-scanner sh -c   'mkdir -p /tmp/home /tmp/config /tmp/cache && test -r /opt/aegis-semgrep-rules/semgrep-parity.yml && test -r /workspace/source/app.py'

for _ in $(seq 1 30); do
  if docker exec -i aegis-semgrep-m5-scanner python - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen('http://127.0.0.1:18771/healthz',timeout=1).read()
PY
  then
    break
  fi
  sleep 1
done

docker exec aegis-semgrep-m5-scanner python /semgrep_default_kali_reality.py default

docker exec   -e AEGIS_SEMGREP_PROVIDER=legacy   aegis-semgrep-m5-scanner   python /semgrep_default_kali_reality.py legacy

docker exec aegis-semgrep-m5-scanner python /semgrep_default_kali_reality.py compare

test -z "$(find "$WORKSPACE_DIR" -mindepth 1 -maxdepth 1 -print -quit)"

docker stop aegis-semgrep-m5-provider >/dev/null

docker exec aegis-semgrep-m5-scanner python /semgrep_default_kali_reality.py outage

docker exec   -e AEGIS_SEMGREP_PROVIDER=legacy   aegis-semgrep-m5-scanner   python /semgrep_default_kali_reality.py rollback

git rev-parse HEAD > "$ARTIFACTS/head-sha.txt"
printf '%s
' "$IMAGE_ID" > "$ARTIFACTS/code-provider-image-id.txt"
python - <<'PY' > "$ARTIFACTS/code-semgrep-default-kali-real.json"
import json
print(json.dumps({
    'schema':'aegis.code-semgrep-default-kali-real.v1',
    'default_kali_executed':True,
    'legacy_reference_executed':True,
    'semantic_equivalence':True,
    'production_finding_projection_equivalent':True,
    'provider_outage_fail_closed':True,
    'explicit_legacy_rollback':True,
    'silent_legacy_fallback':False,
    'provider_capabilities':[],
    'provider_non_root':True,
    'workspace_cleanup_verified':True,
    'network_required':False,
},sort_keys=True,indent=2))
PY

(
  cd "$ARTIFACTS"
  sha256sum     head-sha.txt runtime-manifest.json code-provider-image-id.txt fixture-sha256s.txt     default-kali.json default-kali-result.json legacy-reference.json legacy-reference-result.json     default-kali-semantic-parity.json default-kali-outage.json explicit-legacy-rollback.json     code-semgrep-default-kali-real.json > sha256sums.txt
)
