#!/usr/bin/env bash
set -euo pipefail

: "${AEGIS_EXACT_HEAD:?AEGIS_EXACT_HEAD is required}"
test "$(git rev-parse HEAD)" = "${AEGIS_EXACT_HEAD}"

ROOT="$(pwd)"
ARTIFACTS="$ROOT/artifacts"
SOURCE_DIR="$ROOT/m6-semgrep-source"
RULE_DIR="$ROOT/m6-semgrep-rules"
WORKSPACE_VOLUME="aegis-semgrep-m6-workspace"
AUTH_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

cleanup() {
  docker rm -f aegis-semgrep-m6-provider aegis-semgrep-m6-scanner >/dev/null 2>&1 || true
  docker volume rm -f "$WORKSPACE_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$ARTIFACTS" "$SOURCE_DIR" "$RULE_DIR"
chmod 0777 "$ARTIFACTS"
cp aegis-platform/e2e/fixtures/semgrep-parity-source/app.py "$SOURCE_DIR/app.py"
cp aegis-platform/e2e/fixtures/semgrep-parity.yml "$RULE_DIR/semgrep-parity.yml"
sha256sum "$SOURCE_DIR/app.py" "$RULE_DIR/semgrep-parity.yml" > "$ARTIFACTS/fixture-sha256s.txt"

docker build --no-cache   --build-arg AEGIS_RETIRE_NMAP=1   --build-arg AEGIS_RETIRE_NUCLEI=1   --build-arg AEGIS_RETIRE_SEMGREP=1   --target production-no-legacy-recon   -t aegis-semgrep-m6:scanner   -f aegis-platform/backend/Dockerfile.django   aegis-platform/backend

docker run --rm --entrypoint sh aegis-semgrep-m6:scanner -c   '! command -v semgrep && ! command -v pysemgrep && ! command -v nmap && ! command -v nuclei && command -v masscan >/dev/null && python -c '"'"'import importlib.util; assert importlib.util.find_spec("semgrep") is None'"'"''

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
docker build --no-cache   --build-arg BUILD_COMMIT="$AEGIS_EXACT_HEAD"   --build-arg AEGIS_RUNNER_VERSION=0.1.0   --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"   -t aegis-kali:base   -f aegis-platform/kali/Dockerfile.base   aegis-platform/kali

docker build --no-cache   --build-arg AEGIS_BASE_IMAGE=aegis-kali:base   --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"   --target profile-code   -t aegis-kali:code   -f aegis-platform/kali/Dockerfile.profiles   .

docker build --no-cache   --build-arg AEGIS_CODE_BASE_IMAGE=aegis-kali:code   -t aegis-kali:code-provider   -f aegis-platform/kali/Dockerfile.code-provider   aegis-platform/kali

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

docker volume create "$WORKSPACE_VOLUME" >/dev/null
docker run --rm   -v "$WORKSPACE_VOLUME:/var/lib/aegis-semgrep"   --entrypoint sh aegis-semgrep-m6:scanner -c   'chown 10001:10001 /var/lib/aegis-semgrep && chmod 0700 /var/lib/aegis-semgrep'

docker run -d --name aegis-semgrep-m6-scanner   --network none   --user 10001:10001   --cap-drop ALL --security-opt no-new-privileges:true   --read-only   --tmpfs /tmp:rw,noexec,nosuid,nodev,size=192m   -e AEGIS_SEMGREP_PROVIDER=default-kali   -e AEGIS_SEMGREP_LEGACY_DISABLED=true   -e AEGIS_KALI_SEMGREP_CANARY_BPS=0   -e AEGIS_KALI_CODE_URL=http://127.0.0.1:18771   -e AEGIS_KALI_CODE_AUTH_TOKEN="$AUTH_TOKEN"   -e AEGIS_KALI_CODE_IMAGE="$IMAGE_ID"   -e AEGIS_KALI_CODE_EXPECTED_RUNNER_VERSION="$RUNNER_VERSION"   -e AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT="$BUILD_COMMIT"   -e AEGIS_KALI_CODE_EXPECTED_BASE_IMAGE_DIGEST="$BASE_IMAGE_DIGEST"   -e AEGIS_KALI_CODE_EXPECTED_TOOL_MANIFEST_DIGEST="$TOOL_MANIFEST_DIGEST"   -e AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST="$IMAGE_ID"   -e AEGIS_KALI_CODE_EXPECTED_RUNTIME_MANIFEST_DIGEST="$RUNTIME_MANIFEST_DIGEST"   -e AEGIS_SEMGREP_WORKSPACE_ROOT=/var/lib/aegis-semgrep   -e DJANGO_SETTINGS_MODULE=django_project.settings   -e SECRET_KEY=aegisscan-semgrep-m6-ci-secret-key-not-for-production   -e JWT_SECRET_KEY=aegisscan-semgrep-m6-ci-jwt-key-not-for-production   -e HOME=/tmp/home   -e XDG_CONFIG_HOME=/tmp/config   -e XDG_CACHE_HOME=/tmp/cache   -e TMPDIR=/tmp   -v "$SOURCE_DIR:/workspace/source:ro"   -v "$WORKSPACE_VOLUME:/var/lib/aegis-semgrep"   -v "$ARTIFACTS:/artifacts"   -v "$ROOT/aegis-platform/e2e/semgrep_m6_retirement_reality.py:/semgrep_m6_retirement_reality.py:ro"   --entrypoint sleep aegis-semgrep-m6:scanner infinity

docker exec aegis-semgrep-m6-scanner python -m fastapi_app.services.semgrep_retirement_preflight

docker run -d --name aegis-semgrep-m6-provider   --network container:aegis-semgrep-m6-scanner   --user 10001:10001   --read-only --cap-drop ALL --security-opt no-new-privileges:true   --pids-limit 128 --memory 768m --cpus 1   --tmpfs /tmp:rw,noexec,nosuid,nodev,size=192m   -e AEGIS_CODE_LISTEN_HOST=127.0.0.1   -e AEGIS_CODE_LISTEN_PORT=18771   -e AEGIS_KALI_CODE_AUTH_TOKEN="$AUTH_TOKEN"   -e AEGIS_CODE_WORKSPACE_ROOT=/var/lib/aegis-semgrep   -e AEGIS_CODE_SEMGREP_CONFIG=/opt/aegis-semgrep-rules/semgrep-parity.yml   -e HOME=/tmp/aegis-home   -e TMPDIR=/tmp   -e XDG_CACHE_HOME=/tmp/aegis-home/.cache   -e XDG_CONFIG_HOME=/tmp/aegis-home/.config   -v "$RULE_DIR:/opt/aegis-semgrep-rules:ro"   -v "$WORKSPACE_VOLUME:/var/lib/aegis-semgrep:ro"   "$IMAGE_ID"

docker exec -i aegis-semgrep-m6-provider python3 - <<'PY'
import os
from pathlib import Path
values={}
for line in Path('/proc/1/status').read_text().splitlines():
    if ':' in line:
        key,value=line.split(':',1)
        values[key]=value.strip()
assert os.geteuid()==10001,os.geteuid()
for key in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb'):
    assert values[key]=='0000000000000000',(key,values[key])
assert values['NoNewPrivs']=='1',values['NoNewPrivs']
PY

for _ in $(seq 1 30); do
  if docker exec -i aegis-semgrep-m6-scanner python - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen('http://127.0.0.1:18771/healthz',timeout=1).read()
PY
  then
    break
  fi
  sleep 1
done

docker exec aegis-semgrep-m6-scanner python /semgrep_m6_retirement_reality.py default
docker exec aegis-semgrep-m6-scanner python /semgrep_m6_retirement_reality.py retired-routes

docker run --rm   -v "$WORKSPACE_VOLUME:/workspace:ro"   --entrypoint sh aegis-semgrep-m6:scanner -c   'test -z "$(find /workspace -mindepth 1 -maxdepth 1 -print -quit)"'

docker stop aegis-semgrep-m6-provider >/dev/null
docker exec aegis-semgrep-m6-scanner python /semgrep_m6_retirement_reality.py outage

docker run --rm   -v "$WORKSPACE_VOLUME:/workspace:ro"   --entrypoint sh aegis-semgrep-m6:scanner -c   'test -z "$(find /workspace -mindepth 1 -maxdepth 1 -print -quit)"'

git rev-parse HEAD > "$ARTIFACTS/head-sha.txt"
printf '%s\n' "$IMAGE_ID" > "$ARTIFACTS/code-provider-image-id.txt"
python - <<'PY' > "$ARTIFACTS/code-semgrep-m6-runtime.json"
import json
print(json.dumps({
    'schema':'aegis.code-semgrep-legacy-retirement-runtime.v1',
    'local_semgrep_cli_present':False,
    'local_semgrep_python_module_present':False,
    'production_provider':'default-kali',
    'legacy_route_admitted':False,
    'canary_route_admitted':False,
    'provider_outage_fail_closed':True,
    'provider_capabilities':[],
    'provider_non_root':True,
    'workspace_rw_ro_separation':True,
    'workspace_cleanup_verified':True,
    'network_required':False,
},sort_keys=True,indent=2))
PY

(
  cd "$ARTIFACTS"
  sha256sum     head-sha.txt runtime-manifest.json code-provider-image-id.txt fixture-sha256s.txt     retired-default-kali.json retired-default-kali-result.json retired-routes.json     retired-provider-outage.json code-semgrep-m6-runtime.json > sha256sums.txt
)
