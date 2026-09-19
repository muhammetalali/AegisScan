#!/usr/bin/env bash
set -euo pipefail

: "${AEGIS_EXACT_HEAD:?AEGIS_EXACT_HEAD is required}"
test "$(git rev-parse HEAD)" = "${AEGIS_EXACT_HEAD}"

ROOT="$(pwd)"
ARTIFACTS="$ROOT/artifacts"
NETWORK="aegis-masscan-m6-retired"
TARGET="172.31.6.10"
EGRESS_IP="172.31.6.2"
AUTH_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

cleanup() {
  docker rm -f aegis-masscan-m6-provider aegis-masscan-m6-scanner aegis-masscan-m6-egress aegis-masscan-m6-fixture >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$ARTIFACTS"
chmod 0777 "$ARTIFACTS"

docker build --no-cache \
  --build-arg AEGIS_RETIRE_NMAP=1 \
  --build-arg AEGIS_RETIRE_NUCLEI=1 \
  --build-arg AEGIS_RETIRE_SEMGREP=1 \
  --build-arg AEGIS_RETIRE_MASSCAN=1 \
  --target production-no-legacy-recon \
  -t aegis-masscan-m6:scanner \
  -f aegis-platform/backend/Dockerfile.django \
  aegis-platform/backend

docker run --rm --entrypoint sh aegis-masscan-m6:scanner -c \
  '! command -v masscan && test ! -e /usr/bin/masscan && ! command -v nmap && ! command -v nuclei && ! command -v semgrep'

docker build --no-cache \
  -t aegis-scanner-egress:masscan-m6 \
  -f aegis-platform/docker/scanner-egress/Dockerfile \
  aegis-platform/docker/scanner-egress

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
docker build --no-cache \
  --build-arg BUILD_COMMIT="$AEGIS_EXACT_HEAD" \
  --build-arg AEGIS_RUNNER_VERSION=0.1.0 \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -t aegis-kali:base \
  -f aegis-platform/kali/Dockerfile.base \
  aegis-platform/kali

docker build --no-cache \
  --build-arg AEGIS_BASE_IMAGE=aegis-kali:base \
  --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  --target profile-network \
  -t aegis-kali:network \
  -f aegis-platform/kali/Dockerfile.profiles \
  .

docker build --no-cache \
  --build-arg AEGIS_MASSCAN_BASE_IMAGE=aegis-kali:network \
  -t aegis-kali:masscan-provider \
  -f aegis-platform/kali/Dockerfile.masscan-provider \
  aegis-platform/kali

IMAGE_ID="$(docker image inspect aegis-kali:masscan-provider --format '{{.Id}}')"
case "$IMAGE_ID" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "unexpected Masscan provider image ID: $IMAGE_ID" >&2; exit 1 ;;
esac

docker run --rm --entrypoint cat "$IMAGE_ID" /opt/aegis-runner/runtime-manifest.json > "$ARTIFACTS/runtime-manifest.json"

eval "$(
python - <<'PY'
import hashlib, json, shlex
raw=open('artifacts/runtime-manifest.json','rb').read()
runtime=json.loads(raw)
assert runtime['profile']=='network', runtime
assert runtime['dispatch_enabled'] is True, runtime
assert runtime['dispatch_state']=='semantic-masscan-provider', runtime
assert runtime['dispatch_capabilities']==['network.masscan'], runtime
assert runtime['profile_tools']['masscan']['version']=='2:1.3.2+ds1-2', runtime
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

docker network create --internal --subnet 172.31.6.0/24 "$NETWORK"
test "$(docker network inspect -f '{{.Internal}}' "$NETWORK")" = true

docker run -d --name aegis-masscan-m6-fixture \
  --network "$NETWORK" --ip "$TARGET" --user 0:0 \
  -v "$ROOT/aegis-platform/e2e/nmap_tcp_fixture.py:/fixture.py:ro" \
  --entrypoint python aegis-masscan-m6:scanner /fixture.py

docker run -d --name aegis-masscan-m6-egress \
  --network "$NETWORK" --ip "$EGRESS_IP" --user 0:0 \
  --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  -e SCANNER_CONTROL_ENDPOINTS='' \
  -e SCANNER_EGRESS_PRIVATE_TARGETS="$TARGET/32" \
  aegis-scanner-egress:masscan-m6

container_log_contains() {
  local container="$1"
  local needle="$2"
  local logs
  logs="$(docker logs "$container" 2>&1)" || return 1
  grep -Fq -- "$needle" <<<"$logs"
}

for _ in $(seq 1 30); do
  fixture_ready=false
  egress_ready=false
  container_log_contains aegis-masscan-m6-fixture AEGIS_NMAP_PARITY_FIXTURE_READY && fixture_ready=true || true
  container_log_contains aegis-masscan-m6-egress 'kernel egress policy installed' && egress_ready=true || true
  if "$fixture_ready" && "$egress_ready"; then break; fi
  sleep 1
done
container_log_contains aegis-masscan-m6-fixture AEGIS_NMAP_PARITY_FIXTURE_READY
container_log_contains aegis-masscan-m6-egress 'kernel egress policy installed'

INTERFACE=eth0
ADAPTER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' aegis-masscan-m6-egress)"
ADAPTER_MAC="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' aegis-masscan-m6-egress)"
ROUTER_MAC="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' aegis-masscan-m6-fixture)"
test "$ADAPTER_IP" = "$EGRESS_IP"

python - "$INTERFACE" "$ADAPTER_IP" "$ADAPTER_MAC" "$ROUTER_MAC" <<'PY' > "$ARTIFACTS/link-binding.json"
import ipaddress,json,re,sys
interface,ip,mac,router=sys.argv[1:]
assert ipaddress.ip_address(ip).version == 4
pat=re.compile(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
assert pat.fullmatch(mac) and pat.fullmatch(router)
print(json.dumps({
    'interface':interface,'adapter_ip':ip,
    'adapter_mac':mac.lower(),'router_mac':router.lower(),
},sort_keys=True,indent=2))
PY

docker run -d --name aegis-masscan-m6-scanner \
  --network container:aegis-masscan-m6-egress --user 0:0 \
  --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true \
  -e AUTHORIZED_SCAN_TARGETS="$TARGET/32" \
  -e AEGIS_MASSCAN_PROVIDER=default-kali \
  -e AEGIS_MASSCAN_LEGACY_DISABLED=true \
  -e AEGIS_KALI_MASSCAN_CANARY_BPS=0 \
  -e AEGIS_KALI_MASSCAN_URL=http://127.0.0.1:18767 \
  -e AEGIS_KALI_MASSCAN_AUTH_TOKEN="$AUTH_TOKEN" \
  -e AEGIS_KALI_MASSCAN_IMAGE="$IMAGE_ID" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_RUNNER_VERSION="$RUNNER_VERSION" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_BUILD_COMMIT="$BUILD_COMMIT" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_BASE_IMAGE_DIGEST="$BASE_IMAGE_DIGEST" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_TOOL_MANIFEST_DIGEST="$TOOL_MANIFEST_DIGEST" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_IMAGE_DIGEST="$IMAGE_ID" \
  -e AEGIS_KALI_MASSCAN_EXPECTED_RUNTIME_MANIFEST_DIGEST="$RUNTIME_MANIFEST_DIGEST" \
  -e AEGIS_MASSCAN_INTERFACE="$INTERFACE" \
  -e AEGIS_MASSCAN_ADAPTER_IP="$ADAPTER_IP" \
  -e AEGIS_MASSCAN_ADAPTER_MAC="${ADAPTER_MAC,,}" \
  -e AEGIS_MASSCAN_ROUTER_MAC="${ROUTER_MAC,,}" \
  -v "$ARTIFACTS:/artifacts" \
  -v "$ROOT/aegis-platform/e2e/masscan_m6_retirement_reality.py:/masscan_m6_retirement_reality.py:ro" \
  --entrypoint sleep aegis-masscan-m6:scanner infinity

docker exec aegis-masscan-m6-scanner python -m fastapi_app.services.masscan_retirement_preflight

docker run -d --name aegis-masscan-m6-provider \
  --network container:aegis-masscan-m6-egress --user 0:0 --read-only \
  --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true \
  --pids-limit 128 --memory 512m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -e AEGIS_KALI_MASSCAN_AUTH_TOKEN="$AUTH_TOKEN" \
  "$IMAGE_ID"

docker exec aegis-masscan-m6-provider sh -c \
  "grep -Eq '^CapEff:[[:space:]]+0000000000002000$' /proc/1/status && grep -Eq '^CapPrm:[[:space:]]+0000000000002000$' /proc/1/status && grep -Eq '^CapBnd:[[:space:]]+0000000000002000$' /proc/1/status && grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/1/status"

for _ in $(seq 1 30); do
  if docker exec aegis-masscan-m6-scanner python - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen('http://127.0.0.1:18767/healthz',timeout=1).read()
PY
  then break; fi
  sleep 1
done

docker exec aegis-masscan-m6-scanner python /masscan_m6_retirement_reality.py default
docker exec aegis-masscan-m6-scanner python /masscan_m6_retirement_reality.py retired-routes

docker stop aegis-masscan-m6-provider >/dev/null
docker exec aegis-masscan-m6-scanner python /masscan_m6_retirement_reality.py outage

git rev-parse HEAD > "$ARTIFACTS/head-sha.txt"
printf '%s\n' "$IMAGE_ID" > "$ARTIFACTS/masscan-provider-image-id.txt"

python - <<'PY' > "$ARTIFACTS/network-masscan-m6-runtime.json"
import json
print(json.dumps({
    'schema':'aegis.network-masscan-legacy-retirement-runtime.v1',
    'local_masscan_cli_present':False,
    'production_provider':'default-kali',
    'legacy_route_admitted':False,
    'canary_route_admitted':False,
    'provider_outage_fail_closed':True,
    'provider_capabilities':['CAP_NET_RAW'],
    'scanner_egress_capabilities':['CAP_NET_ADMIN'],
    'rollback_strategy':'previous-release-deployment',
    'public_internet_target_used':False,
},sort_keys=True,indent=2))
PY

(
  cd "$ARTIFACTS"
  sha256sum \
    head-sha.txt runtime-manifest.json masscan-provider-image-id.txt \
    link-binding.json retired-default-kali.json retired-default-kali-result.json \
    retired-routes.json retired-provider-outage.json network-masscan-m6-runtime.json \
    > sha256sums.txt
)
