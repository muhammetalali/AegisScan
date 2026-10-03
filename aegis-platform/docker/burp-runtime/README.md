# Supervised Burp P2 runtime

This optional runtime reuses `network_mode: service:scanner_egress`, as the
existing scanner and governed providers do. MCP must listen on **127.0.0.1:9876**;
the scanner uses `http://127.0.0.1:9876/`. No host networking, bridge endpoint,
proxy, public port, new queue, auth service or credential store is introduced.

The image packages vendor-checksummed Community 2026.9 and the recorded official
BApp 1.3.0 JAR. The extension hash records the downloaded artifact; it does not
claim a vendor signature, SBOM or enterprise acceptance. Build dependencies
are resolved by apt; record the resulting image digest for each build.

From the repository root, prepare a private context and build:

```sh
sh aegis-platform/docker/burp-runtime/prepare-build-context.sh "$VERIFIED_RUNTIME" "$NEW_PRIVATE_CONTEXT"
docker build -t aegis-burp:2026.9 "$NEW_PRIVATE_CONTEXT"
```

Prepare a separate owner-writable profile outside the repository. Use an
authorized desktop session and mount its private Xauthority read-only; never use
`xhost +`. The profile is not part of the image. Load `/opt/burp/burp-mcp-all.jar`,
disable automatic BApp updates, enable MCP only on loopback, keep HTTP/project
approvals and credential filtering enabled, and keep configuration editing off.
Approve only the exact local health fixture host and port for P2. Target approvals
must be rechecked after restart; a copied profile does not prove their persistence.

Community starts with a temporary project through the GUI. This is a supervised
desktop runtime, not an unattended/headless daemon; restart policy is deliberately
`no`. Xauthority grants access to the operator's display and must remain private.
Deployment needs that operator session plus existing immutable provider approval.
Do not register a provider just because a health probe passes.

Review the optional overlay with base and production Compose before activation:

```sh
docker compose -f aegis-platform/docker-compose.yml \
  -f aegis-platform/docker-compose.prod.yml \
  -f aegis-platform/docker-compose.burp.yml --profile burp-runtime config
```

Set the required `AEGIS_BURP_RUNTIME_IMAGE` to the verified image digest,
`AEGIS_BURP_PROFILE_PATH`, `AEGIS_BURP_XAUTHORITY_PATH` and desktop UID/GID.
`AEGIS_BURP_ALLOW_LOOPBACK_HTTP=true` sets `BURP_MCP_ALLOW_INSECURE_LOCAL` only for the
scanner/API processes that validate the approved loopback manifest; remote HTTP
remains prohibited. These variables do not create provider approval or a solver.

`Dockerfile.scanner-candidate` is a P2 validation overlay on the recorded retired
production scanner base. It embeds current `fastapi_app` and `scripts` without
source mounts or changes to binary retirement. It is not a full release rebuild.
The existing `Dockerfile.django` production target remains the release build.

Acceptance requires: packaged schema-pinned live health probe from the shared
namespace, matching image/module hashes, external MCP unreachability,
unrelated private egress still blocked, and exact-commit CI. A health pass never
proves A/B replay, live fixture revision, a finding or a solved lab.
