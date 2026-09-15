# M4 Recon Canary

> Status: completed on canonical main at 022510ca98792fcf0bf409899fcb7bb6dea50768. The exact-main M4 Reality and mandatory release suite were terminal green before M5 began.

## Objective

M4 introduces a bounded, deterministic canary for the governed Kali Recon execution fabric without changing the platform default away from the legacy native worker.

M3 proved semantic parity for `recon.fierce` on a deterministic authorized DNS fixture. M4 uses that proof as the only initial admission to canary routing.

## Routing contract

The authoritative decision is `recon_provider_decision()` in `fastapi_app.services.kali_recon_provider`.

Modes:

- `legacy`: default and rollback state; every capability remains on the legacy native worker.
- `canary`: only parity-approved capabilities are eligible for stable percentage routing.
- `kali`: retained as an explicit engineering/reality override, but production preflight rejects it during M4 so this phase cannot silently become M5.

The M4 canary is hard-bounded to **0–2500 basis points (0–25%)**. A value above 2500 fails closed.

The first and only M4 parity-approved capability is:

- `recon.fierce`

Other Kali Recon capabilities remain legacy-routed even when canary mode is enabled until they gain their own approved semantic-parity evidence.

## Deterministic assignment

Canary selection is never random. The worker computes a SHA-256 assignment from:

`routing schema + capability ID + canonical Scan ID`

The resulting bucket is stable in a 10,000-bucket space. A scan is selected only when its bucket is below `AEGIS_KALI_RECON_CANARY_BPS`.

The raw Scan ID is not copied into routing evidence. Evidence stores the SHA-256 routing-key digest, bucket, threshold, mode, reason, parity-approval state, and selected provider.

This produces a durable cohort that can be correlated with scan outcomes without random reassignment across retries.

## Execution integration

The existing `run_native_capability_scan` path remains authoritative.

M4 does not add another orchestrator, normalizer, Finding lifecycle, Evidence store, or authorization plane. `_execute_runtime()` obtains one routing decision and then chooses either:

- existing `run_native_tool()`; or
- existing `execute_kali_recon()`.

After either backend returns, the existing production normalizer, authorization revalidation, Evidence persistence, Finding projection, scan state machine, and durable execution result path continue unchanged.

The routing decision is added to `runtime_provenance`, so both holdback and selected executions are auditable.

## Failure and rollback semantics

There is no silent fallback from a selected Kali execution to legacy. A selected Kali failure remains a visible execution failure and participates in normal retry/failure semantics. This prevents a broken canary from appearing healthy because the system quietly changed backends.

Emergency rollback is explicit:

`AEGIS_RECON_PROVIDER=canary`
`AEGIS_KALI_RECON_CANARY_BPS=0`

Zero basis points route every eligible execution to legacy without requiring a routing key. Production deployment also removes the `kali-recon` Compose profile at zero BPS.

Operators can also return `AEGIS_RECON_PROVIDER=legacy`; production preflight requires BPS to be zero in that mode.

## Production controls

`production_preflight.py` enforces during M4:

- production mode is only `legacy` or `canary`;
- canary BPS is a canonical integer from 0 through 2500;
- active canary uses only `http://127.0.0.1:<high-port>` for the provider;
- provider auth token is 64-character lowercase hex;
- runner version, build commit, base image, tool manifest, execution image, and runtime manifest pins are complete and immutable;
- full `kali` mode is rejected until M5.

`docker-compose.prod.yml` explicitly propagates the complete governed Recon provider configuration into `scanner_worker` even though the production overlay resets `env_file`.

`production_host_deploy.py` automatically adds the `kali-recon` Compose profile only when canary traffic is non-zero, and removes it on zero-BPS rollback.

## Reality proof

`M4 Recon Canary Reality` proves on the exact PR/main SHA:

1. routing, task wiring, production preflight, deployment-profile, and Compose contracts;
2. exact legacy scanner and exact governed Kali Recon images;
3. immutable Control Plane provenance trust anchors;
4. deterministic selected and holdback routing keys at 25% canary;
5. a real legacy holdback execution against the authorized local DNS fixture;
6. a real Kali-selected execution through the production provider client against the same fixture;
7. non-empty production-normalized observations from both paths;
8. semantic equivalence using the M3 comparator;
9. selected/holdback routing evidence and runtime provenance;
10. zero-BPS rollback of both cohorts to legacy.

## Non-goals

M4 does not:

- make Kali the default provider;
- permit more than 25% canary traffic;
- admit capabilities without approved parity evidence;
- silently fall back after a selected Kali failure;
- retire the legacy worker;
- start M5 Default Kali or M6 Legacy Retirement.

## Exit gate

M4 is complete only after:

- all routing and task integration tests are green;
- production preflight/deployment contracts are green;
- real selected and holdback executions are proven;
- semantic parity remains green for the canary capability;
- zero-BPS rollback is proven;
- exact PR head is terminal green and `behind=0`;
- PR is merged using the verified expected-head SHA;
- fresh exact-main M4 Reality and all mandatory release workflows are terminal green.

Until the final two conditions are satisfied, M5 remains blocked.
