# Governed Kali Masscan — Bounded Canary (M4)

## Scope

This phase advances `network.masscan` from proven M3 semantic parity to a bounded, opt-in production canary. It does **not** promote Governed Kali to the default Masscan provider and does **not** retire the local Masscan runtime.

The authoritative production path becomes:

`run_masscan_scan → masscan_execution_provider → stable provider decision → legacy or governed Kali`.

## Routing policy

- library/deployment default remains `legacy`;
- `AEGIS_MASSCAN_PROVIDER=canary` enables cohort routing;
- `AEGIS_KALI_MASSCAN_CANARY_BPS` is bounded to 0–2500 basis points;
- cohort assignment is SHA-256 stable on the persisted Scan UUID;
- 0 BPS is the immediate rollback to Legacy;
- raw `AEGIS_MASSCAN_PROVIDER=kali` is a provider-library diagnostic decision and is rejected by the production execution layer;
- once a scan is assigned to governed Kali, provider/auth/provenance/runtime/control failure propagates; there is no hidden Legacy retry.

## Governed provider boundary

The M4 provider is a dedicated image and process for `network.masscan`. It is not the M3 parity service and it does not widen the existing Nmap provider.

The sidecar:

- binds only to loopback port 18767 in the scanner-egress namespace;
- accepts only semantic Masscan fields: target, ports, rate and optional deployment-controlled link identity;
- never accepts binary paths, argv, or shell strings;
- executes with exactly `CAP_NET_RAW`, all other capabilities dropped, and `no_new_privs`;
- is read-only, resource bounded and has no published ports;
- verifies the exact runner/build/base/tool/runtime/image provenance pinned by the control plane;
- exposes authenticated runtime attestation and pause/resume/cancel control;
- caps Masscan rate at 100,000 packets/second and timeout at 300 seconds.

The scanner-egress namespace owner remains the only component allowed `CAP_NET_ADMIN` for deterministic link preparation. The scanner worker and Masscan provider receive only `CAP_NET_RAW`.

## Lineage

Every Masscan execution persists:

- provider routing decision;
- stable routing-key digest and bucket for a canary cohort;
- runtime/image provenance for governed execution;
- provider lineage in scanner Evidence;
- provider lineage in per-finding Evidence;
- provider lineage in `ScanEngineExecution.result_data`;
- completion telemetry in `ScanLog`;
- the same lineage through `scan.engine_results`.

## Deployment

`aegis-platform/docker-compose.masscan-canary.yml` is opt-in and leaves base/prod Compose unchanged.

Default render:

- `AEGIS_MASSCAN_PROVIDER=legacy`;
- `AEGIS_KALI_MASSCAN_CANARY_BPS=0`;
- governed provider available only under profile `kali-masscan`.

A controlled rollout can set `AEGIS_MASSCAN_PROVIDER=canary` and a BPS value up to 2500. Rollback is BPS zero and does not require the provider to remain healthy.

## Reality gates

`Network Masscan Canary Reality` proves:

1. deterministic selected and holdback cohorts;
2. 25% hard rollout ceiling and zero-BPS rollback;
3. a real legacy holdback and real governed selected run against the same internal target;
4. semantic equality on persisted Masscan identity `(ip, protocol, port)`;
5. exact `CAP_NET_RAW` + `no_new_privs` provider runtime;
6. immutable runtime/image provenance;
7. selected-provider outage fails closed;
8. zero-BPS rollback still executes Legacy while the provider is unavailable;
9. exact-head evidence and checksums.

`Network Masscan Canary Deployment Reality` independently renders the Compose overlay and proves that it is opt-in, loopback-only, capability-minimal and rollback-safe.

## Next gate

M5 default-Kali promotion is separate. It may begin only after M4 is exact-head terminal green, merged, and the exact merged `main` SHA receives fresh-main terminal-green verification.
