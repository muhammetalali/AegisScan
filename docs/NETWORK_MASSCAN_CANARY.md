# Governed Kali Masscan — Bounded Canary (M4)

## Status

This document records the completed M4 bounded-canary design. After M5 promotion, the authoritative deployment default is `AEGIS_MASSCAN_PROVIDER=default-kali`; the Canary path remains supported as a regression, diagnostic, and controlled rollback-analysis mode until legacy retirement. The current promotion contract is documented in `docs/NETWORK_MASSCAN_DEFAULT_KALI.md`.

## Scope

M4 admitted `network.masscan` to a bounded, deterministic governed-Kali canary without making Kali the default provider and without retiring the local Masscan path. M5 subsequently promotes the parity-proven capability to Governed Kali by default while preserving these Canary semantics as regression evidence.

The authoritative execution path remains:

`run_masscan_scan → masscan_execution_provider → provider decision → legacy or governed Kali`.

## Routing contract

- Current M5 deployment default: `AEGIS_MASSCAN_PROVIDER=default-kali`.
- Canary mode remains explicit: `AEGIS_MASSCAN_PROVIDER=canary`.
- `AEGIS_KALI_MASSCAN_CANARY_BPS` is bounded to 0–2500 basis points.
- Cohort assignment is SHA-256 stable on the persisted Scan UUID.
- In Canary mode, 0 BPS routes to legacy and remains the bounded-canary rollback invariant while legacy exists.
- M5 also retains explicit administrative rollback with `AEGIS_MASSCAN_PROVIDER=legacy`.
- Raw `AEGIS_MASSCAN_PROVIDER=kali` remains rejected by the production execution wrapper.
- A Kali-selected execution never silently falls back to legacy when provider/auth/provenance/runtime/control execution fails.

## Governed provider boundary

The provider is a dedicated image and process for `network.masscan`; it is separate from the historical M3 parity service and from the Nmap provider.

It:

- binds only to `127.0.0.1:18767` in the scanner-egress namespace;
- accepts bounded target, ports, rate, and deployment-controlled link identity;
- never accepts raw binary paths, argv, or shell strings;
- runs with exactly `CAP_NET_RAW`, all other capabilities dropped, and `no_new_privs`;
- is read-only, resource bounded, and exposes no published port;
- verifies immutable runner/build/base/tool/runtime/image provenance;
- supports pause/resume/cancel control;
- caps rate at 100,000 packets/second and timeout at 300 seconds.

The scanner-egress namespace owner remains the only component with `CAP_NET_ADMIN`.

## Canary deployment boundary

`aegis-platform/docker-compose.masscan-canary.yml` is retained as the explicit M4 Canary overlay. It is **not** the current M5 default deployment overlay. M5 uses `aegis-platform/docker-compose.masscan-default-kali.yml`.

The Canary overlay itself intentionally renders legacy + 0 BPS by default, and a controlled rollout explicitly sets `AEGIS_MASSCAN_PROVIDER=canary` with a value no greater than 2500. A selected provider failure remains fail-closed.

## Lineage

Every Masscan execution persists provider routing and trusted runtime provenance through scanner Evidence, per-finding Evidence, `ScanEngineExecution.result_data`, `ScanLog`, and `scan.engine_results`.

## Regression reality proof

`Network Masscan Canary Reality` remains an exact-head regression gate and proves:

1. stable selected and holdback cohorts;
2. real legacy holdback and real governed selected execution against the same deterministic internal fixture;
3. semantic equality on persisted Masscan identity `(ip, protocol, port)`;
4. exact `CAP_NET_RAW` + `no_new_privs` provider runtime;
5. immutable runtime/image provenance;
6. zero-BPS Canary rollback while the provider is unavailable;
7. a selected-provider outage fails closed without a hidden legacy retry;
8. evidence identifies `default-kali` as the current deployment default after M5;
9. no public Internet target is used.

`Network Masscan Canary Deployment Reality` continues to validate the explicit M4 overlay itself as loopback-only, capability-minimal, resource-bounded, and rollback-safe.

## Promotion and retirement boundary

M5 is governed by `Network Masscan Default Kali Reality`. Legacy retirement is a separate M6 phase and may begin only after M5 is exact-head terminal green, merged through `main`, and fresh-main terminal green on the exact merged SHA.
