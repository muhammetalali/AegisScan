# Governed Kali Nmap Canary

## Status

This document records the completed M4 bounded-canary design. After M5 promotion, the authoritative deployment default is `AEGIS_NMAP_PROVIDER=default-kali`; the Canary path remains supported as a regression, diagnostic, and controlled rollback-analysis mode until legacy retirement. The current promotion contract is documented in `docs/NETWORK_NMAP_DEFAULT_KALI.md`.

## Scope

M4 admitted `network.nmap` to a bounded deterministic governed-Kali canary without making Kali the default provider and without retiring the legacy Nmap path. M5 subsequently promoted the parity-proven capability to Governed Kali by default while preserving these Canary semantics for regression evidence.

## Routing contract

- Current deployment default after M5: `AEGIS_NMAP_PROVIDER=default-kali`.
- Canary mode remains explicit: `AEGIS_NMAP_PROVIDER=canary`.
- `AEGIS_KALI_NMAP_CANARY_BPS` is bounded to `0..2500` (0..25%).
- Cohort assignment is deterministic from SHA-256 of the canonical routing schema, `network.nmap`, and the persisted Scan UUID.
- In Canary mode, `0` BPS routes to the legacy adapter and is retained as the bounded-canary rollback invariant while legacy exists.
- M5 also retains explicit administrative rollback through `AEGIS_NMAP_PROVIDER=legacy` until M6 retirement.
- Raw `AEGIS_NMAP_PROVIDER=kali` remains rejected by the production-facing execution layer.
- A scan selected for Kali never silently falls back to legacy when provider execution, authentication, provenance, or runtime attestation fails.

## Runtime boundary

The generic Kali `network` profile remains placement-only. A dedicated derived provider image enables semantic dispatch for **only** `network.nmap`. `network.masscan`, `network.rustscan`, and both NBTSCan capabilities remain non-dispatchable.

The provider:

- listens only on scanner-loopback (`127.0.0.1:18766`),
- requires a 64-character lowercase-hex control token,
- accepts no raw command, binary, shell, or argv authority,
- fixes Nmap semantics to `-Pn -sV -oX - -- <target>`,
- runs with `CAP_NET_RAW` only, all other capabilities dropped, and `no_new_privs`,
- validates immutable runner/build/base/tool/runtime/image provenance,
- supports bounded pause/resume/cancel control,
- fails closed on provenance drift or provider unavailability.

## Canary deployment boundary

`aegis-platform/docker-compose.nmap-canary.yml` is retained as the explicit Canary overlay. It is **not** the current M5 default deployment overlay. Current M5 default-Kali deployments use `aegis-platform/docker-compose.nmap-default-kali.yml`.

A Canary deployment must:

1. build/pull the exact approved `aegis-kali:network-provider` image and record its immutable digest;
2. provide the 64-character provider authentication token and all expected runner/build/base/tool/image/runtime provenance pins;
3. set `AEGIS_NMAP_PROVIDER=canary` and an explicit `AEGIS_KALI_NMAP_CANARY_BPS` no greater than `2500`;
4. include the Canary override and enable only the `kali-network` profile;
5. verify the `kali_network` health check before admitting selected Nmap scans.

The sidecar shares the governed `scanner_egress` network namespace, binds only loopback, drops all capabilities before adding exactly `NET_RAW`, is read-only, uses `no-new-privileges`, and has bounded CPU/memory/PID/tmpfs resources. If Canary routing is enabled without the sidecar or trusted provenance pins, a selected scan fails closed; it does not silently use legacy Nmap.

## Evidence lineage

`run_nmap_scan` persists both the routing decision and trusted runtime provenance in Nmap Evidence, `ScanEngineExecution.result_data`, and the completion `ScanLog`. Existing parser, finding ingestion, authorization revalidation, and finding semantics remain unchanged.

## Regression reality proof

`Network Nmap Canary Reality` remains an exact-head regression gate and must prove:

1. stable selected and holdback cohorts exist at 25% Canary;
2. real legacy holdback and governed Kali selected runs execute against the same deterministic internal fixture;
3. finding-relevant Nmap semantics are equivalent;
4. the Kali runtime is exactly `CAP_NET_RAW` + `no_new_privs`;
5. zero-BPS Canary rollback succeeds even when the provider is unavailable;
6. an outage for a Kali-selected scan fails closed and never executes a legacy fallback;
7. the deployable Canary overlay preserves the loopback, capability, profile, and trusted-provenance boundaries;
8. evidence states that the current deployment default is `default-kali`, not the historical M4 default;
9. no public Internet target is used.

## Promotion and retirement boundary

M5 Default-Kali promotion is governed by `Network Nmap Default Kali Reality`. Legacy retirement is a separate M6 phase and may begin only after M5 is exact-head terminal green, merged through protected `main`, and fresh-main terminal green on the exact merged SHA.
