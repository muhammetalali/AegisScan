# Governed Kali Nmap Canary

## Scope

This phase admits `network.nmap` to a bounded deterministic governed-Kali canary. It does **not** make Kali the default provider and does **not** retire the legacy production Nmap path.

## Routing contract

- Production default remains `AEGIS_NMAP_PROVIDER=legacy`.
- Canary mode is explicit: `AEGIS_NMAP_PROVIDER=canary`.
- `AEGIS_KALI_NMAP_CANARY_BPS` is bounded to `0..2500` (0..25%).
- Cohort assignment is deterministic from SHA-256 of the canonical routing schema, `network.nmap`, and the persisted Scan UUID.
- `0` BPS is the immediate rollback to the existing legacy Nmap adapter.
- Full-Kali routing is rejected by the production-facing execution layer during this phase.
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

## Deployment boundary

The normal platform Compose files remain unchanged during the Canary phase. Deployment is opt-in through `aegis-platform/docker-compose.nmap-canary.yml`, which adds only the Nmap provider settings to `scanner_worker` and a `kali_network` sidecar profile.

A Canary deployment must:

1. build/pull the exact approved `aegis-kali:network-provider` image and record its immutable digest;
2. provide the 64-character provider authentication token and all expected runner/build/base/tool/image/runtime provenance pins;
3. set `AEGIS_NMAP_PROVIDER=canary` and an explicit `AEGIS_KALI_NMAP_CANARY_BPS` no greater than `2500`;
4. include the override and enable only the `kali-network` profile, for example `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.nmap-canary.yml --profile kali-network ...`;
5. verify the `kali_network` health check before admitting selected Nmap scans.

The sidecar shares the governed `scanner_egress` network namespace, binds only loopback, drops all capabilities before adding exactly `NET_RAW`, is read-only, uses `no-new-privileges`, and has bounded CPU/memory/PID/tmpfs resources. If the operator enables canary routing without the sidecar or without trusted provenance pins, a selected scan fails closed; it does not silently use legacy Nmap.

Rollback is configuration-only in this phase: set `AEGIS_KALI_NMAP_CANARY_BPS=0`. The sidecar may then be stopped/removed after in-flight governed executions have drained. This rollback does not change code or Finding semantics.

## Evidence lineage

`run_nmap_scan` persists both the routing decision and trusted runtime provenance in Nmap Evidence, `ScanEngineExecution.result_data`, and the completion `ScanLog`. Existing parser, finding ingestion, authorization revalidation, and finding semantics are unchanged.

## Reality proof

`Network Nmap Canary Reality` must prove on the exact PR/main SHA:

1. default legacy routing remains intact;
2. stable selected and holdback cohorts exist at 25% canary;
3. real legacy holdback and governed Kali selected runs execute against the same deterministic internal fixture;
4. finding-relevant Nmap semantics are equivalent;
5. the Kali runtime is exactly `CAP_NET_RAW` + `no_new_privs`;
6. zero-BPS rollback succeeds even when the provider is unavailable;
7. an outage for a Kali-selected scan fails closed and never executes the legacy fallback;
8. the deployable Canary override preserves the same loopback, capability, profile, and trusted-provenance boundaries;
9. no public Internet target is used.

## Promotion boundary

Default-Kali promotion is a separate phase. It may begin only after this canary PR is exact-head green, merged, and the fresh merged `main` SHA is fully green.
