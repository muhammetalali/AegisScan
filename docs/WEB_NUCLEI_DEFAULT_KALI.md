# Governed Kali Nuclei — Default Provider (M5)

## Scope

M5 promotes the parity-proven and canary-proven `web.nuclei` capability to Governed Kali as the production deployment default.

This phase does **not** retire the legacy scanner-worker Nuclei adapter. Retirement is a separate M6 phase after fresh-main proof.

## Authoritative routing policy

- Production deployment default: `AEGIS_NUCLEI_PROVIDER=default-kali`.
- `default-kali` routes every `web.nuclei` execution to the governed Kali web provider without canary cohort assignment.
- The library fallback remains `legacy` when no deployment policy is supplied, preserving safe development/test behavior outside the production deployment contract.
- `AEGIS_NUCLEI_PROVIDER=legacy` is the explicit M5 administrative rollback route.
- `canary` remains supported for controlled diagnostics.
- Raw `AEGIS_NUCLEI_PROVIDER=kali` remains provider-library diagnostic behavior and is not admitted by the production-facing execution layer.
- A Kali-selected execution never silently falls back to the legacy scanner on provider, authentication, provenance, runtime-attestation, or execution failure.

## Governed provider boundary

M5 promotes the same provider bundle proven during M4 Canary. It does not build a different execution engine.

The provider remains capability-scoped to `web.nuclei` and fixes semantics to the governed Nuclei execution contract:

- Nuclei 3.11.1;
- pinned nuclei-templates commit;
- redirects disabled;
- JSONL output;
- no caller-selected binary, argv, command, shell, or provider options;
- loopback-only authenticated control endpoint;
- immutable control-plane provenance pins;
- non-root UID 10001;
- zero Linux capabilities;
- `no_new_privs`;
- read-only root filesystem;
- bounded PID/memory/CPU resources;
- pause/resume/cancel support.

## Deployment

`aegis-platform/docker-compose.nuclei-default-kali.yml` is the M5 deployment overlay.

It configures:

- scanner policy default `default-kali`;
- canary BPS fixed to zero because cohort routing is no longer required;
- loopback web-provider endpoint;
- immutable expected provenance pins;
- the `kali-web` provider sidecar under the explicit Compose profile.

An operator can perform M5 rollback only by explicitly setting:

`AEGIS_NUCLEI_PROVIDER=legacy`

There is no automatic fallback path.

## Evidence and validation

`Web Nuclei Default Kali Reality` proves on the exact PR/main SHA:

1. static routing and production-admission contracts;
2. Compose rendering with `default-kali` as the deployment default;
3. explicit `legacy` rollback rendering;
4. exact provider image and immutable trust anchors;
5. a real governed default-Kali Nuclei scan against an internal deterministic target;
6. semantic equivalence to a real legacy rollback reference;
7. zero-capability/non-root/`no_new_privs` runtime enforcement;
8. provider outage fails closed under `default-kali` without legacy fallback;
9. explicit legacy rollback succeeds while the provider is unavailable;
10. immutable exact-head evidence artifacts;
11. no public Internet target.

## M6 boundary

Legacy Nuclei retirement may begin only after this M5 PR is exact-head terminal green, merged to `main`, and the exact merged `main` SHA receives fresh-main terminal-green verification.

M6 must remove or disable the legacy production route rather than hide it behind a fallback.
