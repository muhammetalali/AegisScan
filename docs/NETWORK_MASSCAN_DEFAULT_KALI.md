# Governed Kali Masscan — Default Provider (M5)

## Scope

M5 promotes the parity-proven and M4-canary-proven `network.masscan` capability to Governed Kali as the deployment default. This phase does **not** retire the local Masscan adapter or binary. Legacy retirement is a separate M6 gate after exact-head and fresh-main M5 proof.

## Authoritative routing policy

- Deployment default: `AEGIS_MASSCAN_PROVIDER=default-kali`.
- `default-kali` routes every Masscan execution to the governed provider without cohort assignment.
- Library fallback remains `legacy` when no deployment policy is supplied, preserving safe development and historical-reference behavior.
- Explicit `AEGIS_MASSCAN_PROVIDER=legacy` is the M5 administrative rollback.
- `canary` remains available as the bounded M4 regression/diagnostic path.
- Raw `AEGIS_MASSCAN_PROVIDER=kali` remains provider-library diagnostic behavior and is rejected by the production execution wrapper.
- Provider, authentication, provenance, runtime-attestation, control, or execution failure never silently retries through the local Masscan binary.

## Governed provider boundary

The dedicated provider dispatches only `network.masscan`. Requests are semantic and bounded: target, ports, rate, and deployment-controlled link identity. Callers cannot choose a binary, raw argv, shell command, or arbitrary provider options.

The provider:

- binds only to `127.0.0.1:18767` inside the scanner-egress network namespace;
- is authenticated by the Masscan provider token;
- runs with exactly `CAP_NET_RAW`, all other capabilities dropped, and `no_new_privs`;
- is read-only and resource bounded;
- verifies immutable runner/build/base/tool/runtime/image provenance;
- preserves pause/resume/cancel control;
- caps rate at 100,000 packets/second and timeout at 300 seconds.

The scanner-egress namespace owner remains the only component with `CAP_NET_ADMIN`; this separation is unchanged from the proven M3/M4 design.

## Deployment

`aegis-platform/docker-compose.masscan-default-kali.yml` is the M5 overlay. It leaves generic base/prod Compose unchanged and configures:

- scanner policy default `default-kali`;
- canary BPS fixed to zero;
- loopback provider endpoint and immutable trust pins;
- deployment-controlled link identity variables;
- the existing `kali-masscan` provider sidecar under its explicit Compose profile.

Rollback during M5 is explicit `AEGIS_MASSCAN_PROVIDER=legacy`. There is no automatic fallback.

## Evidence and validation

`Network Masscan Default Kali Reality` proves on the exact PR/main SHA:

1. routing and production-execution contracts admit `default-kali` but reject raw `kali`;
2. M4 bounded-canary and parity contracts remain green as regressions;
3. Compose renders `default-kali` by default and an explicit `legacy` rollback;
4. exact legacy-reference, scanner-egress, network-profile, and Masscan-provider images are built;
5. immutable provider trust anchors match the exact build;
6. a deterministic internal network fixture is used with no public Internet target;
7. scanner-egress alone owns `CAP_NET_ADMIN`, while scanner/provider are limited to `CAP_NET_RAW`;
8. real default-Kali Masscan output is finding-semantically equivalent to a real explicit legacy reference;
9. provider outage fails closed without silent legacy fallback;
10. explicit legacy rollback succeeds while the provider is unavailable;
11. exact-head evidence and SHA-256 lineage are uploaded.

## M6 boundary

Masscan legacy retirement may begin only after M5 is exact-head terminal green, merged through `main`, and the exact merged `main` SHA receives fresh-main terminal-green verification. M6 must physically disable/remove the legacy production path and make rollback a previous-release deployment, not a hidden same-release fallback.
