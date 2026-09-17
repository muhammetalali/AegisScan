# Governed Kali Nmap — Default Provider (M5)

## Scope

M5 promotes the parity-proven `network.nmap` capability from bounded canary routing to Governed Kali as the production deployment default. This phase does **not** retire the legacy Nmap adapter; retirement is a separate M6 phase after fresh-main proof.

## Authoritative routing policy

- Production deployment default: `AEGIS_NMAP_PROVIDER=default-kali`.
- `default-kali` routes every `network.nmap` execution to the governed Kali network provider without canary cohort assignment.
- The library fallback remains `legacy` when no deployment policy is supplied, preserving safe development/test behavior outside the production deployment contract.
- `AEGIS_NMAP_PROVIDER=legacy` is the only M5 administrative rollback route.
- `canary` remains supported for diagnostics and controlled rollback analysis.
- Raw `AEGIS_NMAP_PROVIDER=kali` is not admitted by the production-facing execution layer.
- A Kali-selected execution never silently falls back to the legacy adapter on provider, authentication, provenance, runtime-attestation, or execution failure.

## Governed provider boundary

The provider remains capability-scoped to `network.nmap` and fixes semantics to:

`nmap -Pn -sV -oX - -- <target>`

It accepts no caller-selected binary, argv, command, shell, or provider options. It is loopback-only inside the scanner network namespace, authenticated with the network-provider token, read-only, resource bounded, and runs with exactly `CAP_NET_RAW`, all other Linux capabilities dropped, and `no_new_privileges` enabled.

## Deployment

`aegis-platform/docker-compose.nmap-default-kali.yml` is the M5 Nmap deployment overlay. It keeps the generic platform Compose files untouched and configures:

- scanner policy default `default-kali`;
- canary BPS fixed to zero for default routing;
- loopback network-provider endpoint;
- immutable expected provenance pins;
- the `kali-network` provider sidecar under the explicit `kali-network` Compose profile.

An operator can perform the M5 rollback by explicitly setting `AEGIS_NMAP_PROVIDER=legacy`. There is no automatic fallback path.

## Evidence and validation

`Network Nmap Default Kali Reality` proves on the exact PR/main SHA:

1. static routing and provider contracts;
2. Compose rendering with `default-kali` as the deployment default and explicit `legacy` rollback rendering;
3. exact-image build and immutable provider trust anchors;
4. a real governed default-Kali Nmap scan against an internal deterministic target;
5. semantic equivalence to a real legacy rollback reference;
6. runtime `CAP_NET_RAW`/`no_new_privs` enforcement;
7. provider outage fails closed under `default-kali` without legacy fallback;
8. explicit legacy rollback succeeds while the provider is unavailable;
9. immutable exact-head evidence artifacts;
10. no public Internet target.

## M6 boundary

Legacy Nmap retirement may begin only after this M5 PR is exact-head terminal green, merged through protected `main`, and the exact merged `main` SHA is fresh-main terminal green. M6 must remove or disable the legacy production route rather than hide it behind a fallback.
