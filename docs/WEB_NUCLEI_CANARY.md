# Governed Kali Nuclei Canary

## Scope

This phase introduces a bounded M4 canary for `web.nuclei` after semantic
parity was independently proven and merged.

It does **not** promote Kali as the default Nuclei provider and does not retire
the legacy scanner-worker path.

## Routing contract

Production routing is server-controlled:

- `AEGIS_NUCLEI_PROVIDER=legacy` keeps all execution on the legacy scanner.
- `AEGIS_NUCLEI_PROVIDER=canary` enables deterministic cohort assignment.
- `AEGIS_KALI_NUCLEI_CANARY_BPS=0` is the immediate rollback state.
- Canary rollout is capped at 2500 basis points (25%).
- Assignment uses a SHA-256 bucket derived from the immutable scan identity.
- A scan selected for Kali never silently retries through the legacy provider.

Raw `kali` mode is a provider-library diagnostic state only and is rejected by
the production execution layer.

## Governed web provider

The provider is a dedicated bundle layered on the pinned Kali `web` profile.

The shared `profile-web` remains placement-only. The provider bundle enables
semantic dispatch for **only** `web.nuclei`.

Runtime boundary:

- loopback control endpoint only;
- authenticated requests;
- control-plane pinned image/runtime/tool provenance;
- Nuclei 3.11.1;
- pinned nuclei-templates commit;
- non-root UID;
- zero Linux capabilities;
- `no_new_privs`;
- read-only root filesystem in deployment;
- bounded PID/memory/CPU resources;
- fixed Nuclei argv with redirects disabled;
- no caller-controlled binary, argv, command, or provider options;
- pause/resume/cancel control;
- bounded request and output sizes.

## Evidence lineage

When the production task executes Nuclei it persists:

- `provider_routing`;
- `runtime_provenance`;
- authorization-decision lineage;
- scanner Evidence;
- normalized Findings;
- engine execution state.

This allows downstream investigation and governance to distinguish legacy
holdback from Kali-selected executions without changing Finding semantics.

## Reality proof

`Web Nuclei Canary Reality` proves on the exact PR/main SHA:

1. deterministic selected and holdback cohorts exist at 2500 BPS;
2. the holdback executes the real legacy Nuclei adapter;
3. the selected cohort executes the real governed Kali web provider;
4. both execute the same deterministic internal target and template;
5. normalized finding semantics are equivalent;
6. Kali runtime provenance and zero-capability boundary are verified;
7. setting canary BPS to zero continues to execute legacy while the provider is down;
8. a selected Kali provider outage fails closed and never falls back;
9. exact-head artifacts and SHA-256 evidence are captured.

`Web Nuclei Canary Deployment Reality` separately renders the opt-in Compose
override and proves that the operational defaults remain `legacy + 0 BPS`
with least privilege.

## Exit gate

Canary is complete only after:

1. targeted contracts pass;
2. both Nuclei canary Reality workflows pass;
3. full exact-head CI is terminal green;
4. the PR is merged;
5. the exact merged main SHA receives fresh-main verification.

Default-Kali promotion requires a separate M5 phase and separate evidence.
