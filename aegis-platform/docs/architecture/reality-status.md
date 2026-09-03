# AegisScan Reality Status

This document is an operational record, not a completion claim.

## Capability state model

Every material capability is classified as one or more of:

- **Implemented** — code exists.
- **Integrated** — connected to the platform path.
- **Real-data** — operates on persisted non-synthetic data.
- **Tested** — covered by automated tests.
- **E2E validated** — externally observable workflow has passed.
- **Historically proven** — passed in an earlier environment/commit; not current acceptance.
- **Verified** — independently reproduced from the current canonical branch.
- **Production ready** — all applicable proof gates pass.
- **Duplicate** — redundant implementation/artifact requiring consolidation.
- **Not implemented** — no production implementation exists.
- **Planned** — explicitly deferred future capability.

## Governing rule

Presence of a component, endpoint, task, adapter, migration, or UI page is never sufficient to mark a capability complete. Completion requires real execution, persisted state, evidence lineage, authorization controls, negative-path behavior, and reproducible tests appropriate to the capability.

## Security reality chain

`Adversary -> Attack Surface -> Architecture -> Controls -> Telemetry -> Detection -> Response -> Evidence -> Risk -> Governance -> Engineering -> UX -> Continuous Validation`

## Acceptance chain

`Technical Finding -> Attack Path -> Asset -> Control -> Detection -> Evidence -> Business Impact -> Risk -> Compliance Impact -> Remediation -> Validation -> Residual Risk -> Executive Decision`

## Prohibited states

Do not fabricate success, progress, finding counts, risk scores, confidence, agreement, health, evidence counts, or completion status. Failure remains failure until a real retry/recovery operation changes the state. Empty output is valid only when the underlying operation actually executed and returned empty output.

## Authorization rule

Client request fields are intent only. Authorization for security execution must be derived from persisted server-side authorization state and enforced again at the execution boundary.

## Historical proof rule

Historical scan/remediation/Nmap artifacts remain regression evidence only. They must never be represented as current acceptance without a reproducible current run.

## Repository rule

`aegis-platform/` is the canonical platform path. Alternate `packages/backend`, `packages/web`, or parallel platform implementations must not be developed independently. Unique, validated functionality may be migrated; stale, duplicate, synthetic, or obsolete implementations must be retired.
