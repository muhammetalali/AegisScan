# AegisScan Security Reality Gate

## Purpose

AegisScan treats capability state as evidence, not as a code-presence claim. A component, endpoint, task, adapter, or UI screen is not complete merely because it exists.

## Capability state model

Every material capability must progress through:

`Designed -> Implemented -> Integrated -> Real Data -> Tested -> E2E Validated -> Evidence Captured -> Independently Verified -> Production Ready`

The current state must be reported honestly. Never promote `Implemented` to `Completed` without the corresponding proof.

## Reality rules

1. No fabricated success, progress, finding count, risk score, health state, confidence, agreement, evidence count, or completion state.
2. Failure must remain failure. Retry/recovery must be explicit and observable.
3. Empty data is not a successful result unless the underlying operation actually ran and returned an empty result.
4. Authorization is server-side truth. Client intent, a request flag, or UI state cannot create authority.
5. Every security execution must preserve lineage: actor, target/asset, project/tenant scope, engine, execution status, timestamps, output, findings, evidence, and audit context.
6. Historical proof is regression evidence, not current acceptance.
7. Negative paths are first-class acceptance criteria: denied target, denied project, malformed input, engine failure, timeout, dependency failure, stale data, conflicting intelligence, and concurrent mutation.
8. Security changes must be tested at the domain boundary and at the externally observable API/UI boundary.
9. Generated build output is not source-of-truth unless explicitly required by release architecture.
10. A claim of production readiness requires reproducible evidence from the current canonical branch.

## End-to-end security chain

`Adversary -> Attack Surface -> Architecture -> Controls -> Telemetry -> Detection -> Response -> Evidence -> Risk -> Governance -> Engineering -> UX -> Continuous Validation`

## Enterprise acceptance chain

`Technical Finding -> Attack Path -> Asset -> Control -> Detection -> Evidence -> Business Impact -> Risk -> Compliance Impact -> Remediation -> Validation -> Residual Risk -> Executive Decision`

## Review standard

Before merging enterprise-security work, reviewers must be able to answer:

- What is the source of truth?
- What happens on failure?
- What happens when authorization is absent?
- What evidence proves the operation actually executed?
- Can the result be reproduced independently?
- What prevents duplicate or conflicting state?
- What telemetry/audit record proves the change?
- Which UI state represents loading, empty, denied, stale, partial, and error conditions?

A capability that cannot answer these questions is incomplete.