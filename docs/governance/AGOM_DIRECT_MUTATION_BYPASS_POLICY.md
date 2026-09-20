# AGOM Direct Mutation Bypass Policy

This control defines the production authority boundary for governance-sensitive mutations.

## Canonical rule

A sensitive decision must flow through the AGOM execution plane:

Request -> Identity -> Responsibility -> Capability -> SoD -> Evidence Qualification -> Temporal Policy -> CAS/Version -> Atomic Domain Mutation -> Immutable Audit Envelope

Production callers may not invoke sensitive domain writer functions directly. Protected persistence models may only be written by their declared authoritative writer modules.

## Protected decision domains

- asset authorization decisions
- finding confirmations and false-positive decisions
- accepted-risk, wont-fix, and duplicate finding dispositions
- governed finding closure
- investigation closure
- integration live acceptance
- detection publication and its durable delivery intent
- governed action requests and executions

The machine-readable source of truth is .github/governance/agom-direct-mutation-policy.json.

## Explicit non-governed technical operations

The audit intentionally does not treat every status change as a governance decision. These are operational state machines, not decision authority:

- report generation and recipient delivery state
- notification delivery state
- cloud discovery run state
- scanner and continuous-assurance execution state
- durable detection delivery transport state after an already-governed publication request
- integration acceptance test evidence recording; the live acceptance decision remains governed
- remediation verification evidence state; terminal finding closure remains governed
- ExternalIntegration configuration creation/enabling; enabled is not equivalent to live acceptance

These operations remain subject to their own tenant, authorization, idempotency, concurrency, and runtime controls.

## Fail-closed behavior

The CI audit fails when a protected model is mutated outside its authoritative writer, a protected writer callable is invoked outside the governed executor, a protected terminal state is assigned outside its writer, legacy asset configuration authorization is directly mutated, required route-level guards disappear, or the disabled legacy direct publication function is called.

Tests and migrations are excluded from production call-site authority analysis. The real production tree is audited on every relevant pull request and main push.
