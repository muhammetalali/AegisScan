# Project Reality Rules

These rules apply to every AegisScan change, regardless of subsystem.

1. **Implemented is not completed.** State must be reported at the highest level actually proven.
2. **No synthetic success.** Never return completed/healthy/successful values unless the underlying operation produced that state.
3. **Server-side authorization is authoritative.** UI state and request flags cannot grant security execution authority.
4. **Every security execution has lineage.** Record actor, scope, target/asset, engine, execution status, timestamps, output, findings, evidence, and audit context.
5. **Failure is data.** Failed/timeout/dependency-failed operations must remain distinguishable from successful empty results.
6. **Negative paths are mandatory.** Unauthorized, malformed, stale, conflicting, concurrent, timeout, and dependency-failure paths require tests where applicable.
7. **Historical evidence is not current acceptance.** Reproduce acceptance from the current canonical branch.
8. **Database is the source of truth for persisted domain state.** UI mocks, constants, fixtures, and placeholders cannot represent production state.
9. **Canonical platform path is `aegis-platform/`.** Do not create parallel production implementations under `packages/backend` or `packages/web`.
10. **Generated build output is not source.** Do not track generated frontend distributions or Python packaging metadata unless the release architecture explicitly requires them.
11. **Security controls must fail closed.** Missing authorization, unsupported configuration, or missing evidence must not silently downgrade to an allowed or successful state.
12. **A release claim requires reproducible proof.** A reviewer must be able to reproduce the claim from source, database state, execution, evidence, tests, and CI.

## Proof ladder

`Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready`

## System chain

`Adversary → Attack Surface → Architecture → Controls → Telemetry → Detection → Response → Evidence → Risk → Governance → Engineering → UX → Continuous Validation`
