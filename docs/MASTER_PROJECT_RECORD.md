# AegisScan Master Project Record

## Operating standard

AegisScan is developed as an evidence-driven Enterprise Security Validation Platform. Red Team, Blue Team, Purple Team, governance, engineering, and UX are treated as one connected system:

`Adversary → Attack Surface → Architecture → Controls → Telemetry → Detection → Response → Evidence → Risk → Governance → Engineering → UX → Continuous Validation`

## Proof rule

Presence of code, API, UI, model, adapter, migration, or workflow is not completion. A capability is complete only at the highest proof level reproducibly demonstrated on the current canonical branch.

`Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready`

## Current canonical platform

`aegis-platform/`

Parallel production implementations are prohibited. `aegis/` can remain only as a CLI/shared-engine layer when intentionally consumed by the canonical platform.

## Security truth

- Server-side persisted authorization is authoritative.
- Client flags cannot grant security execution authority.
- Failure remains failure until a real recovery changes the state.
- Empty output is not success unless the underlying operation actually executed.
- Historical proof is regression evidence, not current acceptance.
- Findings require provenance and Evidence lineage sufficient for reproduction.

## Current critical controls

The repository contains a Security Reality Gate, canonical-platform integrity checks, a capability Proof Matrix, and an explicit release-readiness contract. Network scan creation now requires an existing persisted authorized asset and an exact target identity match.

## Current branch-reconciliation rule

`main` and the enterprise-completion line diverged after their merge base. Never force-reset `main` to a feature branch. Reconcile both histories through a normal Git merge, preserve valid mainline fixes, and require current CI/proof gates before release.
