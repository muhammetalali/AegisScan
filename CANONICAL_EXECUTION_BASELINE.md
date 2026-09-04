# AegisScan — Canonical Execution Baseline

This file is authoritative for the active remediation stream. One implementation branch only: `codex/full-contract-ui-audit-2026-09-03`.

Completion requires: Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready.

Rules:
- No blind whole-branch merges or cherry-picks when contracts overlap.
- Historical/superseded branch CI does not prove current correctness.
- Mock/demo/random/static business data is never accepted as completion evidence.
- Every scanner execution is asset-bound, authorization-bound, persisted, observable, and terminal on failure.
- Tenant access is project-scoped through Project → Asset → Scan → Vulnerability → Evidence.
- Scanner workers must be redelivery-safe and idempotent.
- Only current canonical HEAD runs are release evidence.

Mandatory current gates:
1. Frontend Lock Sync.
2. Domain Contract Reality.
3. External Black-Box E2E.
4. All scanner engines E2E.
5. Tenant isolation matrix.
6. Scanner failure/reliability/redelivery.
7. Production/runtime integrity.

Superseded/duplicate branch candidates, once unique value is disproven:
`codex/asset-authorization-first-class-2026-09-03`, `codex/asset-authorization-tamper-resistance-2026-09-03`, `codex/authorization-execution-binding-2026-09-03`, `codex/canonical-security-convergence-2026-09-03`, `codex/asset-authorization-control-2026-09-03`, `codex/asset-authorization-control-2026-09-03-pr`, `codex/reality-gate-2026-09-03`, `codex/asset-authorization-lifecycle-2026-09-03`, `codex/intel-realize-2026-09-03`, `codex/intel-pr-2026-09-03`.

Source/reconciliation branches are never merged wholesale; hotspot areas include audit, decision actions, validations, assets authorization, scanner lifecycle, Digital Twin, intelligence persistence/correlation, and remediation validation.

Current release decision: NOT READY until the exact current HEAD has all mandatory gates green.

CI quality: affected TestClient-based Django tests must close clients and call `close_old_connections()` so teardown warnings are treated as defects rather than ignored.
