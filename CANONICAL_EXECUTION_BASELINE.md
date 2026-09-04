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

Current release decision: NOT READY until the exact current HEAD has all mandatory gates green.
