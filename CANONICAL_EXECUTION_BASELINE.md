# AegisScan — Canonical Execution Baseline

This file is authoritative for the active remediation stream. Scoped implementation branches integrate through reviewed pull requests; `main` is the canonical release branch.

Completion requires: Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready.

Canonical layout:
- `aegis-platform/` is the only active enterprise application tree.
- `aegis/` is the installable CLI/client package.
- `packages/` is retired history and is forbidden on canonical `main`.
- Historical source is preserved only under `archive/feature-enterprise-platform-ui-v2-50698f5` at `50698f5dbda1f7eb0a1e9a743e752278323a4c7d`.

Rules:
- No blind whole-branch merges or cherry-picks when contracts overlap.
- Historical/superseded branch CI does not prove current correctness.
- Historical archive refs are provenance-only and must never be used as implementation or release baselines.
- No feature, fix, test, workflow, or migration may target the retired `packages/` tree.
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
