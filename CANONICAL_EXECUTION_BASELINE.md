# AegisScan — Canonical Execution Baseline

**Authoritative date:** 2026-09-04  
**Repository:** `muhammetalali/AegisScan`  
**Canonical implementation branch:** `codex/full-contract-ui-audit-2026-09-03`  
**Current canonical HEAD at publication:** `778aa4ff1d87e03d9503d13d3c82e31e8b5626a3`  
**PR:** #23 → `main`  
**PR state:** OPEN, NOT MERGED  

## 1. Single source of truth

This document is the repository's canonical execution baseline for the current remediation stream.

Rules:

1. No parallel `codex/*` branch may be treated as an independent implementation stream for the same capability.
2. No branch is considered a candidate for merge merely because its name matches a backlog item.
3. Existing implementations must be compared against the canonical branch before any porting.
4. When two branches touch the same security/domain contract, their logic must be reconciled into one canonical implementation; commits must not be cherry-picked blindly.
5. Completion means: `Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready`.
6. Mock/demo/random/static business data is never acceptable as proof of completion.
7. A successful API response is not proof unless the result is persisted and independently observable.

## 2. Current verified state

The canonical branch currently contains the following verified remediation work:

- Frontend `package-lock.json` corruption/truncation was corrected and lock synchronization was restored.
- Nginx duplicate `/vulnerabilities/` routing was removed; the legacy route is explicitly proxied to `/api/v1/vulnerabilities/` instead of falling into the SPA.
- Nginx routing regression tests were added.
- npm audit CI was hardened with bounded retry/backoff while remaining fail-closed.
- FastAPI system telemetry slicing was corrected so direct invocation does not treat FastAPI's `Query` sentinel as an integer.
- Decision/assurance routes were moved away from disconnected legacy validation stores to persisted validation data.
- Generated and disconnected legacy artifacts/trees already identified as obsolete were removed; `packages/backend` and `packages/web` must not be reintroduced.
- Nmap execution now binds to a persisted authorized Asset and converts target/authorization failures into terminal `FAILED` state with persisted engine execution and error log evidence.
- External Black-Box E2E was changed to create and use a real authorized Asset instead of relying on an incompatible synthetic `network_range` target shape.
- Scanner redelivery/idempotency regression coverage was added; repeated delivery of a completed scanner task must not duplicate durable findings/evidence.
- Celery reliability settings were strengthened with late acknowledgements, worker-loss rejection, started-state tracking and single-task prefetch behavior.
- Scanner tenant isolation regression coverage was added for Asset → Scan → Vulnerability → Evidence access.
- CI now executes the scanner failure lifecycle, redelivery and tenant isolation tests as explicit release-gate steps.
- CI scanner target networking was isolated to a dedicated private CI network and a fixed authorized Masscan target IP; production authorization scope is not widened by this fixture.

## 3. Real scanner contract

Each supported scanner execution must satisfy:

`authorized persisted Asset → asset-bound Scan → Celery task → ScanEngineExecution → real binary/provider → raw output → parser → persisted Vulnerability/Evidence → terminal Scan state → API/UI observation`.

Supported real engine paths in the current implementation are:

- Nmap
- Masscan
- Nuclei
- Semgrep

A scanner failure before tool execution must still produce a terminal durable failure state; a Scan must never remain indefinitely `queued` because a precondition exception escaped before lifecycle bookkeeping.

## 4. Authorization contract

Security execution requires:

- a persisted Asset belonging to the same project as the Scan;
- explicit `configuration.authorized == true`;
- a target present in the Asset configuration in the engine-appropriate form;
- server-side authorization through `AUTHORIZED_SCAN_TARGETS` / scope authorization;
- no ambiguous prefix-only authorization semantics.

Legacy `startswith()` target authorization must never be restored.

For URL execution, canonical URL parsing must reject unsupported schemes, userinfo, query/fragment abuse and malformed hosts. Host/IP/domain authorization is performed on canonical values rather than arbitrary string prefixes.

## 5. Tenant isolation contract

For every protected scanner resource, access must be scoped through project ownership or project membership and never by object ID alone.

The mandatory security chain is:

`Project → Asset → Scan → Vulnerability → Evidence`.

A principal from tenant B must receive no object from tenant A through list, detail, update, note, evidence, execution, relationship or scan-triggering routes.

Cross-project Asset relationships must be rejected.

## 6. Worker reliability contract

Scanner tasks must be safe under normal Celery redelivery and worker loss.

Required properties:

- late acknowledgements;
- worker-loss rejection/requeue semantics;
- task started-state tracking;
- bounded prefetch;
- durable execution status;
- idempotent findings/evidence identifiers;
- terminal failure state after bounded retry exhaustion;
- no duplicate `ScanEngineExecution` for the same `(scan, engine)`.

The existing redelivery regression test is mandatory evidence but does not by itself constitute production disaster-recovery proof.

## 7. CI/reality-gate policy

Only runs associated with the current canonical HEAD may be used for final release decisions.

Historical runs on superseded commits are evidence of history, not evidence of current correctness.

Required release gates for this stream:

1. Frontend Lock Sync.
2. Domain Contract Reality.
3. External Black-Box E2E.
4. Real scanner engines E2E.
5. Tenant isolation matrix.
6. Scanner failure lifecycle and redelivery.
7. Final production/runtime audit.

No stage is complete while any required gate is queued, running, skipped or failed.

## 8. Branch de-duplication policy

The remote currently contains multiple `codex/*` branches created from parallel work streams. They are classified into three categories:

### A. Superseded/duplicate candidates

These must not receive new implementation work and should be deleted once repository-side branch deletion is available:

- `codex/asset-authorization-first-class-2026-09-03`
- `codex/asset-authorization-tamper-resistance-2026-09-03`
- `codex/authorization-execution-binding-2026-09-03`
- `codex/canonical-security-convergence-2026-09-03`
- `codex/asset-authorization-control-2026-09-03`
- `codex/asset-authorization-control-2026-09-03-pr`
- `codex/reality-gate-2026-09-03`
- `codex/asset-authorization-lifecycle-2026-09-03`
- `codex/intel-realize-2026-09-03`
- `codex/intel-pr-2026-09-03`

Important: branch-name similarity is not enough for destructive action. Before deletion of any listed branch, compare it to the canonical branch and verify there are no unique required commits/files.

### B. Research/source branches requiring reconciliation, not blind merge

- `codex/audit-reality-2026-09-03`
- `codex/authorization-audit-linkage-2026-09-03`
- `codex/authorization-decision-lifecycle-2026-09-03`
- `codex/authorization-source-of-truth-2026-09-03`
- `codex/asset-authorization-immutability-2026-09-03`
- `codex/digital-twin-realization-2026-09-03`
- `codex/digital-twin-realization-main-2026-09-03`
- `codex/intelligence-realization-2026-09-03`
- `codex/posture-realization-2026-09-03`
- `codex/real-finding-validation-e2e-2026-09-03`
- `codex/real-nmap-e2e-2026-09-03`
- `codex/remediation-validation-loop-2026-09-03`
- `codex/reporting-realization-2026-09-03`
- `codex/fix-assets-migration-drift-2026-09-03`

These branches can contain useful implementation ideas, but their changes must be reconciled into the canonical branch by file/function/contract, not merged as whole branches.

### C. Historical foundation branches

- `codex/enterprise-completion-2026-09-03`
- `codex/reality-gate-merge-2026-09-03`

These are historical reference streams. They must not be treated as additional parallel implementation sources unless a specific missing change is independently proven necessary.

## 9. Known reconciliation hotspots

The following files/capabilities previously had multiple independent implementations and must have exactly one canonical version:

- `fastapi_app/routers/decision_actions.py`
- `fastapi_app/routers/audit.py`
- `fastapi_app/routers/validations.py`
- `django_project/assets/models.py`
- `fastapi_app/routers/assets.py`
- scanner authorization/execution lifecycle
- Digital Twin source-of-truth model
- intelligence correlation/persistence
- remediation/validation lifecycle

No branch is to be merged wholesale at these hotspots.

## 10. Explicit non-goals until verified

The following must remain marked incomplete until independent evidence exists:

- production-ready claim;
- full four-engine E2E success;
- complete worker disaster recovery;
- complete RBAC matrix across every protected endpoint;
- complete SSRF/scanner authorization matrix;
- complete multi-tenant isolation matrix across every platform domain;
- live NVD/OSV/CISA KEV/EPSS/GreyNoise/Shodan/Censys provider lifecycle;
- complete Digital Twin/Attack Path/Blast Radius production evidence;
- complete remediation → revalidation → proof-of-fix chain;
- production secrets/TLS/backups/restore/rollback/monitoring validation.

## 11. Current release decision

**STATUS: NOT READY FOR MAIN MERGE.**

Reason: the canonical branch has real fixes and explicit tests, but the newest GitHub reality gates are still executing and no final all-green External Black-Box + four-engine scanner proof has yet been established for the final HEAD.

The correct next action is not another feature branch. It is to finish verification on this canonical branch, fix any newly demonstrated failures in place, rerun the complete gates, and only then consider PR #23 for merge.

## 12. Branch discipline from this point forward

- One implementation branch only: `codex/full-contract-ui-audit-2026-09-03` until PR #23 is merged or explicitly superseded.
- No new `codex/*` branch for a subtask unless isolation is technically required and its purpose is documented before creation.
- All bug fixes discovered by CI are committed directly to the canonical branch.
- All tests added for release gates must be invoked by CI; an unexecuted test file is not evidence.
- Superseded branches are cleanup artifacts, not implementation sources.
