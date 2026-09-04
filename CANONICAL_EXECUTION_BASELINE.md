# AegisScan — Canonical Execution Baseline

**Authoritative date:** 2026-09-04  
**Repository:** `muhammetalali/AegisScan`  
**Canonical implementation branch:** `codex/full-contract-ui-audit-2026-09-03`  
**Canonical release rule:** only the latest HEAD of the canonical branch can establish release readiness.

## 1. Single source of truth

This document is the repository-wide execution baseline for the current remediation stream.

Rules:

1. One implementation branch owns the active remediation stream.
2. Parallel `codex/*` branches are research/history/cleanup artifacts unless explicitly promoted after comparison.
3. No whole-branch merge or blind cherry-pick is allowed when multiple branches touch the same domain contract.
4. Reconciliation must be performed by file, function, data contract and runtime behavior.
5. Completion is: `Designed → Implemented → Integrated → Real Data → Tested → E2E Validated → Evidence Captured → Independently Verified → Production Ready`.
6. Mock/demo/random/static business data is never acceptable as evidence of completion.
7. A successful response without durable persistence and independent observation is not proof.
8. A historical CI pass on a superseded SHA is not evidence for the current SHA.

## 2. Canonical branch discipline

Canonical implementation branch:

`codex/full-contract-ui-audit-2026-09-03`

All new fixes discovered by CI or runtime validation are committed to this branch. Do not create another branch for the same capability. A temporary isolated branch is allowed only when its purpose is documented and it cannot compete with the canonical implementation stream.

## 3. Verified remediation already present on the canonical branch

The current canonical stream already contains these verified classes of remediation:

- frontend lockfile integrity and deterministic install enforcement;
- canonical Nginx vulnerability routing and regression tests;
- fail-closed npm dependency audit retries;
- FastAPI telemetry parameter normalization;
- persisted validation data for decision/assurance orchestration;
- removal of identified obsolete/generated legacy artifacts;
- persisted Asset-bound Nmap execution and terminal failure lifecycle;
- real authorized Assets in external scanner E2E;
- scanner redelivery/idempotency coverage;
- Celery late-acknowledgement and worker-loss reliability configuration;
- scanner tenant-isolation coverage for Asset → Scan → Vulnerability → Evidence;
- explicit CI execution of scanner lifecycle, reliability and tenant gates;
- isolated CI scanner network and fixed Masscan test target;
- canonical security scope authorization rather than ambiguous prefix matching;
- HTTP TestClient and Django connection cleanup in affected backend tests.

These statements describe implementation state; they do not, by themselves, constitute final production readiness.

## 4. Real scanner contract

Every supported scanner execution must satisfy:

`authorized persisted Asset → asset-bound Scan → Celery task → ScanEngineExecution → real binary/provider → raw output → parser/normalizer → persisted Vulnerability/Evidence → terminal Scan state → API/UI observation`.

A pre-execution failure must also produce durable terminal `FAILED` state. No Scan may remain indefinitely queued because a precondition exception escaped before lifecycle bookkeeping.

Supported real engine paths in the current implementation:

- Nmap
- Masscan
- Nuclei
- Semgrep

## 5. Authorization contract

Every scanner execution requires:

- a persisted Asset in the same project as the Scan;
- explicit `configuration.authorized == true`;
- an engine-appropriate target in the Asset configuration;
- server-side authorization against `AUTHORIZED_SCAN_TARGETS` / scope authorization;
- canonical host/IP/URL handling;
- rejection of ambiguous prefix-only authorization.

The legacy `startswith()` authorization pattern must never return to production execution paths.

## 6. Tenant-isolation contract

Every protected object access must be scoped through project ownership or membership and never through object identifier alone.

Mandatory chain:

`Project → Asset → Scan → Vulnerability → Evidence`.

A principal from tenant B must not be able to list, retrieve, update, annotate, relate, trigger or inspect tenant A resources.

Cross-project Asset relationships must be rejected.

## 7. Worker reliability contract

Scanner tasks must survive normal Celery redelivery and worker-loss conditions without duplicate durable effects.

Required properties:

- late acknowledgements;
- worker-loss rejection/requeue semantics;
- started-state tracking;
- bounded prefetch;
- durable execution state;
- idempotent findings/evidence;
- bounded retry exhaustion to terminal failure;
- no duplicate `ScanEngineExecution` for one `(scan, engine)` lifecycle.

Regression tests are mandatory evidence, but disaster-recovery claims require independent runtime proof.

## 8. CI release gates

Final release decisions must use only runs associated with the current canonical HEAD.

Mandatory gates for this stream:

1. Frontend Lock Sync.
2. Domain Contract Reality.
3. External Black-Box E2E.
4. All scanner engines E2E.
5. Tenant isolation matrix.
6. Scanner failure/reliability/redelivery tests.
7. Production/runtime integrity gate.

A gate is not complete when queued, running, skipped or failed.

Every canonical source change under test-covered domains must trigger the relevant workflow; path filters must include the canonical baseline/control documents when those changes affect release governance.

## 9. Branch reconciliation policy

The remote contains multiple historical `codex/*` branches created by parallel agents. They are divided into:

### Superseded/duplicate candidates

These receive no new implementation work and may be deleted once repository-side branch deletion is available and unique required commits have been disproven:

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

### Reconciliation/source branches

Useful only as source material. Never merge wholesale:

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

### Historical foundation

- `codex/enterprise-completion-2026-09-03`
- `codex/reality-gate-merge-2026-09-03`

These remain historical references, not parallel implementation streams.

## 10. Reconciliation hotspots

The following capabilities must have exactly one canonical implementation:

- `fastapi_app/routers/decision_actions.py`
- `fastapi_app/routers/audit.py`
- `fastapi_app/routers/validations.py`
- `django_project/assets/models.py`
- `fastapi_app/routers/assets.py`
- scanner authorization/execution lifecycle
- Digital Twin source of truth
- intelligence correlation and persistence
- remediation/validation lifecycle

Any competing branch touching one of these areas must be compared against the canonical implementation before reuse.

## 11. Known non-completion conditions

The platform is not production-ready until independently proven:

- four-engine E2E success;
- complete tenant/RBAC isolation matrix;
- SSRF and scanner authorization matrix;
- worker disaster recovery;
- real external provider lifecycle for NVD/OSV/CISA KEV/EPSS and any additional providers advertised by the UI;
- persisted Digital Twin / Attack Path / Blast Radius evidence;
- remediation → revalidation → proof-of-fix lifecycle;
- production secrets, TLS, backups, restore, monitoring and rollback.

## 12. Current release decision

**NOT READY FOR MAIN MERGE.**

Reason: the latest canonical HEAD has active CI verification in progress. No final all-green External Black-Box + all-engine scanner evidence has yet been established for that exact HEAD.

The next action is always:

`verify current HEAD → inspect failing gate → fix in canonical branch → push → verify new runs → repeat until all gates are green`.

## 13. CI/test quality rule

Test harnesses must release HTTP clients and Django database connections explicitly. A warning about a leaked test connection is treated as a defect in the harness, even if pytest exits successfully.

Environment/dependency deprecation warnings are tracked separately from functional failures and must not be converted into false “PASS” evidence.
