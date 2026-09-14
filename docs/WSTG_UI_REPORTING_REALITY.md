# WSTG UI + Reporting + E2E Reality Closure

PR-10 closes the canonical WSTG v4.2 integration surface without introducing a second security state machine.

## Source of truth

The UI and reports project existing persisted state only:

`WSTG Catalog → semantic capability mapping → execution planner → observation lineage → Evidence / Vulnerability → coverage projection → UI / report`.

The coverage service does not persist a new WSTG result table. It reads the existing PostgreSQL Evidence and Vulnerability records.

## Trust validation

Persisted WSTG lineage is revalidated against current canonical server-generated lineage before it contributes to coverage. The schema, methodology/version, capability ID, claim policy, finding-state authority, completion flag, SHA-256 lineage fingerprint, and canonical test set must all match.

Rejected lineage records are counted separately and excluded from coverage metrics.

## Coverage semantics

The 97 canonical tests are always returned exactly once.

- AUTO_EXISTING / ASSISTED_EXISTING: `observed` only when trusted lineage exists; otherwise `not_observed`.
- MANUAL_GOVERNED: remains `manual_required`, even with supporting observations.
- GAP_NATIVE_SMALL: remains `blocked_native_gap` until reviewed validator integration changes the canonical contract.
- CONDITIONAL_NA: remains `inconclusive`; PR-7 applicability evidence remains authoritative.

There are deliberately no `passed` or `failed` coverage states.

## API

Read-only endpoint:

`GET /api/v1/wstg/projects/{project_id}/coverage`

The endpoint enforces project owner/member access and returns a strict Pydantic response contract with PostgreSQL provenance.

## UI

Protected route: `/wstg`.

The page uses centralized `apiHelpers` transport plus strict Zod validation. It exposes project selection, observation coverage, trusted evidence/finding counts, rejected lineage count, category/state filters, canonical classifications, capability provenance, and latest trusted observation time.

The existing Evidence Registry also surfaces WSTG observation-lineage presence.

## Reporting

The existing DataExport pipeline gains a real `wstg` report type.

- JSON includes the complete coverage projection.
- CSV includes all 97 WSTG rows.
- PDF includes WSTG observation summary and rows.
- Full reports include the WSTG coverage section.
- Artifact SHA-256 integrity and retention remain owned by the existing DataExport system.

No parallel report storage is created.

## Reality proof

`WSTG UI Reporting Reality` proves exact-head:

1. clean Django schema and migrations;
2. PostgreSQL project coverage with valid and tampered lineage;
3. tenant isolation on the HTTP coverage endpoint;
4. integrity-bound persisted WSTG JSON report artifact;
5. existing observation persistence remains green;
6. OpenAPI includes the strict WSTG coverage route;
7. the protected UI route exists and the UI audit requires `/wstg`;
8. centralized transport only, with no direct fetch/axios;
9. i18n audit, lint, TypeScript and production build pass;
10. closure artifact confirms all 97 canonical tests and no pass/fail authority.

Fresh post-merge main proof remains mandatory before PR-10 is considered closed.
