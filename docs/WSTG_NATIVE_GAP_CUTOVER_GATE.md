# WSTG Native Gap Cutover Reality — A8

## Purpose

A8 performs the reviewed methodology cutover that the earlier native-gap guard
required. Runtime implementation is still owned by Chat B; this gate does not modify
or certify validator internals. It consumes the current authoritative registry and
semantic-service surfaces and decides whether they may satisfy canonical WSTG
planning and evidence-lineage contracts.

The historical design-gap identities remain exactly:

- `WSTG-v42-CONF-06`
- `WSTG-v42-INPV-04`
- `WSTG-v42-INPV-19`
- `WSTG-v42-CRYP-01`
- `WSTG-v42-CLNT-11`

Their `GAP_NATIVE_SMALL` classification is retained as provenance. Classification
is not a runtime status.

## Cutover invariants

The Reality gate proves that:

- the canonical 97-test matrix remains `25 / 45 / 21 / 5 / 1`;
- all five rows resolve to `availability=existing` with no `planned_native`
  provider left in canonical mapping;
- each row contains its explicitly reviewed registry/service anchor;
- the planner emits `planned` only when that anchor is execution-ready for the
  asset/depth (or its reviewed semantic service is present);
- authorization remains required;
- native/runtime output remains observation evidence, never a final methodology
  decision;
- trusted lineage is `observed` + `supporting_observation` after cutover while
  `completion_claim_allowed=false`;
- CLNT-11 uses bounded browser telemetry plus the existing web-messaging semantic
  service instead of inventing a fake executable capability;
- forged runtime fields cannot promote an observation into final-decision authority.

## Authority boundary

This gate does **not** dispatch scans, change runtime validator code, create or
confirm Findings, close Findings, accept risk, or grant client-side authority.
Governed action execution and finding confirmation remain the only lifecycle
authorities.

If a reviewed provider disappears, loses execution readiness, or its mapping drifts,
A8 fails closed: the mapping/Reality gate fails and the planner returns `blocked`
rather than silently claiming WSTG coverage.
