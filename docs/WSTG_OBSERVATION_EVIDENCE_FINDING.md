# WSTG Observation → Evidence → Finding Integration

## Purpose

PR-9 connects already-authorized AegisScan capability execution to the canonical OWASP WSTG v4.2 methodology without creating a parallel scanner, finding store, evidence store, authorization system, or governance path.

The authoritative chain is:

`Capability execution → normalized observation → existing Evidence → existing Vulnerability/Finding → existing Risk / Attack Path / Detection / Governance consumers`.

## Methodology lineage

`fastapi_app.services.wstg_observation_lineage` reverses the canonical PR-3 mapping only through `registry_capability` provider bindings. It never maps a WSTG identity directly to a binary or shell command.

Each persisted lineage payload contains:

- schema `aegis.wstg-observation-lineage.v1`
- methodology `WSTG`, version `4.2`
- executed semantic `capability_id`
- canonical WSTG IDs and semantic requirement IDs
- canonical classification
- evidence role and methodology state
- deterministic SHA-256 lineage fingerprint
- `claim_policy=observation-only`
- `completion_claim_allowed=false`
- `finding_state_authority=governed-finding-confirmation`

## Fail-closed semantics

Scanner evidence is provenance, not a methodology verdict.

- `AUTO_EXISTING`: direct observation only; no automatic pass/confirmation.
- `ASSISTED_EXISTING`: supporting observation only.
- `MANUAL_GOVERNED`: supporting context with `manual_required`; tool output cannot self-attest.
- `GAP_NATIVE_SMALL`: supporting context with `blocked_native_gap`; the approved native validator must still be reviewed and integrated.
- `CONDITIONAL_NA`: conditional context remains `inconclusive`; applicability still belongs to PR-7 planner evidence.

No lineage record can directly set a finding to confirmed, false-positive, fixed, accepted-risk, won't-fix, duplicate, or closed.

## Persistence integration

The lineage is attached to the existing source of truth:

- scanner-level `Evidence.metadata.wstg_lineage`
- finding-level reserved `Vulnerability.raw_data._aegisscan_wstg`
- native semantic finding evidence `Evidence.metadata.wstg_lineage`

The server overwrites the reserved finding lineage namespace. Scanner-controlled JSON cannot author trusted WSTG provenance.

Integrated execution paths:

- native capability runtime
- Nmap
- Nuclei
- Masscan
- Semgrep
- native finding projection
- Nmap finding ingestion

Capabilities without a canonical WSTG registry binding do not invent WSTG coverage.

## Governance boundary

Finding lifecycle remains owned by the existing governed services, including Finding Confirmation, Finding Disposition, remediation verification, risk correlation, and governed action execution. PR-9 does not add a database migration or a second state machine.

Risk Correlation, Attack Path, Detection Engineering, Investigation, Evidence Registry, and reporting continue consuming the same persisted `Vulnerability` and `Evidence` records. PR-10 may surface the new lineage in UI/reporting, but it must not reinterpret observation lineage as a security verdict.

## Reality proof

`WSTG Observation Evidence Finding Reality` proves on the exact PR/main HEAD:

1. reverse lineage equals the canonical PR-3 provider bindings;
2. no lineage grants methodology completion;
3. manual/gap/conditional classes remain fail-closed;
4. PostgreSQL persists lineage in real Evidence and Finding rows;
5. ingestion creates no FindingConfirmation and does not mutate governed state;
6. redelivery replaces reserved lineage with server-trusted data;
7. native finding projection persists the same contract;
8. repository integration files contain the lineage bindings;
9. no schema migration is introduced.
