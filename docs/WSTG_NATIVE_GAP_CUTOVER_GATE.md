# WSTG Native Gap Cutover Gate

## Purpose

This gate protects the five approved OWASP WSTG v4.2 `GAP_NATIVE_SMALL` rows from being promoted by implementation presence alone.

A registered runtime capability, browser telemetry, or scanner observation is not methodology completion.

The approved set remains:

- `WSTG-v42-CONF-06` → `web.http-method-policy`
- `WSTG-v42-INPV-04` → `web.duplicate-parameter-semantics`
- `WSTG-v42-INPV-19` → `web.ssrf-canary-validation`
- `WSTG-v42-CRYP-01` → `tls.posture`
- `WSTG-v42-CLNT-11` → `browser.postmessage-instrumentation`

## Invariants

The Reality gate independently proves:

- the canonical 97-test classification remains `25 / 45 / 21 / 5 / 1`;
- the exact five approved native-gap WSTG identities are unchanged;
- each gap remains `planned_native` in the canonical mapping;
- each gap remains `blocked` in the WSTG execution planner;
- blocked gaps expose no executable provider capability IDs through the planner;
- a planned capability that is already registered may emit trusted evidence lineage, but that lineage stays `blocked_native_gap` with `completion_claim_allowed=false`;
- the current internal native-gap normalizers force `observation_only=true` and `final_decision=false`;
- CLNT-11 browser `postMessage` telemetry remains supporting blocked-gap evidence and cannot perform methodology cutover.

## Cutover boundary

A future cutover is a separate reviewed change. It must be based on independently proven runtime behavior and the approved architecture, not on capability registration, green unit tests, or passive telemetry alone.

This gate does not dispatch scans, create Findings, confirm Findings, close Findings, accept risk, change WSTG classifications, or grant client-side authorization authority.

This gate also does not certify the technical completeness of a native validator. Runtime implementation and its focused validator tests remain Account B scope; a validator bug discovered by this gate must be fixed and proven in that implementation lane before any methodology cutover.
