# WSTG v4.2 → Capability Mapping

PR-3 binds every canonical WSTG v4.2 test to a **semantic capability requirement**
without turning WSTG into a tool launcher.

The authoritative chain remains:

```text
WSTG Test
  -> Semantic Capability Requirement
  -> Existing Aegis provider binding
  -> (later PR-7) execution policy / applicability / planner
  -> governed execution
```

`mappings.json` contains only WSTG IDs and semantic requirement IDs. It cannot carry
tool names, commands, authorization decisions, runner profiles, results, or finding
state. `capability_requirements.json` is implementation-binding metadata; registry
bindings are verified against the existing `capability_registry.py`, while
control-plane/governed bindings must resolve to existing Aegis service modules.

This deliberately preserves current executable capability IDs even where legacy IDs
still expose a tool-oriented name such as `web.nuclei`. Those IDs are provider
implementation details, not WSTG identities. Renaming the execution registry is not
part of PR-3 and would be a breaking API migration.

## A8 reviewed native-gap cutover

The five original `GAP_NATIVE_SMALL` classifications are retained permanently as
design provenance; A8 does not rewrite the approved 25/45/21/5/1 matrix. Their
methodology mappings are no longer unresolved `planned_native` placeholders.

The reviewed canonical anchors are:

- WSTG-v42-CONF-06 → registry `web.http-method-policy`
- WSTG-v42-INPV-04 → registry `web.duplicate-parameter-semantics`
- WSTG-v42-INPV-19 → registry `web.ssrf-canary-validation`
- WSTG-v42-CRYP-01 → registry `tls.posture`
- WSTG-v42-CLNT-11 → `browser.spa-discovery` telemetry plus
  `fastapi_app.services.web_messaging_semantics`

Chat B continues to own runtime implementation and validator behavior. Chat A owns
this methodology acceptance boundary. A mapped provider becomes plannable only when
the existing capability planner reports it execution-ready (or the reviewed semantic
service is present). Runtime observations remain non-authoritative evidence:
`completion_claim_allowed=false`, and pass/fail/finding state remains governed.

## Boundaries

PR-3 does **not** add an execution planner, applicability decisions, Kali profiles,
runtime backend selection, scanner database, REST execution route, evidence model,
finding lifecycle, authorization system, or UI. Existing Control Plane authority and
the Governed Action Executor remain unchanged.

The dedicated `WSTG Capability Mapping Reality` gate verifies exact-head metadata,
all 97 mappings, current registry provider identities, service-module existence,
classification semantics, immutable/fail-closed contracts, and the exact five-gap set.
