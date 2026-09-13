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

## Approved unresolved native gaps

Only the five design-approved native gaps may appear as `planned_native`:

- WSTG-v42-CONF-06 → `web.http-method-policy`
- WSTG-v42-INPV-04 → `web.duplicate-parameter-semantics`
- WSTG-v42-INPV-19 → `web.ssrf-canary-validation`
- WSTG-v42-CRYP-01 → `tls.posture`
- WSTG-v42-CLNT-11 → `browser.postmessage-instrumentation`

They are requirements, not fake executable capabilities. Account B owns their native
validator implementation in PR-8; this account owns their contracts and integration.
No unmerged Account B capability is accepted by this PR.

## Boundaries

PR-3 does **not** add an execution planner, applicability decisions, Kali profiles,
runtime backend selection, scanner database, REST execution route, evidence model,
finding lifecycle, authorization system, or UI. Existing Control Plane authority and
the Governed Action Executor remain unchanged.

The dedicated `WSTG Capability Mapping Reality` gate verifies exact-head metadata,
all 97 mappings, current registry provider identities, service-module existence,
classification semantics, immutable/fail-closed contracts, and the exact five-gap set.
