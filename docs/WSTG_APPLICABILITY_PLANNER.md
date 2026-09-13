# WSTG v4.2 Applicability / Execution Planner

PR-7 extends the existing `capability_planner.py`; it does **not** create a second
orchestration subsystem.

The authoritative planning chain is:

```text
Authoritative Asset
  -> existing AssetAuthorization ledger
  -> WSTG canonical test
  -> semantic capability requirement
  -> applicability rule
  -> current Capability Registry / control-plane service coverage
  -> execution policy metadata
  -> plan state
```

This PR performs planning only. It creates no `Scan`, dispatches no Celery task,
executes no Kali command, accepts no client-supplied authorization decision, and
cannot emit `passed` or `failed`.

## Plan states

The planner is deliberately narrower than execution state:

- `planned`: authoritative capability/service coverage is available under the current
  asset/depth/packaging policy. Dispatch is still a separate governed action.
- `manual_required`: one of the 21 `MANUAL_GOVERNED` tests; tool output cannot
  self-attest or auto-pass it.
- `blocked`: a required provider is unavailable/ineligible, or one of the five
  native gaps is not yet reviewed into the canonical mapping.
- `inconclusive`: applicability evidence is insufficient or conflicting.
- `not_applicable`: the methodology or a conditional test is explicitly N/A with a
  reason and evidence reference.

`passed`, `failed`, `queued`, `running`, and `error` are not planner outputs.

## Versioned policy metadata

`execution_policies.json` is derived from the approved 97-row implementation matrix.
For every canonical WSTG ID it freezes:

- classification/mode;
- runner preference;
- execution backend semantics;
- runtime action semantics;
- evidence contract;
- Kali requirement (`required`, `manual_only`, or `conditional`).

`applicability.json` contains methodology applicability and the only currently
approved conditional WSTG row: `WSTG-v42-CLNT-08` (Cross Site Flashing).

Absence of a Flash fingerprint alone does **not** prove N/A. Without authoritative
positive or negative evidence the planner returns `inconclusive`. A negative
applicability fact must carry evidence references.

## Existing components reused

- `WSTGCatalog` remains authoritative for the 97 official identities.
- `WSTGCapabilityMapping` remains authoritative for semantic requirements and
  provider bindings.
- `capability_registry.py` remains authoritative for executable capabilities.
- `native_packaging.py` remains authoritative for native packaging readiness.
- `current_asset_authorization()` remains authoritative for persisted authorization
  when planning directly from an Asset.
- No WSTG-specific database, scanner registry, authorization system, or evidence
  store is introduced.

## Persisted-asset integration

`plan_wstg_for_authorized_asset()` resolves an active project-scoped Asset, reuses
the current immutable authorization ledger, derives positive technology facts from
persisted `TechnologyFingerprint` records, and returns a deterministic WSTG plan.

Planning revalidates the current authorization binding but does not weaken or replace
the execution-time authorization/egress checks. Dispatch must still pass through the
existing control plane.

## Account B boundary

The five `GAP_NATIVE_SMALL` requirements remain `blocked` in this PR. A capability
implemented by Account B is not automatically trusted merely because its ID appears
in another branch. Those validators become eligible only after explicit review and
canonical mapping integration.

## Reality proof

`WSTG Applicability Planner Reality` proves at exact HEAD that:

- all 97 official tests are planned exactly once;
- manual tests remain `manual_required`;
- the five approved native gaps remain blocked pending reviewed integration;
- conditional applicability fails closed without evidence;
- positive Flash evidence makes the conditional row plannable through the existing
  browser capability;
- non-web assets produce reasoned `not_applicable` results rather than execution;
- missing authorization binding is rejected;
- planner output contains capability/service identities, not tool/command authority;
- policy/applicability file fingerprints match the manifest.

Domain Contract Reality additionally proves the persisted integration path with real
PostgreSQL-backed Asset, immutable AssetAuthorization and TechnologyFingerprint
records, including fail-closed behavior after authorization revocation.

The proof is planning evidence only, not a claim that any WSTG security test passed.
