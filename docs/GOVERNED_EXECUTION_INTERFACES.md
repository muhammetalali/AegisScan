# AegisScan Governed Execution Interfaces

## Purpose

All platform-connected execution surfaces converge on one server-owned path:

```text
Web UI
REST/API
Aegis CLI
Automation / CI
    |
    v
POST /api/v1/capabilities/{capability_id}/execute
    |
    v
Governed Execution Contract
    |
    v
Authorization -> Capability -> Runner -> Evidence -> Governance
```

Interfaces submit intent; the control plane resolves and persists execution authority.

## Canonical request ownership

Clients may supply only supported intent:
- `project_id`
- `asset_id`
- semantic `capability_id`
- governed `depth`
- capability-validated `options`
- Credential Vault references
- `idempotency_key`
- `correlation_id`

Clients do not supply or override scanner binary paths, runner images, target authority, authorization decisions, runtime profile selection, Evidence authority, Finding confirmation authority, or shell commands.

The server resolves the Asset, AssetAuthorization, capability implementation, runner profile, WSTG lineage, risk class, execution mode, and policy fingerprint.

## Web UI

The Scan registry uses:

`GET /api/v1/capabilities/plan/{asset_id}?project_id=...&depth=...`

Only `execution_ready=true` capabilities are selectable. The UI then invokes the governed execution endpoint. It does not construct raw `/scans/` execution requests, derive a target, select a scanner engine, or submit client authorization authority.

## REST/API

The authoritative transport is:

`POST /api/v1/capabilities/{capability_id}/execute`

The response carries the canonical Scan identity, contract version, policy version, server-owned authorization reference, resolved semantic capability, runner profile, methodology references, policy fingerprint, execution-contract fingerprint, correlation identity, and idempotency reuse state.

## CLI

`aegis run` is a thin platform client implemented over `PlatformClient.execute_capability()`. It never invokes a local scanner or shell adapter.

Historical `local-scan` and `local-validate` remain explicitly separate local-only workflows and are not classified as platform-governed execution.

## Automation / CI

`PlatformClient.execute_capability()` is the canonical programmatic automation surface. CI and external automation use the same endpoint and response contract as Web/API/CLI.

No second scheduler or orchestrator is created. The existing `ScheduledScan` model is not claimed as an active governed dispatcher because no live canonical dispatcher exists in the current tree.

## Idempotency parity

External Black-Box proves convergence by:
1. creating a real authorized Nmap execution through the REST capability endpoint;
2. persisting the returned Scan and immutable execution envelope;
3. replaying the same idempotency key through `PlatformClient`;
4. replaying it through installed `aegis run`;
5. requiring `idempotency_reused=true`;
6. requiring the same Scan identity and execution contract;
7. requiring the same policy fingerprint.

A second scanner dispatch or contract drift fails the Reality gate.

## Explicit non-goals

This phase does not create a second orchestrator, scanner database, Evidence store, authorization system, web terminal, direct UI command execution, ScheduledScan dispatcher, or arbitrary-shell CLI execution.

## Release evidence

Completion requires root CLI/client tests, frontend UI/i18n/lint/build checks, interface contract regression checks, External Black-Box real platform proof, exact PR HEAD green, and exact merged main HEAD green.
