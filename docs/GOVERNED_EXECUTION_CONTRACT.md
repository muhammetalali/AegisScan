# Unified Governed Execution Contract Core

## Scope

This contract extends the existing governed capability endpoint and the existing `Scan` persistence model. It does not introduce a second orchestrator, execution database, authorization authority, Evidence store, Finding lifecycle, or Kali control plane.

Canonical entry point remains:

`POST /api/v1/capabilities/{capability_id}/execute`

## Server-owned envelope

A capability execution persists an immutable versioned envelope on its canonical `Scan`:

- actor reference;
- project-backed tenant scope;
- project and asset references;
- authoritative immutable asset-authorization reference;
- requested and resolved semantic capability IDs;
- WSTG methodology references derived from canonical server lineage;
- normalized allowed options;
- credential references only, never credential material;
- authoritative runner profile;
- execution mode and risk class;
- depth;
- correlation ID;
- optional idempotency key with enforced request fingerprint;
- policy fingerprint and whole-contract fingerprint.

The client cannot author authorization, methodology, runner placement, risk, execution mode, or policy fingerprints.

## Idempotency

During migration, `idempotency_key` is optional for backward compatibility.

When supplied, PostgreSQL enforces uniqueness for:

`project + initiated_by + execution_idempotency_key`

A retry with the same key and same semantic request reuses the existing `Scan` and does not enqueue a second Celery task. A reuse returns the original correlation ID and original persisted envelope.

The same key with a different semantic request fails closed with HTTP 409.

The request fingerprint deliberately excludes tracing metadata such as `correlation_id`, so transport retries may use a new attempted correlation value without changing the semantic idempotency identity. The persisted execution keeps the original correlation value.

## Authority boundaries

The envelope is finalized only after the server resolves the current immutable `AssetAuthorization`. WSTG references come from `wstg_observation_lineage`; capability placement comes from the authoritative Capability Registry.

No WSTG pass/fail, Finding confirmation, closure, accepted-risk, false-positive, or governance authority is added.

## Explicitly deferred

The design baseline also calls for an `execution_budget_ref`. AegisScan does not yet have an authoritative execution-budget subsystem, so this PR does not invent a placeholder reference. Budget authority must be implemented as a separate reviewed extension before it is added to the contract.

This Core PR also does not yet migrate the Web UI, CLI, or scheduled automation callers. Those interfaces must next call this same governed capability endpoint and provide idempotency/correlation values before M3 legacy-vs-Kali dual-run parity is eligible for cutover review.
