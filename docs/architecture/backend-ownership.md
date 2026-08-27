# Backend Ownership Contract

**Status:** Active architectural contract  
**Scope:** Django, FastAPI, Celery, PostgreSQL, Redis  
**Applies to:** `feature/enterprise-platform-ui-v2` and subsequent platform branches

## 1. Purpose

AegisScan uses Django and FastAPI for different responsibilities. This document makes ownership explicit so that new endpoints do not create duplicate sources of truth or legacy API surfaces.

## 2. System-of-record rule

Django is the authoritative owner of durable business state.

Django owns:

- Users, teams, memberships and durable identity state.
- Projects and durable project relationships.
- Assets and durable asset relationships/fingerprints.
- Scans, scan lifecycle metadata, logs and engine-execution records.
- Vulnerabilities, evidence, notes and remediation state.
- Reports and report artifacts/metadata.
- Compliance assessments, controls and durable compliance records.
- Audit history and durable audit records.
- Other business entities when they require PostgreSQL persistence, durable lifecycle state, authorization, auditability, or CRUD semantics.

A FastAPI endpoint must not create an independent in-memory or database-backed source of truth for a durable Django-owned resource.

## 3. FastAPI responsibility

FastAPI is the runtime and orchestration layer.

FastAPI owns:

- High-throughput runtime APIs.
- Scan/validation orchestration and execution control.
- Engine execution and runtime coordination.
- Runtime progress and WebSocket delivery.
- Stateless or explicitly ephemeral runtime views.
- Integration adapters that execute work and return normalized results to the owning service.

FastAPI may receive a Django-owned Scan/Asset/Vulnerability identifier and operate on it as runtime input, but durable creation, mutation, authorization and persistence remain owned by Django.

Runtime state that must survive process restart, worker replacement, or deployment must be promoted to a durable owner rather than remaining only in FastAPI process memory.

## 4. Celery responsibility

Celery owns asynchronous execution, not business ownership.

A Celery task may read/write durable state through the authoritative service/model layer, but a queue or worker-local dictionary is not a substitute for PostgreSQL persistence.

Report generation is the canonical example:

```text
Django Report
    -> Celery task
    -> artifact generation
    -> Django persistence
```

## 5. PostgreSQL and Redis

PostgreSQL is the durable persistence layer.

Redis is infrastructure for transient coordination such as queues, caching, and runtime messaging. Redis data must not silently become the canonical business record when PostgreSQL persistence is required.

## 6. API namespace contract

All FastAPI HTTP application routes use `/api/v1`.

Django REST APIs use `/api/v1` as well, but route ownership is determined by the resource owner, not by the URL prefix.

There must be one authoritative HTTP surface for each durable resource. Compatibility aliases require an explicit deprecation plan and tests.

## 7. Resource ownership matrix

| Resource/capability | Authoritative owner | FastAPI role |
| --- | --- | --- |
| Identity/users | Django | Authentication/runtime verification only |
| Projects/membership | Django | Runtime consumption |
| Assets + relationships | Django | Runtime target/reference |
| Scans + durable lifecycle | Django | Execution/orchestration |
| Scan logs/executions | Django | Produce runtime telemetry/results |
| Vulnerabilities + evidence | Django | Analyze/normalize findings |
| Reports + artifacts/metadata | Django | Trigger/observe runtime generation |
| Compliance records | Django | Runtime analysis/aggregation only |
| Audit history | Django | Emit runtime events; no duplicate durable store |
| Validation runtime state | FastAPI service | Runtime-only state |
| Engine execution | FastAPI/Core | Execute and normalize |
| Runtime progress/WebSockets | FastAPI | Primary delivery |
| Async report generation | Celery | Worker execution |
| Durable artifacts | Django/storage owned by report subsystem | Generate, then persist |
| Queue/broker | Redis | Infrastructure only |

## 8. Boundary rules

1. Do not add a second CRUD API for a Django-owned durable resource in FastAPI.
2. Do not import FastAPI routers to obtain application state or business state.
3. Runtime services must expose state through service interfaces, not router modules.
4. Core must remain independent of HTTP framework concerns.
5. FastAPI may call an owning Django/service boundary, but must not silently duplicate its persistence model.
6. New durable state requires an explicit owner, persistence strategy, authorization model, and migration/test coverage.
7. Legacy endpoints are removed only after repository-wide reference checks and contract tests.
8. Every ownership exception must be documented here before implementation.
9. FastAPI route modules for Django-owned resources must not contain placeholder CRUD implementations.
10. A deleted/retired FastAPI resource surface must not be reintroduced without an explicit architecture review.

## 9. Validation runtime rule

Validation execution state belongs to the runtime service layer. It must not live in `routers/validations.py` or another HTTP router module.

The current runtime boundary is:

```text
FastAPI Router
    -> validation runtime service
        -> validation state
            -> engines/orchestration
                -> WebSocket/events
```

If validation history becomes a durable business record, its persistence owner must be explicitly assigned to Django and this contract updated before implementation.

## 10. Ownership contract tests

The permanent regression guard is:

```text
packages/backend/tests/test_ownership_contract.py
```

The suite verifies that:

- FastAPI CRUD router files for Django-owned resources do not reappear.
- `main.py` does not register duplicate CRUD routers for those resources.
- Django exposes the authoritative URL module for every owned resource.
- FastAPI retains only the explicitly permitted Scan runtime/orchestration endpoints.

Any future architectural change that intentionally violates this contract must update this document and the tests in the same change.

## 11. Change-control requirement

Any new endpoint must answer these questions before merge:

- Who owns the resource?
- Is the state durable or ephemeral?
- Which database/service is authoritative?
- Which service performs authorization?
- Is another endpoint already serving the same resource?
- What happens after process restart?
- What test proves the ownership boundary?

A change that cannot answer these questions is not considered architecture-complete.
