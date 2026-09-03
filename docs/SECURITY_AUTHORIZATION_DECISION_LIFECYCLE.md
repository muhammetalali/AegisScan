# Asset Authorization Decision Lifecycle

## Status

`AssetAuthorization` is the authoritative, immutable append-only security ledger for network execution. The legacy `configuration.authorized` field is compatibility state only and can never grant or preserve authorization.

## Current decision semantics

For a live asset, the effective decision is the newest persisted record ordered by `created_at DESC, id DESC`.

- `authorized=true` permits execution only when the decision is the effective decision and is temporally valid.
- `authorized=false` revokes execution.
- no decision is fail-closed.
- an expired decision is not valid for execution.
- deleted assets retain immutable lineage but cannot authorize execution.

## Lineage

Every decision may reference the immediately preceding decision through `supersedes`. This makes authorization transitions reconstructable without mutating historical records. Configuration-change revocations explicitly supersede the authorization they invalidate.

## Target binding

Each decision stores `target_snapshot` captured from the asset at decision time. Network execution must compare the requested target with the effective decision snapshot. Network-relevant asset configuration changes create a revocation decision in the same transaction, preventing authorization from silently carrying over to a changed target.

## Correlation and idempotency

Every decision has a unique `correlation_id`. The authorization API accepts a caller-supplied correlation ID. Retrying the same decision with the same correlation ID returns the already committed result; attempting to reuse the ID for a different asset/state/reason is rejected with a conflict. This prevents retry storms from producing duplicate governance decisions while preserving the append-only ledger.

## Temporal validity

Decisions have `valid_from` and optional `expires_at`. The execution boundary evaluates temporal validity in addition to state and target binding. API-provided expiry timestamps must be future-dated. A revoked decision remains revoked regardless of its expiry value.

## Immutability and tamper resistance

Decision records cannot be modified or deleted through model instance methods, QuerySet `update/delete`, or `bulk_update`. Asset deletion uses `SET_NULL` so the decision record and durable asset identity snapshot survive asset lifecycle events.

## Concurrency

Authorization-sensitive mutations execute inside a database transaction and lock the target asset row as the serialization point. The decision and compatibility-state update commit atomically. Correlation checks occur while the asset row is locked, preventing concurrent retries from creating duplicate decisions.

## Legacy compatibility field

`configuration.authorized` is not a security control. Generic asset create/update operations cannot establish authorization through it, and scan enforcement never trusts it. The authorization endpoint is the supported mutation path for authorization state.

## Governance evidence

Each decision retains actor identity, state, target snapshot, reason, correlation ID, lineage, validity window, creation timestamp, and durable asset identity. Together these fields provide a reconstructable authorization trail even after the asset itself is deleted.

## Remaining governance hardening

The next security layer is first-class audit-event linkage and request/trace propagation across the Django → FastAPI → Celery execution boundary, followed by retention policy, privileged-action monitoring, and compliance reporting. These must be implemented without weakening the fail-closed execution boundary.
