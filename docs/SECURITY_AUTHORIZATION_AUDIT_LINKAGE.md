# Authorization Decision Audit Linkage

AegisScan treats `AssetAuthorization` as an immutable append-only authorization ledger. Each decision created through the authorization API has two distinct request-tracing identifiers:

- `correlation_id`: the idempotency key for the authorization decision. Reusing it for the same decision is safe; reusing it for different decision content is rejected.
- `request_id`: the identity of the HTTP request that created the decision. It is persisted on the decision and copied to the corresponding `AuditLog` entry.

Successful grant/revoke operations create the `AssetAuthorization` row and its `AuditLog` row in the same database transaction. A failure while writing the audit record therefore rolls back the authorization decision rather than leaving an un-audited authorization state.

The audit record uses `resource_type=AssetAuthorization` and `resource_id=<decision UUID>`. Its metadata preserves the asset identity snapshot, target snapshot, reason, correlation ID, request ID, expiry, and superseded decision ID. This makes the decision stream traceable from authorization evidence to the audit trail without introducing a cross-application foreign-key cycle.

`X-Request-ID` is accepted as the request identity when it is a valid UUID. When it is absent, the API generates a UUID server-side. Invalid request IDs are rejected before persistence.

Idempotent retries do not create a second decision or audit record. The original decision retains the request ID of the request that actually committed it.
