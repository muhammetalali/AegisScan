# AegisScan: scoped API key consumer

## Implementation boundary

The existing user API-key lifecycle already supports creation, one-time
material reveal, SHA-256 digest storage, rotation, expiry, revocation and
audit. Prior to this patch, Django/DRF and FastAPI did **not** authenticate
these issued keys. Showing an active key in Settings was not proof that it
could access an API.

This change opts in **only** the Django ProjectViewSet to accept
`X-API-Key: aegis_...`. Do not globally enable this authentication class.
An issued key returns the original user identity plus the persisted key as
the DRF authentication object, then the **existing HasPermission** requires
both (a) an allowed key scope and (b) the user's current RBAC permission.
The first consumer is read-only: non-GET/HEAD/OPTIONS requests are denied
even if a key carries a write scope. Project querysets remain scoped to
owned/member projects, independent of key permissions.

## Fail-closed controls

- Missing key: existing JWT/cookie/session authentication remains available.
- Invalid header, unknown digest, revoked/expired key and deactivated user:
  HTTP 401.
- Users marked two_factor_enabled are denied API key access until a proper
  second-factor and machine-credential policy is implemented.
- Valid key with insufficient scope, or a mutation using a read key:
  HTTP 403.
- No API-key authentication on unrelated DRF endpoints or FastAPI.
- Last-used timestamp and IP are updated; raw key is never logged or
  returned by the listing API.
- Existing SHA-256 digest lookup gets a PostgreSQL B-tree index through the
  existing users app migration sequence; do not brute-force scan the API-key
  table per incoming request.
- Frontend clearly states the supported consumer. Existing key issuance UI
  remains intact; other key scopes are **not yet enabled for API access**.

## Validation and release requirements

Isolated PostgreSQL tests for project-list auth, cross-tenant exclusion,
permission escalation, expiry/revocation, account deactivation, unsupported
endpoint, legacy login and 2FA flag; plus pre-existing API key lifecycle
coverage. Wire them into the existing Domain Contract Reality workflow,
not a duplicate workflow.

Do not close issue #349 until exact-SHA CI, a governed production release,
actual owner/Admin/Viewer UI control evidence and a live key-consumer
positive/negative acceptance have been collected. Wider API key adoption
requires per-endpoint permission and object-scope audits, not a global
authentication shortcut.
