# Asset Network Authorization Boundary

AegisScan treats network execution authorization as a server-side security boundary.

## Rules

1. A scan request's `authorized` field is never an authorization grant.
2. Network scans require an existing project asset.
3. The persisted asset must explicitly contain `configuration.authorized=true`.
4. The requested target must match the persisted asset identity when a target is supplied.
5. Generic asset create/update endpoints cannot set `configuration.authorized`.
6. A configuration change on an already-authorized asset revokes its authorization and requires explicit re-authorization.
7. Only the project owner or staff may change network authorization through `POST /assets/{asset_id}/authorization`.
8. Authorization can be explicitly revoked through the same endpoint.

## Security rationale

Asset membership and asset modification are not equivalent to authorization to perform network activity. Separating generic asset CRUD from the authorization decision prevents a project member from creating or modifying an asset and then using that client-controlled state to authorize a network scan.

Authorization is also revoked when the persisted target configuration changes. This prevents an already-authorized asset from being repointed to a different network target while retaining the old authorization state.

The current JSON-backed authorization flag is an interim compatibility boundary. The production target is a first-class authorization/approval record containing actor identity, timestamp, scope, expiry, audit evidence, policy decision, and revocation lineage.
