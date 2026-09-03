# Asset Network Authorization Boundary

AegisScan treats network execution authorization as a server-side security boundary.

## Rules

1. A scan request's `authorized` field is never an authorization grant.
2. Network scans require an existing project asset.
3. The persisted asset must explicitly contain `configuration.authorized=true`.
4. The requested target must match the persisted asset identity when a target is supplied.
5. Generic asset create/update endpoints cannot set or change `configuration.authorized`.
6. Only the project owner or staff may change network authorization through `POST /assets/{asset_id}/authorization`.
7. Authorization can be explicitly revoked through the same endpoint.

## Security rationale

Asset membership and asset modification are not equivalent to authorization to perform network activity. Separating generic asset CRUD from the authorization decision prevents a project member from creating or modifying an asset and then using that client-controlled state to authorize a network scan.

The authorization decision remains persisted and server-side, while the authorization endpoint provides an explicit control point that can later be extended with approval records, actor identity, timestamps, audit evidence, expiry, and policy evaluation without reintroducing client-controlled elevation.
