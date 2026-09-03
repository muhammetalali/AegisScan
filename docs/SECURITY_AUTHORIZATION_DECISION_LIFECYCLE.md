# Asset Authorization Decision Lifecycle

## Status

The `AssetAuthorization` ledger is the authoritative security state for network execution. The legacy `configuration.authorized` field is compatibility state only and must never grant authorization.

## Decision model

Each authorization change creates a new immutable decision. Existing decisions are never updated or deleted. The asset row is locked while an authorization-sensitive mutation is committed so concurrent writers serialize against the same asset.

## Current decision

For an asset that still exists, the current decision is the newest persisted `AssetAuthorization` record ordered by `created_at DESC, id DESC`.

- `authorized=true` means the asset is currently authorized only when that record is the latest decision.
- `authorized=false` means the asset is currently revoked.
- No decision means fail closed: the asset is not authorized for network execution.

For a deleted asset, authorization records remain as immutable historical lineage. They are never eligible to authorize execution because execution requires a live asset and a current decision attached to that asset.

## Target binding

Every decision stores a `target_snapshot` captured from the asset configuration at decision time. The execution path must independently verify that the requested network target matches the persisted asset identity and that the latest decision is authorized.

Changing network-relevant configuration while an asset is authorized creates a new immutable revocation decision. This prevents authorization from silently carrying over to a changed target.

## Legacy compatibility field

`configuration.authorized` is not a security control. It may be maintained for backward compatibility, but:

1. generic asset create/update operations cannot use it to authorize an asset;
2. the authorization endpoint is the only supported mutation path for an authorization decision;
3. scan enforcement must consult `AssetAuthorization`, not the compatibility flag;
4. a legacy flag set to `true` while the latest ledger decision is revoked must still deny execution.

## Concurrency requirements

Authorization-sensitive mutations must execute inside a database transaction and lock the target asset row. A decision must be inserted in the same transaction as the compatibility-state update. If any part fails, no partial authorization state may become visible.

## Governance requirements

Every decision retains:

- actor identity;
- authorized/revoked state;
- target snapshot;
- reason;
- creation timestamp;
- durable asset identity snapshot.

These fields form the minimum immutable evidence required to reconstruct authorization history after an asset is deleted.

## Future lifecycle extensions

The next governance hardening stage may add explicit decision lineage (`supersedes`), correlation/request identifiers, temporal validity (`valid_from`/`expires_at`), and first-class audit-event linkage. These should be introduced only with explicit API and threat-model requirements; they must not weaken the current fail-closed semantics.
