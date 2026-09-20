from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from django.db import IntegrityError, transaction

from django_project.assets.models import Asset, AssetAuthorization
from fastapi_app.services.authorization_guard import asset_target


class AssetAuthorizationGovernanceError(ValueError):
    pass


class StaleAssetAuthorizationVersion(AssetAuthorizationGovernanceError):
    pass


class AssetAuthorizationConflict(AssetAuthorizationGovernanceError):
    pass


@dataclass(frozen=True)
class AssetAuthorizationDecisionResult:
    decision: AssetAuthorization
    version: int
    replayed: bool


def _normalize_reason(value: str) -> str:
    reason = ' '.join(str(value or '').split())
    if len(reason) < 3:
        raise AssetAuthorizationGovernanceError('Asset authorization requires a meaningful reason.')
    if len(reason) > 500:
        raise AssetAuthorizationGovernanceError('Asset authorization reason exceeds 500 characters.')
    return reason


def _normalize_expiry(value: datetime | str | None) -> datetime | None:
    if value in (None, ''):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        except ValueError as exc:
            raise AssetAuthorizationGovernanceError('expires_at must be a valid ISO-8601 timestamp.') from exc
    if parsed.tzinfo is None:
        raise AssetAuthorizationGovernanceError('expires_at must be timezone-aware.')
    if parsed <= datetime.now(timezone.utc):
        raise AssetAuthorizationGovernanceError('expires_at must be in the future.')
    return parsed


def asset_authorization_version(asset: Asset) -> int:
    return AssetAuthorization.objects.filter(asset=asset).count() + 1


def govern_asset_authorization(
    *,
    asset_id: str,
    project_id: str,
    actor_id: str,
    expected_version: int,
    authorized: bool,
    reason: str,
    governed_request_id: str,
    correlation_id: str,
    expires_at: datetime | str | None = None,
) -> AssetAuthorizationDecisionResult:
    reason = _normalize_reason(reason)
    expiry = _normalize_expiry(expires_at) if authorized else None
    try:
        request_uuid = UUID(str(governed_request_id))
        correlation_uuid = UUID(str(correlation_id))
    except ValueError as exc:
        raise AssetAuthorizationGovernanceError('Governed request and correlation identifiers must be UUIDs.') from exc

    with transaction.atomic():
        asset = (
            Asset.objects.select_for_update(of=('self',))
            .filter(pk=asset_id, project_id=project_id, is_active=True)
            .first()
        )
        if asset is None:
            raise AssetAuthorizationGovernanceError('Active asset was not found in the governed project scope.')

        target = asset_target(asset)
        if not target:
            raise AssetAuthorizationGovernanceError('Asset has no server-derived authorization target.')
        if len(target) > 500:
            raise AssetAuthorizationGovernanceError('Server-derived asset authorization target exceeds 500 characters.')

        existing = (
            AssetAuthorization.objects.filter(request_id=request_uuid)
            .order_by('-created_at', '-id')
            .first()
        )
        if existing is not None:
            same = (
                str(existing.asset_identity_snapshot) == str(asset.id)
                and bool(existing.authorized) is bool(authorized)
                and existing.reason == reason
                and existing.target_snapshot == target
                and str(existing.correlation_id) == str(correlation_uuid)
                and existing.expires_at == expiry
            )
            if not same:
                raise AssetAuthorizationConflict(
                    'Governed request id is already bound to a different asset authorization decision.'
                )
            return AssetAuthorizationDecisionResult(
                decision=existing,
                version=asset_authorization_version(asset),
                replayed=True,
            )

        current_version = asset_authorization_version(asset)
        if int(expected_version) != int(current_version):
            raise StaleAssetAuthorizationVersion(
                f'Expected asset authorization version {expected_version}, current version is {current_version}.'
            )

        latest = (
            AssetAuthorization.objects.select_for_update(of=('self',))
            .filter(asset=asset)
            .order_by('-created_at', '-id')
            .first()
        )
        if not authorized:
            if latest is None or latest.authorized is not True or not latest.is_currently_valid:
                raise AssetAuthorizationGovernanceError(
                    'Revocation requires the latest asset authorization decision to be currently valid and authorized.'
                )
            if latest.target_snapshot != target:
                raise AssetAuthorizationGovernanceError(
                    'Revocation target no longer matches the latest authorization decision.'
                )

        configuration = dict(asset.configuration or {})
        configuration['authorized'] = bool(authorized)
        asset.configuration = configuration
        asset.save(update_fields=['configuration', 'updated_at'])

        try:
            decision = AssetAuthorization.objects.create(
                asset=asset,
                actor_id=actor_id,
                authorized=bool(authorized),
                target_snapshot=target,
                reason=reason,
                correlation_id=correlation_uuid,
                request_id=request_uuid,
                supersedes=latest,
                expires_at=expiry,
            )
        except IntegrityError as exc:
            raise AssetAuthorizationConflict(
                'Asset authorization decision could not be committed idempotently.'
            ) from exc

        return AssetAuthorizationDecisionResult(
            decision=decision,
            version=current_version + 1,
            replayed=False,
        )
