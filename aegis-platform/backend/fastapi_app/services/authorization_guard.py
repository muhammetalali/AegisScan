from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from django.db import transaction

from django_project.assets.models import Asset, AssetAuthorization
from django_project.scans.models import Scan

from .scope_authorization import is_target_authorized


_NETWORK_SCAN_TYPES = {Scan.Type.IP, Scan.Type.URL, Scan.Type.NETWORK}


def _first_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return ''


def asset_target(asset: Asset) -> str:
    configuration = asset.configuration or {}
    return _first_string(
        configuration.get('url')
        or configuration.get('host')
        or configuration.get('ip')
        or configuration.get('domain')
        or configuration.get('cidr')
        or configuration.get('target')
        or configuration.get('repo_url')
        or configuration.get('path')
    )


def _requested_scan_target(scan: Scan) -> str:
    config = scan.config or {}
    return _first_string(
        config.get('target')
        or config.get('host')
        or config.get('ip')
        or config.get('url')
        or config.get('domain')
        or config.get('cidr')
        or config.get('repo_url')
        or config.get('path')
    )


def require_bound_scan_authorization(scan_id: str) -> tuple[Scan | None, str, AssetAuthorization | None]:
    """Resolve the immutable authorization bound to a scan.

    The persisted AssetAuthorization decision is authoritative for both network
    and source-code scans. Mutable Asset.configuration flags never grant
    execution authority. Network scans additionally require the server-side
    target scope allowlist.
    """
    with transaction.atomic():
        scan = Scan.objects.select_for_update().select_related('project', 'initiated_by').get(pk=scan_id)
        if not scan.asset_id:
            return None, 'Execution blocked: scan has no persisted asset.', None
        if not scan.authorization_decision_id:
            return None, 'Execution blocked: scan has no bound asset authorization decision.', None
        asset = Asset.objects.select_for_update().get(pk=scan.asset_id)
        decision = AssetAuthorization.objects.select_for_update().get(pk=scan.authorization_decision_id)
        latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
        if decision.asset_identity_snapshot != asset.id:
            return None, 'Execution blocked: authorization decision is not bound to the current asset identity.', None
        if latest is None or latest.id != decision.id:
            return None, 'Execution blocked: bound authorization decision is no longer the latest asset decision.', None
        if decision.authorized is not True or not decision.is_currently_valid:
            return None, 'Execution blocked: bound authorization decision is not currently valid.', None
        current_target = asset_target(asset)
        authorized_target = _first_string(decision.target_snapshot)
        requested_target = _requested_scan_target(scan)
        if not authorized_target:
            return None, 'Execution blocked: authorization decision has no target snapshot.', None
        if current_target != authorized_target:
            return None, 'Execution blocked: asset target no longer matches the bound authorization decision.', None
        if requested_target and requested_target != authorized_target:
            return None, 'Execution blocked: scan target no longer matches the bound authorization decision.', None
        if scan.scan_type in _NETWORK_SCAN_TYPES and not is_target_authorized(authorized_target):
            return None, 'Execution blocked: target is outside the server-side authorized scan scope.', None
        return scan, authorized_target, decision


def authorization_snapshot(decision: AssetAuthorization) -> dict[str, Any]:
    return {
        'authorization_decision_id': str(decision.id),
        'authorization_target': decision.target_snapshot,
        'authorization_correlation_id': str(decision.correlation_id),
        'authorization_request_id': str(decision.request_id),
        'authorization_expires_at': decision.expires_at.isoformat() if decision.expires_at else None,
        'authorization_valid_from': decision.valid_from.isoformat() if decision.valid_from else None,
    }


def current_asset_authorization(asset: Asset, expected_target: str = '') -> tuple[AssetAuthorization | None, str]:
    """Return the current immutable grant only when identity and target still match."""
    decision = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
    if decision is None:
        return None, 'Execution blocked: asset has no authoritative authorization decision.'
    if decision.asset_identity_snapshot != asset.id:
        return None, 'Execution blocked: authorization decision is not bound to the current asset identity.'
    if decision.authorized is not True or not decision.is_currently_valid:
        return None, 'Execution blocked: latest authorization decision is not currently valid.'
    target = asset_target(asset)
    if not target or target != _first_string(decision.target_snapshot):
        return None, 'Execution blocked: asset target does not match the authorization snapshot.'
    if expected_target and _first_string(expected_target) != target:
        return None, 'Execution blocked: requested target does not match the authorization snapshot.'
    return decision, ''


def require_bound_validation_authorization(validation) -> tuple[Asset | None, str, AssetAuthorization | None]:
    """Resolve a ValidationRun against its immutable, still-current authorization grant."""
    finding = validation.finding
    asset = finding.asset if finding else None
    if asset is None:
        return None, 'Execution blocked: validation finding has no persisted asset.', None
    if not validation.authorization_decision_id:
        return None, 'Execution blocked: validation has no bound asset authorization decision.', None
    decision, reason = current_asset_authorization(asset, validation.target_value)
    if decision is None:
        return None, reason, None
    if decision.id != validation.authorization_decision_id:
        return None, 'Execution blocked: bound authorization decision is no longer the latest asset decision.', None
    if not is_target_authorized(decision.target_snapshot):
        return None, 'Execution blocked: target is outside the server-side authorized scan scope.', None
    return asset, decision.target_snapshot, decision


def revalidate_bound_authorization(scan: Scan, decision: AssetAuthorization) -> tuple[bool, str]:
    """Re-check the latest persisted decision immediately before evidence commit."""
    with transaction.atomic():
        asset = Asset.objects.select_for_update().get(pk=scan.asset_id)
        latest = AssetAuthorization.objects.select_for_update().filter(asset=asset).order_by('-created_at', '-id').first()
        if latest is None or latest.id != decision.id:
            return False, 'Execution blocked: authorization was superseded before evidence persistence.'
        if latest.authorized is not True or not latest.is_currently_valid:
            return False, 'Execution blocked: authorization is no longer valid before evidence persistence.'
        if asset_target(asset) != decision.target_snapshot:
            return False, 'Execution blocked: asset target changed before evidence persistence.'
        if scan.scan_type in _NETWORK_SCAN_TYPES and not is_target_authorized(decision.target_snapshot):
            return False, 'Execution blocked: target left the server-side authorized scan scope before evidence persistence.'
        return True, ''


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
