from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from asgiref.sync import sync_to_async
from django.db import IntegrityError, transaction
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from django_project.audit.models import AuditLog
from django_project.assets.models import Asset, AssetAuthorization
from ..core.dependencies import get_current_user
from ..services.authorization_guard import asset_target

router = APIRouter()


class AuthorizationUpdate(BaseModel):
    authorized: bool
    reason: str = Field(default='', max_length=500)
    correlation_id: Optional[UUID] = None
    expires_at: Optional[str] = None


def _request_id(request: Request) -> UUID:
    raw = request.headers.get('X-Request-ID')
    if not raw:
        return uuid4()
    try:
        return UUID(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail='X-Request-ID must be a valid UUID') from exc


def _request_ip(request: Request) -> str:
    import ipaddress
    host = request.client.host if request.client and request.client.host else ''
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return '0.0.0.0'


def _response(asset: Asset) -> dict:
    return {
        'id': str(asset.id),
        'project_id': str(asset.project_id),
        'name': asset.name,
        'slug': asset.slug,
        'type': asset.type,
        'description': asset.description,
        'environment': asset.environment,
        'criticality': asset.criticality,
        'configuration': asset.configuration or {},
        'tags': asset.tags or [],
        'is_active': asset.is_active,
        'scan_count': asset.scan_count,
        'last_scanned_at': asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
        'created_at': asset.created_at.isoformat(),
        'updated_at': asset.updated_at.isoformat(),
    }


@sync_to_async
def _set_authorization(asset_id: str, user_id: str, is_staff: bool, update: AuthorizationUpdate, request_id: UUID, ip_address: str, user_agent: str) -> dict:
    with transaction.atomic():
        asset = Asset.objects.select_related('project').select_for_update().filter(pk=asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail='Asset not found')
        if not is_staff and str(asset.project.owner_id) != str(user_id):
            raise HTTPException(status_code=403, detail='Only the project owner or staff may change asset network authorization')
        correlation_id = update.correlation_id or uuid4()
        existing = AssetAuthorization.objects.filter(correlation_id=correlation_id).first()
        if existing:
            if existing.asset_id != asset.id or existing.authorized != update.authorized or existing.reason != update.reason:
                raise HTTPException(status_code=409, detail='Correlation ID is already bound to a different authorization decision')
            return _response(asset)
        if AssetAuthorization.objects.filter(request_id=request_id).exists():
            raise HTTPException(status_code=409, detail='Request ID is already bound to an authorization decision')
        expiry = None
        if update.expires_at:
            try:
                expiry = datetime.fromisoformat(update.expires_at.replace('Z', '+00:00'))
            except ValueError as exc:
                raise HTTPException(status_code=422, detail='expires_at must be a valid ISO-8601 timestamp') from exc
            if expiry <= datetime.now(timezone.utc):
                raise HTTPException(status_code=422, detail='expires_at must be in the future')
        latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
        configuration = dict(asset.configuration or {})
        configuration['authorized'] = update.authorized
        asset.configuration = configuration
        asset.save(update_fields=['configuration', 'updated_at'])
        try:
            decision = AssetAuthorization.objects.create(
                asset=asset,
                actor_id=user_id,
                authorized=update.authorized,
                target_snapshot=asset_target(asset)[:500],
                reason=update.reason,
                correlation_id=correlation_id,
                request_id=request_id,
                supersedes=latest,
                expires_at=expiry,
            )
        except IntegrityError as exc:
            raise HTTPException(status_code=409, detail='Authorization decision could not be committed idempotently') from exc
        AuditLog.objects.create(
            user_id=user_id,
            action='asset_authorization_grant' if update.authorized else 'asset_authorization_revoke',
            result=AuditLog.Result.SUCCESS,
            resource_type='AssetAuthorization',
            resource_id=str(decision.id),
            resource_repr=f'Asset {asset.id} authorization decision',
            changes={'authorized': update.authorized, 'supersedes': str(latest.id) if latest else None},
            metadata={
                'asset_id': str(asset.id),
                'asset_identity_snapshot': str(decision.asset_identity_snapshot),
                'target_snapshot': decision.target_snapshot,
                'reason': update.reason,
                'correlation_id': str(decision.correlation_id),
                'request_id': str(decision.request_id),
                'expires_at': decision.expires_at.isoformat() if decision.expires_at else None,
            },
            ip_address=ip_address,
            user_agent=user_agent[:10000],
            request_id=decision.request_id,
        )
        return _response(asset)


@router.post('/assets/{asset_id}/authorization')
@router.post('/api/v1/assets/{asset_id}/authorization')
async def set_asset_authorization(asset_id: str, update: AuthorizationUpdate, request: Request, user=Depends(get_current_user)):
    return await _set_authorization(asset_id, str(user.get('user_id')), bool(user.get('is_staff')), update, _request_id(request), _request_ip(request), request.headers.get('User-Agent', ''))


@sync_to_async
def _authorization_history(asset_id: str, user_id: str):
    asset = Asset.objects.filter(pk=asset_id).filter(project__owner_id=user_id).first() or Asset.objects.filter(pk=asset_id, project__members__id=user_id).first()
    if not asset:
        return None
    return list(AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id'))


@router.get('/assets/{asset_id}/authorization')
@router.get('/api/v1/assets/{asset_id}/authorization')
async def get_asset_authorization_history(asset_id: str, user=Depends(get_current_user)):
    history = await _authorization_history(asset_id, str(user.get('user_id')))
    if history is None:
        raise HTTPException(status_code=404, detail='Asset not found')
    return [
        {
            'id': str(item.id),
            'asset_id': str(item.asset_identity_snapshot),
            'authorized': item.authorized,
            'target_snapshot': item.target_snapshot,
            'reason': item.reason,
            'correlation_id': str(item.correlation_id),
            'request_id': str(item.request_id),
            'supersedes': str(item.supersedes_id) if item.supersedes_id else None,
            'valid_from': item.valid_from.isoformat(),
            'expires_at': item.expires_at.isoformat() if item.expires_at else None,
            'currently_valid': item.is_currently_valid,
            'created_at': item.created_at.isoformat(),
        }
        for item in history
    ]
