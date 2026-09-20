from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from django_project.assets.models import Asset, AssetAuthorization
from ..core.dependencies import get_current_user
from ..services.asset_authorization_governance import asset_authorization_version
from ..services.governed_action_requests import (
    GovernedActionRequestConflict,
    GovernedActionRequestError,
    create_governed_action_request,
    governed_action_request_view,
)

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
def _submit_authorization_request(
    asset_id: str,
    user_id: str,
    is_staff: bool,
    update: AuthorizationUpdate,
    request_id: UUID,
) -> dict:
    asset = Asset.objects.select_related('project').filter(pk=asset_id, is_active=True).first()
    if asset is None:
        raise HTTPException(status_code=404, detail='Asset not found')
    if not is_staff and str(asset.project.owner_id) != str(user_id):
        raise HTTPException(status_code=403, detail='Only the project owner or staff may propose asset network authorization')
    if not update.authorized and update.expires_at:
        raise HTTPException(status_code=422, detail='expires_at is not valid for an authorization revocation request')

    action_id = 'asset.authorization.approve' if update.authorized else 'asset.authorization.revoke'
    parameters = {'reason': update.reason}
    if update.authorized and update.expires_at:
        parameters['expires_at'] = update.expires_at

    try:
        result = create_governed_action_request(
            project_id=str(asset.project_id),
            requested_by_id=str(user_id),
            action_id=action_id,
            entity_type='asset',
            entity_id=str(asset.id),
            expected_version=asset_authorization_version(asset),
            idempotency_key=f'asset-authorization:{request_id}',
            parameters=parameters,
            correlation_id=update.correlation_id or request_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except GovernedActionRequestConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GovernedActionRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        'status': 'submitted',
        'governed_action': governed_action_request_view(result),
        'asset': _response(asset),
    }


@router.post('/assets/{asset_id}/authorization', status_code=202)
@router.post('/api/v1/assets/{asset_id}/authorization', status_code=202)
async def set_asset_authorization(asset_id: str, update: AuthorizationUpdate, request: Request, user=Depends(get_current_user)):
    return await _submit_authorization_request(
        asset_id,
        str(user.get('user_id')),
        bool(user.get('is_staff')),
        update,
        _request_id(request),
    )


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
