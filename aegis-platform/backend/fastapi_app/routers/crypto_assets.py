from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from django_project.projects.models import Project
from enterprise.crypto_asset_models import CryptographicInventorySnapshot

from ..core.dependencies import get_current_user
from ..services.crypto_asset_plane import (
    CryptoAssetAuthorizationError,
    CryptoAssetError,
    record_crypto_inventory,
)


router = APIRouter()


class CryptoInventoryRecordIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    kind: str = Field(min_length=1, max_length=24)
    name: str = Field(min_length=1, max_length=255)
    algorithm: str = Field(default='', max_length=128)
    key_size: int | None = Field(default=None, ge=1, le=65536)
    curve: str = Field(default='', max_length=128)
    protocol: str = Field(default='', max_length=64)
    version: str = Field(default='', max_length=64)
    issuer: str = Field(default='', max_length=500)
    subject: str = Field(default='', max_length=500)
    not_before: str | None = None
    not_after: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CryptoInventoryIn(BaseModel):
    model_config = ConfigDict(extra='forbid')

    asset_id: UUID
    authorization_id: UUID
    scan_id: UUID | None = None
    source_type: str = Field(min_length=1, max_length=64)
    records: list[CryptoInventoryRecordIn] = Field(min_length=1, max_length=5000)


def _actor_id(user: dict[str, Any]) -> str:
    value = user.get('user_id') or user.get('id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user.')
    return str(value)


@sync_to_async
def _project_access(project_id: str, actor_id: str) -> bool:
    return Project.objects.filter(pk=project_id).filter(
        Q(owner_id=actor_id) | Q(members__id=actor_id)
    ).distinct().exists()


def _serialize(snapshot: CryptographicInventorySnapshot) -> dict[str, Any]:
    return {
        'id': str(snapshot.id),
        'organization_id': str(snapshot.organization_id),
        'project_id': str(snapshot.project_id),
        'asset_id': str(snapshot.asset_id),
        'scan_id': str(snapshot.scan_id or ''),
        'authorization_decision_id': str(snapshot.authorization_decision_id),
        'predecessor_id': str(snapshot.predecessor_id or ''),
        'snapshot_version': int(snapshot.snapshot_version),
        'source_type': snapshot.source_type,
        'inventory_sha256': snapshot.inventory_sha256,
        'cbom_sha256': snapshot.cbom_sha256,
        'cbom': dict(snapshot.cbom or {}),
        'risk_summary': dict(snapshot.risk_summary or {}),
        'drift': dict(snapshot.drift or {}),
        'request_fingerprint': snapshot.request_fingerprint,
        'policy_version': snapshot.policy_version,
        'created_at': snapshot.created_at.isoformat(),
    }


@router.post('/projects/{project_id}/inventory', status_code=201)
async def create_crypto_inventory(
    project_id: UUID,
    payload: CryptoInventoryIn,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(record_crypto_inventory)(
            project_id=str(project_id),
            asset_id=str(payload.asset_id),
            authorization_id=str(payload.authorization_id),
            actor_id=actor_id,
            scan_id=str(payload.scan_id) if payload.scan_id else None,
            source_type=payload.source_type,
            records=[record.model_dump(mode='json') for record in payload.records],
        )
    except CryptoAssetAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CryptoAssetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize(result.snapshot)}


@router.get('/projects/{project_id}/inventory')
async def list_crypto_inventory(
    project_id: UUID,
    limit: int = Query(default=100, ge=1, le=1000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        CryptographicInventorySnapshot.objects.filter(project_id=project_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize(row) for row in rows]


@router.get('/projects/{project_id}/inventory/{snapshot_id}')
async def get_crypto_inventory(
    project_id: UUID,
    snapshot_id: UUID,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    row = await sync_to_async(
        lambda: CryptographicInventorySnapshot.objects.filter(
            pk=snapshot_id,
            project_id=project_id,
        ).first()
    )()
    if row is None:
        raise HTTPException(status_code=404, detail='Cryptographic inventory snapshot not found.')
    return _serialize(row)
