from __future__ import annotations

from typing import Any
from uuid import UUID

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query

from django_project.projects.models import Project
from enterprise.crypto_lifecycle_models import CryptoLifecycleAssessment

from ..core.dependencies import get_current_user
from ..services.crypto_lifecycle_pqc import (
    CryptoLifecycleAuthorizationError,
    CryptoLifecycleError,
    evaluate_crypto_lifecycle,
)


router = APIRouter()


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


def _serialize(row: CryptoLifecycleAssessment) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'organization_id': str(row.organization_id),
        'project_id': str(row.project_id),
        'asset_id': str(row.asset_id),
        'inventory_snapshot_id': str(row.inventory_snapshot_id),
        'predecessor_id': str(row.predecessor_id or ''),
        'assessment_version': int(row.assessment_version),
        'lifecycle_state': row.lifecycle_state,
        'pqc_readiness': row.pqc_readiness,
        'total_records': int(row.total_records),
        'weak_deprecated_count': int(row.weak_deprecated_count),
        'expired_count': int(row.expired_count),
        'expiring_30d_count': int(row.expiring_30d_count),
        'expiring_90d_count': int(row.expiring_90d_count),
        'quantum_vulnerable_count': int(row.quantum_vulnerable_count),
        'quantum_resistant_count': int(row.quantum_resistant_count),
        'hybrid_count': int(row.hybrid_count),
        'policy_snapshot': dict(row.policy_snapshot or {}),
        'migration_plan': dict(row.migration_plan or {}),
        'assessment_sha256': row.assessment_sha256,
        'request_fingerprint': row.request_fingerprint,
        'policy_version': row.policy_version,
        'created_at': row.created_at.isoformat(),
    }


@router.post('/snapshots/{snapshot_id}/evaluate', status_code=201)
async def evaluate_snapshot_lifecycle(
    snapshot_id: UUID,
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    try:
        result = await sync_to_async(evaluate_crypto_lifecycle)(
            snapshot_id=str(snapshot_id),
            actor_id=actor_id,
        )
    except CryptoLifecycleAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except CryptoLifecycleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'replayed': result.replayed, **_serialize(result.assessment)}


@router.get('/projects/{project_id}/assessments')
async def list_lifecycle_assessments(
    project_id: UUID,
    limit: int = Query(default=100, ge=1, le=1000),
    user=Depends(get_current_user),
):
    actor_id = _actor_id(user)
    if not await _project_access(str(project_id), actor_id):
        raise HTTPException(status_code=404, detail='Project not found or inaccessible.')
    rows = await sync_to_async(lambda: list(
        CryptoLifecycleAssessment.objects.filter(project_id=project_id)
        .order_by('-created_at', '-id')[:limit]
    ))()
    return [_serialize(row) for row in rows]
