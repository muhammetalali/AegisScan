from __future__ import annotations

from typing import Any, Optional

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user

router = APIRouter()


class EvidenceResponse(BaseModel):
    id: str
    project_id: Optional[str] = None
    scan_id: Optional[str] = None
    asset_id: Optional[str] = None
    finding_id: Optional[str] = None
    source: str
    evidence_type: str
    target: Optional[str] = None
    sha256: str
    collected_at: str
    metadata: dict[str, Any]


def _target(asset) -> Optional[str]:
    if not asset:
        return None
    config = asset.configuration or {}
    for key in ('url', 'base_url', 'ip', 'host', 'domain', 'cidr', 'repo_url', 'path', 'image_name', 'file_path'):
        value = config.get(key)
        if value:
            return str(value)
    return asset.name or None


@sync_to_async
def _list_evidence(user_id: str, project_id: Optional[str], finding_id: Optional[str], scan_id: Optional[str], asset_id: Optional[str], source: Optional[str], evidence_type: Optional[str], limit: int, offset: int):
    from django_project.evidence.models import Evidence

    access = Q(scan__project__owner_id=user_id) | Q(scan__project__members__id=user_id)
    access |= Q(finding__project__owner_id=user_id) | Q(finding__project__members__id=user_id)
    access |= Q(asset__project__owner_id=user_id) | Q(asset__project__members__id=user_id)
    qs = Evidence.objects.select_related('scan__project', 'asset', 'finding__project').filter(access).distinct().order_by('-collected_at')
    if project_id:
        qs = qs.filter(Q(scan__project_id=project_id) | Q(finding__project_id=project_id) | Q(asset__project_id=project_id))
    if finding_id:
        qs = qs.filter(finding_id=finding_id)
    if scan_id:
        qs = qs.filter(scan_id=scan_id)
    if asset_id:
        qs = qs.filter(asset_id=asset_id)
    if source:
        qs = qs.filter(source__iexact=source)
    if evidence_type:
        qs = qs.filter(evidence_type__iexact=evidence_type)
    return list(qs[offset:offset + limit])


def _serialize(item) -> EvidenceResponse:
    project = item.scan.project if item.scan_id and item.scan else (item.finding.project if item.finding_id and item.finding else (item.asset.project if item.asset_id and item.asset else None))
    return EvidenceResponse(
        id=str(item.id),
        project_id=str(project.id) if project else None,
        scan_id=str(item.scan_id) if item.scan_id else None,
        asset_id=str(item.asset_id) if item.asset_id else None,
        finding_id=str(item.finding_id) if item.finding_id else None,
        source=item.source,
        evidence_type=item.evidence_type,
        target=_target(item.asset),
        sha256=item.sha256,
        collected_at=item.collected_at.isoformat(),
        metadata=item.metadata or {},
    )


@router.get('/', response_model=list[EvidenceResponse])
async def list_evidence(
    project_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    source: Optional[str] = None,
    evidence_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
):
    rows = await _list_evidence(str(user.get('user_id')), project_id, finding_id, scan_id, asset_id, source, evidence_type, limit, offset)
    return [_serialize(item) for item in rows]


@sync_to_async
def _get_evidence(evidence_id: str, user_id: str):
    from django_project.evidence.models import Evidence

    access = Q(scan__project__owner_id=user_id) | Q(scan__project__members__id=user_id)
    access |= Q(finding__project__owner_id=user_id) | Q(finding__project__members__id=user_id)
    access |= Q(asset__project__owner_id=user_id) | Q(asset__project__members__id=user_id)
    return Evidence.objects.select_related('scan__project', 'asset', 'finding__project').filter(Q(id=evidence_id) & access).distinct().first()


@router.get('/{evidence_id}', response_model=EvidenceResponse)
async def get_evidence(evidence_id: str, user=Depends(get_current_user)):
    item = await _get_evidence(evidence_id, str(user.get('user_id')))
    if not item:
        raise HTTPException(status_code=404, detail='Evidence not found')
    return _serialize(item)
