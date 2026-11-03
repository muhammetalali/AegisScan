from __future__ import annotations

import base64
import binascii
import hashlib
import json

from typing import Any, Optional

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from ..core.dependencies import get_current_user, project_access_q

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

    access = project_access_q(user_id, relation="scan__project")
    access |= project_access_q(user_id, relation="finding__project")
    access |= project_access_q(user_id, relation="asset__project")
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

    access = project_access_q(user_id, relation="scan__project")
    access |= project_access_q(user_id, relation="finding__project")
    access |= project_access_q(user_id, relation="asset__project")
    return Evidence.objects.select_related('scan__project', 'asset', 'finding__project').filter(Q(id=evidence_id) & access).distinct().first()


@router.get('/{evidence_id}', response_model=EvidenceResponse)
async def get_evidence(evidence_id: str, user=Depends(get_current_user)):
    item = await _get_evidence(evidence_id, str(user.get('user_id')))
    if not item:
        raise HTTPException(status_code=404, detail='Evidence not found')
    return _serialize(item)


_MAX_VISUAL_BYTES = 1024 * 1024
_PNG_MAGIC = bytes.fromhex('89504e470d0a1a0a')


def _visual_png_from_evidence(item: Any) -> bytes | None:
    """Validate a privately retained browser image without implying XSS execution."""
    if getattr(item, 'source', None) != 'aegis-browser-security' or getattr(item, 'evidence_type', None) != 'scanner_output':
        return None
    raw = getattr(item, 'raw_output', None)
    if not isinstance(raw, str) or not raw or len(raw) > 4 * 1024 * 1024:
        return None
    if hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest() != getattr(item, 'sha256', None):
        return None
    try:
        body = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict) or body.get('schema') != 'aegis.browser-security.v1':
        return None
    artifacts = body.get('visual_artifacts')
    observations = body.get('observations')
    if not isinstance(artifacts, list) or not isinstance(observations, list):
        return None
    for artifact in artifacts[:2]:
        if not isinstance(artifact, dict) or artifact.get('kind') != 'browser-render-snapshot':
            continue
        if artifact.get('media_type') != 'image/png' or artifact.get('browser_family') != 'firefox':
            continue
        encoded = artifact.get('png_base64')
        expected_sha = artifact.get('sha256')
        if not isinstance(encoded, str) or len(encoded) > (_MAX_VISUAL_BYTES * 4 // 3 + 8):
            continue
        if not isinstance(expected_sha, str) or len(expected_sha) != 64:
            continue
        try:
            png = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not (32 <= len(png) <= _MAX_VISUAL_BYTES and png.startswith(_PNG_MAGIC)
                and png[12:16] == b'IHDR' and len(png) == artifact.get('size_bytes')):
            continue
        if hashlib.sha256(png).hexdigest() != expected_sha:
            continue
        if not any(isinstance(obs, dict) and obs.get('kind') == 'browser-render-verification'
                   and obs.get('browser_family') == 'firefox'
                   and obs.get('screenshot_sha256') == expected_sha
                   and obs.get('screenshot_retained') is True for obs in observations[:2000]):
            continue
        return png
    return None


@router.get('/{evidence_id}/visual', response_class=Response)
async def get_visual_evidence(evidence_id: str, user=Depends(get_current_user)):
    item = await _get_evidence(evidence_id, str(user.get('user_id')))
    if item is None:
        raise HTTPException(status_code=404, detail='Evidence not found')
    png = _visual_png_from_evidence(item)
    if png is None:
        raise HTTPException(status_code=404, detail='Verified visual evidence unavailable')
    return Response(
        content=png,
        media_type='image/png',
        headers={
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'; sandbox",
        },
    )
