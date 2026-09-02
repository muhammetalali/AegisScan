from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityNote
from ..core.dependencies import get_current_user
from ..services.remediation_lifecycle import RemediationState, get_state, verify_validation

router = APIRouter()


class VulnerabilityResponse(BaseModel):
    id: str
    scan_id: str
    project_id: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_target: Optional[str] = None
    source_engine: str = ''
    title: str
    description: str
    severity: str
    status: str
    confidence: str
    cvss_score: float
    risk_score: float
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: str
    assigned_to: Optional[str] = None
    created_at: str
    updated_at: str


class VulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    remediation: Optional[str] = None


@sync_to_async
def _serialize(vulnerability: Vulnerability) -> VulnerabilityResponse:
    config = (vulnerability.asset.configuration or {}) if vulnerability.asset else {}
    source_engine = (vulnerability.source_engine or '').strip().lower()
    asset_target = None
    if source_engine == 'nuclei':
        asset_target = config.get('url')
    else:
        asset_target = config.get('host') or config.get('ip') or config.get('domain') or vulnerability.url or None

    return VulnerabilityResponse(
        id=str(vulnerability.id),
        scan_id=str(vulnerability.scan_id),
        project_id=str(vulnerability.project_id),
        asset_id=str(vulnerability.asset_id) if vulnerability.asset_id else None,
        asset_name=vulnerability.asset.name if vulnerability.asset else None,
        asset_target=str(asset_target) if asset_target else None,
        source_engine=source_engine,
        title=vulnerability.title,
        description=vulnerability.description,
        severity=vulnerability.severity,
        status=vulnerability.status,
        confidence=vulnerability.confidence,
        cvss_score=vulnerability.cvss_score,
        risk_score=vulnerability.risk_score,
        file_path=vulnerability.file_path or None,
        line_start=vulnerability.line_start,
        line_end=vulnerability.line_end,
        code_snippet=vulnerability.code_snippet or None,
        remediation=vulnerability.remediation,
        assigned_to=str(vulnerability.assigned_to_id) if vulnerability.assigned_to_id else None,
        created_at=vulnerability.created_at.astimezone(timezone.utc).isoformat(),
        updated_at=vulnerability.updated_at.astimezone(timezone.utc).isoformat(),
    )


@sync_to_async
def _list_vulnerabilities(user_id: str, project_id: Optional[str], scan_id: Optional[str], severity: Optional[str], status: Optional[str], assigned_to: Optional[str], search: Optional[str], limit: int, offset: int):
    qs = Vulnerability.objects.filter(project__owner_id=user_id) | Vulnerability.objects.filter(project__members__id=user_id)
    qs = qs.select_related('scan', 'project', 'asset', 'assigned_to').distinct()
    if project_id:
        qs = qs.filter(project_id=project_id)
    if scan_id:
        qs = qs.filter(scan_id=scan_id)
    if severity:
        qs = qs.filter(severity=severity)
    if status:
        qs = qs.filter(status=status)
    if assigned_to:
        qs = qs.filter(assigned_to_id=assigned_to)
    if search:
        from django.db.models import Q
        qs = qs.filter(Q(title__icontains=search) | Q(description__icontains=search) | Q(url__icontains=search))
    return list(qs.order_by('-created_at')[offset:offset + limit])


@router.get('/', response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    project_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
):
    items = await _list_vulnerabilities(str(user.get('user_id')), project_id, scan_id, severity, status, assigned_to, search, limit, offset)
    return [await _serialize(item) for item in items]


@sync_to_async
def _get_vulnerability(vuln_id: UUID, user_id: str):
    return Vulnerability.objects.select_related('scan', 'project', 'asset', 'assigned_to').filter(id=vuln_id).filter(
        project__owner_id=user_id,
    ).first() or Vulnerability.objects.select_related('scan', 'project', 'asset', 'assigned_to').filter(id=vuln_id, project__members__id=user_id).first()


@router.get('/{vuln_id}', response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: UUID, user=Depends(get_current_user)):
    vulnerability = await _get_vulnerability(vuln_id, str(user.get('user_id')))
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    return await _serialize(vulnerability)


@sync_to_async
def _update_vulnerability(vuln_id: UUID, user_id: str, update: VulnerabilityUpdate):
    vulnerability = Vulnerability.objects.filter(id=vuln_id).filter(project__owner_id=user_id).first()
    if not vulnerability:
        vulnerability = Vulnerability.objects.filter(id=vuln_id, project__members__id=user_id).first()
    if not vulnerability:
        return None
    if update.status is not None:
        allowed = {choice.value for choice in Vulnerability.Status}
        if update.status not in allowed:
            raise ValueError(f'invalid vulnerability status: {update.status}')
        vulnerability.status = update.status
    if update.assigned_to is not None:
        from django.contrib.auth import get_user_model
        User = get_user_model()
        assignee = User.objects.filter(pk=update.assigned_to, is_active=True).first()
        if not assignee:
            raise ValueError('assigned_to user not found')
        vulnerability.assigned_to = assignee
        vulnerability.assigned_at = datetime.now(timezone.utc)
    if update.remediation is not None:
        vulnerability.remediation = update.remediation
    vulnerability.save(update_fields=['status', 'assigned_to', 'assigned_at', 'remediation', 'updated_at'])
    return vulnerability


@router.patch('/{vuln_id}', response_model=VulnerabilityResponse)
async def update_vulnerability(vuln_id: UUID, update: VulnerabilityUpdate, user=Depends(get_current_user)):
    try:
        vulnerability = await _update_vulnerability(vuln_id, str(user.get('user_id')), update)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    return await _serialize(vulnerability)


@sync_to_async
def _add_note(vuln_id: UUID, user_id: str, content: str, is_private: bool):
    vulnerability = Vulnerability.objects.filter(id=vuln_id).filter(project__owner_id=user_id).first()
    if not vulnerability:
        vulnerability = Vulnerability.objects.filter(id=vuln_id, project__members__id=user_id).first()
    if not vulnerability:
        return None
    return VulnerabilityNote.objects.create(vulnerability=vulnerability, author_id=user_id, content=content, is_private=is_private)


@router.post('/{vuln_id}/notes')
async def add_note(vuln_id: UUID, content: str, is_private: bool = False, user=Depends(get_current_user)):
    if not content.strip():
        raise HTTPException(status_code=400, detail='content is required')
    note = await _add_note(vuln_id, str(user.get('user_id')), content.strip(), is_private)
    if not note:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    return {'id': str(note.id), 'vulnerability_id': str(vuln_id), 'content': note.content, 'is_private': note.is_private, 'created_at': note.created_at.astimezone(timezone.utc).isoformat()}


@sync_to_async
def _get_evidences(vuln_id: UUID, user_id: str):
    vulnerability = Vulnerability.objects.filter(id=vuln_id).filter(project__owner_id=user_id).first()
    if not vulnerability:
        vulnerability = Vulnerability.objects.filter(id=vuln_id, project__members__id=user_id).first()
    if not vulnerability:
        return None, []
    return vulnerability, list(Evidence.objects.filter(finding=vulnerability).order_by('-collected_at'))


@router.get('/{vuln_id}/evidences')
async def get_evidences(vuln_id: UUID, user=Depends(get_current_user)):
    vulnerability, evidences = await _get_evidences(vuln_id, str(user.get('user_id')))
    if not vulnerability:
        raise HTTPException(status_code=404, detail='Vulnerability not found')
    return [
        {
            'id': str(e.id),
            'scan_id': str(e.scan_id) if e.scan_id else None,
            'asset_id': str(e.asset_id) if e.asset_id else None,
            'finding_id': str(e.finding_id) if e.finding_id else None,
            'source': e.source,
            'evidence_type': e.evidence_type,
            'sha256': e.sha256,
            'metadata': e.metadata,
            'collected_at': e.collected_at.astimezone(timezone.utc).isoformat(),
        }
        for e in evidences
    ]


@sync_to_async
def _verify_fix(vuln_id: UUID, user_id: str):
    vulnerability = Vulnerability.objects.filter(id=vuln_id, project__owner_id=user_id).first()
    if not vulnerability:
        vulnerability = Vulnerability.objects.filter(id=vuln_id, project__members__id=user_id).first()
    if not vulnerability:
        return None, None, 'Vulnerability not found'

    validation = ValidationRun.objects.filter(
        finding=vulnerability,
        user_id=user_id,
        status=ValidationRun.Status.COMPLETED,
        authorized=True,
    ).order_by('-completed_at').first()
    if not validation:
        return vulnerability, None, 'Fix verification requires a completed authorized finding-linked validation run.'

    result = validation.result if isinstance(validation.result, dict) else {}
    if result.get('finding_present') is not False:
        return vulnerability, validation, 'The latest authorized validation still detects the finding; fix cannot be verified.'

    evidence = Evidence.objects.filter(
        finding=vulnerability,
        evidence_type='validation_output',
        metadata__validation_id=str(validation.id),
    ).order_by('-collected_at').first()
    if not evidence:
        return vulnerability, validation, 'Completed validation has no linked validation evidence; verification is not trusted.'

    try:
        validation = verify_validation(validation.id)
    except ValueError as exc:
        return vulnerability, validation, str(exc)

    vulnerability.refresh_from_db()
    vulnerability.validation_status = 'verified'
    vulnerability.validated_at = validation.completed_at or datetime.now(timezone.utc)
    vulnerability.validated_by_id = user_id
    vulnerability.verified_evidence_count = vulnerability.evidence_records.filter(
        evidence_type='validation_output',
        metadata__finding_present=False,
    ).count()
    vulnerability.save(update_fields=['validation_status', 'validated_at', 'validated_by', 'verified_evidence_count', 'updated_at'])
    return vulnerability, validation, None


@router.post('/{vuln_id}/verify')
async def verify_fix(vuln_id: UUID, user=Depends(get_current_user)):
    vulnerability, validation, error = await _verify_fix(vuln_id, str(user.get('user_id')))
    if not vulnerability:
        raise HTTPException(status_code=404, detail=error or 'Vulnerability not found')
    if error:
        raise HTTPException(status_code=409, detail=error)
    return {
        'status': 'verified',
        'remediation_state': RemediationState.VERIFIED,
        'vulnerability_id': str(vulnerability.id),
        'validation_id': str(validation.id),
        'verified_evidence_count': vulnerability.verified_evidence_count,
        'validated_at': vulnerability.validated_at.astimezone(timezone.utc).isoformat() if vulnerability.validated_at else None,
    }


@sync_to_async
def _bulk_update(vuln_ids: List[str], user_id: str, update: VulnerabilityUpdate):
    allowed = {choice.value for choice in Vulnerability.Status}
    if update.status is not None and update.status not in allowed:
        raise ValueError(f'invalid vulnerability status: {update.status}')
    qs = Vulnerability.objects.filter(id__in=vuln_ids).filter(project__owner_id=user_id) | Vulnerability.objects.filter(id__in=vuln_ids, project__members__id=user_id)
    qs = qs.distinct()
    values = {}
    if update.status is not None:
        values['status'] = update.status
    if update.remediation is not None:
        values['remediation'] = update.remediation
    if values:
        values['updated_at'] = datetime.now(timezone.utc)
        return qs.update(**values)
    return 0


@router.post('/bulk-update')
async def bulk_update(vuln_ids: List[str], update: VulnerabilityUpdate, user=Depends(get_current_user)):
    try:
        updated = await _bulk_update(vuln_ids, str(user.get('user_id')), update)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {'updated': updated}
