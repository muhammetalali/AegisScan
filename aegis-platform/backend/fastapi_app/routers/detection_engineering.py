from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from enterprise.detection_models import DetectionRule
from enterprise.models import OrganizationMembership, TenantProject
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.services.detection_engineering import (
    DetectionEngineeringError,
    create_revision,
    publish_revision,
    validate_revision,
)

router = APIRouter()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class PredicateIn(StrictModel):
    field: str = Field(min_length=1, max_length=128)
    operator: Literal['equals', 'contains', 'in', 'exists']
    value: Any = None


class DetectionSpecIn(StrictModel):
    logsource: str = Field(min_length=1, max_length=120)
    condition: Literal['all', 'any'] = 'all'
    match: list[PredicateIn] = Field(min_length=1, max_length=64)
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = 'medium'
    attack_techniques: list[str] = Field(min_length=1, max_length=64)
    description: str = Field(default='', max_length=4000)


class DetectionRevisionCreate(StrictModel):
    slug: str = Field(pattern=r'^[a-z0-9]+(?:-[a-z0-9]+)*$', min_length=1, max_length=180)
    title: str = Field(min_length=3, max_length=240)
    description: str = Field(default='', max_length=4000)
    finding_id: UUID
    evidence_id: UUID | None = None
    spec: DetectionSpecIn


class DetectionValidationCreate(StrictModel):
    telemetry: list[dict[str, Any]] = Field(min_length=1, max_length=5000)
    minimum_matches: int = Field(default=1, ge=1, le=5000)


class DetectionPublicationCreate(StrictModel):
    integration_id: UUID


def _uid(user: dict) -> str:
    value = user.get('user_id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user')
    return str(value)


def _translate(exc: Exception) -> HTTPException:
    if isinstance(exc, PermissionError):
        return HTTPException(status_code=403, detail=str(exc))
    return HTTPException(status_code=409, detail=str(exc))


@router.post('/projects/{project_id}/rules', status_code=201)
async def create_detection_revision(project_id: UUID, body: DetectionRevisionCreate, user=Depends(get_current_user)):
    try:
        result = await sync_to_async(create_revision)(
            project_id=str(project_id), user_id=_uid(user), slug=body.slug, title=body.title,
            description=body.description, finding_id=str(body.finding_id),
            evidence_id=str(body.evidence_id) if body.evidence_id else None,
            spec=body.spec.model_dump(),
        )
    except (DetectionEngineeringError, PermissionError) as exc:
        raise _translate(exc) from exc
    revision = result.revision
    return {
        'rule_id': str(revision.rule_id), 'revision_id': str(revision.id), 'version': revision.version,
        'content_sha256': revision.content_sha256, 'compiled': revision.compiled,
        'attack_techniques': revision.attack_techniques, 'replayed': result.replayed,
    }


@router.post('/projects/{project_id}/revisions/{revision_id}/validate', status_code=201)
async def validate_detection_revision(project_id: UUID, revision_id: UUID, body: DetectionValidationCreate, user=Depends(get_current_user)):
    try:
        result = await sync_to_async(validate_revision)(
            revision_id=str(revision_id), project_id=str(project_id), user_id=_uid(user),
            telemetry=body.telemetry, minimum_matches=body.minimum_matches,
        )
    except (DetectionEngineeringError, PermissionError) as exc:
        raise _translate(exc) from exc
    item = result.validation
    return {
        'validation_id': str(item.id), 'status': item.status, 'telemetry_sha256': item.telemetry_sha256,
        'telemetry_count': item.telemetry_count, 'matched_count': item.matched_count,
        'minimum_matches': item.minimum_matches, 'result_sha256': item.result_sha256,
        'replayed': result.replayed,
    }


@router.post('/projects/{project_id}/revisions/{revision_id}/publish', status_code=201)
async def publish_detection_revision(project_id: UUID, revision_id: UUID, body: DetectionPublicationCreate, user=Depends(get_current_user)):
    try:
        result = await sync_to_async(publish_revision)(
            revision_id=str(revision_id), integration_id=str(body.integration_id),
            project_id=str(project_id), user_id=_uid(user),
        )
    except (DetectionEngineeringError, PermissionError) as exc:
        raise _translate(exc) from exc
    item = result.publication
    return {
        'publication_id': str(item.id), 'revision_id': str(item.revision_id),
        'integration_id': str(item.integration_id), 'provider': item.provider,
        'package_sha256': item.package_sha256, 'response_sha256': item.response_sha256,
        'transport_status': item.transport_status, 'replayed': result.replayed,
    }


@sync_to_async
def _list_rules(project_id: str, user_id: str, state: str | None, limit: int):
    link = TenantProject.objects.select_related('organization').filter(project_id=project_id).first()
    if link is None:
        raise DetectionEngineeringError('Project is not bound to an enterprise tenant.')
    permitted = OrganizationMembership.objects.filter(
        organization=link.organization,
        user_id=user_id,
        user__is_active=True,
        is_active=True,
        role__in=OrganizationMembership.Role.values,
    ).exists()
    if not permitted:
        raise PermissionError('Active tenant membership is required to read detection rules.')
    qs = DetectionRule.objects.filter(
        project_id=project_id,
        organization=link.organization,
    ).order_by('-updated_at')
    if state:
        qs = qs.filter(state=state)
    rows = list(qs[:limit])
    return [
        {
            'rule_id': str(row.id), 'slug': row.slug, 'title': row.title, 'description': row.description,
            'state': row.state, 'latest_version': row.revisions.aggregate(v=__import__('django.db.models', fromlist=['Max']).Max('version'))['v'] or 0,
            'updated_at': row.updated_at.isoformat(),
        }
        for row in rows
    ]


@router.get('/projects/{project_id}/rules')
async def list_detection_rules(project_id: UUID, state: str | None = None, limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    if state and state not in set(DetectionRule.State.values):
        raise HTTPException(status_code=422, detail='Unsupported detection rule state')
    try:
        return await _list_rules(str(project_id), _uid(user), state, limit)
    except (DetectionEngineeringError, PermissionError) as exc:
        raise _translate(exc) from exc
