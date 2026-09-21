from __future__ import annotations

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from enterprise.models import AttackPathValidation
from enterprise.services import ensure_project_tenant
from django_project.projects.models import Project

from ..core.dependencies import get_current_user
from ..services.validated_attack_chain import (
    AttackPathValidationError,
    serialize_attack_path_validation,
    validate_attack_path,
)

router = APIRouter()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttackPathValidationIn(StrictModel):
    threat_model_snapshot_id: str = Field(min_length=1, max_length=64)
    scenario_refs: list[str] = Field(min_length=1, max_length=128)
    evidence_ids: list[str] = Field(min_length=1, max_length=512)
    crown_jewel_asset_ids: list[str] = Field(default_factory=list, max_length=512)
    max_depth: int = Field(default=4, ge=1, le=8)


@sync_to_async
def _validate(project_id: str, attack_path_id: str, user_id: str, body: AttackPathValidationIn):
    project = (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )
    if project is None:
        raise AttackPathValidationError("project not found or inaccessible")
    try:
        organization = ensure_project_tenant(project, user_id)
    except PermissionError as exc:
        raise AttackPathValidationError("project tenant membership is not authorized") from exc
    row, created = validate_attack_path(
        organization=organization,
        project=project,
        attack_path_id=attack_path_id,
        threat_model_snapshot_id=body.threat_model_snapshot_id,
        scenario_refs=body.scenario_refs,
        evidence_ids=body.evidence_ids,
        crown_jewel_asset_ids=body.crown_jewel_asset_ids,
        max_depth=body.max_depth,
        actor_id=user_id,
    )
    result = serialize_attack_path_validation(row)
    result["created"] = created
    return result


@sync_to_async
def _list(project_id: str, attack_path_id: str, user_id: str, limit: int):
    project = (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )
    if project is None:
        raise AttackPathValidationError("project not found or inaccessible")
    try:
        ensure_project_tenant(project, user_id)
    except PermissionError as exc:
        raise AttackPathValidationError("project tenant membership is not authorized") from exc
    rows = (
        AttackPathValidation.objects.filter(project_id=project_id, attack_path_id=attack_path_id)
        .select_related("blast_radius_snapshot", "threat_model_snapshot", "validated_by")
        .order_by("-created_at", "-id")[:limit]
    )
    return [serialize_attack_path_validation(row) for row in rows]


@router.post("/projects/{project_id}/{attack_path_id}/validate", status_code=201)
async def validate_path(
    project_id: str,
    attack_path_id: str,
    body: AttackPathValidationIn,
    user=Depends(get_current_user),
):
    try:
        return await _validate(project_id, attack_path_id, str(user.get("user_id")), body)
    except AttackPathValidationError as exc:
        detail = str(exc)
        status = 404 if detail == "project not found or inaccessible" else 422
        raise HTTPException(status_code=status, detail=detail) from exc


@router.get("/projects/{project_id}/{attack_path_id}/validations")
async def list_validations(
    project_id: str,
    attack_path_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(get_current_user),
):
    try:
        return await _list(project_id, attack_path_id, str(user.get("user_id")), limit)
    except AttackPathValidationError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
