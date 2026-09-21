from __future__ import annotations

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from enterprise.models import ThreatModelSnapshot
from enterprise.services import ensure_project_tenant
from projects.models import Project

from ..core.dependencies import get_current_user
from ..services.threat_modeling import (
    METHODOLOGIES,
    ThreatModelError,
    create_threat_model_snapshot,
    serialize_threat_model,
)

router = APIRouter()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ThreatScenarioIn(StrictModel):
    ref: str = Field(min_length=1, max_length=160)
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=4000)
    source_ref: str = Field(min_length=1, max_length=500)
    target_ref: str = Field(min_length=1, max_length=500)
    severity: str = Field(min_length=1, max_length=32)
    pasta_stage: int = Field(ge=1, le=7)
    stride: list[str] = Field(default_factory=list, max_length=16)
    linddun: list[str] = Field(default_factory=list, max_length=16)
    capec_ids: list[str] = Field(default_factory=list, max_length=128)
    assumptions: list[str] = Field(default_factory=list, max_length=128)
    preconditions: list[str] = Field(default_factory=list, max_length=128)
    impacts: list[str] = Field(default_factory=list, max_length=128)
    control_refs: list[str] = Field(default_factory=list, max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=128)


class ThreatModelCreateIn(StrictModel):
    title: str = Field(min_length=1, max_length=240)
    methodologies: list[str] = Field(min_length=1, max_length=4)
    pasta_stage: int = Field(ge=1, le=7)
    scope: dict = Field(default_factory=dict)
    scenarios: list[ThreatScenarioIn] = Field(min_length=1, max_length=1000)


class ThreatModelView(StrictModel):
    id: str
    project_id: str
    organization_id: str
    title: str
    methodologies: list[str]
    pasta_stage: int
    scope: dict
    scenarios: list[dict]
    architecture_sha256: str
    model_sha256: str
    created_by: str
    created_at: str


@sync_to_async
def _project_for_user(project_id: str, user_id: str) -> Project | None:
    return (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )


@sync_to_async
def _create(project_id: str, user_id: str, payload: ThreatModelCreateIn) -> dict:
    project = (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )
    if not project:
        raise ThreatModelError("project not found or inaccessible")
    try:
        organization = ensure_project_tenant(project, user_id)
    except PermissionError as exc:
        raise ThreatModelError("project tenant membership is not authorized") from exc
    snapshot, created = create_threat_model_snapshot(
        organization=organization,
        project=project,
        actor_id=user_id,
        title=payload.title,
        methodologies=payload.methodologies,
        pasta_stage=payload.pasta_stage,
        scope=payload.scope,
        scenarios=[scenario.model_dump(mode="json") for scenario in payload.scenarios],
    )
    result = serialize_threat_model(snapshot)
    result["created"] = created
    return result


@sync_to_async
def _list(project_id: str, user_id: str, limit: int) -> list[dict]:
    accessible = (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .exists()
    )
    if not accessible:
        raise ThreatModelError("project not found or inaccessible")
    return [
        serialize_threat_model(row)
        for row in ThreatModelSnapshot.objects.filter(project_id=project_id)
        .select_related("organization", "project", "created_by")
        .order_by("-created_at", "-id")[:limit]
    ]


@sync_to_async
def _get(project_id: str, snapshot_id: str, user_id: str) -> dict | None:
    accessible = (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .exists()
    )
    if not accessible:
        return None
    row = (
        ThreatModelSnapshot.objects.filter(project_id=project_id, pk=snapshot_id)
        .select_related("organization", "project", "created_by")
        .first()
    )
    return serialize_threat_model(row) if row else None


@router.get("/contract")
async def threat_modeling_contract():
    return {
        "contract_version": "aegis.threat-model.v1",
        "snapshot_semantics": "immutable",
        "methodologies": sorted(METHODOLOGIES),
        "pasta_stages": list(range(1, 8)),
        "architecture_binding": "security-graph-sha256",
        "evidence_projection": "evidence-graph-threat-nodes",
    }


@router.post("/projects/{project_id}/snapshots", status_code=201)
async def create_threat_model(
    project_id: str,
    payload: ThreatModelCreateIn,
    user=Depends(get_current_user),
):
    try:
        return await _create(project_id, str(user.get("user_id")), payload)
    except ThreatModelError as exc:
        detail = str(exc)
        status = 404 if detail == "project not found or inaccessible" else 422
        raise HTTPException(status_code=status, detail=detail) from exc


@router.get("/projects/{project_id}/snapshots", response_model=list[ThreatModelView])
async def list_threat_models(
    project_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(get_current_user),
):
    try:
        return await _list(project_id, str(user.get("user_id")), limit)
    except ThreatModelError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/projects/{project_id}/snapshots/{snapshot_id}", response_model=ThreatModelView)
async def get_threat_model(
    project_id: str,
    snapshot_id: str,
    user=Depends(get_current_user),
):
    result = await _get(project_id, snapshot_id, str(user.get("user_id")))
    if not result:
        raise HTTPException(status_code=404, detail="Threat model snapshot not found or inaccessible")
    return result
