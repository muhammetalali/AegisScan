from __future__ import annotations

from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from django_project.projects.models import Project
from fastapi_app.core.dependencies import get_current_user
from fastapi_app.services.threat_modeling import (
    build_threat_model,
    threat_model_snapshot,
    validate_attack_chain,
)

router = APIRouter()


def _uid(user: dict) -> str:
    value = user.get("user_id") or user.get("sub")
    if not value:
        raise HTTPException(status_code=401, detail="Invalid authenticated user")
    return str(value)


@sync_to_async
def _project_for_user(project_id: str, user_id: str) -> Project | None:
    return (
        Project.objects.filter(pk=project_id, owner_id=user_id).first()
        or Project.objects.filter(pk=project_id, members__id=user_id).first()
    )


@router.post("/projects/{project_id}/build")
async def build_project_threat_model(project_id: UUID, user=Depends(get_current_user)):
    uid = _uid(user)
    project = await _project_for_user(str(project_id), uid)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        return await sync_to_async(build_threat_model)(project=project, actor_id=uid)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}")
async def get_project_threat_model(project_id: UUID, user=Depends(get_current_user)):
    uid = _uid(user)
    project = await _project_for_user(str(project_id), uid)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return await sync_to_async(threat_model_snapshot)(project=project)


@router.post("/projects/{project_id}/attack-paths/{attack_path_id}/validate")
async def validate_project_attack_chain(
    project_id: UUID,
    attack_path_id: UUID,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(str(project_id), uid)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        return await sync_to_async(validate_attack_chain)(
            project=project,
            actor_id=uid,
            attack_path_id=str(attack_path_id),
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
