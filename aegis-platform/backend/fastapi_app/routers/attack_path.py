from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django

django.setup()

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..contracts import AttackPathEdge, AttackPathGraph, AttackPathNode, AttackPathPath
from ..core.dependencies import get_current_user
from ..services.enterprise_tenant import ensure_project_tenant
from assets.models import Asset, AssetRelationship
from enterprise.models import AttackPath
from projects.models import Project
from vulnerabilities.models import Vulnerability

router = APIRouter()


class AttackPathAnalysisRequest(BaseModel):
    source_asset_id: str
    target_asset_id: str
    max_hops: int = Field(default=8, ge=1, le=12)


class AttackPathAnalysisResponse(BaseModel):
    contract_version: str = "1.0"
    project_id: str
    source: str = "postgresql"
    generated_at: datetime
    source_asset_id: str
    target_asset_id: str
    paths: list[AttackPathPath]
    persisted_attack_path_ids: list[str] = []


def _project_access(project_id: str, user_id: str) -> bool:
    return Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).exists()


def _criticality_weight(value: Any) -> float:
    return {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5}.get(str(value or "medium").lower(), 2.0)


def _asset_exposure(configuration: dict[str, Any]) -> bool:
    for key in ("internet_exposed", "public", "externally_exposed", "internet_accessible"):
        value = configuration.get(key)
        if isinstance(value, bool) and value:
            return True
        if isinstance(value, str) and value.strip().lower() in {"true", "yes", "1"}:
            return True
    return False


def _load_graph(project_id: str, user_id: str) -> AttackPathGraph:
    if not _project_access(project_id, user_id):
        raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    assets = list(Asset.objects.filter(project_id=project_id).order_by("id"))
    asset_ids = {str(asset.id) for asset in assets}
    finding_weight: dict[str, float] = {}
    rows = Vulnerability.objects.filter(project_id=project_id).exclude(status=Vulnerability.Status.CLOSED).values("asset_id", "risk_score", "severity")
    for row in rows:
        asset_id = str(row["asset_id"])
        try:
            score = float(row["risk_score"]) if row["risk_score"] is not None else _criticality_weight(row["severity"])
        except (TypeError, ValueError):
            score = _criticality_weight(row["severity"])
        finding_weight[asset_id] = finding_weight.get(asset_id, 0.0) + max(0.0, score)

    nodes = [
        AttackPathNode(
            id=str(asset.id), name=asset.name, kind=str(asset.type), criticality=str(asset.criticality),
            open_finding_weight=round(finding_weight.get(str(asset.id), 0.0), 2),
            internet_exposed=_asset_exposure(asset.configuration or {}),
        )
        for asset in assets
    ]
    relationships = AssetRelationship.objects.filter(project_id=project_id, source_id__in=asset_ids, target_id__in=asset_ids).order_by("id")
    edges = [
        AttackPathEdge(source=str(r.source_id), target=str(r.target_id), relationship=str(r.relationship_type), metadata=r.metadata or {})
        for r in relationships
    ]
    return AttackPathGraph(project_id=project_id, generated_at=datetime.now(timezone.utc), nodes=nodes, edges=edges)


@sync_to_async
def _get_graph(project_id: str, user_id: str) -> AttackPathGraph:
    return _load_graph(project_id, user_id)


@sync_to_async
def _analyze(request: AttackPathAnalysisRequest, project_id: str, user_id: str) -> AttackPathAnalysisResponse:
    graph = _load_graph(project_id, user_id)
    node_map = {node.id: node for node in graph.nodes}
    if request.source_asset_id not in node_map or request.target_asset_id not in node_map:
        raise HTTPException(status_code=404, detail="Source or target asset not found in project")

    adjacency: dict[str, list[str]] = {node_id: [] for node_id in node_map}
    for edge in graph.edges:
        adjacency[edge.source].append(edge.target)
        adjacency[edge.target].append(edge.source)

    paths: list[AttackPathPath] = []
    stack: list[tuple[str, list[str]]] = [(request.source_asset_id, [request.source_asset_id])]
    while stack and len(paths) < 20:
        current, path = stack.pop()
        if current == request.target_asset_id:
            raw_score = sum(_criticality_weight(node_map[n].criticality) + node_map[n].open_finding_weight for n in path)
            paths.append(AttackPathPath(nodes=path, risk_score=round(min(100.0, raw_score * 3.0), 2), hops=max(0, len(path) - 1)))
            continue
        if len(path) - 1 >= request.max_hops:
            continue
        for neighbor in adjacency.get(current, []):
            if neighbor not in path:
                stack.append((neighbor, [*path, neighbor]))

    paths.sort(key=lambda item: (-item.risk_score, item.hops, item.nodes))
    persisted_ids: list[str] = []
    if paths:
        project = Project.objects.get(pk=project_id)
        organization = ensure_project_tenant(project, user_id)
        for path in paths:
            row = AttackPath.objects.create(
                organization=organization,
                project=project,
                source_node={"asset_id": request.source_asset_id, "name": node_map[request.source_asset_id].name},
                target_node={"asset_id": request.target_asset_id, "name": node_map[request.target_asset_id].name},
                steps=path.nodes,
                risk_score=path.risk_score,
                evidence={"source": "asset_relationships_and_open_vulnerabilities", "contract_version": "1.0"},
                status=AttackPath.Status.DISCOVERED,
            )
            persisted_ids.append(str(row.id))

    return AttackPathAnalysisResponse(project_id=project_id, generated_at=graph.generated_at, source_asset_id=request.source_asset_id, target_asset_id=request.target_asset_id, paths=paths, persisted_attack_path_ids=persisted_ids)


@router.get("/projects/{project_id}", response_model=AttackPathGraph)
async def get_attack_path_graph(project_id: str, user=Depends(get_current_user)):
    return await _get_graph(project_id, str(user.get("user_id")))


@router.post("/projects/{project_id}/analyze", response_model=AttackPathAnalysisResponse)
async def analyze_attack_paths(project_id: str, request: AttackPathAnalysisRequest, user=Depends(get_current_user)):
    return await _analyze(request, project_id, str(user.get("user_id")))
