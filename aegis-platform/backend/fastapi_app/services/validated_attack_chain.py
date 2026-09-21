from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import Any

from django.db import transaction
from django.db.models import Q

from assets.models import Asset, AssetAuthorization, AssetRelationship
from evidence.models import Evidence
from enterprise.models import (
    AttackPath,
    AttackPathValidation,
    BlastRadiusSnapshot,
    ThreatModelSnapshot,
)
from vulnerabilities.models import Vulnerability

from fastapi_app.services.authorization_guard import asset_target
from fastapi_app.services.threat_modeling import architecture_snapshot


class AttackPathValidationError(ValueError):
    pass


_INACTIVE_FINDING_STATES = {
    Vulnerability.Status.FIXED,
    Vulnerability.Status.FALSE_POSITIVE,
    Vulnerability.Status.ACCEPTED_RISK,
    Vulnerability.Status.WONT_FIX,
    Vulnerability.Status.DUPLICATE,
}
_CRITICALITY = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}


def _sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _path_node_id(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("asset_id") or value.get("id") or "").strip()
    return str(value or "").strip()


def _path_steps(path: AttackPath) -> list[str]:
    steps = [_path_node_id(value) for value in (path.steps or [])]
    steps = [value for value in steps if value]
    source = _path_node_id(path.source_node)
    target = _path_node_id(path.target_node)
    if not steps:
        steps = [source, target]
    if len(steps) < 2 or not source or not target:
        raise AttackPathValidationError("attack path does not contain a complete source/target lineage")
    if steps[0] != source or steps[-1] != target:
        raise AttackPathValidationError("attack path steps are not bound to the persisted source/target")
    if len(set(steps)) != len(steps):
        raise AttackPathValidationError("attack path contains a cycle and cannot be validated as a simple chain")
    return steps


def _current_authorization(asset: Asset) -> AssetAuthorization:
    decision = (
        AssetAuthorization.objects.filter(asset=asset)
        .order_by("-created_at", "-id")
        .first()
    )
    if decision is None or decision.authorized is not True or not decision.is_currently_valid:
        raise AttackPathValidationError(f"asset {asset.id} has no current governed authorization")
    current_target = asset_target(asset)
    if decision.target_snapshot != current_target:
        raise AttackPathValidationError(f"asset {asset.id} authorization target no longer matches the asset")
    return decision


def _validate_relationships(project_id: str, steps: list[str]) -> list[str]:
    relationship_refs: list[str] = []
    for source_id, target_id in zip(steps, steps[1:]):
        relationship = (
            AssetRelationship.objects.filter(project_id=project_id)
            .filter(
                Q(source_id=source_id, target_id=target_id)
                | Q(source_id=target_id, target_id=source_id)
            )
            .order_by("id")
            .first()
        )
        if relationship is None:
            raise AttackPathValidationError(
                f"attack path step {source_id} -> {target_id} has no persisted AssetRelationship"
            )
        relationship_refs.append(str(relationship.id))
    return relationship_refs


def _validate_evidence(
    *,
    project_id: str,
    steps: list[str],
    evidence_ids: list[str],
) -> list[dict[str, str]]:
    unique_ids = sorted({str(value).strip() for value in evidence_ids if str(value).strip()})
    if not unique_ids:
        raise AttackPathValidationError("validated attack path requires evidence")
    rows = list(
        Evidence.objects.filter(pk__in=unique_ids, asset__project_id=project_id)
        .select_related("asset", "finding")
        .order_by("id")
    )
    if len(rows) != len(unique_ids):
        raise AttackPathValidationError("attack path evidence crossed the project boundary or does not exist")
    step_set = set(steps)
    target_id = steps[-1]
    target_covered = False
    normalized: list[dict[str, str]] = []
    for evidence in rows:
        if not evidence.asset_id or str(evidence.asset_id) not in step_set:
            raise AttackPathValidationError("attack path evidence is not bound to a path asset")
        digest = hashlib.sha256((evidence.raw_output or "").encode("utf-8", errors="replace")).hexdigest()
        if evidence.sha256 != digest:
            raise AttackPathValidationError("attack path evidence integrity check failed")
        if str(evidence.asset_id) == target_id:
            target_covered = True
        if evidence.finding_id and str(evidence.finding.project_id) != str(project_id):
            raise AttackPathValidationError("attack path evidence finding crossed the project boundary")
        normalized.append({
            "id": str(evidence.id),
            "asset_id": str(evidence.asset_id),
            "finding_id": str(evidence.finding_id or ""),
            "sha256": evidence.sha256,
            "type": str(evidence.evidence_type),
        })
    if not target_covered:
        raise AttackPathValidationError("validated attack path requires evidence bound to the target asset")
    return normalized


def _impact_value(asset: Asset) -> float:
    baseline = _CRITICALITY.get(str(asset.criticality or "medium").lower(), 50.0)
    risks = list(
        Vulnerability.objects.filter(project=asset.project, asset=asset)
        .exclude(status__in=_INACTIVE_FINDING_STATES)
        .values_list("risk_score", flat=True)
    )
    normalized = []
    for value in risks:
        try:
            score = float(value or 0.0)
        except (TypeError, ValueError):
            continue
        normalized.append(min(100.0, max(0.0, score * 10.0 if score <= 10.0 else score)))
    return round(max([baseline, *normalized]), 2)


def _derive_blast_radius(
    *,
    project_id: str,
    root_asset_id: str,
    crown_jewel_asset_ids: list[str],
    max_depth: int,
) -> dict[str, Any]:
    if not 1 <= max_depth <= 8:
        raise AttackPathValidationError("blast radius max_depth must be between 1 and 8")
    assets = {
        str(asset.id): asset
        for asset in Asset.objects.filter(project_id=project_id, is_active=True).order_by("id")
    }
    if root_asset_id not in assets:
        raise AttackPathValidationError("blast radius root asset is outside the active project asset set")
    crowns = sorted({str(value).strip() for value in crown_jewel_asset_ids if str(value).strip()})
    if any(value not in assets for value in crowns):
        raise AttackPathValidationError("blast radius crown jewel crossed the project boundary")

    adjacency: dict[str, set[str]] = {asset_id: set() for asset_id in assets}
    for relation in AssetRelationship.objects.filter(project_id=project_id).values("source_id", "target_id"):
        source = str(relation["source_id"])
        target = str(relation["target_id"])
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)

    distances = {root_asset_id: 0}
    queue: deque[str] = deque([root_asset_id])
    while queue:
        current = queue.popleft()
        if distances[current] >= max_depth:
            continue
        for neighbor in sorted(adjacency.get(current, ())):
            if neighbor in distances:
                continue
            distances[neighbor] = distances[current] + 1
            queue.append(neighbor)

    if any(crown not in distances for crown in crowns):
        raise AttackPathValidationError("configured crown jewel is not reachable within the validated blast radius")

    impacted = []
    total = 0.0
    for asset_id, distance in sorted(distances.items(), key=lambda item: (item[1], item[0])):
        asset = assets[asset_id]
        risk = _impact_value(asset)
        multiplier = 1.35 if asset_id in crowns else 1.0
        total += (risk / max(1, distance)) * multiplier
        impacted.append({
            "id": asset_id,
            "label": asset.name,
            "type": asset.type,
            "criticality": asset.criticality,
            "risk": risk,
            "distance": distance,
            "crown_jewel": asset_id in crowns,
        })
    score = round(min(100.0, total / max(1, len(impacted))), 2)
    return {
        "root_ref": root_asset_id,
        "crown_jewel_refs": crowns,
        "impacted_nodes": impacted,
        "score": score,
    }


@transaction.atomic
def validate_attack_path(
    *,
    organization,
    project,
    attack_path_id: str,
    threat_model_snapshot_id: str,
    scenario_refs: list[str],
    evidence_ids: list[str],
    crown_jewel_asset_ids: list[str],
    max_depth: int,
    actor_id: str,
) -> tuple[AttackPathValidation, bool]:
    path = (
        AttackPath.objects.select_for_update()
        .filter(pk=attack_path_id, project=project, organization=organization)
        .first()
    )
    if path is None:
        raise AttackPathValidationError("attack path is outside the tenant/project scope")
    if path.status == AttackPath.Status.CLOSED:
        raise AttackPathValidationError("closed attack path cannot be validated")

    threat_model = (
        ThreatModelSnapshot.objects.filter(
            pk=threat_model_snapshot_id,
            project=project,
            organization=organization,
        )
        .first()
    )
    if threat_model is None:
        raise AttackPathValidationError("threat model snapshot is outside the tenant/project scope")
    current_architecture = architecture_snapshot(str(project.id))
    if current_architecture["sha256"] != threat_model.architecture_sha256:
        raise AttackPathValidationError("threat model architecture binding is stale")

    requested_scenarios = sorted({str(value).strip() for value in scenario_refs if str(value).strip()})
    if not requested_scenarios:
        raise AttackPathValidationError("validated attack path requires at least one threat scenario")
    model_scenarios = {str(item.get("ref")): item for item in (threat_model.scenarios or []) if isinstance(item, dict)}
    if any(value not in model_scenarios for value in requested_scenarios):
        raise AttackPathValidationError("attack path references a scenario outside the threat model snapshot")

    steps = _path_steps(path)
    assets = {
        str(asset.id): asset
        for asset in Asset.objects.filter(project=project, id__in=steps, is_active=True)
    }
    if set(assets) != set(steps):
        raise AttackPathValidationError("attack path references inactive or foreign assets")
    authorization_refs = []
    for asset_id in steps:
        authorization_refs.append(str(_current_authorization(assets[asset_id]).id))
    relationship_refs = _validate_relationships(str(project.id), steps)
    evidence = _validate_evidence(project_id=str(project.id), steps=steps, evidence_ids=evidence_ids)

    root_asset_id = steps[-1]
    blast = _derive_blast_radius(
        project_id=str(project.id),
        root_asset_id=root_asset_id,
        crown_jewel_asset_ids=crown_jewel_asset_ids,
        max_depth=max_depth,
    )
    material = {
        "contract_version": "aegis.validated-attack-chain.v1",
        "project_id": str(project.id),
        "organization_id": str(organization.id),
        "attack_path_id": str(path.id),
        "source_node": path.source_node,
        "target_node": path.target_node,
        "steps": steps,
        "path_risk_score": float(path.risk_score or 0.0),
        "threat_model_id": str(threat_model.id),
        "threat_model_sha256": threat_model.model_sha256,
        "architecture_sha256": threat_model.architecture_sha256,
        "scenario_refs": requested_scenarios,
        "scenario_sha256": [model_scenarios[value].get("scenario_sha256") for value in requested_scenarios],
        "authorization_refs": authorization_refs,
        "relationship_refs": relationship_refs,
        "evidence": evidence,
        "blast_radius": blast,
    }
    validation_sha256 = _sha(material)
    existing = AttackPathValidation.objects.filter(validation_sha256=validation_sha256).first()
    if existing is not None:
        if existing.project_id != project.id or existing.organization_id != organization.id:
            raise AttackPathValidationError("attack path validation digest collision crossed a tenant boundary")
        return existing, False

    evidence_refs = [item["id"] for item in evidence]
    blast_snapshot = BlastRadiusSnapshot.objects.create(
        organization=organization,
        project=project,
        attack_path=path,
        root_ref=blast["root_ref"],
        crown_jewel_refs=blast["crown_jewel_refs"],
        impacted_nodes=blast["impacted_nodes"],
        score=blast["score"],
        evidence_refs=evidence_refs,
    )
    validation = AttackPathValidation.objects.create(
        organization=organization,
        project=project,
        attack_path=path,
        threat_model_snapshot=threat_model,
        blast_radius_snapshot=blast_snapshot,
        scenario_refs=requested_scenarios,
        evidence_refs=evidence_refs,
        authorization_refs=authorization_refs,
        relationship_refs=relationship_refs,
        validation_sha256=validation_sha256,
        validated_by_id=actor_id,
    )
    if path.status != AttackPath.Status.VALIDATED:
        path.status = AttackPath.Status.VALIDATED
        path.save(update_fields=["status", "updated_at"])
    return validation, True


def serialize_attack_path_validation(row: AttackPathValidation) -> dict[str, Any]:
    blast = row.blast_radius_snapshot
    return {
        "id": str(row.id),
        "project_id": str(row.project_id),
        "attack_path_id": str(row.attack_path_id),
        "threat_model_snapshot_id": str(row.threat_model_snapshot_id),
        "blast_radius_snapshot_id": str(row.blast_radius_snapshot_id),
        "scenario_refs": row.scenario_refs,
        "evidence_refs": row.evidence_refs,
        "authorization_refs": row.authorization_refs,
        "relationship_refs": row.relationship_refs,
        "validation_sha256": row.validation_sha256,
        "blast_radius": {
            "root_ref": blast.root_ref,
            "crown_jewel_refs": blast.crown_jewel_refs,
            "impacted_nodes": blast.impacted_nodes,
            "score": blast.score,
        },
        "validated_by": str(row.validated_by_id),
        "created_at": row.created_at.isoformat(),
    }
