from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from django_project.assets.models import Asset, AssetRelationship
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.vulnerabilities.models import Vulnerability
from enterprise.models import AttackPath, BlastRadiusSnapshot, EvidenceGraphEdge, EvidenceGraphNode
from enterprise.services import ensure_project_tenant
from fastapi_app.services.enterprise_gap_closure import persist_blast_radius, persist_evidence_graph


MODEL_VERSION = "threat-model.v1"
ATTACK_CHAIN_VALIDATION_VERSION = "attack-chain-validation.v1"

_INACTIVE_STATUSES = {
    Vulnerability.Status.FIXED,
    Vulnerability.Status.FALSE_POSITIVE,
    Vulnerability.Status.ACCEPTED_RISK,
    Vulnerability.Status.WONT_FIX,
    Vulnerability.Status.DUPLICATE,
}

_STRIDE_RULES: dict[str, tuple[str, ...]] = {
    "spoofing": (
        r"\bauthentication\b", r"\bauthn\b", r"\bidentity\b", r"\bsession\b",
        r"\bjwt\b", r"\boauth\b", r"\bsaml\b", r"\bcredential\b", r"\bpassword\b",
        r"\baccount takeover\b", r"\bspoof",
        r"\bcwe[-_: ]?(287|306|521|522|798)\b",
    ),
    "tampering": (
        r"\binjection\b", r"\bxss\b", r"\bcross[- ]site scripting\b",
        r"\bcommand injection\b", r"\bsql injection\b", r"\bdeseriali[sz]ation\b",
        r"\btemplate injection\b", r"\bfile upload\b",
        r"\bcwe[-_: ]?(20|74|79|89|94|434|502)\b",
    ),
    "repudiation": (
        r"\brepudiation\b", r"\baudit\b", r"\blogging\b", r"\btraceability\b",
        r"\bcwe[-_: ]?(778|779)\b",
    ),
    "information_disclosure": (
        r"\binformation disclosure\b", r"\bdata exposure\b", r"\bsensitive\b",
        r"\bsecret\b", r"\bleak\b", r"\bssrf\b", r"\bpath traversal\b",
        r"\bcwe[-_: ]?(22|200|209|532|918)\b",
    ),
    "denial_of_service": (
        r"\bdenial of service\b", r"\bdos\b", r"\bresource exhaustion\b",
        r"\brate limit", r"\bcwe[-_: ]?(400|770)\b",
    ),
    "elevation_of_privilege": (
        r"\bprivilege\b", r"\bauthori[sz]ation\b", r"\baccess control\b",
        r"\bidor\b", r"\bvertical escalation\b", r"\bhorizontal escalation\b",
        r"\bcwe[-_: ]?(269|284|285|639)\b",
    ),
}

_LINDDUN_RULES: dict[str, tuple[str, ...]] = {
    "linking": (r"\blinkability\b", r"\btracking\b", r"\bcorrelation\b"),
    "identifying": (
        r"\bpii\b", r"\bpersonal data\b", r"\bidentity\b", r"\buser enumeration\b",
        r"\bemail\b", r"\bphone\b",
    ),
    "non_repudiation": (r"\bnon[- ]?repudiation\b", r"\bimmutable audit\b"),
    "detecting": (r"\bpresence\b", r"\blocation\b", r"\benumeration\b", r"\bstatus inference\b"),
    "data_disclosure": (
        r"\bprivacy\b", r"\bdata disclosure\b", r"\bdata exposure\b", r"\bsensitive\b",
        r"\bleak\b",
    ),
    "unawareness": (r"\bconsent\b", r"\bprivacy notice\b", r"\bunawareness\b"),
    "non_compliance": (
        r"\bgdpr\b", r"\bccpa\b", r"\bhipaa\b", r"\bretention\b",
        r"\bpurpose limitation\b", r"\bprivacy policy\b",
    ),
}

_CAPEC_RE = re.compile(r"\bCAPEC[-_:\s]*(\d{1,4})\b", re.IGNORECASE)


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _criticality_weight(value: str) -> float:
    return {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
    }.get(str(value or "medium").lower(), 50.0)


def _finding_text(finding: Vulnerability) -> str:
    parts: list[str] = [
        finding.title or "",
        finding.description or "",
        finding.category or "",
        finding.cwe_id or "",
        finding.owasp_category or "",
        " ".join(str(value) for value in (finding.tags or [])),
        json.dumps(finding.raw_data or {}, sort_keys=True, default=str),
        " ".join(str(value) for value in (finding.references or [])),
    ]
    return " ".join(parts).lower()


def _matches(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _framework_observations(finding: Vulnerability, evidence_refs: list[str]) -> list[dict[str, Any]]:
    text = _finding_text(finding)
    confidence = 0.95 if finding.status == Vulnerability.Status.CONFIRMED else 0.8
    if evidence_refs:
        confidence = min(1.0, confidence + 0.03)

    observations: list[dict[str, Any]] = []
    for category, patterns in _STRIDE_RULES.items():
        if _matches(text, patterns):
            observations.append({
                "framework": "STRIDE",
                "category": category,
                "finding_id": str(finding.id),
                "asset_id": str(finding.asset_id) if finding.asset_id else "",
                "confidence": round(confidence, 2),
                "evidence_refs": sorted(set(evidence_refs)),
            })

    for category, patterns in _LINDDUN_RULES.items():
        if _matches(text, patterns):
            observations.append({
                "framework": "LINDDUN",
                "category": category,
                "finding_id": str(finding.id),
                "asset_id": str(finding.asset_id) if finding.asset_id else "",
                "confidence": round(confidence, 2),
                "evidence_refs": sorted(set(evidence_refs)),
            })

    capec_ids = sorted({f"CAPEC-{match}" for match in _CAPEC_RE.findall(text)})
    for capec_id in capec_ids:
        observations.append({
            "framework": "CAPEC",
            "category": capec_id,
            "finding_id": str(finding.id),
            "asset_id": str(finding.asset_id) if finding.asset_id else "",
            "confidence": round(confidence, 2),
            "evidence_refs": sorted(set(evidence_refs)),
            "claim": "observed-reference-only",
        })
    return observations


def _project_graph_payload(project: Project) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[Vulnerability]]:
    assets = list(Asset.objects.filter(project=project, is_active=True).order_by("id"))
    findings = list(
        Vulnerability.objects.filter(project=project, asset__isnull=False)
        .exclude(status__in=_INACTIVE_STATUSES)
        .select_related("asset")
        .order_by("id")
    )
    evidence_by_finding: dict[str, list[Evidence]] = {}
    finding_ids = [finding.id for finding in findings]
    for row in Evidence.objects.filter(finding_id__in=finding_ids).order_by("id"):
        evidence_by_finding.setdefault(str(row.finding_id), []).append(row)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    for asset in assets:
        nodes.append({
            "kind": "asset",
            "external_ref": f"asset:{asset.id}",
            "label": asset.name,
            "confidence": 1.0,
            "properties": {
                "asset_id": str(asset.id),
                "type": asset.type,
                "criticality": asset.criticality,
                "environment": asset.environment,
                "internet_exposed": bool((asset.configuration or {}).get("internet_exposed")),
                "crown_jewel": bool((asset.configuration or {}).get("crown_jewel")) or asset.criticality == Asset.Criticality.CRITICAL,
            },
        })

    for relationship in AssetRelationship.objects.filter(project=project).select_related("source", "target").order_by("id"):
        edges.append({
            "source": f"asset:{relationship.source_id}",
            "target": f"asset:{relationship.target_id}",
            "edge_type": f"asset_{relationship.relationship_type}",
            "weight": 1.0,
            "evidence_refs": [],
            "properties": {
                "relationship_id": str(relationship.id),
                "relationship_type": relationship.relationship_type,
                "metadata": relationship.metadata or {},
            },
        })

    for finding in findings:
        evidence_rows = evidence_by_finding.get(str(finding.id), [])
        evidence_refs = [row.sha256 for row in evidence_rows if row.sha256]
        nodes.append({
            "kind": "finding",
            "external_ref": f"finding:{finding.id}",
            "label": finding.title,
            "confidence": 0.95 if finding.status == Vulnerability.Status.CONFIRMED else 0.8,
            "properties": {
                "finding_id": str(finding.id),
                "asset_id": str(finding.asset_id or ""),
                "severity": finding.severity,
                "status": finding.status,
                "cwe_id": finding.cwe_id,
                "risk_score": float(finding.risk_score or 0),
                "evidence_count": len(evidence_rows),
            },
        })
        if finding.asset_id:
            edges.append({
                "source": f"finding:{finding.id}",
                "target": f"asset:{finding.asset_id}",
                "edge_type": "affects",
                "weight": max(0.1, min(1.0, float(finding.risk_score or 0) / 10.0 or 0.5)),
                "evidence_refs": evidence_refs,
                "properties": {"finding_status": finding.status},
            })
        for evidence in evidence_rows:
            nodes.append({
                "kind": "evidence",
                "external_ref": f"evidence:{evidence.id}",
                "label": f"{evidence.source}:{evidence.evidence_type}",
                "confidence": 1.0,
                "properties": {
                    "evidence_id": str(evidence.id),
                    "sha256": evidence.sha256,
                    "source": evidence.source,
                    "evidence_type": evidence.evidence_type,
                },
            })
            edges.append({
                "source": f"evidence:{evidence.id}",
                "target": f"finding:{finding.id}",
                "edge_type": "supports",
                "weight": 1.0,
                "evidence_refs": [evidence.sha256],
                "properties": {},
            })

        observations.extend(_framework_observations(finding, evidence_refs))

    for observation in observations:
        digest = _canonical_digest({
            "framework": observation["framework"],
            "category": observation["category"],
            "finding_id": observation["finding_id"],
            "asset_id": observation["asset_id"],
        })
        threat_ref = f"threat:{observation['framework'].lower()}:{digest[:32]}"
        observation["threat_ref"] = threat_ref
        nodes.append({
            "kind": "threat",
            "external_ref": threat_ref,
            "label": f"{observation['framework']}:{observation['category']}",
            "confidence": observation["confidence"],
            "properties": {
                "framework": observation["framework"],
                "category": observation["category"],
                "model_version": MODEL_VERSION,
                "finding_id": observation["finding_id"],
                "asset_id": observation["asset_id"],
                "claim": observation.get("claim", "evidence-derived-classification"),
            },
        })
        edges.append({
            "source": threat_ref,
            "target": f"finding:{observation['finding_id']}",
            "edge_type": "derived_from",
            "weight": observation["confidence"],
            "evidence_refs": observation["evidence_refs"],
            "properties": {"framework": observation["framework"]},
        })
        if observation["asset_id"]:
            edges.append({
                "source": threat_ref,
                "target": f"asset:{observation['asset_id']}",
                "edge_type": "threatens",
                "weight": observation["confidence"],
                "evidence_refs": observation["evidence_refs"],
                "properties": {"framework": observation["framework"]},
            })

    return nodes, edges, observations, findings


def _pasta_summary(project: Project, observations: list[dict[str, Any]], findings: list[Vulnerability]) -> dict[str, Any]:
    relationships = AssetRelationship.objects.filter(project=project).count()
    attack_paths = AttackPath.objects.filter(project=project)
    blast_count = BlastRadiusSnapshot.objects.filter(project=project).count()
    stages = [
        {
            "stage": 1,
            "name": "Define Objectives",
            "status": "evidence_present",
            "evidence_count": 1,
            "evidence": {"project_id": str(project.id), "project_name": project.name, "environment": project.environment},
        },
        {
            "stage": 2,
            "name": "Define Technical Scope",
            "status": "evidence_present" if project.assets.filter(is_active=True).exists() else "not_observed",
            "evidence_count": project.assets.filter(is_active=True).count(),
        },
        {
            "stage": 3,
            "name": "Application Decomposition",
            "status": "evidence_present" if relationships else "not_observed",
            "evidence_count": relationships,
        },
        {
            "stage": 4,
            "name": "Threat Analysis",
            "status": "evidence_present" if observations else "not_observed",
            "evidence_count": len(observations),
        },
        {
            "stage": 5,
            "name": "Vulnerability Analysis",
            "status": "evidence_present" if findings else "not_observed",
            "evidence_count": len(findings),
        },
        {
            "stage": 6,
            "name": "Attack Modeling",
            "status": "evidence_present" if attack_paths.exists() else "not_observed",
            "evidence_count": attack_paths.count(),
            "validated_paths": attack_paths.filter(status=AttackPath.Status.VALIDATED).count(),
        },
        {
            "stage": 7,
            "name": "Risk and Impact Analysis",
            "status": "evidence_present" if blast_count else "not_observed",
            "evidence_count": blast_count,
        },
    ]
    return {
        "framework": "PASTA",
        "stages": stages,
        "completion_claim_allowed": all(stage["status"] == "evidence_present" for stage in stages),
    }


@transaction.atomic
def build_threat_model(*, project: Project, actor_id: str) -> dict[str, Any]:
    ensure_project_tenant(project, actor_id)
    nodes, edges, observations, findings = _project_graph_payload(project)
    graph_result = persist_evidence_graph(project=project, nodes=nodes, edges=edges)
    by_framework: dict[str, list[dict[str, Any]]] = {"STRIDE": [], "LINDDUN": [], "CAPEC": []}
    for observation in observations:
        by_framework.setdefault(observation["framework"], []).append(observation)

    result = {
        "schema": "aegis.threat-model.v1",
        "model_version": MODEL_VERSION,
        "project_id": str(project.id),
        "generated_at": timezone.now().isoformat(),
        "frameworks": {
            "STRIDE": {"observations": by_framework.get("STRIDE", [])},
            "LINDDUN": {"observations": by_framework.get("LINDDUN", [])},
            "CAPEC": {
                "observations": by_framework.get("CAPEC", []),
                "claim": "CAPEC identifiers are preserved only when observed in finding metadata; no CWE-to-CAPEC mapping is fabricated.",
            },
            "PASTA": _pasta_summary(project, observations, findings),
        },
        "evidence_graph": graph_result,
        "source_counts": {
            "assets": project.assets.filter(is_active=True).count(),
            "relationships": project.asset_relationships.count(),
            "active_findings": len(findings),
            "evidence": Evidence.objects.filter(finding__project=project).count(),
        },
    }
    result["model_sha256"] = _canonical_digest(result)
    return result


def _step_asset_id(step: Any) -> str:
    if isinstance(step, dict):
        return str(step.get("node") or step.get("asset_id") or "")
    return str(step)


def _confirmed_finding_support(project: Project, asset_id: str) -> tuple[list[str], list[str]]:
    finding_qs = (
        Vulnerability.objects.filter(project=project, asset_id=asset_id)
        .exclude(status__in=_INACTIVE_STATUSES)
        .filter(
            Q(status=Vulnerability.Status.CONFIRMED)
            | Q(confirmation_records__verdict="confirmed", confirmation_records__finding_present=True)
        )
        .distinct()
        .order_by("id")
    )
    finding_ids = [str(value) for value in finding_qs.values_list("id", flat=True)]
    if not finding_ids:
        return [], []
    evidence_refs = sorted(
        {
            value
            for value in Evidence.objects.filter(finding_id__in=finding_ids).values_list("sha256", flat=True)
            if value
        }
    )
    return finding_ids, evidence_refs


def _relationship_between(project: Project, source_id: str, target_id: str) -> AssetRelationship | None:
    return (
        AssetRelationship.objects.filter(project=project, source_id=source_id, target_id=target_id).order_by("id").first()
        or AssetRelationship.objects.filter(project=project, source_id=target_id, target_id=source_id).order_by("id").first()
    )


def _derive_blast_radius(*, project: Project, attack_path: AttackPath, path_assets: list[Asset], evidence_refs: list[str]) -> BlastRadiusSnapshot:
    root = path_assets[0]
    all_assets = {str(asset.id): asset for asset in Asset.objects.filter(project=project, is_active=True)}
    adjacency: dict[str, set[str]] = {asset_id: set() for asset_id in all_assets}
    for relationship in AssetRelationship.objects.filter(project=project).values("source_id", "target_id"):
        source = str(relationship["source_id"])
        target = str(relationship["target_id"])
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)

    path_ids = {str(asset.id) for asset in path_assets}
    queue: deque[tuple[str, int]] = deque([(str(root.id), 0)])
    seen = {str(root.id)}
    impacted: list[dict[str, Any]] = []
    all_evidence = set(evidence_refs)

    while queue:
        asset_id, distance = queue.popleft()
        asset = all_assets[asset_id]
        finding_ids, node_evidence = _confirmed_finding_support(project, asset_id)
        if asset_id in path_ids or finding_ids or distance == 0:
            risk = _criticality_weight(asset.criticality)
            if finding_ids:
                risks = list(Vulnerability.objects.filter(pk__in=finding_ids).values_list("risk_score", flat=True))
                risk = min(100.0, risk * 0.55 + min(100.0, sum(float(v or 0) for v in risks) * 5.0) * 0.45)
            impacted.append({
                "id": asset_id,
                "label": asset.name,
                "distance": distance,
                "risk": round(risk, 2),
                "criticality": asset.criticality,
                "confirmed_finding_ids": finding_ids,
                "evidence_refs": node_evidence,
            })
            all_evidence.update(node_evidence)

        if distance >= 6:
            continue
        for neighbor in sorted(adjacency.get(asset_id, set())):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, distance + 1))

    crown_jewels = sorted(
        asset_id
        for asset_id, asset in all_assets.items()
        if asset.criticality == Asset.Criticality.CRITICAL or bool((asset.configuration or {}).get("crown_jewel"))
    )
    return persist_blast_radius(
        project=project,
        root_ref=str(root.id),
        impacted_nodes=impacted,
        crown_jewel_refs=crown_jewels,
        evidence_refs=sorted(all_evidence),
        attack_path_id=str(attack_path.id),
    )


@transaction.atomic
def validate_attack_chain(*, project: Project, actor_id: str, attack_path_id: str) -> dict[str, Any]:
    ensure_project_tenant(project, actor_id)
    attack_path = AttackPath.objects.select_for_update().filter(project=project, pk=attack_path_id).first()
    if attack_path is None:
        raise ValueError("attack path does not exist in this project")

    step_ids = [_step_asset_id(step) for step in (attack_path.steps or [])]
    if any(not step for step in step_ids) or len(step_ids) < 2:
        raise ValueError("attack path requires at least two concrete asset steps")
    if len(set(step_ids)) != len(step_ids):
        raise ValueError("attack path contains a cycle or duplicate asset step")

    assets = {str(asset.id): asset for asset in Asset.objects.filter(project=project, pk__in=step_ids)}
    if len(assets) != len(step_ids):
        raise ValueError("attack path references an asset outside the project")

    hop_evidence: list[dict[str, Any]] = []
    all_evidence: set[str] = set()
    for index in range(len(step_ids) - 1):
        source_id = step_ids[index]
        target_id = step_ids[index + 1]
        relationship = _relationship_between(project, source_id, target_id)
        if relationship is None:
            raise ValueError(f"attack path hop {source_id}->{target_id} lacks an authoritative asset relationship")
        finding_ids, evidence_refs = _confirmed_finding_support(project, target_id)
        if not finding_ids or not evidence_refs:
            raise ValueError(f"attack path hop {source_id}->{target_id} lacks confirmed finding evidence on target asset")
        all_evidence.update(evidence_refs)
        hop_evidence.append({
            "source_asset_id": source_id,
            "target_asset_id": target_id,
            "relationship_id": str(relationship.id),
            "relationship_type": relationship.relationship_type,
            "finding_ids": finding_ids,
            "evidence_refs": evidence_refs,
        })

    validation_payload = {
        "schema": "aegis.attack-chain-validation.v1",
        "policy_version": ATTACK_CHAIN_VALIDATION_VERSION,
        "attack_path_id": str(attack_path.id),
        "project_id": str(project.id),
        "steps": step_ids,
        "hops": hop_evidence,
        "validated_by": str(actor_id),
    }
    validation_sha256 = _canonical_digest(validation_payload)
    attack_path.status = AttackPath.Status.VALIDATED
    attack_path.evidence = {
        **(attack_path.evidence or {}),
        **validation_payload,
        "validation_sha256": validation_sha256,
        "validated_at": timezone.now().isoformat(),
    }
    attack_path.save(update_fields=["status", "evidence", "updated_at"])

    path_assets = [assets[asset_id] for asset_id in step_ids]
    blast = _derive_blast_radius(
        project=project,
        attack_path=attack_path,
        path_assets=path_assets,
        evidence_refs=sorted(all_evidence),
    )
    return {
        "schema": "aegis.validated-attack-chain.v1",
        "attack_path_id": str(attack_path.id),
        "status": attack_path.status,
        "validation_sha256": validation_sha256,
        "hop_count": len(hop_evidence),
        "hops": hop_evidence,
        "blast_radius": {
            "snapshot_id": str(blast.id),
            "root_ref": blast.root_ref,
            "score": blast.score,
            "crown_jewel_refs": blast.crown_jewel_refs,
            "impacted_nodes": blast.impacted_nodes,
            "evidence_refs": blast.evidence_refs,
        },
    }


def threat_model_snapshot(*, project: Project) -> dict[str, Any]:
    nodes = list(
        EvidenceGraphNode.objects.filter(project=project)
        .values("id", "kind", "external_ref", "label", "confidence", "properties")
        .order_by("kind", "external_ref")
    )
    node_ids = [row["id"] for row in nodes]
    edges = list(
        EvidenceGraphEdge.objects.filter(project=project, source_id__in=node_ids, target_id__in=node_ids)
        .values("id", "source__external_ref", "target__external_ref", "edge_type", "weight", "evidence_refs", "properties")
        .order_by("edge_type", "id")
    )
    latest_blast = BlastRadiusSnapshot.objects.filter(project=project).order_by("-created_at", "-id").first()
    return {
        "schema": "aegis.threat-model-snapshot.v1",
        "project_id": str(project.id),
        "nodes": [
            {
                **{key: value for key, value in row.items() if key != "id"},
                "id": str(row["id"]),
            }
            for row in nodes
        ],
        "edges": [
            {
                "id": str(row["id"]),
                "source": row["source__external_ref"],
                "target": row["target__external_ref"],
                "edge_type": row["edge_type"],
                "weight": row["weight"],
                "evidence_refs": row["evidence_refs"],
                "properties": row["properties"],
            }
            for row in edges
        ],
        "latest_blast_radius": None if latest_blast is None else {
            "id": str(latest_blast.id),
            "attack_path_id": str(latest_blast.attack_path_id) if latest_blast.attack_path_id else None,
            "root_ref": latest_blast.root_ref,
            "crown_jewel_refs": latest_blast.crown_jewel_refs,
            "impacted_nodes": latest_blast.impacted_nodes,
            "score": latest_blast.score,
            "evidence_refs": latest_blast.evidence_refs,
            "created_at": latest_blast.created_at.isoformat(),
        },
    }
