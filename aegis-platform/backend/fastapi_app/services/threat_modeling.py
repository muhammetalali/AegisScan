from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from django.db import transaction

from enterprise.models import EvidenceGraphEdge, EvidenceGraphNode, ThreatModelSnapshot
from enterprise.web_security_models import SecurityGraphEdge, SecurityGraphNode

METHODOLOGIES = {"STRIDE", "LINDDUN", "CAPEC", "PASTA"}
STRIDE_CATEGORIES = {
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
}
LINDDUN_CATEGORIES = {
    "linkability",
    "identifiability",
    "non-repudiation",
    "detectability",
    "disclosure",
    "unawareness",
    "non-compliance",
}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
CAPEC_RE = re.compile(r"^CAPEC-[1-9][0-9]{0,4}$")


class ThreatModelError(ValueError):
    pass


def _canonical(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def architecture_snapshot(project_id: str) -> dict[str, Any]:
    nodes = list(
        SecurityGraphNode.objects.filter(project_id=project_id)
        .order_by("external_ref")
        .values("external_ref", "plane", "kind", "protocol", "tenant_ref")
    )
    edges = list(
        SecurityGraphEdge.objects.filter(project_id=project_id)
        .select_related("source", "target")
        .order_by("source__external_ref", "target__external_ref", "relation")
    )
    edge_rows = [
        {
            "source_ref": edge.source.external_ref,
            "target_ref": edge.target.external_ref,
            "relation": edge.relation,
        }
        for edge in edges
    ]
    return {
        "nodes": nodes,
        "edges": edge_rows,
        "sha256": _canonical({"nodes": nodes, "edges": edge_rows}),
    }


def _validate_scenarios(
    project_id: str,
    methodologies: list[str],
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not scenarios:
        raise ThreatModelError("threat model requires at least one scenario")
    graph_nodes = {
        row["external_ref"]: row
        for row in SecurityGraphNode.objects.filter(project_id=project_id).values(
            "external_ref", "label", "plane", "kind"
        )
    }
    if not graph_nodes:
        raise ThreatModelError("threat model requires a persisted project security graph")

    normalized: list[dict[str, Any]] = []
    refs: set[str] = set()
    coverage = {"STRIDE": False, "LINDDUN": False, "CAPEC": False, "PASTA": False}

    for index, raw in enumerate(scenarios):
        ref = str(raw.get("ref") or "").strip()
        title = str(raw.get("title") or "").strip()
        description = str(raw.get("description") or "").strip()
        source_ref = str(raw.get("source_ref") or "").strip()
        target_ref = str(raw.get("target_ref") or "").strip()
        severity = str(raw.get("severity") or "").strip().lower()
        pasta_stage = raw.get("pasta_stage")

        if not ref or len(ref) > 160:
            raise ThreatModelError(f"scenario {index} has invalid ref")
        if ref in refs:
            raise ThreatModelError(f"duplicate threat scenario ref: {ref}")
        refs.add(ref)
        if not title or len(title) > 240:
            raise ThreatModelError(f"scenario {ref} has invalid title")
        if len(description) > 4000:
            raise ThreatModelError(f"scenario {ref} description exceeds 4000 characters")
        if source_ref not in graph_nodes or target_ref not in graph_nodes:
            raise ThreatModelError(f"scenario {ref} references architecture nodes outside the project graph")
        if severity not in SEVERITIES:
            raise ThreatModelError(f"scenario {ref} severity is invalid")
        if not isinstance(pasta_stage, int) or isinstance(pasta_stage, bool) or not 1 <= pasta_stage <= 7:
            raise ThreatModelError(f"scenario {ref} PASTA stage must be an integer from 1 to 7")

        stride = sorted({str(v).strip().lower() for v in (raw.get("stride") or []) if str(v).strip()})
        linddun = sorted({str(v).strip().lower() for v in (raw.get("linddun") or []) if str(v).strip()})
        capec_ids = sorted({str(v).strip().upper() for v in (raw.get("capec_ids") or []) if str(v).strip()})
        if any(value not in STRIDE_CATEGORIES for value in stride):
            raise ThreatModelError(f"scenario {ref} contains an invalid STRIDE category")
        if any(value not in LINDDUN_CATEGORIES for value in linddun):
            raise ThreatModelError(f"scenario {ref} contains an invalid LINDDUN category")
        if any(not CAPEC_RE.fullmatch(value) for value in capec_ids):
            raise ThreatModelError(f"scenario {ref} contains an invalid CAPEC identifier")
        if stride and "STRIDE" not in methodologies:
            raise ThreatModelError(f"scenario {ref} contains STRIDE mappings but STRIDE was not declared")
        if linddun and "LINDDUN" not in methodologies:
            raise ThreatModelError(f"scenario {ref} contains LINDDUN mappings but LINDDUN was not declared")
        if capec_ids and "CAPEC" not in methodologies:
            raise ThreatModelError(f"scenario {ref} contains CAPEC mappings but CAPEC was not declared")

        assumptions = [str(v).strip() for v in (raw.get("assumptions") or []) if str(v).strip()]
        preconditions = [str(v).strip() for v in (raw.get("preconditions") or []) if str(v).strip()]
        impacts = [str(v).strip() for v in (raw.get("impacts") or []) if str(v).strip()]
        controls = [str(v).strip() for v in (raw.get("control_refs") or []) if str(v).strip()]
        evidence = [str(v).strip() for v in (raw.get("evidence_refs") or []) if str(v).strip()]
        for label, values in {
            "assumptions": assumptions,
            "preconditions": preconditions,
            "impacts": impacts,
            "control_refs": controls,
            "evidence_refs": evidence,
        }.items():
            if len(values) > 128 or any(len(value) > 700 for value in values):
                raise ThreatModelError(f"scenario {ref} {label} exceeds bounded contract")

        coverage["STRIDE"] = coverage["STRIDE"] or bool(stride)
        coverage["LINDDUN"] = coverage["LINDDUN"] or bool(linddun)
        coverage["CAPEC"] = coverage["CAPEC"] or bool(capec_ids)
        coverage["PASTA"] = True

        semantic = {
            "ref": ref,
            "title": title,
            "description": description,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "severity": severity,
            "pasta_stage": pasta_stage,
            "stride": stride,
            "linddun": linddun,
            "capec_ids": capec_ids,
            "assumptions": assumptions,
            "preconditions": preconditions,
            "impacts": impacts,
            "control_refs": controls,
            "evidence_refs": evidence,
        }
        semantic["scenario_sha256"] = _canonical(semantic)
        normalized.append(semantic)

    for methodology in methodologies:
        if not coverage[methodology]:
            raise ThreatModelError(f"{methodology} was declared but has no scenario coverage")
    return normalized


def _project_evidence_graph(
    snapshot: ThreatModelSnapshot,
    scenarios: list[dict[str, Any]],
) -> None:
    graph_nodes = {
        row.external_ref: row
        for row in SecurityGraphNode.objects.filter(project=snapshot.project)
    }
    for scenario in scenarios:
        source_graph = graph_nodes[scenario["source_ref"]]
        target_graph = graph_nodes[scenario["target_ref"]]
        source, _ = EvidenceGraphNode.objects.get_or_create(
            organization=snapshot.organization,
            project=snapshot.project,
            kind=EvidenceGraphNode.Kind.ASSET,
            external_ref=f"architecture:{source_graph.external_ref}",
            defaults={
                "label": source_graph.label,
                "confidence": 1.0,
                "properties": {
                    "security_graph_ref": source_graph.external_ref,
                    "security_graph_plane": source_graph.plane,
                    "security_graph_kind": source_graph.kind,
                },
            },
        )
        target, _ = EvidenceGraphNode.objects.get_or_create(
            organization=snapshot.organization,
            project=snapshot.project,
            kind=EvidenceGraphNode.Kind.ASSET,
            external_ref=f"architecture:{target_graph.external_ref}",
            defaults={
                "label": target_graph.label,
                "confidence": 1.0,
                "properties": {
                    "security_graph_ref": target_graph.external_ref,
                    "security_graph_plane": target_graph.plane,
                    "security_graph_kind": target_graph.kind,
                },
            },
        )
        threat, _ = EvidenceGraphNode.objects.get_or_create(
            organization=snapshot.organization,
            project=snapshot.project,
            kind=EvidenceGraphNode.Kind.THREAT,
            external_ref=f"threat-model:{snapshot.model_sha256}:{scenario['ref']}",
            defaults={
                "label": scenario["title"],
                "confidence": 1.0,
                "properties": {
                    "threat_model_id": str(snapshot.id),
                    "threat_model_sha256": snapshot.model_sha256,
                    "scenario_sha256": scenario["scenario_sha256"],
                    "severity": scenario["severity"],
                    "pasta_stage": scenario["pasta_stage"],
                    "stride": scenario["stride"],
                    "linddun": scenario["linddun"],
                    "capec_ids": scenario["capec_ids"],
                },
            },
        )
        EvidenceGraphEdge.objects.get_or_create(
            organization=snapshot.organization,
            project=snapshot.project,
            source=source,
            target=threat,
            edge_type="originates_threat",
            defaults={
                "weight": 1.0,
                "evidence_refs": scenario["evidence_refs"],
                "properties": {"scenario_ref": scenario["ref"]},
            },
        )
        EvidenceGraphEdge.objects.get_or_create(
            organization=snapshot.organization,
            project=snapshot.project,
            source=threat,
            target=target,
            edge_type="threatens",
            defaults={
                "weight": 1.0,
                "evidence_refs": scenario["evidence_refs"],
                "properties": {
                    "scenario_ref": scenario["ref"],
                    "control_refs": scenario["control_refs"],
                },
            },
        )


@transaction.atomic
def create_threat_model_snapshot(
    *,
    organization,
    project,
    actor_id: str,
    title: str,
    methodologies: list[str],
    pasta_stage: int,
    scope: dict[str, Any],
    scenarios: list[dict[str, Any]],
) -> tuple[ThreatModelSnapshot, bool]:
    title = title.strip()
    if not title or len(title) > 240:
        raise ThreatModelError("threat model title is invalid")
    methods = sorted({str(value).strip().upper() for value in methodologies if str(value).strip()})
    if not methods or any(value not in METHODOLOGIES for value in methods):
        raise ThreatModelError("threat model methodologies are invalid")
    if not isinstance(pasta_stage, int) or isinstance(pasta_stage, bool) or not 1 <= pasta_stage <= 7:
        raise ThreatModelError("threat model PASTA stage must be an integer from 1 to 7")
    if "PASTA" not in methods:
        raise ThreatModelError("PASTA methodology must be declared for staged threat-model snapshots")
    if not isinstance(scope, dict):
        raise ThreatModelError("threat model scope must be an object")
    if len(json.dumps(scope, ensure_ascii=False)) > 16000:
        raise ThreatModelError("threat model scope exceeds 16 KiB")

    architecture = architecture_snapshot(str(project.id))
    normalized_scenarios = _validate_scenarios(str(project.id), methods, scenarios)
    if any(scenario["pasta_stage"] > pasta_stage for scenario in normalized_scenarios):
        raise ThreatModelError("scenario PASTA stage cannot exceed the snapshot PASTA stage")

    lineage = {
        "contract_version": "aegis.threat-model.v1",
        "project_id": str(project.id),
        "organization_id": str(organization.id),
        "title": title,
        "methodologies": methods,
        "pasta_stage": pasta_stage,
        "scope": scope,
        "architecture_sha256": architecture["sha256"],
        "scenarios": normalized_scenarios,
    }
    model_sha256 = _canonical(lineage)
    snapshot, created = ThreatModelSnapshot.objects.get_or_create(
        model_sha256=model_sha256,
        defaults={
            "organization": organization,
            "project": project,
            "title": title,
            "methodologies": methods,
            "pasta_stage": pasta_stage,
            "scope": scope,
            "scenarios": normalized_scenarios,
            "architecture_sha256": architecture["sha256"],
            "created_by_id": actor_id,
        },
    )
    if snapshot.project_id != project.id or snapshot.organization_id != organization.id:
        raise ThreatModelError("threat model digest collision crossed tenant or project boundary")
    if created:
        _project_evidence_graph(snapshot, normalized_scenarios)
    return snapshot, created


def serialize_threat_model(snapshot: ThreatModelSnapshot) -> dict[str, Any]:
    return {
        "id": str(snapshot.id),
        "project_id": str(snapshot.project_id),
        "organization_id": str(snapshot.organization_id),
        "title": snapshot.title,
        "methodologies": snapshot.methodologies,
        "pasta_stage": snapshot.pasta_stage,
        "scope": snapshot.scope,
        "scenarios": snapshot.scenarios,
        "architecture_sha256": snapshot.architecture_sha256,
        "model_sha256": snapshot.model_sha256,
        "created_by": str(snapshot.created_by_id),
        "created_at": snapshot.created_at.isoformat(),
    }
