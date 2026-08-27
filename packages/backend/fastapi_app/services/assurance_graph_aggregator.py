from __future__ import annotations

from collections import defaultdict
from typing import Any


def _node(nodes: dict[str, dict[str, Any]], node_id: str, kind: str, label: str, **meta: Any) -> None:
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "kind": kind, "label": label, "risk": 0, "confidence": 0, "conflicts": 0, "sources": 0}
    nodes[node_id].update({k: v for k, v in meta.items() if v is not None})


def _edge(edges: list[dict[str, Any]], seen: set[tuple[str, str, str]], source: str, target: str, relation: str, **meta: Any) -> None:
    key = (source, target, relation)
    if key in seen:
        return
    seen.add(key)
    edges.append({"source": source, "target": target, "relation": relation, **meta})


def _attach_real_results(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]], seen: set[tuple[str, str, str]], validation_id: str, validation: dict[str, Any]) -> None:
    v_id = f"validation:{validation_id}"
    results = validation.get("results") or {}
    evidence_items = {str(item.get("id")): item for item in results.get("evidence", []) if item.get("id")}

    for evidence_id, evidence in evidence_items.items():
        label = evidence.get("type") or "Evidence"
        data = evidence.get("data") or {}
        _node(nodes, f"evidence:{evidence_id}", "evidence", label, evidenceBacked=True, source=evidence.get("engine"), status="verified", confidence=95, evidenceData=data)
        _edge(edges, seen, v_id, f"evidence:{evidence_id}", "produced")

    for finding in results.get("findings", []):
        finding_id = str(finding.get("id") or f"{validation_id}:{finding.get('title', 'finding')}")
        f_id = f"finding:{finding_id}"
        severity = str(finding.get("severity", "medium")).lower()
        risk = {"critical": 90, "high": 75, "medium": 55, "low": 30, "info": 10}.get(severity, 50)
        _node(nodes, f_id, "finding", finding.get("title", "Finding"), risk=risk, confidence=int(finding.get("confidence", 0) or 0), severity=severity, category=finding.get("category"), asset=finding.get("asset"), description=finding.get("description"), evidenceBacked=bool(finding.get("evidence_ids")))
        engine = finding.get("engine") or validation.get("engine") or finding.get("category") or "validation"
        e_id = f"engine:{engine}"
        _node(nodes, e_id, "engine", engine, source=engine)
        _edge(edges, seen, e_id, f_id, "detected")
        _edge(edges, seen, v_id, f_id, "observed")
        for evidence_id in finding.get("evidence_ids", []) or []:
            evidence_node = f"evidence:{evidence_id}"
            if evidence_node in nodes:
                _edge(edges, seen, f_id, evidence_node, "supported-by", verified=True)
        asset = finding.get("asset")
        if asset:
            asset_id = f"asset:{asset}"
            _node(nodes, asset_id, "asset", asset, risk=risk, confidence=int(finding.get("confidence", 0) or 0), evidenceBacked=True)
            _edge(edges, seen, f_id, asset_id, "impacts")


def build_assurance_graph(validations: dict[str, dict[str, Any]], correlations: dict[str, Any] | None = None) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    conflict_items = (correlations or {}).get("items", [])

    for validation_id, validation in validations.items():
        v_id = f"validation:{validation_id}"
        _node(nodes, v_id, "validation", validation_id, status=validation.get("status"), risk=min(100, int(validation.get("progress", 0))))
        _attach_real_results(nodes, edges, seen_edges, validation_id, validation)

        selected_engines = validation.get("engines", []) or []
        for engine in selected_engines:
            e_id = f"engine:{engine}"
            _node(nodes, e_id, "engine", engine, source=engine)
            _edge(edges, seen_edges, v_id, e_id, "validated-by")
            state = validation.get("engines_state", {}).get(engine, {})
            findings = int(state.get("findings", 0) or 0)
            if findings and not (validation.get("results") or {}).get("findings"):
                f_id = f"finding:{validation_id}:{engine}"
                confidence = 60 + min(35, findings * 8)
                _node(nodes, f_id, "finding", f"{engine} finding", risk=min(100, 35 + findings * 12), confidence=confidence, findings=findings)
                _edge(edges, seen_edges, e_id, f_id, "detected")

    conflicts_by_validation: defaultdict[str, int] = defaultdict(int)
    for conflict in conflict_items:
        entity_id = str(conflict.get("entityId", ""))
        conflicts_by_validation[entity_id] += 1
        c_id = f"conflict:{conflict.get('id')}"
        _node(nodes, c_id, "conflict", conflict.get("entityLabel", "Assurance conflict"), risk=conflict.get("impact", 0), confidence=conflict.get("confidenceAfter", 0), conflicts=1, sources=len(conflict.get("signals", [])))
        if entity_id:
            _edge(edges, seen_edges, f"validation:{entity_id}", c_id, "conflicted-by")
        for signal in conflict.get("signals", []):
            s_id = f"signal:{signal.get('id')}"
            _node(nodes, s_id, "signal", signal.get("source", "source"), confidence=signal.get("confidence", 0), source=signal.get("source"), claim=signal.get("claim"), value=signal.get("value"))
            _edge(edges, seen_edges, s_id, c_id, "contributes-to")

    for validation_id, count in conflicts_by_validation.items():
        v_id = f"validation:{validation_id}"
        if v_id in nodes:
            nodes[v_id]["conflicts"] = count
            nodes[v_id]["confidence"] = max(0, 100 - min(80, count * 8))

    for node in nodes.values():
        node["risk"] = max(0, min(100, int(node.get("risk", 0) or 0)))
        node["confidence"] = max(0, min(100, int(node.get("confidence", 0) or 0)))
        node["sources"] = int(node.get("sources", 0) or 0)
        node["conflicts"] = int(node.get("conflicts", 0) or 0)

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "validations": sum(1 for n in nodes.values() if n["kind"] == "validation"),
            "findings": sum(1 for n in nodes.values() if n["kind"] == "finding"),
            "evidence": sum(1 for n in nodes.values() if n["kind"] == "evidence"),
            "conflicts": sum(1 for n in nodes.values() if n["kind"] == "conflict"),
            "assets": sum(1 for n in nodes.values() if n["kind"] == "asset"),
        },
    }
