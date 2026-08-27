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


def _severity_risk(severity: str) -> int:
    return {"critical": 95, "high": 80, "medium": 60, "low": 35, "info": 10}.get(str(severity).lower(), 0)


def build_assurance_graph(validations: dict[str, dict[str, Any]], correlations: dict[str, Any] | None = None) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    conflict_items = (correlations or {}).get("items", [])

    for validation_id, validation in validations.items():
        v_id = f"validation:{validation_id}"
        _node(nodes, v_id, "validation", validation_id, status=validation.get("status"), risk=0, confidence=0)
        selected_engines = validation.get("engines", []) or []
        for engine in selected_engines:
            e_id = f"engine:{engine}"
            _node(nodes, e_id, "engine", engine, source=engine)
            _edge(edges, seen_edges, v_id, e_id, "validated-by")

        results = validation.get("results", {}) or {}
        findings = results.get("findings", []) or []
        evidence = results.get("evidence", []) or []

        evidence_map: dict[str, str] = {}
        for item in evidence:
            evidence_id = str(item.get("id") or f"evidence:{validation_id}:{len(evidence_map)}")
            engine = str(item.get("engine") or "unknown")
            evidence_map[evidence_id] = evidence_id
            confidence = int(item.get("confidence", 90) or 90)
            data = item.get("data") or {}
            label = str(item.get("type") or "Evidence")
            _node(nodes, evidence_id, "evidence", label, confidence=confidence, evidenceBacked=True, source=engine, data=data)
            _edge(edges, seen_edges, f"engine:{engine}", evidence_id, "produced")
            _edge(edges, seen_edges, evidence_id, v_id, "validated-by")

        finding_ids = set()
        for finding in findings:
            finding_id = str(finding.get("id") or f"finding:{validation_id}:{len(finding_ids)}")
            finding_ids.add(finding_id)
            severity = str(finding.get("severity") or "info").lower()
            risk = int(finding.get("risk", _severity_risk(severity)) or 0)
            confidence = int(finding.get("confidence", 85) or 85)
            engine = str(finding.get("engine") or finding.get("source") or "unknown")
            _node(nodes, finding_id, "finding", str(finding.get("title") or finding_id), risk=risk, confidence=confidence, severity=severity, rule=finding.get("rule"), asset=finding.get("asset"))
            _edge(edges, seen_edges, f"engine:{engine}", finding_id, "detected")

            linked_evidence = [str(value) for value in (finding.get("evidence_ids") or [])]
            if linked_evidence:
                for evidence_id in linked_evidence:
                    if evidence_id in evidence_map:
                        _edge(edges, seen_edges, finding_id, evidence_id, "supported-by")
            else:
                for evidence_item in evidence:
                    if str(evidence_item.get("engine") or "") == engine:
                        evidence_id = str(evidence_item.get("id"))
                        if evidence_id in evidence_map:
                            _edge(edges, seen_edges, finding_id, evidence_id, "supported-by")
                            break

            asset = finding.get("asset")
            if asset:
                asset_id = f"asset:{asset}"
                _node(nodes, asset_id, "asset", str(asset), risk=risk, confidence=confidence)
                _edge(edges, seen_edges, finding_id, asset_id, "impacts")

        if findings:
            finding_risks = [_severity_risk(str(item.get("severity", "info"))) for item in findings]
            v_node = nodes[v_id]
            v_node["risk"] = max(finding_risks)
            v_node["confidence"] = round(sum(int(item.get("confidence", 85) or 85) for item in findings) / len(findings))
        elif evidence:
            nodes[v_id]["confidence"] = 90

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
            nodes[v_id]["confidence"] = max(0, int(nodes[v_id].get("confidence", 100)) - min(80, count * 8))

    for node in nodes.values():
        node["risk"] = max(0, min(100, int(node.get("risk", 0))))
        node["confidence"] = max(0, min(100, int(node.get("confidence", 0))))
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
            "assets": sum(1 for n in nodes.values() if n["kind"] == "asset"),
            "conflicts": sum(1 for n in nodes.values() if n["kind"] == "conflict"),
        },
    }
