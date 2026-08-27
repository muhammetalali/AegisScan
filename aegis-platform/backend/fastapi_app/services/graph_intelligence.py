from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def _neighbors(edges: list[dict[str, Any]]) -> dict[str, list[str]]:
    graph: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        source, target = edge.get("source"), edge.get("target")
        if source and target:
            graph[source].append(target)
            graph[target].append(source)
    return graph


def _distance_map(start: str, graph: dict[str, list[str]]) -> dict[str, int]:
    distances = {start: 0}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for neighbor in graph.get(current, []):
            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                queue.append(neighbor)
    return distances


def _attack_path_candidates(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    node_map = {str(node.get("id")): node for node in nodes if node.get("id") is not None}
    finding_to_asset: dict[str, list[str]] = defaultdict(list)
    supported_by: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        source, target, relation = str(edge.get("source", "")), str(edge.get("target", "")), edge.get("relation")
        if relation == "impacts":
            finding_to_asset[source].append(target)
        elif relation == "supported-by":
            supported_by[source].append(target)

    candidates: list[dict[str, Any]] = []
    for finding_id, assets in finding_to_asset.items():
        finding = node_map.get(finding_id)
        if not finding:
            continue
        for asset_id in assets:
            asset = node_map.get(asset_id)
            if not asset:
                continue
            evidence = supported_by.get(finding_id, [])
            risk = _clamp(float(finding.get("risk", 0)) * 0.7 + float(asset.get("risk", 0)) * 0.3)
            confidence = _clamp(float(finding.get("confidence", 0)) * 0.75 + min(100, len(evidence) * 15) * 0.25)
            candidates.append({
                "id": f"path:{finding_id}:{asset_id}",
                "root": finding_id,
                "entry": asset_id,
                "label": f"{finding.get('label', finding_id)} → {asset.get('label', asset_id)}",
                "risk": risk,
                "confidence": confidence,
                "evidence": evidence,
                "steps": [
                    {"id": finding_id, "kind": "finding", "label": finding.get("label", finding_id)},
                    *[{"id": evidence_id, "kind": "evidence", "label": node_map.get(evidence_id, {}).get("label", evidence_id)} for evidence_id in evidence],
                    {"id": asset_id, "kind": "asset", "label": asset.get("label", asset_id)},
                ],
                "basis": "finding-to-impacted-asset path supported by observed evidence",
            })
    candidates.sort(key=lambda item: (item["risk"], item["confidence"]), reverse=True)
    return candidates[:20]


def analyze_graph(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = list(graph.get("nodes", []))
    edges = list(graph.get("edges", []))
    adjacency = _neighbors(edges)
    node_map = {str(node["id"]): node for node in nodes if node.get("id") is not None}

    enriched: list[dict[str, Any]] = []
    for node in nodes:
        node_id = str(node["id"])
        degree = len(adjacency.get(node_id, []))
        risk = float(node.get("risk", 0) or 0)
        confidence = float(node.get("confidence", 0) or 0)
        conflicts = float(node.get("conflicts", 0) or 0)
        sources = float(node.get("sources", 0) or 0)
        evidence_bonus = 12 if node.get("evidenceBacked") else 0
        conflict_penalty = min(30, conflicts * 6)
        centrality_bonus = min(18, degree * 3)
        priority = _clamp(risk * 0.48 + (100 - confidence) * 0.18 + conflict_penalty * 0.55 + centrality_bonus + evidence_bonus * 0.25)
        enriched.append({**node, "degree": degree, "priority": priority})

    enriched.sort(key=lambda item: (item["priority"], item.get("risk", 0)), reverse=True)

    paths: list[dict[str, Any]] = []
    for item in enriched[:12]:
        if item.get("kind") not in {"finding", "conflict", "validation"}:
            continue
        start = str(item["id"])
        distances = _distance_map(start, adjacency)
        impact_nodes = [
            {"id": target, "distance": distance, "risk": node_map[target].get("risk", 0), "kind": node_map[target].get("kind")}
            for target, distance in distances.items()
            if target != start and node_map.get(target, {}).get("risk", 0) > 0
        ]
        impact_nodes.sort(key=lambda value: (value["risk"], -value["distance"]), reverse=True)
        blast = len(impact_nodes)
        max_impact = max((float(value["risk"]) for value in impact_nodes), default=0)
        score = _clamp(item.get("priority", 0) * 0.65 + max_impact * 0.25 + min(10, blast))
        paths.append({
            "root": start,
            "label": item.get("label", start),
            "priority": score,
            "blastRadius": blast,
            "maxImpact": _clamp(max_impact),
            "impactNodes": impact_nodes[:20],
        })
    paths.sort(key=lambda path: path["priority"], reverse=True)

    attack_candidates = _attack_path_candidates(enriched, edges)
    executive_priority = _clamp(sum(float(item.get("priority", 0)) for item in enriched[:5]) / max(1, min(5, len(enriched))) if enriched else 0)
    risk_nodes = [item for item in enriched if item.get("kind") in {"finding", "conflict"}]
    risk_exposure = _clamp(sum(float(item.get("risk", 0)) for item in risk_nodes) / max(1, len(risk_nodes)))
    return {
        **graph,
        "nodes": enriched,
        "intelligence": {
            "topPriorityNodes": enriched[:10],
            "attackPriorityPaths": paths[:10],
            "attackPathCandidates": attack_candidates,
            "executivePriority": executive_priority,
            "riskExposure": risk_exposure,
            "highImpactNodes": sum(1 for node in enriched if node.get("risk", 0) >= 70),
            "conflictedNodes": sum(1 for node in enriched if node.get("conflicts", 0) > 0),
            "evidenceBackedNodes": sum(1 for node in enriched if node.get("evidenceBacked")),
        },
    }
