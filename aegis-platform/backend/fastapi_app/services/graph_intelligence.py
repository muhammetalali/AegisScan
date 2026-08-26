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
        item = {**node, "degree": degree, "priority": priority}
        enriched.append(item)

    priority_map = {str(item["id"]): item["priority"] for item in enriched}
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

    executive_priority = _clamp(
        sum(float(item.get("priority", 0)) for item in enriched[:5]) / max(1, min(5, len(enriched)))
        if enriched else 0
    )
    risk_exposure = _clamp(sum(float(item.get("risk", 0)) for item in enriched if item.get("kind") in {"finding", "conflict"}) / max(1, len([item for item in enriched if item.get("kind") in {"finding", "conflict"}])) if enriched else 0)
    return {
        **graph,
        "nodes": enriched,
        "intelligence": {
            "topPriorityNodes": enriched[:10],
            "attackPriorityPaths": paths[:10],
            "executivePriority": executive_priority,
            "riskExposure": risk_exposure,
            "highImpactNodes": sum(1 for node in enriched if node.get("risk", 0) >= 70),
            "conflictedNodes": sum(1 for node in enriched if node.get("conflicts", 0) > 0),
            "evidenceBackedNodes": sum(1 for node in enriched if node.get("evidenceBacked")),
        },
    }
