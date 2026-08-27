from __future__ import annotations

from collections import defaultdict, deque
from typing import Any


def build_blast_radius(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = {str(node["id"]): node for node in graph.get("nodes", []) if node.get("id") is not None}
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for edge in graph.get("edges", []) or []:
        source, target = str(edge.get("source", "")), str(edge.get("target", ""))
        relation = str(edge.get("relation", edge.get("label", "related-to")))
        if source and target:
            adjacency[source].append((target, relation))
            adjacency[target].append((source, relation))

    roots = [n for n in nodes.values() if n.get("kind") in {"finding", "conflict", "validation"}]
    scenarios: list[dict[str, Any]] = []

    for root in roots:
        root_id = str(root["id"])
        queue = deque([(root_id, 0)])
        seen = {root_id}
        impacted: list[dict[str, Any]] = []
        services = set()
        business_nodes = set()
        paths: list[list[str]] = []
        path_edges: list[dict[str, str]] = []

        while queue and len(impacted) < 100:
            current, distance = queue.popleft()
            for neighbor, relation in adjacency.get(current, []):
                if neighbor in seen or neighbor not in nodes:
                    continue
                seen.add(neighbor)
                node = nodes[neighbor]
                kind = node.get("kind")
                if kind in {"asset", "endpoint", "service", "data", "business"}:
                    impact = {
                        "id": neighbor,
                        "label": node.get("label", neighbor),
                        "kind": kind,
                        "distance": distance + 1,
                        "risk": int(node.get("risk", 0) or 0),
                        "confidence": int(node.get("confidence", 0) or 0),
                        "relation": relation,
                    }
                    impacted.append(impact)
                    if kind == "service":
                        services.add(neighbor)
                    if kind in {"data", "business"}:
                        business_nodes.add(neighbor)
                queue.append((neighbor, distance + 1))

        affected_assets = [item for item in impacted if item["kind"] == "asset"]
        max_impact = max((item["risk"] for item in impacted), default=0)
        avg_conf = round(sum(item["confidence"] for item in impacted) / len(impacted)) if impacted else int(root.get("confidence", 0) or 0)
        radius_score = max_impact * 0.55 + min(30, len(impacted) * 3) + len(business_nodes) * 4 + len(services) * 2
        scenarios.append({
            "root": root_id,
            "label": root.get("label", root_id),
            "blastRadius": len(impacted),
            "affectedAssets": len(affected_assets),
            "affectedServices": len(services),
            "businessNodes": len(business_nodes),
            "maxImpact": min(100, round(max_impact)),
            "confidence": min(100, max(0, round(avg_conf))),
            "blastRadiusScore": min(100, max(0, round(radius_score))),
            "impactNodes": impacted[:30],
        })

    scenarios.sort(key=lambda item: (item["blastRadiusScore"], item["maxImpact"], item["blastRadius"]), reverse=True)
    top = scenarios[:10]
    return {
        "scenarios": top,
        "summary": {
            "maxBlastRadius": max((item["blastRadius"] for item in top), default=0),
            "maxImpact": max((item["maxImpact"] for item in top), default=0),
            "affectedAssets": max((item["affectedAssets"] for item in top), default=0),
            "affectedServices": max((item["affectedServices"] for item in top), default=0),
            "businessExposureNodes": max((item["businessNodes"] for item in top), default=0),
        },
    }
