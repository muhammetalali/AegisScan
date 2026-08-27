"""Evidence Graph Engine — محرك دليل Evidence Graph.

يبني شبكة تربط الأصول بالثغرات بالأدلة بالأحداث بالأصلاحات.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.evidence_graph")


class GraphNodeType(str, Enum):
    ASSET = "asset"
    FINDING = "finding"
    EVIDENCE = "evidence"
    INCIDENT = "incident"
    REMEDIATION = "remediation"
    CONTROL = "control"
    THREAT = "threat"


class GraphEdgeType(str, Enum):
    AFFECTS = "affects"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    REMEDIATES = "remediates"
    DETECTS = "detects"
    CAUSED_BY = "caused_by"
    RELATED_TO = "related_to"


@dataclass
class GraphNode:
    """عقدة في الشبكة."""
    node_id: str
    node_type: GraphNodeType
    label: str
    confidence: float = 0.5
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """حافة في الشبكة."""
    source_id: str
    target_id: str
    edge_type: GraphEdgeType
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubGraph:
    """شبكة فرعية."""
    subgraph_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    description: str = ""


class EvidenceGraphEngine:
    """محرك دليل Evidence Graph — يبني ويحلل الشبكة."""

    name = "EvidenceGraphEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []

    async def add_node(
        self,
        node_id: str,
        node_type: GraphNodeType,
        label: str,
        confidence: float = 0.5,
        **properties: Any,
    ) -> GraphNode:
        """إضافة عقدة."""
        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            confidence=confidence,
            properties=properties,
        )
        self._nodes[node_id] = node
        return node

    async def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: GraphEdgeType,
        weight: float = 1.0,
        **properties: Any,
    ) -> GraphEdge:
        """إضافة حافة."""
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            properties=properties,
        )
        self._edges.append(edge)
        return edge

    async def build_from_results(
        self,
        assets: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        evidences: List[Dict[str, Any]],
        remediations: List[Dict[str, Any]],
    ) -> None:
        """بناء الشبكة من نتائج التحليل."""
        # الأصول
        for asset in assets:
            await self.add_node(
                node_id=asset.get("asset_id", ""),
                node_type=GraphNodeType.ASSET,
                label=asset.get("name", ""),
                confidence=1.0,
                criticality=asset.get("criticality", "medium"),
            )

        # النتائج
        for finding in findings:
            fid = finding.get("finding_id", "")
            await self.add_node(
                node_id=fid,
                node_type=GraphNodeType.FINDING,
                label=finding.get("title", ""),
                confidence=finding.get("confidence", 0.5),
                severity=finding.get("severity", "medium"),
            )
            # ربط بالأصول
            for asset_id in finding.get("affected_assets", []):
                if asset_id in self._nodes:
                    await self.add_edge(fid, asset_id, GraphEdgeType.AFFECTS)

        # الأدلة
        for evidence in evidences:
            eid = evidence.get("evidence_id", "")
            await self.add_node(
                node_id=eid,
                node_type=GraphNodeType.EVIDENCE,
                label=evidence.get("description", "")[:50],
                confidence=evidence.get("confidence", 0.5),
            )
            # ربط بالنتائج
            for finding_id in evidence.get("related_findings", []):
                if finding_id in self._nodes:
                    await self.add_edge(eid, finding_id, GraphEdgeType.SUPPORTS)

        # الإصلاحات
        for rem in remediations:
            rid = rem.get("remediation_id", "")
            await self.add_node(
                node_id=rid,
                node_type=GraphNodeType.REMEDIATION,
                label=rem.get("title", ""),
                confidence=1.0,
            )
            for finding_id in rem.get("related_findings", []):
                if finding_id in self._nodes:
                    await self.add_edge(rid, finding_id, GraphEdgeType.REMEDIATES)

        await self.event_bus.publish(
            topic="evidence_graph.built",
            payload={"nodes": len(self._nodes), "edges": len(self._edges)},
            source=self.name,
        )

    async def find_connected(
        self, node_id: str, max_depth: int = 3
    ) -> SubGraph:
        """البحث عن العقد المتصلة."""
        visited: Set[str] = set()
        connected_nodes: Dict[str, GraphNode] = {}
        connected_edges: List[GraphEdge] = []

        def _bfs(start: str, depth: int) -> None:
            if depth > max_depth or start in visited:
                return
            visited.add(start)
            if start in self._nodes:
                connected_nodes[start] = self._nodes[start]
            for edge in self._edges:
                if edge.source_id == start and edge.target_id not in visited:
                    connected_edges.append(edge)
                    _bfs(edge.target_id, depth + 1)
                elif edge.target_id == start and edge.source_id not in visited:
                    connected_edges.append(edge)
                    _bfs(edge.source_id, depth + 1)

        _bfs(node_id, 0)

        return SubGraph(
            subgraph_id=f"sub_{node_id}",
            nodes=list(connected_nodes.values()),
            edges=connected_edges,
            description=f"شبكة مرتبطة بـ {node_id}",
        )

    async def calculate_evidence_strength(
        self, finding_id: str
    ) -> Dict[str, Any]:
        """حساب قوة الدليل لنتيجة معينة."""
        supporting = [
            e for e in self._edges
            if e.target_id == finding_id and e.edge_type == GraphEdgeType.SUPPORTS
        ]
        contradicting = [
            e for e in self._edges
            if e.target_id == finding_id and e.edge_type == GraphEdgeType.CONTRADICTS
        ]
        remediations = [
            e for e in self._edges
            if e.target_id == finding_id and e.edge_type == GraphEdgeType.REMEDIATES
        ]

        strength = len(supporting) - len(contradicting) * 2
        return {
            "finding_id": finding_id,
            "supporting_evidence": len(supporting),
            "contradicting_evidence": len(contradicting),
            "remediations": len(remediations),
            "net_strength": strength,
            "verdict": "supported" if strength > 0 else "weak",
        }

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_nodes_by_type(self, node_type: GraphNodeType) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        for n in self._nodes.values():
            by_type[n.node_type.value] = by_type.get(n.node_type.value, 0) + 1
        return {"total_nodes": len(self._nodes), "total_edges": len(self._edges), "by_type": by_type}
