"""Attack Path Analyzer — محلل مسار الهجوم.

تحليل مسار الهجوم بشكل تحليلي (مو تنفيذي).
يحدد كيف يمكن للمهاجم الوصول للأهداف عبر الثغرات والivate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.attack_path")


class NodeType(str, Enum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    NETWORK = "network"
    USER = "user"
    EXTERNAL = "external"


class EdgeType(str, Enum):
    EXPLOITS = "exploits"
    ACCESSES = "accesses"
    ESCALATES = "escalates"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_FLOW = "data_flow"
    TRUST_RELATION = "trust_relation"


@dataclass
class AttackNode:
    """عقدة في مسار الهجوم."""
    node_id: str
    node_type: NodeType
    name: str
    description: str = ""
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """حافة في مسار الهجوم."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    description: str = ""
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackPath:
    """مسار هجوم كامل."""
    path_id: str
    nodes: List[AttackNode]
    edges: List[AttackEdge]
    total_risk: float = 0.0
    length: int = 0
    entry_point: str = ""
    target: str = ""
    description: str = ""


@dataclass
class AttackPathAnalysis:
    """تحليل مسار الهجوم."""
    analysis_id: str
    paths: List[AttackPath]
    critical_paths: List[AttackPath]
    total_nodes: int = 0
    total_edges: int = 0
    highest_risk: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: Optional[datetime] = None


class AttackPathAnalyzer:
    """محرك تحليل مسار الهجوم — تحليلي، مو تنفيذي."""

    name = "AttackPathAnalyzer"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._nodes: Dict[str, AttackNode] = {}
        self._edges: List[AttackEdge] = []

    async def build_graph(
        self,
        assets: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        controls: List[Dict[str, Any]],
    ) -> None:
        """بناء رسم بياني للأصول والثغرات."""
        self._nodes.clear()
        self._edges.clear()

        # إضافة العقد
        for asset in assets:
            node = AttackNode(
                node_id=asset.get("asset_id", ""),
                node_type=NodeType.ASSET,
                name=asset.get("name", asset.get("asset_id", "")),
                risk_score=asset.get("risk_score", 0),
            )
            self._nodes[node.node_id] = node

        for finding in findings:
            node = AttackNode(
                node_id=finding.get("finding_id", ""),
                node_type=NodeType.VULNERABILITY,
                name=finding.get("title", ""),
                risk_score=finding.get("risk_score", 0),
                metadata={"severity": finding.get("severity", "medium")},
            )
            self._nodes[node.node_id] = node

        # إضافة الحواف — ربط الثغرات بالأصول
        for finding in findings:
            finding_id = finding.get("finding_id", "")
            affected = finding.get("affected_assets", [])
            for asset_id in affected:
                if asset_id in self._nodes:
                    self._edges.append(AttackEdge(
                        source_id=finding_id,
                        target_id=asset_id,
                        edge_type=EdgeType.EXPLOITS,
                        confidence=finding.get("confidence", 0.5),
                    ))

        # ربط الأصول ببعضها
        for i, asset_a in enumerate(assets):
            for asset_b in assets[i + 1:]:
                if self._same_network(asset_a, asset_b):
                    self._edges.append(AttackEdge(
                        source_id=asset_a.get("asset_id", ""),
                        target_id=asset_b.get("asset_id", ""),
                        edge_type=EdgeType.TRUST_RELATION,
                        confidence=0.7,
                    ))

        await self.event_bus.publish(
            topic="attack_path.graph_built",
            payload={"nodes": len(self._nodes), "edges": len(self._edges)},
            source=self.name,
        )

    async def analyze(
        self, entry_points: Optional[List[str]] = None
    ) -> AttackPathAnalysis:
        """تحليل مسارات الهجوم."""
        # تحديد نقاط الدخول
        if not entry_points:
            entry_points = [
                n.node_id for n in self._nodes.values()
                if n.node_type in (NodeType.EXTERNAL, NodeType.USER)
            ]
        if not entry_points:
            entry_points = [n.node_id for n in self._nodes.values()][:3]

        # BFS لايجاد المسارات
        all_paths: List[AttackPath] = []
        for entry in entry_points:
            paths = self._find_paths_bfs(entry)
            all_paths.extend(paths)

        # ترتيب حسب الخطورة
        all_paths.sort(key=lambda p: p.total_risk, reverse=True)
        critical = [p for p in all_paths if p.total_risk >= 7.0]

        recommendations = self._generate_recommendations(all_paths, critical)

        analysis = AttackPathAnalysis(
            analysis_id=f"apa_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            paths=all_paths,
            critical_paths=critical,
            total_nodes=len(self._nodes),
            total_edges=len(self._edges),
            highest_risk=all_paths[0].total_risk if all_paths else 0.0,
            recommendations=recommendations,
            analyzed_at=datetime.now(timezone.utc),
        )

        await self.event_bus.publish(
            topic="attack_path.analyzed",
            payload={
                "total_paths": len(all_paths),
                "critical_paths": len(critical),
                "highest_risk": analysis.highest_risk,
            },
            source=self.name,
        )

        return analysis

    def _find_paths_bfs(self, start: str, max_depth: int = 6) -> List[AttackPath]:
        """البحث عن مسارات بـ BFS."""
        paths: List[AttackPath] = []
        queue: List[Tuple[str, List[str], List[AttackEdge]]] = [
            (start, [start], [])
        ]
        visited: Set[str] = set()

        while queue:
            current, path_nodes, path_edges = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if len(path_nodes) > max_depth:
                continue

            # البحث عن الحواف الصادرة
            for edge in self._edges:
                if edge.source_id == current and edge.target_id not in visited:
                    target_node = self._nodes.get(edge.target_id)
                    if target_node:
                        new_path = path_nodes + [edge.target_id]
                        new_edges = path_edges + [edge]
                        queue.append((edge.target_id, new_path, new_edges))

                        # حساب الخطورة
                        risk = sum(
                            self._nodes[nid].risk_score
                            for nid in new_path
                            if nid in self._nodes
                        )
                        if risk > 0:
                            attack_path = AttackPath(
                                path_id=f"path_{start}_{edge.target_id}",
                                nodes=[
                                    self._nodes[nid]
                                    for nid in new_path
                                    if nid in self._nodes
                                ],
                                edges=new_edges,
                                total_risk=risk,
                                length=len(new_path),
                                entry_point=start,
                                target=edge.target_id,
                            )
                            paths.append(attack_path)

        return paths

    @staticmethod
    def _same_network(a: Dict, b: Dict) -> bool:
        """هل الأصلان في نفس الشبكة؟"""
        return (
            a.get("environment", "") == b.get("environment", "")
            and a.get("network", "") == b.get("network", "")
        )

    def _generate_recommendations(
        self, all_paths: List[AttackPath], critical: List[AttackPath]
    ) -> List[str]:
        """توليد توصيات."""
        recs = []
        if critical:
            recs.append(
                f"⚠️ {len(critical)} مسار هجوم حرجة — عزل الأصول الحرجة أولاً"
            )
        # كشف أنماط
        lateral_count = sum(
            1 for p in all_paths
            if any(e.edge_type == EdgeType.LATERAL_MOVEMENT for e in p.edges)
        )
        if lateral_count > 0:
            recs.append(f"🔗 {lateral_count} مسار يحتوي على حركة جانبية — تحسين التقسيم")
        escalation_count = sum(
            1 for p in all_paths
            if any(e.edge_type == EdgeType.ESCALATES for e in p.edges)
        )
        if escalation_count > 0:
            recs.append(f"⬆️ {escalation_count} مسار ترقي صلاحيات — مراجعة IAM")
        if not all_paths:
            recs.append("✅ لا توجد مسارات هجوم معروفة")
        return recs

    def summary(self) -> Dict[str, Any]:
        """ملخص."""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
        }
