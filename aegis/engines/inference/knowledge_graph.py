"""Knowledge Graph Engine — محرك الرسم البياني للمعرفة.

يربط بين الأدلة، الثغرات، الأصول، والتهديدات في رسم بياني.
يستخدم NetworkX لتخزين العلاقات واستعلامها.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence,    EvidenceCategory
from aegis.models.finding import Finding, Severity

logger = logging.getLogger("aegis.inference.kg")


class KnowledgeGraphEngine:
    """محرك الرسم البياني — يبني ويتő(query) العلاقات بين الكيانات الأمنية."""

    name = "KnowledgeGraphEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self.graph = nx.DiGraph()

    # ── بناء الرسم البياني ──────────────────────────────

    async def add_evidence(self, evidence: Evidence) -> None:
        """إضافة دليل كعقدة مع ربطه بال Scan."""
        nid = f"ev:{evidence.id}"
        self.graph.add_node(
            nid,
            type="evidence",
            category=evidence.category.value,
            source=evidence.source_tool,
            confidence=evidence.confidence_weight,
            description=evidence.description[:200],
        )
        # ربط بالـ Scan
        scan_nid = f"scan:{evidence.scan_id}"
        self.graph.add_node(scan_nid, type="scan")
        self.graph.add_edge(scan_nid, nid, relation="produces")

        # ربط بالتصنيف
        cat_nid = f"category:{evidence.category.value}"
        self.graph.add_node(cat_nid, type="category")
        self.graph.add_edge(nid, cat_nid, relation="categorized_as")

    async def add_finding(self, finding: Finding) -> None:
        """إضافة ثغرة كعقدة مع ربطها بالأدلة."""
        nid = f"finding:{finding.id}"
        self.graph.add_node(
            nid,
            type="finding",
            severity=finding.severity.value,
            confidence=finding.confidence_score,
            title=finding.title,
        )
        # ربط بالأدلة
        for ev_id in finding.evidence_ids:
            ev_nid = f"ev:{ev_id}"
            if ev_nid in self.graph:
                self.graph.add_edge(ev_nid, nid, relation="supports")

    async def add_asset(self, asset_id: str, asset_type: str, name: str) -> None:
        """إضافة أصل (خادم، تطبيق، قاعدة بيانات)."""
        nid = f"asset:{asset_id}"
        self.graph.add_node(nid, type="asset", asset_type=asset_type, name=name)

    async def link_asset_finding(
        self, asset_id: str, finding_id: str
    ) -> None:
        """ربط أصل بثغرة."""
        asset_nid = f"asset:{asset_id}"
        finding_nid = f"finding:{finding_id}"
        self.graph.add_edge(asset_nid, finding_nid, relation="affected_by")

    # ── استعلامات ────────────────────────────────────────

    def get_evidence_for_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        """استرجاع كل الأدلة الداعمة لثغرة معينة."""
        finding_nid = f"finding:{finding_id}"
        evidences = []
        for predecessor in self.graph.predecessors(finding_nid):
            node = self.graph.nodes[predecessor]
            if node.get("type") == "evidence":
                evidences.append({
                    "id": predecessor.split(":", 1)[1],
                    "category": node.get("category"),
                    "source": node.get("source"),
                    "confidence": node.get("confidence"),
                })
        return evidences

    def get_findings_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        """استرجاع ثغرات أصل معين."""
        asset_nid = f"asset:{asset_id}"
        findings = []
        for successor in self.graph.successors(asset_nid):
            node = self.graph.nodes[successor]
            if node.get("type") == "finding":
                findings.append({
                    "id": successor.split(":", 1)[1],
                    "severity": node.get("severity"),
                    "title": node.get("title"),
                })
        return findings

    def get_related_evidence(
        self, evidence_id: str, max_depth: int = 2
    ) -> List[Dict[str, Any]]:
        """استرجاع الأدلة المترابطة بعمق معين."""
        start = f"ev:{evidence_id}"
        if start not in self.graph:
            return []

        related: List[Dict[str, Any]] = []
        visited: Set[str] = set()

        def _bfs(nid: str, depth: int) -> None:
            if depth > max_depth or nid in visited:
                return
            visited.add(nid)
            for neighbor in set(self.graph.successors(nid)) | set(self.graph.predecessors(nid)):
                node = self.graph.nodes[neighbor]
                if node.get("type") == "evidence" and neighbor != start:
                    related.append({
                        "id": neighbor.split(":", 1)[1],
                        "category": node.get("category"),
                        "confidence": node.get("confidence"),
                    })
                _bfs(neighbor, depth + 1)

        _bfs(start, 0)
        return related

    def get_category_stats(self) -> Dict[str, int]:
        """إحصائيات العقد حسب النوع."""
        stats: Dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            ntype = data.get("type", "unknown")
            stats[ntype] = stats.get(ntype, 0) + 1
        return stats

    def get_high_confidence_findings(
        self, threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """استرجاع الثغرات ذات الثقة العالية."""
        results = []
        for nid, data in self.graph.nodes(data=True):
            if data.get("type") == "finding":
                conf = data.get("confidence", 0)
                if conf >= threshold:
                    results.append({
                        "id": nid.split(":", 1)[1],
                        "severity": data.get("severity"),
                        "title": data.get("title"),
                        "confidence": conf,
                    })
        return results

    def summary(self) -> Dict[str, Any]:
        """ملخص الرسم البياني."""
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "categories": self.get_category_stats(),
        }
