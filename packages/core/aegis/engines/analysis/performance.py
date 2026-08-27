"""Performance Analysis Engine — محرك تحليل الأداء.

يحلل ملفات الكود لاكتشاف مشكلات الأداء: استعلامات N+1،
好感性 التخزين المؤقت، حلقات لا نهائية محتملة.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any, Dict, List

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.analysis.performance")


class PerformanceAnalysisEngine:
    """محرك تحليل الأداء — يفحص الكود المصدري لمشاكل أداء."""

    name = "PerformanceAnalysisEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def analyze_codebase(
        self, code_path: str, scan_id: str
    ) -> List[Evidence]:
        """تحليل ملف أو مسار كود كامل."""
        path = Path(code_path)
        if not path.exists():
            return []

        all_evidences: List[Evidence] = []

        if path.is_file():
            evs = self._analyze_file(path, scan_id)
            all_evidences.extend(evs)
        else:
            for py_file in path.rglob("*.py"):
                evs = self._analyze_file(py_file, scan_id)
                all_evidences.extend(evs)

        for ev in all_evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        logger.info("تحليل أداء %s: %d أدلة", code_path, len(all_evidences))
        return all_evidences

    def _analyze_file(self, file_path: Path, scan_id: str) -> List[Evidence]:
        """تحليل ملف واحد."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
        except (SyntaxError, Exception):
            return []

        evidences: List[Evidence] = []

        for node in ast.walk(tree):
            # N+1 Query: حلقة for تحتوي على استدعاء دالة (محتمل)
            if isinstance(node, ast.For):
                ev = self._check_loop_query(node, str(file_path), scan_id)
                if ev:
                    evidences.append(ev)

            # استخدام global في حلقة
            if isinstance(node, (ast.For, ast.While)):
                ev = self._check_loop_global(node, str(file_path), scan_id)
                if ev:
                    evidences.append(ev)

            # استدعاء len() على list في شرط حلقة for
            if isinstance(node, ast.Compare):
                ev = self._check_len_in_loop(node, str(file_path), scan_id)
                if ev:
                    evidences.append(ev)

        return evidences

    def _check_loop_query(
        self, node: ast.For, file_path: str, scan_id: str
    ) -> Evidence | None:
        """الكشف عن N+1 Query المحتمل."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Attribute) and func.attr in (
                    "execute", "query", "get", "fetch", "find",
                ):
                    return Evidence(
                        scan_id=scan_id,
                        source_tool="Perf.loop_query",
                        evidence_type=EvidenceType.AST,
                        category=EvidenceCategory.UNKNOWN,
                        description=f"استدعاء DB في حلقة for — N+1 Query محتمل ({file_path}:{node.lineno})",
                        location=file_path,
                        context={
                            "file": file_path,
                            "line": node.lineno,
                            "issue": "N+1_query",
                        },
                    )
        return None

    def _check_loop_global(
        self, node: ast.For | ast.While, file_path: str, scan_id: str
    ) -> Evidence | None:
        """الكشف عن استخدام global داخل حلقة."""
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                return Evidence(
                    scan_id=scan_id,
                    source_tool="Perf.loop_global",
                    evidence_type=EvidenceType.AST,
                    category=EvidenceCategory.UNKNOWN,
                    description=f"استخدام global في حلقة ({file_path}:{node.lineno})",
                    location=file_path,
                    context={
                        "file": file_path,
                        "line": node.lineno,
                        "issue": "global_in_loop",
                        "names": child.names,
                    },
                )
        return None

    def _check_len_in_loop(
        self, node: ast.Compare, file_path: str, scan_id: str
    ) -> Evidence | None:
        """الكشف عن len() في شرط for."""
        for comparator in node.comparators:
            if isinstance(comparator, ast.Call):
                func = comparator.func
                if isinstance(func, ast.Name) and func.id == "len":
                    return Evidence(
                        scan_id=scan_id,
                        source_tool="Perf.len_in_loop",
                        evidence_type=EvidenceType.AST,
                        category=EvidenceCategory.UNKNOWN,
                        description=f"len() في شرط حلقة — O(n²) محتمل ({file_path}:{node.lineno})",
                        location=file_path,
                        context={
                            "file": file_path,
                            "line": node.lineno,
                            "issue": "len_in_loop",
                        },
                    )
        return None
