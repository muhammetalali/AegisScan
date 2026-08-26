"""Runtime Analysis Engine — محرك تحليل سلوك التشغيل.

يحلل ملفات السجلات (logs) لاكتشاف أنماط سلوكية مشبوهة.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.analysis.runtime")

# أنماط السجلات المشبوهة
LOG_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"(?i)(?:error|exception|traceback)",
        "severity": "medium",
        "category": EvidenceCategory.UNKNOWN,
        "desc": "خطأ في السجلات — قد يدل على ثغرة",
    },
    {
        "pattern": r"(?i)(?:segfault|segmentation fault|core dumped)",
        "severity": "high",
        "category": EvidenceCategory.UNKNOWN,
        "desc": "انهيار ذاكرة — ثغرة buffer overflow محتملة",
    },
    {
        "pattern": r"(?i)(?:unauthorized|forbidden|401|403)",
        "severity": "medium",
        "category": EvidenceCategory.AUTHENTICATION,
        "desc": "خطأ صلاحية — محاولة وصول غير مصرّح بها",
    },
    {
        "pattern": r"(?i)(?:brute.?force|multiple.?failed.?login|login.?failed)",
        "severity": "high",
        "category": EvidenceCategory.AUTHENTICATION,
        "desc": "محاولة تخمين كلمة مرور",
    },
    {
        "pattern": r"(?i)(?:sql.?syntax|mysql.?error|ora-\d{5})",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "desc": "خطأ SQL — ثغرة SQL Injection محتملة",
    },
    {
        "pattern": r"(?i)(?:xxe|xml.?external|entity.?expansion)",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "desc": "إشارة إلى XXE Injection",
    },
    {
        "pattern": r"(?i)(?:path.?traversal|directory.?traversal|\.\.\/|\.\.\\)",
        "severity": "high",
        "category": EvidenceCategory.INJECTION,
        "desc": "محاولة تجاوز مسار — Path Traversal",
    },
]


class RuntimeAnalysisEngine:
    """محرك تحليل سلوك التشغيل — يفحص السجلات لاكتشاف الثغرات."""

    name = "RuntimeAnalysisEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    async def analyze_logs(
        self,
        log_path: str,
        scan_id: str,
        max_lines: int = 10000,
    ) -> List[Evidence]:
        """تحليل ملف سجلات واحد."""
        path = Path(log_path)
        if not path.exists():
            logger.warning("ملف سجلات غير موجود: %s", log_path)
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines = content.splitlines()[:max_lines]
        evidences = self._scan_log_lines(lines, scan_id, str(path))

        for ev in evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        logger.info("تحليل %s: %d أدلة", log_path, len(evidences))
        return evidences

    async def analyze_log_content(
        self,
        log_content: str,
        scan_id: str,
        source_name: str = "runtime",
    ) -> List[Evidence]:
        """تحليل محتوى سجلات كنص."""
        lines = log_content.splitlines()
        evidences = self._scan_log_lines(lines, scan_id, source_name)

        for ev in evidences:
            await self.event_bus.publish(
                topic="evidence.new", payload=ev.to_dict(), source=self.name
            )

        return evidences

    def _scan_log_lines(
        self,
        lines: List[str],
        scan_id: str,
        source: str,
    ) -> List[Evidence]:
        """فحص أسطر السجلات."""
        evidences: List[Evidence] = []
        seen: set = set()

        for i, line in enumerate(lines, 1):
            for pat_def in LOG_PATTERNS:
                if re.search(pat_def["pattern"], line, re.IGNORECASE):
                    key = f"{pat_def['desc']}:{i}"
                    if key in seen:
                        continue
                    seen.add(key)

                    evidences.append(Evidence(
                        scan_id=scan_id,
                        source_tool="RuntimeAnalysis.logs",
                        evidence_type=EvidenceType.NETWORK,
                        category=pat_def["category"],
                        description=f"{pat_def['desc']} [{source}:{i}]",
                        location=source,
                        context={
                            "source": source,
                            "line_no": i,
                            "severity": pat_def["severity"],
                            "matched_line": line.strip()[:200],
                        },
                    ))
                    break  # سطر واحد = دليل واحد

        return evidences
