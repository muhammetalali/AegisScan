"""SOC Engine — بناء قصص الهجوم (الطبقة 2).

يحوّل الأدلة والثغرات إلى خط زمني + أنماط هجومية + سرد مقروء.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.models.finding import Severity
from aegis.models.soc import AttackStory

logger = logging.getLogger("aegis.operational.soc")

_SEVERITY_RANK = {s.value: i for i, s in enumerate(Severity)}


class SOCEngine:
    """راوي القصة: من مئات الأحداث إلى حادثة واحدة مفهومة."""

    name = "SOCEngine"

    def __init__(self, event_bus: EventBus, data_manager: DataManager) -> None:
        self.event_bus = event_bus
        self.data_manager = data_manager

    async def build_story(
        self, scan_id: str, findings: List[Dict[str, Any]]
    ) -> Optional[AttackStory]:
        evidences = self.data_manager.get_evidences_by_scan(scan_id)
        if not findings and not evidences:
            return None

        timeline = self._timeline(evidences, findings)
        categories = {ev.get("category") for ev in evidences}
        patterns = self._patterns(categories, findings)
        narrative = self._narrative(timeline, patterns, findings)

        max_severity = max(
            (f.get("severity", "info") for f in findings),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
            default="info",
        )

        story = AttackStory(
            scan_id=scan_id,
            title=narrative["title"],
            summary=narrative["summary"],
            severity=max_severity,
            event_count=len(timeline),
            detected_patterns=[p["name"] for p in patterns],
            pattern_details=patterns,
            recommended_actions=self._actions(patterns),
        )

        await self.event_bus.publish(
            topic="incident.detected", payload=story.to_dict(), source="SOCEngine"
        )
        logger.info("قصة الفحص %s: %s", scan_id, story.title)
        return story

    @staticmethod
    def _timeline(
        evidences: List[Dict[str, Any]], findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for ev in evidences:
            events.append({
                "type": "evidence",
                "timestamp": ev.get("timestamp"),
                "source": ev.get("source_tool"),
                "description": f"[{ev.get('source_tool')}] {ev.get('description')}",
            })
        for f in findings:
            events.append({
                "type": "finding",
                "timestamp": f.get("created_at"),
                "source": "CorrelationEngine",
                "description": (
                    f"ثغرة مؤكدة: {f.get('title')} "
                    f"(خطورة {f.get('severity')}, ثقة "
                    f"{round(float(f.get('confidence_score', 0)) * 100)}%)"
                ),
            })
        return sorted(events, key=lambda e: e.get("timestamp") or "")

    @staticmethod
    def _patterns(
        categories: set, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        patterns: List[Dict[str, Any]] = []

        has_critical = any(f.get("severity") == "critical" for f in findings)
        if "secrets" in categories and "injection" in categories:
            patterns.append({
                "name": "سلسلة اختراق كاملة محتملة",
                "detail": "أسرار مكشوفة + ثغرة حقن في نفس النطاق — "
                          "قد تتيح وصولاً مباشراً لقاعدة البيانات",
                "mitre": "T1552 → T1190",
            })
        elif has_critical:
            patterns.append({
                "name": "ثغرات حرجة قابلة للاستغلال",
                "detail": "ثغرة حرجة واحدة على الأقل بثقة عالية",
                "mitre": "T1190",
            })
        if "authentication" in categories and "injection" in categories:
            patterns.append({
                "name": "استطلاع يتبعه وصول",
                "detail": "مزيج حقن ومصادقة",
                "mitre": "T1595 → T1190",
            })
        return patterns

    @staticmethod
    def _narrative(
        timeline: List[Dict[str, Any]],
        patterns: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, str]:
        if patterns:
            title = f"🚨 {patterns[0]['name']}"
        elif findings:
            title = f"📊 فحص أمني — {len(findings)} ثغرة"
        else:
            title = "✅ فحص نظيف"

        parts = [f"رُصد {len(timeline)} حدثاً خلال الفحص."]
        if patterns:
            parts.append(f"النمط السائد: {patterns[0]['detail']}.")
        if timeline:
            parts.append(f"البداية: {timeline[0]['description']}")
        return {"title": title, "summary": " ".join(parts)}

    @staticmethod
    def _actions(patterns: List[Dict[str, Any]]) -> List[str]:
        names = " ".join(p["name"] for p in patterns)
        actions: List[str] = []
        if "أسرار" in names:
            actions += [
                "🔑 تدوير جميع المفاتيح المكشوفة فوراً",
                "🔐 نقل الأسرار إلى Vault/متغيرات بيئة",
            ]
        if "حقن" in names or "وصول" in names:
            actions += [
                "🔒 Parameterized Queries في كل الاستعلامات",
                "🛡️ تفعيل WAF على نقاط الوصول",
            ]
        if not actions:
            actions.append("📋 مراجعة الثغرات وتطبيق الإصلاحات حسب الأولوية")
        return actions
