"""Correlation Engine — محرك الربط وحساب الثقة (الطبقة 2).

الإصلاح الحرج #3: المعادلة في الأكواد السابقة كانت معطوبة رياضياً
(لا تتجاوز 0.35 عملياً → لا ثغرة تُعلن أبداً). المعادلة المصححة:

    base        = 0.45  (دليلان مستقلان متفقاان)
    + 0.15      وجود دليل سلوكي (BEHAVIORAL/NETWORK/VERIFICATION/EXPLOIT)
    + 0.15      وجود دليل هيكلي (AST/DATA_FLOW/TAINT/SECRET)
    + 0.05 ×    كل مصدر إضافي فوق الثاني (حد أقصى +0.15)
    + 0.05      وجود دليل تاريخي (DEPENDENCY/DARKWEB/LOG)
    − 0.15 ×    كل تعارض (مثلاً: خادمان مختلفان → تمويه/WAF)

القاعدة الصارمة: مجموعة بدون دليلين من مصدرين مستقلين → مرفوضة.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.models.evidence import EvidenceCategory, EvidenceType
from aegis.models.finding import Finding, FindingStatus, Severity

logger = logging.getLogger("aegis.operational.correlation")

BASE_CONFIDENCE = 0.45
BEHAVIORAL_BONUS = 0.15
STRUCTURAL_BONUS = 0.15
EXTRA_SOURCE_BONUS = 0.05
HISTORICAL_BONUS = 0.05
CONFLICT_PENALTY = 0.15

BEHAVIORAL_TYPES = {
    EvidenceType.BEHAVIORAL,
    EvidenceType.NETWORK,
    EvidenceType.VERIFICATION,
    EvidenceType.EXPLOIT,
}
STRUCTURAL_TYPES = {
    EvidenceType.AST,
    EvidenceType.DATA_FLOW,
    EvidenceType.TAINT,
    EvidenceType.SECRET,
}
HISTORICAL_TYPES = {
    EvidenceType.DEPENDENCY,
    EvidenceType.DARKWEB,
    EvidenceType.LOG,
}

SERVER_NAMES = ("apache", "nginx", "iis", "lighttpd", "caddy")


class CorrelationEngine:
    """يجمع الأدلة، يرفض الضعيف، ويحكم بالباقي بمعادلة صريحة."""

    name = "CorrelationEngine"

    def __init__(
        self,
        event_bus: EventBus,
        data_manager: DataManager,
        confidence_threshold: float = 0.60,
    ) -> None:
        self.event_bus = event_bus
        self.data_manager = data_manager
        self.confidence_threshold = confidence_threshold

    async def correlate_scan(self, scan_id: str) -> List[Finding]:
        evidences = self.data_manager.get_evidences_by_scan(scan_id)
        if not evidences:
            logger.info("لا أدلة للفحص %s", scan_id)
            return []

        logger.info("ربط %d دليل للفحص %s", len(evidences), scan_id)
        findings: List[Finding] = []

        for category, group in self._group_by_category(evidences).items():
            sources = {ev.get("source_tool") for ev in group}
            if len(sources) < 2:
                logger.debug(
                    "رفض %s: مصدر واحد فقط %s", category.value, sorted(sources)
                )
                continue

            deduped = self._deduplicate(group)
            if len({ev.get("source_tool") for ev in deduped}) < 2:
                continue

            confidence, reasoning = self._confidence(deduped)
            if confidence < self.confidence_threshold:
                logger.debug(
                    "رفض %s: ثقة %.2f < %.2f",
                    category.value, confidence, self.confidence_threshold,
                )
                continue

            finding = Finding(
                scan_id=scan_id,
                title=self._title(category),
                severity=self._severity(category, confidence),
                confidence_score=round(confidence, 3),
                status=FindingStatus.CORRELATED,
                category=category,
                description=self._description(deduped),
                root_cause=self._root_cause(deduped),
                remediation_suggestion=self._remediation(category),
                evidence_ids=[ev["id"] for ev in deduped],
                context={
                    "reasoning": reasoning,
                    "unique_sources": sorted(
                        {ev.get("source_tool") for ev in deduped}
                    ),
                },
            )

            self.data_manager.save_finding(finding.to_dict())
            await self.event_bus.publish(
                topic="finding.new", payload=finding.to_dict(),
                source="CorrelationEngine",
            )
            findings.append(finding)

        logger.info(
            "اكتمل الربط: %d ثغرة من %d دليل", len(findings), len(evidences)
        )
        return findings

    # ─── التجميع والتنقية ─────────────────────────────────────

    @staticmethod
    def _group_by_category(
        evidences: List[Dict[str, Any]],
    ) -> Dict[EvidenceCategory, List[Dict[str, Any]]]:
        grouped: Dict[EvidenceCategory, List[Dict[str, Any]]] = defaultdict(list)
        for ev in evidences:
            try:
                cat = EvidenceCategory(ev.get("category", "unknown"))
            except ValueError:
                cat = EvidenceCategory.UNKNOWN
            grouped[cat].append(ev)
        return dict(grouped)

    @staticmethod
    def _deduplicate(evidences: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set = set()
        unique: List[Dict[str, Any]] = []
        for ev in evidences:
            h = ev.get("content_hash")
            if h:
                if h in seen:
                    continue
                seen.add(h)
            unique.append(ev)
        return unique

    # ─── المعادلة المصححة ─────────────────────────────────────

    def _confidence(
        self, evidences: List[Dict[str, Any]]
    ) -> Tuple[float, Dict[str, Any]]:
        groups = {"behavioral": 0, "structural": 0, "historical": 0}
        for ev in evidences:
            try:
                etype = EvidenceType(ev.get("evidence_type"))
            except ValueError:
                continue
            if etype in BEHAVIORAL_TYPES:
                groups["behavioral"] += 1
            elif etype in STRUCTURAL_TYPES:
                groups["structural"] += 1
            elif etype in HISTORICAL_TYPES:
                groups["historical"] += 1

        all_sources = {ev.get("source_tool") for ev in evidences}
        extra = max(0, len(all_sources) - 2)

        conflicts, conflict_details = self._detect_conflicts(evidences)

        score = (
            BASE_CONFIDENCE
            + (BEHAVIORAL_BONUS if groups["behavioral"] else 0)
            + (STRUCTURAL_BONUS if groups["structural"] else 0)
            + min(extra * EXTRA_SOURCE_BONUS, 0.15)
            + (HISTORICAL_BONUS if groups["historical"] else 0)
            - conflicts * CONFLICT_PENALTY
        )
        score = max(0.0, min(1.0, score))

        reasoning = {
            "formula": (
                f"base={BASE_CONFIDENCE} "
                f"+behavioral={BEHAVIORAL_BONUS if groups['behavioral'] else 0} "
                f"+structural={STRUCTURAL_BONUS if groups['structural'] else 0} "
                f"+extra_sources={min(extra * EXTRA_SOURCE_BONUS, 0.15):.2f} "
                f"+historical={HISTORICAL_BONUS if groups['historical'] else 0} "
                f"-conflicts={conflicts * CONFLICT_PENALTY:.2f}"
            ),
            "counts": groups,
            "unique_source_count": len(all_sources),
            "conflicts": conflict_details,
            "final_score": round(score, 3),
        }
        return score, reasoning

    @staticmethod
    def _detect_conflicts(
        evidences: List[Dict[str, Any]]
    ) -> Tuple[int, List[Dict[str, Any]]]:
        server_claims: Dict[str, set] = defaultdict(set)
        for ev in evidences:
            ctx = ev.get("context") or {}
            detected = ctx.get("detected_tech") or []
            if isinstance(detected, str):
                detected = [detected]
            for tech in detected:
                tech_l = str(tech).lower()
                for server in SERVER_NAMES:
                    if server in tech_l:
                        server_claims[server].add(ev.get("source_tool", "?"))

        details: List[Dict[str, Any]] = []
        if len(server_claims) > 1:
            details.append({
                "type": "server_mismatch",
                "claims": {k: sorted(v) for k, v in server_claims.items()},
                "interpretation": (
                    "تضارب في نوع الخادم بين المصادر — احتمال WAF أو تمويه"
                ),
            })
        return len(details), details

    # ─── التصنيف ──────────────────────────────────────────────

    @staticmethod
    def _severity(category: EvidenceCategory, confidence: float) -> Severity:
        if category in (EvidenceCategory.SECRETS, EvidenceCategory.INJECTION):
            return Severity.CRITICAL if confidence >= 0.75 else Severity.HIGH
        if category in (
            EvidenceCategory.AUTHENTICATION, EvidenceCategory.AUTHORIZATION,
            EvidenceCategory.PRIVILEGE,
        ):
            return Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM
        if category in (
            EvidenceCategory.CRYPTOGRAPHY, EvidenceCategory.CONFIGURATION,
            EvidenceCategory.BUSINESS_LOGIC,
        ):
            return Severity.MEDIUM
        if category == EvidenceCategory.INFORMATION_DISCLOSURE:
            return Severity.LOW
        return Severity.MEDIUM

    @staticmethod
    def _title(category: EvidenceCategory) -> str:
        titles = {
            EvidenceCategory.INJECTION: "ثغرة حقن مؤكدة عبر أدلة متعددة",
            EvidenceCategory.SECRETS: "تسريب أسرار حساسة في الكود",
            EvidenceCategory.AUTHENTICATION: "ضعف مصادقة مؤكد",
            EvidenceCategory.AUTHORIZATION: "خلل صلاحيات مؤكد",
            EvidenceCategory.PRIVILEGE: "مسار رفع صلاحيات محتمل",
            EvidenceCategory.CRYPTOGRAPHY: "ضعف تشفيري",
            EvidenceCategory.CONFIGURATION: "إعدادات غير آمنة",
            EvidenceCategory.DEPENDENCY: "تبعية قديمة أو معروفة الثغرات",
            EvidenceCategory.BUSINESS_LOGIC: "خلل منطق أعمال",
            EvidenceCategory.INFORMATION_DISCLOSURE: "تسريب معلومات",
        }
        return titles.get(category, f"مشكلة أمنية: {category.value}")

    @staticmethod
    def _description(evidences: List[Dict[str, Any]]) -> str:
        lines = [
            f"- [{ev.get('source_tool')}] {ev.get('description')}"
            for ev in evidences[:5]
        ]
        return (
            f"تم ربط {len(evidences)} دليل مستقل:\n" + "\n".join(lines)
        )

    @staticmethod
    def _root_cause(evidences: List[Dict[str, Any]]) -> str:
        for ev in evidences:
            ctx = ev.get("context") or {}
            if isinstance(ctx, str):
                continue
            if "function" in ctx:
                return f"استخدام دالة خطيرة: {ctx['function']}()"
            if "secret_type" in ctx:
                return f"تضمين {ctx['secret_type']} داخل الكود"
            if "dependency" in ctx:
                return f"اعتماد على مكتبة: {ctx['dependency']}"
        return "قيد التحليل"

    @staticmethod
    def _remediation(category: EvidenceCategory) -> str:
        suggestions = {
            EvidenceCategory.INJECTION: (
                "استخدم Parameterized Queries وتجنب دمج النصوص في الاستعلامات."
            ),
            EvidenceCategory.SECRETS: (
                "انقل الأسرار إلى Vault/متغيرات البيئة ودوّر المفاتيح فوراً."
            ),
            EvidenceCategory.AUTHENTICATION: (
                "فعّل MFA وRate Limiting على نقاط المصادقة."
            ),
            EvidenceCategory.DEPENDENCY: "رقّ المكتبة لأحدث إصدار آمن.",
            EvidenceCategory.CONFIGURATION: (
                "راجع الإعدادات وطبّق مبدأ أقل صلاحية."
            ),
        }
        return suggestions.get(
            category, "راجع الكود وفق أفضل الممارسات الأمنية."
        )
