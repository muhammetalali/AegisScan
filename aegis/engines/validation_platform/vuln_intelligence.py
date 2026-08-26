"""Vulnerability Intelligence Engine — محرك استخبارات الثغرات.

المرحلة الثالثة: يجمع معلومات الثغرات من مصادر متعددة ويُقيّمها
ويحسب درجة الخطورة بناءً على التتبع والمصداقية.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus

logger = logging.getLogger("aegis.platform.vuln_intel")


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, Enum):
    OPEN = "open"
    PATCHED = "patched"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"


class ExploitAvailability(str, Enum):
    PUBLIC = "public"         # كود استغلال عام
    WEAPONIZED = "weaponized"  # أداة جاهزة
    POC = "poc"               # إثبات مفهوم
    NONE = "none"             # لا يوجد


@dataclass
class VulnIntelligence:
    """معلومة ثغرة من مصدر خارجي."""
    vuln_id: str
    cve_id: Optional[str]
    title: str
    severity: VulnSeverity
    cvss_score: float = 0.0
    exploit_availability: ExploitAvailability = ExploitAvailability.NONE
    affected_products: List[str] = field(default_factory=list)
    patch_available: bool = False
    patch_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    source: str = ""
    published_at: Optional[str] = None
    last_updated: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnImpact:
    """تقييم تأثير ثغرة على البيئة."""
    vuln_id: str
    affected_assets: List[str] = field(default_factory=list)
    exploitability_score: float = 0.0
    business_impact: str = "unknown"
    risk_score: float = 0.0
    recommendation: str = ""


class VulnerabilityIntelligenceEngine:
    """محرك استخبارات الثغرات — يجمع ويُقيّم وي追跡 الثغرات."""

    name = "VulnerabilityIntelligenceEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._vulns: Dict[str, VulnIntelligence] = {}
        self._impacts: Dict[str, VulnImpact] = {}
        self._history: List[Dict[str, Any]] = []

    async def ingest_vuln(self, vuln: VulnIntelligence) -> VulnIntelligence:
        """إدخال معلومة ثغرة."""
        existing = self._vulns.get(vuln.vuln_id)
        if existing:
            # تحديث
            if vuln.cvss_score > existing.cvss_score:
                vuln.severity = self._score_to_severity(vuln.cvss_score)
            vuln.last_updated = datetime.now(timezone.utc).isoformat()

        self._vulns[vuln.vuln_id] = vuln

        await self.event_bus.publish(
            topic="vuln_intel.ingested",
            payload={
                "vuln_id": vuln.vuln_id,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity.value,
            },
            source=self.name,
        )
        return vuln

    async def assess_impact(
        self,
        vuln_id: str,
        affected_assets: List[str],
        asset_criticalities: Optional[Dict[str, str]] = None,
    ) -> VulnImpact:
        """تقييم تأثير ثغرة على أصول محددة."""
        vuln = self._vulns.get(vuln_id)
        if not vuln:
            raise ValueError(f"ثغرة غير موجودة: {vuln_id}")

        # حساب قابلية الاستغلال
        exploitability = self._calc_exploitability(vuln)

        # حساب تأثير الأعمال
        business_impact = self._calc_business_impact(
            vuln, affected_assets, asset_criticalities or {}
        )

        # النتيجة النهائية
        risk_score = min(
            vuln.cvss_score * 0.4
            + exploitability * 0.3
            + business_impact * 0.3,
            10.0,
        )

        recommendation = self._generate_recommendation(vuln, risk_score)

        impact = VulnImpact(
            vuln_id=vuln_id,
            affected_assets=affected_assets,
            exploitability_score=exploitability,
            business_impact=str(round(business_impact, 1)),
            risk_score=round(risk_score, 1),
            recommendation=recommendation,
        )

        self._impacts[vuln_id] = impact
        self._history.append({
            "vuln_id": vuln_id,
            "action": "impact_assessed",
            "risk_score": risk_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        await self.event_bus.publish(
            topic="vuln_intel.impact_assessed",
            payload={
                "vuln_id": vuln_id,
                "risk_score": risk_score,
                "recommendation": recommendation,
            },
            source=self.name,
        )
        return impact

    async def correlate_with_assets(
        self, vuln_id: str, asset_technologies: Dict[str, List[str]]
    ) -> List[str]:
        """ربط ثغرة بالأصول المتأثرة."""
        vuln = self._vulns.get(vuln_id)
        if not vuln:
            return []

        affected = []
        for asset_id, techs in asset_technologies.items():
            for product in vuln.affected_products:
                if any(product.lower() in t.lower() for t in techs):
                    affected.append(asset_id)
                    break

        return affected

    def get_vuln(self, vuln_id: str) -> Optional[VulnIntelligence]:
        """استرجاع معلومة ثغرة."""
        return self._vulns.get(vuln_id)

    def get_by_severity(self, severity: VulnSeverity) -> List[VulnIntelligence]:
        """استرجاع ثغرات حسب الخطورة."""
        return [v for v in self._vulns.values() if v.severity == severity]

    def get_unpatched(self) -> List[VulnIntelligence]:
        """استرجاع الثغرات غير المعالجة."""
        return [v for v in self._vulns.values() if not v.patch_available]

    def get_with_exploits(self) -> List[VulnIntelligence]:
        """استرجاع الثغرات التي لها استغلال."""
        return [
            v for v in self._vulns.values()
            if v.exploit_availability in (
                ExploitAvailability.PUBLIC, ExploitAvailability.WEAPONIZED
            )
        ]

    def summary(self) -> Dict[str, Any]:
        """ملخص الاستخبارات."""
        by_sev: Dict[str, int] = {}
        for v in self._vulns.values():
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
        return {
            "total_vulns": len(self._vulns),
            "by_severity": by_sev,
            "unpatched": len(self.get_unpatched()),
            "with_exploits": len(self.get_with_exploits()),
        }

    @staticmethod
    def _calc_exploitability(vuln: VulnIntelligence) -> float:
        """حساب قابلية الاستغلال (0-10)."""
        scores = {
            ExploitAvailability.WEAPONIZED: 10.0,
            ExploitAvailability.PUBLIC: 8.0,
            ExploitAvailability.POC: 5.0,
            ExploitAvailability.NONE: 1.0,
        }
        return scores.get(vuln.exploit_availability, 1.0)

    @staticmethod
    def _calc_business_impact(
        vuln: VulnIntelligence,
        affected_assets: List[str],
        criticalities: Dict[str, str],
    ) -> float:
        """حساب التأثير على الأعمال (0-10)."""
        if not affected_assets:
            return 1.0
        crit_scores = {"critical": 10, "high": 7, "medium": 4, "low": 2}
        max_impact = 1.0
        for asset_id in affected_assets:
            crit = criticalities.get(asset_id, "medium")
            score = crit_scores.get(crit, 4)
            max_impact = max(max_impact, score)
        return max_impact

    @staticmethod
    def _generate_recommendation(vuln: VulnIntelligence, risk: float) -> str:
        """توليد توصية."""
        if risk >= 8:
            return "إصلاح فوري — ثغرة حرجة باستغلال متاح"
        if risk >= 6:
            return "إصلاح في أقرب دورة صيانة"
        if risk >= 4:
            return "جدولة الإصلاح مع المراقبة"
        return "ملاحظة للمراجعة الدورية"

    @staticmethod
    def _score_to_severity(score: float) -> VulnSeverity:
        """تحويل CVSS إلى خطورة."""
        if score >= 9.0:
            return VulnSeverity.CRITICAL
        if score >= 7.0:
            return VulnSeverity.HIGH
        if score >= 4.0:
            return VulnSeverity.MEDIUM
        if score >= 0.1:
            return VulnSeverity.LOW
        return VulnSeverity.INFO
