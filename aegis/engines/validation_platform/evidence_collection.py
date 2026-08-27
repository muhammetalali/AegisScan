"""Evidence Collection Engine — محرك جمع الأدلة.

يجمع الأدلة من مصادر متعددة (كود، سجلات، إعدادات، استخبارات)
ويُوحّدها في نموذج موحد مع تتبع المصدر والجودة.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.platform.evidence_collection")


class EvidenceQuality(str, Enum):
    """جودة الدليل."""
    VERIFIED = "verified"       # تم التحقق منه بطرق متعددة
    HIGH = "high"               # من مصدر موثوق
    MEDIUM = "medium"           # من مصدر مقبول
    LOW = "low"                 # من مصدر غير موثوق
    UNVERIFIED = "unverified"   # لم يتم التحقق


class EvidenceSource(str, Enum):
    """مصدر الدليل."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    LOG_ANALYSIS = "log_analysis"
    CONFIG_CHECK = "config_check"
    DEPENDENCY_SCAN = "dependency_scan"
    EXTERNAL_INTEL = "external_intel"
    MANUAL_REVIEW = "manual_review"
    VALIDATION_TEST = "validation_test"


@dataclass
class CollectedEvidence:
    """دليل مجمّع مع معلومات الجودة والتتبع."""
    evidence_id: str
    scan_id: str
    source: EvidenceSource
    quality: EvidenceQuality
    category: EvidenceCategory
    description: str
    location: Optional[str] = None
    raw_data: Optional[str] = None
    confidence: float = 0.5
    corroboration_count: int = 0
    tags: List[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


class EvidenceCollectionEngine:
    """محرك جمع الأدلة — يجمع ويُوحّد ويُقيّم جودة كل دليل."""

    name = "EvidenceCollectionEngine"

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus
        self._evidences: Dict[str, CollectedEvidence] = {}
        self._by_scan: Dict[str, List[str]] = {}

    async def collect_evidence(
        self,
        scan_id: str,
        source: EvidenceSource,
        category: EvidenceCategory,
        description: str,
        confidence: float = 0.5,
        location: Optional[str] = None,
        raw_data: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> CollectedEvidence:
        """جمع دليل واحد."""
        eid = hashlib.sha256(
            f"{scan_id}:{source.value}:{description[:100]}".encode()
        ).hexdigest()[:12]

        quality = self._assess_quality(source, confidence)

        evidence = CollectedEvidence(
            evidence_id=f"ev_{eid}",
            scan_id=scan_id,
            source=source,
            quality=quality,
            category=category,
            description=description,
            location=location,
            raw_data=raw_data,
            confidence=confidence,
            tags=tags or [],
        )

        self._evidences[evidence.evidence_id] = evidence
        self._by_scan.setdefault(scan_id, []).append(evidence.evidence_id)

        await self.event_bus.publish(
            topic="evidence.collected",
            payload={
                "evidence_id": evidence.evidence_id,
                "source": source.value,
                "quality": quality.value,
            },
            source=self.name,
        )

        return evidence

    async def collect_batch(
        self,
        scan_id: str,
        items: List[Dict[str, Any]],
    ) -> List[CollectedEvidence]:
        """جمع مجموعة أدلة دفعة واحدة."""
        results = []
        for item in items:
            ev = await self.collect_evidence(
                scan_id=scan_id,
                source=EvidenceSource(item.get("source", "static_analysis")),
                category=EvidenceCategory(item.get("category", "unknown")),
                description=item["description"],
                confidence=item.get("confidence", 0.5),
                location=item.get("location"),
                raw_data=item.get("raw_data"),
                tags=item.get("tags"),
            )
            results.append(ev)
        return results

    async def corroborate(
        self, evidence_id: str, new_source: EvidenceSource
    ) -> CollectedEvidence:
        """تعزيز دليل بمصدر مستقل إضافي."""
        ev = self._evidences.get(evidence_id)
        if not ev:
            raise ValueError(f"دليل غير موجود: {evidence_id}")

        ev.corroboration_count += 1
        # تعزيز الثقة بمصدر مستقل
        ev.confidence = min(ev.confidence + 0.1, 1.0)
        if ev.corroboration_count >= 2:
            ev.quality = EvidenceQuality.VERIFIED

        await self.event_bus.publish(
            topic="evidence.corroborated",
            payload={
                "evidence_id": evidence_id,
                "corroboration_count": ev.corroboration_count,
                "new_quality": ev.quality.value,
            },
            source=self.name,
        )
        return ev

    def get_evidence(self, evidence_id: str) -> Optional[CollectedEvidence]:
        """استرجاع دليل."""
        return self._evidences.get(evidence_id)

    def get_by_scan(self, scan_id: str) -> List[CollectedEvidence]:
        """استرجاع أدلة فحص معين."""
        ids = self._by_scan.get(scan_id, [])
        return [self._evidences[eid] for eid in ids if eid in self._evidences]

    def get_by_quality(self, quality: EvidenceQuality) -> List[CollectedEvidence]:
        """استرجاع أدلة حسب الجودة."""
        return [e for e in self._evidences.values() if e.quality == quality]

    def get_verified(self) -> List[CollectedEvidence]:
        """استرجاع الأدلة الموثّقة فقط."""
        return self.get_by_quality(EvidenceQuality.VERIFIED)

    def quality_summary(self) -> Dict[str, Any]:
        """ملخص جودة الأدلة."""
        summary: Dict[str, int] = {}
        for e in self._evidences.values():
            summary[e.quality.value] = summary.get(e.quality.value, 0) + 1
        return {
            "total": len(self._evidences),
            "by_quality": summary,
            "verification_rate": (
                summary.get("verified", 0) / max(len(self._evidences), 1)
            ),
        }

    @staticmethod
    def _assess_quality(source: EvidenceSource, confidence: float) -> EvidenceQuality:
        """تقييم جودة الدليل."""
        if confidence >= 0.8 and source in (
            EvidenceSource.STATIC_ANALYSIS,
            EvidenceSource.VALIDATION_TEST,
        ):
            return EvidenceQuality.HIGH
        if confidence >= 0.6:
            return EvidenceQuality.MEDIUM
        if confidence >= 0.3:
            return EvidenceQuality.LOW
        return EvidenceQuality.UNVERIFIED
