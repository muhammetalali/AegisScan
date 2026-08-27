"""Source Trust Framework — تقييم موثوقية مصادر الاستخبارات الخارجية.

كل مصدر خارجي يحصل على درجة موثوقية تؤثر على وزن أدلةه عند الدمج.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("aegis.trust")


class TrustLevel(str, Enum):
    """مستويات الموثوقية."""
    VERIFIED = "verified"       # مصدر موثّق رسمياً (NVD, GitHub Advisory)
    HIGH = "high"               # مصدر موثوق (مواقع أمنية معروفة)
    MEDIUM = "medium"           # مصدر مقبول ( منتدى أمني، بحث أكاديمي)
    LOW = "low"                 # مصدر غير موثّق (منشور عشوائي)
    UNKNOWN = "unknown"         # مصدر غير معروف


@dataclass
class SourceProfile:
    """ملف مصدر واحد — يحدد هويته ودرجة موثوقيته."""
    source_id: str
    name: str
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    base_weight: float = 0.5
    description: str = ""
    last_updated: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SourceTrustFramework:
    """إطار تقييم موثوقية المصادر — يُحدّث الأوزان ديناميكياً."""

    def __init__(self) -> None:
        self._profiles: Dict[str, SourceProfile] = {}
        self._initialize_defaults()

    def _initialize_defaults(self) -> None:
        """تهيئة المصادر الافتراضية."""
        defaults = [
            SourceProfile(
                source_id="github_advisory",
                name="GitHub Security Advisories",
                trust_level=TrustLevel.VERIFIED,
                base_weight=0.9,
                description="تقارير أمنية رسمية من GitHub",
            ),
            SourceProfile(
                source_id="nvd_cve",
                name="NIST NVD",
                trust_level=TrustLevel.VERIFIED,
                base_weight=0.95,
                description="قاعدة بيانات الثغرات الرسمية من NIST",
            ),
            SourceProfile(
                source_id="osv",
                name="Open Source Vulnerabilities (OSV)",
                trust_level=TrustLevel.VERIFIED,
                base_weight=0.85,
                description="قاعدة بيانات مفتوحة المصدر للثغرات",
            ),
            SourceProfile(
                source_id="security_blog",
                name="Security Research Blogs",
                trust_level=TrustLevel.MEDIUM,
                base_weight=0.6,
                description="مدونات بحث أمني (SecurityAffairs, Krebs, etc.)",
            ),
            SourceProfile(
                source_id="osint_forums",
                name="OSINT Forums",
                trust_level=TrustLevel.LOW,
                base_weight=0.4,
                description="منتديات مصادر المعلومات المفتوحة",
            ),
            SourceProfile(
                source_id="internal_scan",
                name="Aegis Internal Scan",
                trust_level=TrustLevel.VERIFIED,
                base_weight=1.0,
                description="نتائج الفحص الداخلي للنظام",
            ),
        ]
        for profile in defaults:
            self._profiles[profile.source_id] = profile

    def register_source(self, profile: SourceProfile) -> None:
        """تسجيل مصدر جديد."""
        self._profiles[profile.source_id] = profile
        logger.info("مصدر مسجل: %s (%s)", profile.name, profile.trust_level.value)

    def get_profile(self, source_id: str) -> Optional[SourceProfile]:
        """استرجاع ملف مصدر."""
        return self._profiles.get(source_id)

    def get_weight(self, source_id: str) -> float:
        """حساب وزن مصدر معين (base_weight × multipliers)."""
        profile = self._profiles.get(source_id)
        if not profile:
            return 0.3  # وزن افتراضي لمصادر غير معروفة
        return profile.base_weight

    def evaluate_claim(
        self,
        source_id: str,
        claim_confidence: float,
        corroboration_count: int = 0,
    ) -> float:
        """تقييم مصداقية ادعاء معين.

        Args:
            source_id: معرف المصدر
            claim_confidence: ثقة المصدر الأصلية بالادعاء (0-1)
            corroboration_count: عدد المصادر الأخرى التي تدعم الادعاء

        Returns:
            درجة الثقة المعدّلة (0-1)
        """
        base = self.get_weight(source_id)
        # تعزيز بوجود مصادر مُ助长دة
        corroboration_bonus = min(corroboration_count * 0.1, 0.3)
        return min(base * claim_confidence + corroboration_bonus, 1.0)

    def list_sources(self) -> Dict[str, Dict[str, Any]]:
        """سرد كل المصادر مع ملفاتها."""
        return {
            sid: {
                "name": p.name,
                "trust_level": p.trust_level.value,
                "base_weight": p.base_weight,
            }
            for sid, p in self._profiles.items()
        }
