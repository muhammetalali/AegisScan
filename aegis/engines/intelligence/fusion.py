"""Evidence Fusion Engine — محرك دمج الأدلة.

يدمج الأدلة الداخلية (AegisScan, BTE) مع الاستخبارات الخارجية (Hub)
ويُنتج أدلة مدعومة بعدة مصادر مع تقييم موثوقية موحد.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

from aegis.core.event_bus import EventBus
from aegis.engines.intelligence.trust import SourceTrustFramework
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.intelligence.fusion")


class EvidenceFusionEngine:
    """محرك دمج الأدلة — يجمع، يُزيل التكرار، ويُقيّم الأدلة المدعومة بعدة مصادر."""

    name = "EvidenceFusionEngine"

    def __init__(
        self,
        event_bus: EventBus,
        trust_framework: Optional[SourceTrustFramework] = None,
    ) -> None:
        self.event_bus = event_bus
        self.trust = trust_framework or SourceTrustFramework()

    async def fuse(
        self,
        internal_evidences: List[Evidence],
        external_evidences: List[Evidence],
    ) -> List[Evidence]:
        """دمج الأدلة الداخلية والخارجية.

        1. دمج التكرارات حسب الموضوع + الموقع
        2. تعزيز الأدلة المدعومة بعدة مصادر
        3. تخفيض ثقة الأدلة الوحيدة
        """
        # فهرسة الأدلة الداخلية بالموضوع + الموقع
        internal_index = self._build_index(internal_evidences)
        fused: List[Evidence] = []
        matched_external: set = set()

        # مرور على الأدلة الخارجية والبحث عن تطابق
        for ext_ev in external_evidences:
            key = self._fingerprint(ext_ev)
            matched = False

            for int_key, int_ev in internal_index.items():
                similarity = self._similarity(key, int_key)
                if similarity > 0.6:
                    # دمج: زيادة الثقة + تحديث السياق
                    merged = self._merge_evidences(int_ev, ext_ev)
                    fused.append(merged)
                    matched_external.add(id(ext_ev))
                    matched = True
                    logger.info(
                        "دمج: %s + %s → ثقة %.2f",
                        int_ev.source_tool, ext_ev.source_tool,
                        merged.confidence_weight,
                    )
                    break

            if not matched:
                # دليل خارجي وحيد — ثقته أقل
                ext_ev.confidence_weight *= 0.7
                fused.append(ext_ev)

        # إضافة الأدلة الداخلية غير المطابقة
        for int_ev in internal_evidences:
            if not any(
                self._fingerprint(int_ev) == self._fingerprint(f)
                for f in fused
            ):
                fused.append(int_ev)

        # ترتيب حسب الثقة
        fused.sort(key=lambda e: e.confidence_weight, reverse=True)

        # نشر الأدلة المُدمجة
        for ev in fused:
            await self.event_bus.publish(
                topic="evidence.fused",
                payload=ev.to_dict(),
                source=self.name,
            )

        logger.info(
            "الدمج: %d داخلية + %d خارجية → %d مدمجة",
            len(internal_evidences), len(external_evidences), len(fused),
        )
        return fused

    @staticmethod
    def _fingerprint(ev: Evidence) -> str:
        """بصمة للدمج: الفئة + الموقع + أول 50 حرف من الوصف."""
        raw = f"{ev.category.value}|{ev.location or ''}|{ev.description[:50]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @staticmethod
    def _build_index(evidences: List[Evidence]) -> Dict[str, Evidence]:
        """بناء فهرس بالبصمة."""
        return {EvidenceFusionEngine._fingerprint(ev): ev for ev in evidences}

    @staticmethod
    def _similarity(key1: str, key2: str) -> float:
        """حساب التشابه بين بصمتين (Hamming ratio)."""
        if key1 == key2:
            return 1.0
        matches = sum(c1 == c2 for c1, c2 in zip(key1, key2))
        return matches / max(len(key1), len(key2))

    def _merge_evidences(
        self, primary: Evidence, secondary: Evidence
    ) -> Evidence:
        """دمج حالتين: تعزيز الثقة + دمج السياق."""
        # حساب الثقة المدمجة
        w1 = primary.confidence_weight
        w2 = secondary.confidence_weight
        merged_confidence = min(
            w1 + w2 * 0.3,  # تعزيز 30% من ثقة الدليل الثاني
            1.0,
        )

        # دمج السياق
        merged_context = {**primary.context}
        merged_context["fused_from"] = [
            primary.source_tool, secondary.source_tool
        ]
        merged_context["fusion_boost"] = round(merged_confidence - w1, 3)

        return Evidence(
            scan_id=primary.scan_id,
            source_tool=f"Fused({primary.source_tool}+{secondary.source_tool})",
            evidence_type=primary.evidence_type,
            category=primary.category,
            description=primary.description,
            location=primary.location,
            raw_data=primary.raw_data,
            confidence_weight=round(merged_confidence, 3),
            context=merged_context,
        )
