"""External Intelligence Hub — محرك تجميع الاستخبارات الخارجية.

يجمع من مصادر متعددة (GitHub, NVD, OSINT)، يمررها عبر Source Trust Framework،
وينتج أدلة موحدة تُدمج مع الأدلة الداخلية.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession

from aegis.core.event_bus import EventBus
from aegis.engines.intelligence.sources import (
    GitHubAdvisorySource,
    NVDSource,
    OSINTSource,
)
from aegis.engines.intelligence.trust import SourceTrustFramework
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.intelligence.hub")


class ExternalIntelligenceHub:
    """محرك تجميع الاستخبارات الخارجية — يجمع، يُوثّق، وينتج أدلة موحدة."""

    name = "ExternalIntelligenceHub"

    def __init__(
        self,
        event_bus: EventBus,
        trust_framework: Optional[SourceTrustFramework] = None,
    ) -> None:
        self.event_bus = event_bus
        self.trust = trust_framework or SourceTrustFramework()
        self._github = GitHubAdvisorySource()
        self._nvd = NVDSource()
        self._osint = OSINTSource()

    async def collect_all(
        self,
        target: str,
        scan_id: str,
        ecosystem: str = "pip",
        keywords: Optional[List[str]] = None,
    ) -> List[Evidence]:
        """جمع الاستخبارات من كل المصادر المتاحة."""
        all_intel: List[Dict[str, Any]] = []

        async with ClientSession() as session:
            # GitHub Advisory
            try:
                gh = await self._github.collect(session, ecosystem=ecosystem)
                all_intel.extend(gh)
            except Exception as exc:
                logger.warning("GitHub Advisory فشل: %s", exc)

            # NVD
            try:
                nvd = await self._nvd.collect(session, keyword=target)
                all_intel.extend(nvd)
            except Exception as exc:
                logger.warning("NVD فشل: %s", exc)

            # OSINT
            try:
                osint = await self._osint.collect(session, keywords=keywords)
                all_intel.extend(osint)
            except Exception as exc:
                logger.warning("OSINT فشل: %s", exc)

        # تمويه كل إشارة إلى Evidence موحدة
        evidences = self._to_evidences(all_intel, scan_id)

        # نشر عبر EventBus
        for ev in evidences:
            await self.event_bus.publish(
                topic="evidence.new",
                payload=ev.to_dict(),
                source=self.name,
            )

        logger.info(
            "الاستخبارات الخارجية: %d إشارة → %d دليل",
            len(all_intel), len(evidences),
        )
        return evidences

    def _to_evidences(
        self, intel_items: List[Dict[str, Any]], scan_id: str
    ) -> List[Evidence]:
        """تحويل الإشارات إلى أدلة موحدة مع تقييم الثقة."""
        evidences: List[Evidence] = []

        for item in intel_items:
            source_id = item.get("source_id", "unknown")
            trust_weight = self.trust.get_weight(source_id)
            cve_id = item.get("cve_id", "")
            summary = item.get("summary", "")

            if not summary:
                continue

            # تحديد الفئة بناءً على المحتوى
            category = self._categorize(item)
            # تحديد النوع
            ev_type = self._determine_type(item)

            description = f"[外部] {source_id}: {summary[:200]}"
            if cve_id:
                description = f"[外部] {cve_id} ({source_id}): {summary[:200]}"

            ev = Evidence(
                scan_id=scan_id,
                source_tool=f"ExtIntel.{source_id}",
                evidence_type=ev_type,
                category=category,
                description=description,
                location=item.get("raw_url") or item.get("url", ""),
                confidence_weight=trust_weight,
                context={
                    "source_id": source_id,
                    "cve_id": cve_id,
                    "trust_level": self.trust.get_profile(source_id).trust_level.value
                    if self.trust.get_profile(source_id) else "unknown",
                    "raw_intel": item,
                },
            )
            evidences.append(ev)

        return evidences

    @staticmethod
    def _categorize(item: Dict[str, Any]) -> EvidenceCategory:
        """تحديد الفئة الأمنية بناءً على محتوى الإشارة."""
        summary = (item.get("summary", "") + item.get("cve_id", "")).lower()
        if any(w in summary for w in ("injection", "sql", "xss", "csrf")):
            return EvidenceCategory.INJECTION
        if any(w in summary for w in ("auth", "login", "password", "credential")):
            return EvidenceCategory.AUTHENTICATION
        if any(w in summary for w in ("privilege", "escalation", "elevat")):
            return EvidenceCategory.PRIVILEGE
        if any(w in summary for w in ("crypt", "ssl", "tls", "cipher")):
            return EvidenceCategory.CRYPTOGRAPHY
        if any(w in summary for w in ("depend", "package", "library", "npm", "pip")):
            return EvidenceCategory.DEPENDENCY
        return EvidenceCategory.UNKNOWN

    @staticmethod
    def _determine_type(item: Dict[str, Any]) -> EvidenceType:
        """تحديد نوع الدليل."""
        source_id = item.get("source_id", "")
        if source_id in ("github_advisory", "nvd_cve", "osv"):
            return EvidenceType.DEPENDENCY
        return EvidenceType.NETWORK
