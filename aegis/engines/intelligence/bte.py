"""BTE — محرك التضاريس السلوكية (الطبقة 1).

لا يصدق بانر الخادم؛ يقيس السلوك (زمن، أحجام، رموز أخطاء، تقنيات مسربة
من الهيدرز/الكوكيز). طلبات استكشافية آمنة تماماً — لا حمولات.
"""

from __future__ import annotations

import logging
import statistics
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession, ClientTimeout

from aegis.core.data_manager import DataManager
from aegis.core.event_bus import EventBus
from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.intelligence.bte")


class BTE:
    """بصمة سلوكية للهدف عبر طلبات GET استكشافية آمنة."""

    name = "BTE"
    PROBE_PATHS = ["/", "/nonexistent_page_aegis", "/favicon.ico", "/robots.txt"]

    def __init__(self, event_bus: EventBus, data_manager: DataManager) -> None:
        self.event_bus = event_bus
        self.data_manager = data_manager

    async def analyze_target(self, target_url: str, scan_id: str) -> Optional[Evidence]:
        if not target_url.startswith(("http://", "https://")):
            return None

        logger.info("تحليل سلوكي: %s", target_url)
        profile = await self._collect_profile(target_url)

        evidence = Evidence(
            scan_id=scan_id,
            source_tool="BTE",
            evidence_type=EvidenceType.BEHAVIORAL,
            category=EvidenceCategory.CONFIGURATION,
            description=f"بصمة سلوكية لـ {target_url}",
            location=target_url,
            confidence_weight=0.7,
            context=profile,
        )

        self.data_manager.save_evidence(evidence.to_dict())
        await self.event_bus.publish(
            topic="evidence.new", payload=evidence.to_dict(), source="BTE"
        )
        return evidence

    async def _collect_profile(self, base_url: str) -> Dict[str, Any]:
        responses: List[Dict[str, Any]] = []
        timeout = ClientTimeout(total=10)

        try:
            async with ClientSession(timeout=timeout) as session:
                for path in self.PROBE_PATHS:
                    url = f"{base_url.rstrip('/')}{path}"
                    resp = await self._safe_get(session, url)
                    if resp:
                        responses.append(resp)
        except Exception as exc:  # aiohttp missing أو فشل شبكة عام
            logger.warning("فشل جمع البصمة السلوكية: %s", exc)
            return {"error": str(type(exc).__name__)}

        return self._build_profile(responses)

    @staticmethod
    async def _safe_get(session: ClientSession, url: str) -> Optional[Dict[str, Any]]:
        try:
            async with session.get(url, allow_redirects=False, ssl=False) as resp:
                body = await resp.text(errors="ignore")
                return {
                    "url": url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body_size": len(body),
                    "elapsed": (
                        resp.elapsed.total_seconds() if resp.elapsed else 0.0
                    ),
                }
        except Exception as exc:
            logger.debug("فشل طلب %s: %s", url, type(exc).__name__)
            return None

    @staticmethod
    def _build_profile(responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        ok = [r for r in responses if "status" in r]
        profile: Dict[str, Any] = {
            "total_probes": len(responses),
            "successful_probes": len(ok),
            "status_codes": [r["status"] for r in ok],
        }
        if not ok:
            profile["error"] = "no_responses"
            return profile

        times = [r["elapsed"] for r in ok if r.get("elapsed")]
        if times:
            profile["avg_response_time"] = round(statistics.mean(times), 4)

        sizes = [r.get("body_size", 0) for r in ok]
        profile["avg_body_size"] = round(statistics.mean(sizes), 1)

        verbose_404 = any(
            r["status"] == 404 and r.get("body_size", 0) > 5000 for r in ok
        )
        profile["error_behavior"] = "verbose_errors" if verbose_404 else "standard"

        tech: set = set()
        for r in ok:
            headers = r.get("headers", {})
            server = str(headers.get("Server", "")).lower()
            for known in ("nginx", "apache", "iis", "lighttpd", "caddy"):
                if known in server:
                    tech.add(known)
            powered = headers.get("X-Powered-By")
            if powered:
                tech.add(f"powered:{str(powered).lower()}")
            cookie = str(headers.get("Set-Cookie", "")).lower()
            for marker, name in (
                ("phpsessid", "php"),
                ("jsessionid", "java"),
                ("asp.net_sessionid", "asp.net"),
            ):
                if marker in cookie:
                    tech.add(name)
        profile["detected_tech"] = sorted(tech)
        return profile
