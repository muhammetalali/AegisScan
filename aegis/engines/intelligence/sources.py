"""مصادر الاستخبارات الخارجية — External Intelligence Sources.

كل مصدر يُطبّع مخرجاته إلى Evidence موحدة.
المصادر الحالية: GitHub Advisory, NVD/CVE, OSINT
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from aiohttp import ClientSession

from aegis.models.evidence import Evidence, EvidenceCategory, EvidenceType

logger = logging.getLogger("aegis.intelligence.sources")


class GitHubAdvisorySource:
    """مصدر: GitHub Security Advisories API."""

    SOURCE_ID = "github_advisory"
    API_URL = "https://api.github.com/advisories"

    async def collect(
        self,
        session: ClientSession,
        ecosystem: str = "pip",
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """جمع الإشارات من GitHub Advisory Database."""
        params = {"ecosystem": ecosystem, "per_page": 30}
        if severity:
            params["severity"] = severity

        try:
            async with session.get(
                self.API_URL, params=params, timeout=30
            ) as resp:
                if resp.status != 200:
                    logger.warning("GitHub Advisory %s", resp.status)
                    return []
                data = await resp.json()
        except Exception as exc:
            logger.error("فشل جمع GitHub Advisory: %s", exc)
            return []

        results = []
        for adv in data:
            cve_id = adv.get("cve_id") or adv.get("ghsa_id", "")
            summary = adv.get("summary", "")
            severity_val = adv.get("severity", "unknown")
            published = adv.get("published_at", "")

            # استخراج تبعيات متأثرة
            affected = []
            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                affected.append({
                    "name": pkg.get("name", ""),
                    "ecosystem": pkg.get("ecosystem", ""),
                    "vulnerable_range": vuln.get("vulnerable_version_range", ""),
                })

            results.append({
                "source_id": self.SOURCE_ID,
                "cve_id": cve_id,
                "summary": summary,
                "severity": severity_val,
                "published_at": published,
                "affected_packages": affected,
                "raw_url": adv.get("html_url", ""),
            })

        logger.info("GitHub Advisory: %d إشارات", len(results))
        return results


class NVDSource:
    """مصدر: NIST National Vulnerability Database."""

    SOURCE_ID = "nvd_cve"
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def collect(
        self,
        session: ClientSession,
        keyword: Optional[str] = None,
        results_per_page: int = 20,
    ) -> List[Dict[str, Any]]:
        """جمع الثغرات من NVD."""
        params = {"resultsPerPage": results_per_page}
        if keyword:
            params["keywordSearch"] = keyword

        try:
            async with session.get(
                self.API_URL, params=params, timeout=60
            ) as resp:
                if resp.status != 200:
                    logger.warning("NVD API %s", resp.status)
                    return []
                data = await resp.json()
        except Exception as exc:
            logger.error("فشل جمع NVD: %s", exc)
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # استخراج CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(version_key):
                    cvss_data = metrics[version_key][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    break

            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )

            results.append({
                "source_id": self.SOURCE_ID,
                "cve_id": cve_id,
                "summary": desc_en[:500],
                "cvss_score": cvss_score,
                "published_at": cve.get("published", ""),
            })

        logger.info("NVD: %d ثغرات", len(results))
        return results


class OSINTSource:
    """مصدر: مصادر معلومات مفتوحة (Security Blogs, Forums)."""

    SOURCE_ID = "osint_forums"
    PROBE_URLS = [
        "https://www.exploit-db.com/",
        "https://packetstormsecurity.com/",
    ]

    async def collect(
        self,
        session: ClientSession,
        keywords: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """جمع إشارات من مصادر OSINT (استكشافي — لا ضمانة)."""
        results = []
        for url in self.PROBE_URLS:
            try:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # بحث بسيط عن كلمات مفتاحية أمنية
                        findings = re.findall(
                            r"(?i)(CVE-\d{4}-\d{4,7}|sql injection|xss|"
                            r"remote code execution|buffer overflow)",
                            text[:5000],
                        )
                        if findings:
                            results.append({
                                "source_id": self.SOURCE_ID,
                                "url": url,
                                "matches": list(set(findings))[:10],
                                "summary": f"OSINT signals from {url}",
                            })
            except Exception:
                continue

        logger.info("OSINT: %d إشارات", len(results))
        return results
