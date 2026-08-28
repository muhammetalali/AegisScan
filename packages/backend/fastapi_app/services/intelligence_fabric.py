from __future__ import annotations

import asyncio
import hashlib
import json
import os
import random
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import redis


@dataclass(frozen=True)
class IntelligenceRecord:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss: float | None
    epss: float | None
    kev: bool
    published: str | None
    modified: str | None
    references: tuple[str, ...]
    source: str
    source_url: str
    matched_assets: tuple[str, ...] = ()
    risk_score: float = 0.0
    confidence: float = 0.0
    evidence: tuple[dict[str, Any], ...] = ()


class ProviderUnavailable(RuntimeError):
    pass


class CircuitBreaker:
    def __init__(self, threshold: int = 3, cooldown: float = 30.0):
        self.threshold, self.cooldown = threshold, cooldown
        self.failures = 0
        self.opened_at = 0.0

    def allow(self) -> bool:
        return not self.opened_at or time.monotonic() - self.opened_at >= self.cooldown

    def success(self) -> None:
        self.failures, self.opened_at = 0, 0.0

    def failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold:
            self.opened_at = time.monotonic()


class IntelligenceProvider(ABC):
    name: str
    base_url: str

    @abstractmethod
    async def query(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        raise NotImplementedError


class NVDProvider(IntelligenceProvider):
    name = "nvd"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def query(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        headers = {}
        if os.getenv("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]
        response = await client.get(self.base_url, params={"cveId": cve_id}, headers=headers)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        return vulnerabilities[0].get("cve", {}) if vulnerabilities else {}


class OSVProvider(IntelligenceProvider):
    name = "osv"
    base_url = "https://api.osv.dev/v1/vulns"

    async def query(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        response = await client.get(f"{self.base_url}/{cve_id}")
        if response.status_code == 404:
            return {}
        response.raise_for_status()
        return response.json()


class KEVProvider(IntelligenceProvider):
    name = "cisa_kev"
    base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def query(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        response = await client.get(self.base_url)
        response.raise_for_status()
        for item in response.json().get("vulnerabilities", []):
            if item.get("cveID") == cve_id:
                return item
        return {}


class EPSSProvider(IntelligenceProvider):
    name = "epss"
    base_url = "https://api.first.org/data/v1/epss"

    async def query(self, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        response = await client.get(self.base_url, params={"cve": cve_id})
        response.raise_for_status()
        rows = response.json().get("data", [])
        return rows[0] if rows else {}


class IntelligenceFabric:
    def __init__(self, redis_url: str | None = None):
        self.redis = redis.from_url(redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
        self.providers: dict[str, IntelligenceProvider] = {
            "nvd": NVDProvider(), "osv": OSVProvider(), "cisa_kev": KEVProvider(), "epss": EPSSProvider()
        }
        self.breakers = {name: CircuitBreaker() for name in self.providers}
        self.timeout = float(os.getenv("INTELLIGENCE_HTTP_TIMEOUT", "12"))
        self.retries = int(os.getenv("INTELLIGENCE_HTTP_RETRIES", "3"))
        self.cache_ttl = int(os.getenv("INTELLIGENCE_CACHE_TTL", "21600"))

    def _key(self, cve_id: str) -> str:
        return "aegis:intelligence:v2:" + hashlib.sha256(cve_id.upper().encode()).hexdigest()

    async def _call(self, name: str, client: httpx.AsyncClient, cve_id: str) -> dict[str, Any]:
        breaker = self.breakers[name]
        if not breaker.allow():
            raise ProviderUnavailable(f"{name} circuit is open")
        provider = self.providers[name]
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                result = await provider.query(client, cve_id)
                breaker.success()
                return result
            except (httpx.HTTPError, ProviderUnavailable) as exc:
                last = exc
                if attempt + 1 < self.retries:
                    await asyncio.sleep((2 ** attempt) * 0.25 + random.random() * 0.15)
        breaker.failure()
        raise ProviderUnavailable(f"{name} unavailable: {last}")

    @staticmethod
    def _cvss(nvd: dict[str, Any]) -> float | None:
        metrics = nvd.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            rows = metrics.get(key) or []
            if rows:
                score = rows[0].get("cvssData", {}).get("baseScore")
                return float(score) if score is not None else None
        return None

    @staticmethod
    def _severity(cvss: float | None) -> str:
        if cvss is None: return "unknown"
        if cvss >= 9: return "critical"
        if cvss >= 7: return "high"
        if cvss >= 4: return "medium"
        return "low"

    @staticmethod
    def _normalize(cve_id: str, nvd: dict[str, Any], osv: dict[str, Any], kev: dict[str, Any], epss: dict[str, Any], assets: list[dict[str, Any]]) -> IntelligenceRecord:
        cve_id = cve_id.upper()
        desc = next((x.get("value", "") for x in nvd.get("descriptions", []) if x.get("lang") == "en"), "") or osv.get("details", "")
        cvss = IntelligenceFabric._cvss(nvd)
        epss_score = float(epss.get("epss")) if epss.get("epss") is not None else None
        kev_flag = bool(kev)
        refs = tuple(dict.fromkeys([r.get("url", "") for r in nvd.get("references", []) if r.get("url")] + [r.get("url", "") for r in osv.get("references", []) if r.get("url")]))
        configurations = json.dumps(nvd.get("configurations", []), sort_keys=True).lower()
        matched = []
        for asset in assets:
            fingerprint = " ".join(str(asset.get(k, "")) for k in ("name", "product", "vendor", "version", "cpe")).lower()
            if cve_id.lower() in fingerprint or (fingerprint and any(token in configurations for token in fingerprint.split() if len(token) > 3)):
                matched.append(str(asset.get("id") or asset.get("name") or "unknown"))
        exposure = 1.0 if matched else 0.55
        exploit = 1.0 if kev_flag else (epss_score or 0.0)
        base = cvss or 0.0
        risk = min(100.0, round((base / 10 * 55) + (exploit * 30) + (15 if kev_flag else 0) * exposure, 2))
        evidence = (
            {"source": "nvd", "type": "cve_record", "url": "https://nvd.nist.gov/vuln/detail/" + cve_id},
            {"source": "osv", "type": "vulnerability_record", "url": "https://osv.dev/vulnerability/" + cve_id},
        )
        if kev_flag: evidence += ({"source": "cisa_kev", "type": "known_exploited", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},)
        if epss_score is not None: evidence += ({"source": "epss", "type": "exploit_probability", "value": epss_score},)
        confidence = min(1.0, 0.45 + 0.15 * sum(bool(x) for x in (nvd, osv, kev, epss)))
        return IntelligenceRecord(cve_id=cve_id, title=nvd.get("id", cve_id), description=desc, severity=IntelligenceFabric._severity(cvss), cvss=cvss, epss=epss_score, kev=kev_flag, published=nvd.get("published") or osv.get("published"), modified=nvd.get("lastModified") or osv.get("modified"), references=refs, source="multi-source", source_url="https://nvd.nist.gov/vuln/detail/" + cve_id, matched_assets=tuple(dict.fromkeys(matched)), risk_score=risk, confidence=confidence, evidence=evidence)

    async def enrich(self, cve_id: str, assets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            raise ValueError("cve_id must use CVE-YYYY-NNNN format")
        key = self._key(cve_id)
        cached = await asyncio.to_thread(self.redis.get, key)
        if cached:
            return {**json.loads(cached), "cache": "hit"}
        assets = assets or []
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=5), follow_redirects=True) as client:
            results: dict[str, dict[str, Any]] = {}
            for name in self.providers:
                try:
                    results[name] = await self._call(name, client, cve_id)
                except ProviderUnavailable as exc:
                    results[name] = {"_error": str(exc)}
        record = asdict(self._normalize(cve_id, results["nvd"], results["osv"], results["cisa_kev"], results["epss"], assets))
        await asyncio.to_thread(self.redis.setex, key, self.cache_ttl, json.dumps(record, default=str))
        return {**record, "cache": "miss", "provider_status": {k: "error" if "_error" in v else "ok" for k, v in results.items()}}
