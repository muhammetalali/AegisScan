from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class ThreatIntelItem:
    indicator: str
    kind: str
    confidence: float
    source: str
    observed_at: str | None = None
    provenance: dict[str, Any] | None = None


class ExternalIntelProvider(ABC):
    name: str

    @abstractmethod
    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        raise NotImplementedError


class _HttpProvider(ExternalIntelProvider):
    timeout = float(os.getenv("INTELLIGENCE_EXTERNAL_TIMEOUT", "12"))

    async def _get(self, url: str, *, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None) -> httpx.Response:
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response


class GreyNoiseProvider(_HttpProvider):
    name = "greynoise"

    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        token = os.getenv("GREYNOISE_API_KEY")
        if not token:
            return []
        url = f"https://api.greynoise.io/v3/community/{indicator}"
        response = await self._get(url, headers={"key": token, "Accept": "application/json"})
        data = response.json()
        if not isinstance(data, dict):
            return []
        confidence = 0.9 if data.get("noise") else 0.7 if data.get("riot") else 0.4
        return [ThreatIntelItem(
            indicator=indicator,
            kind="greynoise_context",
            confidence=confidence,
            source=self.name,
            observed_at=str(data.get("last_seen") or "") or None,
            provenance={"classification": data.get("classification"), "noise": data.get("noise"), "riot": data.get("riot"), "name": data.get("name")},
        )]


class GithubAdvisoryProvider(_HttpProvider):
    name = "github_advisory"

    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        token = os.getenv("GITHUB_ADVISORY_TOKEN") or os.getenv("GITHUB_TOKEN")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = await self._get(
            "https://api.github.com/security-advisories",
            headers=headers,
            params={"cve_id": indicator.upper(), "per_page": 100},
        )
        data = response.json()
        if not isinstance(data, list):
            return []
        items: list[ThreatIntelItem] = []
        for advisory in data:
            items.append(ThreatIntelItem(
                indicator=indicator,
                kind="github_security_advisory",
                confidence=0.85,
                source=self.name,
                observed_at=str(advisory.get("updated_at") or "") or None,
                provenance={
                    "ghsa_id": advisory.get("ghsa_id"),
                    "severity": advisory.get("severity"),
                    "summary": advisory.get("summary"),
                    "html_url": advisory.get("html_url"),
                    "published_at": advisory.get("published_at"),
                },
            ))
        return items


class ShodanHostProvider(_HttpProvider):
    name = "shodan"

    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return []
        response = await self._get(f"https://api.shodan.io/shodan/host/{indicator}", params={"key": api_key})
        data = response.json()
        if not isinstance(data, dict):
            return []
        return [ThreatIntelItem(
            indicator=indicator,
            kind="shodan_host",
            confidence=0.9,
            source=self.name,
            observed_at=str(data.get("last_update") or "") or None,
            provenance={
                "organization": data.get("org"),
                "isp": data.get("isp"),
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name"),
            },
        )]


class DisabledDarkIntelProvider(ExternalIntelProvider):
    """Safe boundary: no anonymous-market scraping or illicit collection."""

    name = "dark-intel-disabled"

    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        return []


class ExternalIntelligenceFabric:
    def __init__(self, providers: list[ExternalIntelProvider] | None = None):
        self.providers = providers or [
            GreyNoiseProvider(),
            GithubAdvisoryProvider(),
            ShodanHostProvider(),
            DisabledDarkIntelProvider(),
        ]

    async def search(self, indicator: str) -> dict[str, Any]:
        items: list[ThreatIntelItem] = []
        status: dict[str, str] = {}
        for provider in self.providers:
            try:
                provider_items = await provider.search(indicator)
                items.extend(provider_items)
                status[provider.name] = "ok" if provider_items or provider.name == "github_advisory" else "not_configured"
            except Exception as exc:
                status[provider.name] = f"error:{type(exc).__name__}"
        return {"indicator": indicator, "items": [item.__dict__ for item in items], "provider_status": status}
