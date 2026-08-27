"""مصادر استخبارات سلبية اختيارية لا ترسل حزمًا إلى الهدف.

كل مزود معطل افتراضيًا، ولا يعمل إلا عند توفر بيانات الاعتماد الخاصة به.
الاستجابة تُحوّل إلى ملاحظات موحدة، وفشل مزود واحد لا يوقف عملية الجمع.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

logger = logging.getLogger("aegis.intelligence.passive")


@dataclass(frozen=True)
class PassiveObservation:
    provider: str
    target: str
    summary: str
    source_url: str = ""
    confidence: float = 0.5
    metadata: dict[str, Any] | None = None


class PassiveProvider(Protocol):
    name: str

    def available(self) -> bool: ...

    async def collect(self, target: str) -> list[PassiveObservation]: ...


class HttpPassiveProvider:
    """قاعدة لمزود HTTP بمهلة وحجم استجابة محدودين."""

    max_response_bytes = 2_000_000

    def __init__(self, name: str, api_key_env: str, timeout: float = 8.0) -> None:
        self.name = name
        self.api_key_env = api_key_env
        self.timeout = timeout

    def available(self) -> bool:
        return bool(os.getenv(self.api_key_env))

    async def collect(self, target: str) -> list[PassiveObservation]:
        if not self.available():
            return []
        try:
            payload, source_url = await asyncio.to_thread(self._request, target)
            return self.normalize(target, payload, source_url)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            return []

    def _request(self, target: str) -> tuple[dict[str, Any], str]:
        url, headers = self.build_request(target)
        request = Request(url, headers=headers, method="GET")
        with urlopen(request, timeout=self.timeout) as response:  # nosec B310 - fixed HTTPS provider URLs
            body = response.read(self.max_response_bytes + 1)
        if len(body) > self.max_response_bytes:
            raise ValueError("passive provider response is too large")
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("passive provider response must be an object")
        return payload, url

    def build_request(self, target: str) -> tuple[str, dict[str, str]]:
        raise NotImplementedError

    def normalize(
        self, target: str, payload: dict[str, Any], source_url: str
    ) -> list[PassiveObservation]:
        raise NotImplementedError


class ShodanProvider(HttpPassiveProvider):
    def __init__(self) -> None:
        super().__init__("shodan", "SHODAN_API_KEY")

    def build_request(self, target: str) -> tuple[str, dict[str, str]]:
        key = quote(os.environ[self.api_key_env], safe="")
        return f"https://api.shodan.io/shodan/host/{quote(target, safe='')}?key={key}", {}

    def normalize(self, target, payload, source_url):
        ports = payload.get("ports", [])
        return [PassiveObservation(
            provider=self.name,
            target=target,
            summary=f"Shodan سجل {len(ports)} منافذ تاريخية لهذا الأصل",
            source_url=source_url,
            confidence=0.7,
            metadata={"ports": ports, "organization": payload.get("org"), "os": payload.get("os")},
        )]


class CensysProvider(HttpPassiveProvider):
    def __init__(self) -> None:
        super().__init__("censys", "CENSYS_API_ID")

    def available(self) -> bool:
        return bool(os.getenv(self.api_key_env) and os.getenv("CENSYS_API_SECRET"))

    def build_request(self, target: str) -> tuple[str, dict[str, str]]:
        token = base64.b64encode(
            f"{os.environ[self.api_key_env]}:{os.environ['CENSYS_API_SECRET']}".encode()
        ).decode()
        return f"https://search.censys.io/api/v2/hosts/{quote(target, safe='')}", {
            "Authorization": f"Basic {token}",
        }

    def normalize(self, target, payload, source_url):
        result = payload.get("result", payload)
        services = result.get("services", []) if isinstance(result, dict) else []
        return [PassiveObservation(
            provider=self.name,
            target=target,
            summary=f"Censys سجل {len(services)} خدمات تاريخية لهذا الأصل",
            source_url=source_url,
            confidence=0.7,
            metadata={"services": services[:100]},
        )]


class AlienVaultOTXProvider(HttpPassiveProvider):
    def __init__(self) -> None:
        super().__init__("alienvault_otx", "OTX_API_KEY")

    def build_request(self, target: str) -> tuple[str, dict[str, str]]:
        return f"https://otx.alienvault.com/api/v1/indicators/IPv4/{quote(target, safe='')}/general", {
            "X-OTX-API-KEY": os.environ[self.api_key_env],
        }

    def normalize(self, target, payload, source_url):
        pulses = payload.get("pulse_info", {}).get("count", 0)
        return [PassiveObservation(
            provider=self.name,
            target=target,
            summary=f"OTX وجد {pulses} مؤشرات تاريخية مرتبطة بالأصل",
            source_url=source_url,
            confidence=0.6,
            metadata={"pulse_count": pulses, "asn": payload.get("asn")},
        )]


class URLScanProvider(HttpPassiveProvider):
    def __init__(self) -> None:
        super().__init__("urlscan", "URLSCAN_API_KEY")

    def build_request(self, target: str) -> tuple[str, dict[str, str]]:
        return f"https://urlscan.io/api/v1/search/?q=domain:{quote(target, safe='')}", {
            "API-Key": os.environ[self.api_key_env],
        }

    def normalize(self, target, payload, source_url):
        results = payload.get("results", [])
        return [PassiveObservation(
            provider=self.name,
            target=target,
            summary=f"URLScan سجل {len(results)} نتائج تاريخية للنطاق",
            source_url=source_url,
            confidence=0.6,
            metadata={"results": results[:100]},
        )]


DEFAULT_PASSIVE_PROVIDERS: tuple[PassiveProvider, ...] = (
    ShodanProvider(),
    CensysProvider(),
    AlienVaultOTXProvider(),
    URLScanProvider(),
)


async def collect_passive(
    target: str, providers: tuple[PassiveProvider, ...] = DEFAULT_PASSIVE_PROVIDERS
) -> list[PassiveObservation]:
    """جمع الملاحظات المتاحة فقط، مع عزل فشل أي مزود."""
    observations: list[PassiveObservation] = []
    for provider in providers:
        if not provider.available():
            continue
        observations.extend(await _safe_collect(provider, target))
    return observations


async def _safe_collect(
    provider: PassiveProvider, target: str
) -> list[PassiveObservation]:
    """اعزل فشل مزود واحد مع إبقاء بقية عملية الجمع متاحة."""
    try:
        return await provider.collect(target)
    except Exception as exc:  # pragma: no cover - provider-specific failure
        logger.warning("Passive provider %s failed: %s", provider.name, exc)
        return []
