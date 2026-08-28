from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


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


class DisabledDarkIntelProvider(ExternalIntelProvider):
    """Explicit safe boundary for dark-web intelligence.

    No anonymous-market scraping, credential collection, or illicit acquisition is
    performed. Authorized commercial/organizational providers can implement the
    interface and return provenance-tagged intelligence.
    """

    name = "dark-intel-disabled"

    async def search(self, indicator: str) -> list[ThreatIntelItem]:
        return []


class ExternalIntelligenceFabric:
    def __init__(self, providers: list[ExternalIntelProvider] | None = None):
        self.providers = providers or [DisabledDarkIntelProvider()]

    async def search(self, indicator: str) -> dict[str, Any]:
        items: list[ThreatIntelItem] = []
        status: dict[str, str] = {}
        for provider in self.providers:
            try:
                items.extend(await provider.search(indicator))
                status[provider.name] = "ok"
            except Exception:
                status[provider.name] = "error"
        return {"indicator": indicator, "items": [item.__dict__ for item in items], "provider_status": status}
