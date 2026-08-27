"""واجهات استخبارات سلبية اختيارية بلا لمس نشط للهدف."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class PassiveObservation:
    provider: str
    target: str
    summary: str
    source_url: str = ''
    confidence: float = 0.5
    metadata: dict[str, Any] | None = None


class PassiveProvider(Protocol):
    name: str
    api_key_env: str

    def available(self) -> bool: ...

    async def collect(self, target: str) -> list[PassiveObservation]: ...


class ConfiguredPassiveProvider:
    """وصف مزود خارجي؛ لا ينفذ اتصالًا قبل أن يضيفه التطبيق صراحة."""

    def __init__(self, name: str, api_key_env: str) -> None:
        self.name = name
        self.api_key_env = api_key_env

    def available(self) -> bool:
        return bool(os.getenv(self.api_key_env))

    async def collect(self, target: str) -> list[PassiveObservation]:
        if not self.available():
            return []
        raise NotImplementedError(
            f'{self.name} is configured but requires an approved adapter implementation'
        )


DEFAULT_PASSIVE_PROVIDERS = (
    ConfiguredPassiveProvider('shodan', 'SHODAN_API_KEY'),
    ConfiguredPassiveProvider('censys', 'CENSYS_API_ID'),
    ConfiguredPassiveProvider('alienvault_otx', 'OTX_API_KEY'),
    ConfiguredPassiveProvider('urlscan', 'URLSCAN_API_KEY'),
)


async def collect_passive(
    target: str, providers: tuple[PassiveProvider, ...] = DEFAULT_PASSIVE_PROVIDERS
) -> list[PassiveObservation]:
    """جمع الملاحظات المتاحة فقط، مع عزل فشل أي مزود."""
    observations: list[PassiveObservation] = []
    for provider in providers:
        if not provider.available():
            continue
        try:
            observations.extend(await provider.collect(target))
        except Exception:
            # Passive intelligence must never block the primary scan.
            continue
    return observations
