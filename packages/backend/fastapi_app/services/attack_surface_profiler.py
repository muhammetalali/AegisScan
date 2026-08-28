from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class SurfaceObservation:
    asset: str
    port: int
    protocol: str
    service: str
    version: str | None = None
    source: str = "approved-scan"


class AttackSurfaceProfiler:
    """Normalizes authorized scanner observations without executing scanners."""

    def normalize(self, observations: Iterable[dict]) -> list[dict]:
        result: list[dict] = []
        for raw in observations:
            try:
                port = int(raw["port"])
            except (KeyError, TypeError, ValueError):
                continue
            if not 1 <= port <= 65535:
                continue
            asset = str(raw.get("asset", "")).strip()
            if not asset:
                continue
            result.append(asdict(SurfaceObservation(asset, port, str(raw.get("protocol", "tcp")), str(raw.get("service", "unknown")), raw.get("version"))))
        return result

    def diff(self, previous: Iterable[dict], current: Iterable[dict]) -> dict:
        key = lambda x: (x.get("asset"), x.get("port"), x.get("protocol"), x.get("service"))
        before, after = {key(x): x for x in previous}, {key(x): x for x in current}
        return {"added": [after[k] for k in after.keys() - before.keys()], "removed": [before[k] for k in before.keys() - after.keys()]}
