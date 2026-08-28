from __future__ import annotations

from collections import defaultdict
from typing import Any


class PostureState:
    def __init__(self) -> None:
        self._snapshots: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def record(self, scope: str, assessment: dict[str, Any]) -> dict[str, Any]:
        snapshot = {
            "scope": scope,
            "evaluated_at": assessment.get("evaluated_at"),
            "score": assessment.get("score", 0),
            "rating": assessment.get("rating", "unknown"),
            "metrics": assessment.get("metrics", []),
        }
        self._snapshots[scope].append(snapshot)
        self._snapshots[scope] = self._snapshots[scope][-90:]
        return snapshot

    def history(self, scope: str, limit: int = 30) -> list[dict[str, Any]]:
        return self._snapshots.get(scope, [])[-max(1, min(limit, 90)):]


posture_state = PostureState()
