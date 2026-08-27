"""تعلّم محافظ من تأكيدات المحلل، مع حدود تمنع انجراف الأوزان."""

from __future__ import annotations

from collections import defaultdict


class FeedbackWeights:
    """إحصاء Beta بسيط يحوّل صحيح/خاطئ إلى وزن مصدر مستقر."""

    def __init__(self, prior: float = 0.5) -> None:
        self._stats: dict[str, list[float]] = defaultdict(lambda: [prior * 2, (1 - prior) * 2])

    def record(self, source: str, confirmed: bool) -> float:
        alpha, beta = self._stats[source]
        self._stats[source] = [alpha + int(confirmed), beta + int(not confirmed)]
        return self.weight(source)

    def weight(self, source: str) -> float:
        alpha, beta = self._stats[source]
        # prior remains influential until at least four observations exist.
        estimate = alpha / (alpha + beta)
        return round(max(0.2, min(0.95, estimate)), 3)

    def snapshot(self) -> dict[str, float]:
        return {source: self.weight(source) for source in sorted(self._stats)}
