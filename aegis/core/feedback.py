"""تعلّم محافظ من تأكيدات المحلل، مع حدود تمنع انجراف الأوزان."""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path


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

    def save(self, path: str | Path) -> None:
        """حفظ الإحصاءات الخام لاستمرار التعلم بين عمليات التشغيل."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {source: values for source, values in self._stats.items()}
        target.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path, prior: float = 0.5) -> "FeedbackWeights":
        """استعادة إحصاءات سابقة مع تجاهل الملف التالف أو غير الصالح."""
        instance = cls(prior=prior)
        target = Path(path)
        if not target.exists():
            return instance
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return instance
            for source, values in payload.items():
                if (
                    isinstance(source, str)
                    and isinstance(values, list)
                    and len(values) == 2
                    and all(
                        isinstance(value, (int, float)) and value > 0
                        for value in values
                    )
                ):
                    instance._stats[source] = [float(values[0]), float(values[1])]
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            return instance
        return instance
