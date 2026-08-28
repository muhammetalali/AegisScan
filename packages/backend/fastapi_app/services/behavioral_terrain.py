from __future__ import annotations

from dataclasses import dataclass
from math import sqrt
from typing import Any


@dataclass(frozen=True)
class BehavioralFingerprint:
    asset_id: str
    vector: tuple[float, ...]
    anomaly_score: float
    confidence: float
    signals: tuple[dict[str, Any], ...]


def _z(value: float, mean: float, stddev: float) -> float:
    return abs(value - mean) / stddev if stddev > 0 else (1.0 if value != mean else 0.0)


def build_fingerprint(asset_id: str, baseline: dict[str, float], observed: dict[str, float]) -> BehavioralFingerprint:
    keys = tuple(sorted(set(baseline) & set(observed)))
    if not keys:
        return BehavioralFingerprint(asset_id, (), 0.0, 0.0, ())
    vector = tuple(float(observed[k]) for k in keys)
    deviations = []
    signals = []
    for key in keys:
        expected = float(baseline[key])
        actual = float(observed[key])
        # Baselines may provide *_std keys; otherwise use a conservative unit scale.
        stddev = max(float(baseline.get(f"{key}_std", 1.0)), 1e-6)
        score = _z(actual, expected, stddev)
        deviations.append(score)
        if score >= 3.0:
            signals.append({"metric": key, "z_score": round(score, 3), "expected": expected, "observed": actual})
    anomaly = min(100.0, round((sum(deviations) / len(deviations)) * 20.0, 2))
    confidence = min(1.0, 0.5 + min(len(keys), 10) * 0.05)
    return BehavioralFingerprint(asset_id, vector, anomaly, round(confidence, 3), tuple(signals))


def compare_fingerprints(current: BehavioralFingerprint, previous: BehavioralFingerprint) -> float:
    if not current.vector or not previous.vector or len(current.vector) != len(previous.vector):
        return 0.0
    distance = sqrt(sum((a - b) ** 2 for a, b in zip(current.vector, previous.vector)))
    return round(min(100.0, distance * 10.0), 2)
