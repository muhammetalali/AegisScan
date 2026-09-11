from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("performance_reality.py")
SPEC = importlib.util.spec_from_file_location("performance_reality", MODULE_PATH)
assert SPEC and SPEC.loader
performance_reality = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(performance_reality)


def test_percentile_uses_nearest_rank() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert performance_reality.percentile(values, 50) == 3.0
    assert performance_reality.percentile(values, 95) == 5.0
    assert performance_reality.percentile(values, 99) == 5.0


def test_percentile_rejects_empty_samples() -> None:
    with pytest.raises(ValueError, match="at least one sample"):
        performance_reality.percentile([], 95)


def test_benchmark_result_contract_is_stable() -> None:
    result = performance_reality.BenchmarkResult(
        name="control-plane",
        requests=100,
        concurrency=10,
        errors=0,
        duration_seconds=2.0,
        requests_per_second=50.0,
        mean_ms=10.0,
        p50_ms=9.0,
        p95_ms=20.0,
        p99_ms=25.0,
        max_ms=30.0,
    )
    assert result.errors == 0
    assert result.p95_ms < result.p99_ms
    assert result.requests_per_second == 50.0
