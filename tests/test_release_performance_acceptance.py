from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.release_performance_acceptance import (
    PerformanceAcceptanceError,
    build_acceptance,
)

SHA = "a" * 40


def _write(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _fixture(tmp_path: Path):
    capacity = _write(
        tmp_path / "release-capacity-reality.json",
        {
            "schema": "aegisscan.release-capacity-reality.v1",
            "source_sha": SHA,
            "passed": True,
            "proof": {
                "multi_tenant_e2e": True,
                "max_concurrent_tenants": 6,
                "postgres_concurrent_activity_observed": True,
                "max_postgres_connections": 12,
                "celery_broker_observed": True,
                "max_queue_depths": {"default": 1, "scanners": 4, "browser": 0},
                "kali_scanner_concurrency_exercised": True,
                "controlled_recovery": True,
            },
            "thresholds": {
                "minimum_tenants": 6,
                "minimum_postgres_connections": 2,
            },
        },
    )
    performance = _write(
        tmp_path / "release-performance-reality.json",
        {
            "schema": "aegisscan.performance-reality.v1",
            "source_sha": SHA,
            "passed": True,
            "stages": [
                {"concurrency": 30, "duration_seconds": 120.0},
                {"concurrency": 75, "duration_seconds": 180.0},
                {"concurrency": 125, "duration_seconds": 180.0},
                {"concurrency": 50, "duration_seconds": 900.0},
            ],
            "summary": {
                "requests": 10000,
                "failures": 0,
                "error_rate": 0.0,
                "worst_stage_p95_ms": 300.0,
                "minimum_stage_rps": 20.0,
            },
            "thresholds": {
                "min_requests": 5000,
                "max_error_rate": 0.01,
                "max_p95_ms": 750.0,
                "min_rps": 10.0,
                "stage_warmup_seconds": 3.0,
            },
        },
    )
    return capacity, performance


def test_release_performance_acceptance_requires_extended_exact_sha_profile(tmp_path: Path):
    capacity, performance = _fixture(tmp_path)
    payload = build_acceptance(
        release_sha=SHA,
        profile="release",
        capacity_path=capacity,
        performance_path=performance,
        output=tmp_path / "acceptance.json",
    )
    assert payload["schema"] == "aegisscan.release-performance-acceptance.v1"
    assert payload["status"] == "success"
    assert payload["decision"] == "ACCEPTED"
    assert payload["release_sha"] == SHA
    assert payload["profile"] == "release"
    assert payload["capacity"]["minimum_tenants"] == 6
    assert payload["performance"]["source_sha"] == SHA
    assert payload["performance"]["stage_concurrency"] == [30, 75, 125, 50]
    assert payload["performance"]["final_soak_duration_seconds"] >= 850
    assert all(payload["controls"].values())
    assert len(payload["acceptance_sha256"]) == 64


def test_ci_profile_cannot_be_promoted_to_release_acceptance(tmp_path: Path):
    capacity, performance = _fixture(tmp_path)
    with pytest.raises(PerformanceAcceptanceError, match="release profile"):
        build_acceptance(
            release_sha=SHA,
            profile="ci",
            capacity_path=capacity,
            performance_path=performance,
            output=tmp_path / "acceptance.json",
        )


def test_release_acceptance_rejects_short_soak(tmp_path: Path):
    capacity, performance = _fixture(tmp_path)
    payload = json.loads(performance.read_text())
    payload["stages"][-1]["duration_seconds"] = 120.0
    performance.write_text(json.dumps(payload))
    with pytest.raises(PerformanceAcceptanceError, match="extended_soak"):
        build_acceptance(
            release_sha=SHA,
            profile="release",
            capacity_path=capacity,
            performance_path=performance,
            output=tmp_path / "acceptance.json",
        )


def test_release_acceptance_rejects_three_tenant_capacity(tmp_path: Path):
    capacity, performance = _fixture(tmp_path)
    payload = json.loads(capacity.read_text())
    payload["thresholds"]["minimum_tenants"] = 3
    payload["proof"]["max_concurrent_tenants"] = 3
    capacity.write_text(json.dumps(payload))
    with pytest.raises(PerformanceAcceptanceError, match="minimum_tenants"):
        build_acceptance(
            release_sha=SHA,
            profile="release",
            capacity_path=capacity,
            performance_path=performance,
            output=tmp_path / "acceptance.json",
        )

def test_release_acceptance_rejects_cross_sha_performance_evidence(tmp_path: Path):
    capacity, performance = _fixture(tmp_path)
    payload = json.loads(performance.read_text())
    payload["source_sha"] = "f" * 40
    performance.write_text(json.dumps(payload))
    with pytest.raises(PerformanceAcceptanceError, match="source_sha"):
        build_acceptance(
            release_sha=SHA,
            profile="release",
            capacity_path=capacity,
            performance_path=performance,
            output=tmp_path / "acceptance.json",
        )


@pytest.mark.parametrize("limit", [0.0, 0.01])
def test_zero_errors_remain_zero_under_strict_release_policy(tmp_path, limit):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    data["thresholds"]["max_error_rate"] = limit
    performance.write_text(json.dumps(data))
    result = build_acceptance(
        release_sha=SHA, profile="release", capacity_path=capacity,
        performance_path=performance, output=tmp_path / "acceptance.json",
    )
    assert result["performance"]["error_rate"] == 0.0
    assert result["performance"]["thresholds"]["max_error_rate"] == limit


@pytest.mark.parametrize("section,key", [
    ("summary", "error_rate"), ("thresholds", "max_error_rate"),
])
@pytest.mark.parametrize("value", [None, True, False, "0.0", -0.01, 1.01, float("nan"), float("inf")])
def test_error_rate_requires_an_explicit_finite_fraction(tmp_path, section, key, value):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    data[section][key] = value
    performance.write_text(json.dumps(data))
    with pytest.raises(PerformanceAcceptanceError, match="error_rate"):
        build_acceptance(
            release_sha=SHA, profile="release", capacity_path=capacity,
            performance_path=performance, output=tmp_path / "acceptance.json",
        )
    assert not (tmp_path / "acceptance.json").exists()


@pytest.mark.parametrize("section,key", [
    ("summary", "error_rate"), ("thresholds", "max_error_rate"),
])
def test_missing_error_rate_is_rejected_without_creating_acceptance(tmp_path, section, key):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    del data[section][key]
    performance.write_text(json.dumps(data))
    with pytest.raises(PerformanceAcceptanceError, match="error_rate"):
        build_acceptance(
            release_sha=SHA, profile="release", capacity_path=capacity,
            performance_path=performance, output=tmp_path / "acceptance.json",
        )
    assert not (tmp_path / "acceptance.json").exists()


def test_excessive_nonzero_error_rate_is_rejected(tmp_path):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    data["summary"]["error_rate"] = 0.01001
    performance.write_text(json.dumps(data))
    with pytest.raises(PerformanceAcceptanceError, match="error_rate"):
        build_acceptance(
            release_sha=SHA, profile="release", capacity_path=capacity,
            performance_path=performance, output=tmp_path / "acceptance.json",
        )


def test_zero_measured_latency_is_valid_numeric_evidence(tmp_path):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    data["summary"]["worst_stage_p95_ms"] = 0.0
    performance.write_text(json.dumps(data))
    result = build_acceptance(
        release_sha=SHA, profile="release", capacity_path=capacity,
        performance_path=performance, output=tmp_path / "acceptance.json",
    )
    assert result["performance"]["worst_stage_p95_ms"] == 0.0


@pytest.mark.parametrize("section,key", [
    ("summary", "worst_stage_p95_ms"), ("thresholds", "max_p95_ms"),
])
@pytest.mark.parametrize("value", [None, True, "0.0", -0.01, float("nan"), float("inf")])
def test_latency_requires_finite_nonnegative_numeric_evidence(tmp_path, section, key, value):
    capacity, performance = _fixture(tmp_path)
    data = json.loads(performance.read_text())
    data[section][key] = value
    performance.write_text(json.dumps(data))
    with pytest.raises(PerformanceAcceptanceError, match="p95"):
        build_acceptance(
            release_sha=SHA, profile="release", capacity_path=capacity,
            performance_path=performance, output=tmp_path / "acceptance.json",
        )
