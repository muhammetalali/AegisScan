#!/usr/bin/env python3
"""Build exact-SHA AegisScan final release performance acceptance evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "aegisscan.release-performance-acceptance.v1"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class PerformanceAcceptanceError(RuntimeError):
    pass


def _load(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > 32 * 1024 * 1024:
        raise PerformanceAcceptanceError(f"{label} is missing or has invalid size")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PerformanceAcceptanceError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise PerformanceAcceptanceError(f"{label} must be a JSON object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_acceptance(
    *,
    release_sha: str,
    profile: str,
    capacity_path: Path,
    performance_path: Path,
    output: Path,
) -> dict[str, Any]:
    release_sha = release_sha.strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise PerformanceAcceptanceError("release SHA must be exactly 40 lowercase hexadecimal characters")
    if profile != "release":
        raise PerformanceAcceptanceError("final performance acceptance requires the release profile")

    capacity = _load(capacity_path, "capacity evidence")
    performance = _load(performance_path, "performance evidence")

    capacity_proof = capacity.get("proof") or {}
    capacity_thresholds = capacity.get("thresholds") or {}
    capacity_checks = {
        "schema": capacity.get("schema") == "aegisscan.release-capacity-reality.v1",
        "source_sha": capacity.get("source_sha") == release_sha,
        "passed": capacity.get("passed") is True,
        "minimum_tenants": int(capacity_thresholds.get("minimum_tenants") or 0) >= 6,
        "multi_tenant_e2e": capacity_proof.get("multi_tenant_e2e") is True,
        "max_concurrent_tenants": int(capacity_proof.get("max_concurrent_tenants") or 0) >= 6,
        "postgres": capacity_proof.get("postgres_concurrent_activity_observed") is True,
        "celery": capacity_proof.get("celery_broker_observed") is True,
        "kali": capacity_proof.get("kali_scanner_concurrency_exercised") is True,
        "recovery": capacity_proof.get("controlled_recovery") is True,
    }
    failures = [name for name, passed in capacity_checks.items() if not passed]
    if failures:
        raise PerformanceAcceptanceError(f"release capacity evidence failed checks: {failures}")

    thresholds = performance.get("thresholds") or {}
    summary = performance.get("summary") or {}
    stages = performance.get("stages") or []
    stage_concurrency = [
        int(stage.get("concurrency") or 0)
        for stage in stages
        if isinstance(stage, dict)
    ]
    final_stage_duration = (
        float(stages[-1].get("duration_seconds") or 0)
        if isinstance(stages, list) and stages and isinstance(stages[-1], dict)
        else 0.0
    )
    perf_checks = {
        "schema": performance.get("schema") == "aegisscan.performance-reality.v1",
        "source_sha": performance.get("source_sha") == release_sha,
        "passed": performance.get("passed") is True,
        "min_requests": int(thresholds.get("min_requests") or 0) >= 5000,
        "min_rps": float(thresholds.get("min_rps") or 0) >= 10.0,
        "max_p95": float(thresholds.get("max_p95_ms") or 999999) <= 750.0,
        "max_error_rate": float(thresholds.get("max_error_rate") or 1.0) <= 0.01,
        "requests": int(summary.get("requests") or 0) >= int(thresholds.get("min_requests") or 0),
        "p95": float(summary.get("worst_stage_p95_ms") or 999999) <= float(thresholds.get("max_p95_ms") or 0),
        "error_rate": float(summary.get("error_rate") or 1.0) <= float(thresholds.get("max_error_rate") or 0),
        "rps": float(summary.get("minimum_stage_rps") or 0) >= float(thresholds.get("min_rps") or 0),
        "release_concurrency_shape": stage_concurrency == [30, 75, 125, 50],
        "extended_soak": final_stage_duration >= 850.0,
    }
    failures = [name for name, passed in perf_checks.items() if not passed]
    if failures:
        raise PerformanceAcceptanceError(f"release performance evidence failed checks: {failures}")

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "success",
        "decision": "ACCEPTED",
        "release_sha": release_sha,
        "profile": profile,
        "capacity": {
            "minimum_tenants": capacity_thresholds["minimum_tenants"],
            "max_concurrent_tenants": capacity_proof["max_concurrent_tenants"],
            "max_postgres_connections": capacity_proof.get("max_postgres_connections"),
            "max_queue_depths": capacity_proof.get("max_queue_depths"),
            "multi_tenant_e2e": True,
            "kali_scanner_concurrency_exercised": True,
            "controlled_recovery": True,
        },
        "performance": {
            "source_sha": performance["source_sha"],
            "stage_concurrency": stage_concurrency,
            "requests": summary["requests"],
            "worst_stage_p95_ms": summary["worst_stage_p95_ms"],
            "minimum_stage_rps": summary["minimum_stage_rps"],
            "error_rate": summary["error_rate"],
            "thresholds": thresholds,
            "final_soak_duration_seconds": final_stage_duration,
        },
        "evidence_sha256": {
            capacity_path.name: _sha256(capacity_path),
            performance_path.name: _sha256(performance_path),
        },
        "controls": {
            "exact_sha": True,
            "six_tenant_minimum": True,
            "postgres_concurrency": True,
            "celery_broker": True,
            "governed_kali_concurrency": True,
            "controlled_recovery": True,
            "extended_saturation_and_soak": True,
            "latency_threshold": True,
            "error_rate_threshold": True,
            "throughput_threshold": True,
        },
    }
    digest_input = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["acceptance_sha256"] = hashlib.sha256(digest_input).hexdigest()

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--capacity", type=Path, required=True)
    parser.add_argument("--performance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_acceptance(
            release_sha=args.release_sha,
            profile=args.profile,
            capacity_path=args.capacity,
            performance_path=args.performance,
            output=args.output,
        )
    except PerformanceAcceptanceError as exc:
        print(f"RELEASE_PERFORMANCE_ACCEPTANCE_FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
