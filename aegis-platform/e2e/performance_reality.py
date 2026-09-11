#!/usr/bin/env python3
"""Concurrent HTTP performance and soak reality harness for AegisScan.

This intentionally drives the real reverse-proxy/API/database path. Thresholds are
configuration, not hard-coded capacity claims, so CI can prove regression safety
while a production-like host can run the same harness at a larger envelope.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import requests


@dataclass(frozen=True)
class BenchmarkResult:
    name: str
    requests: int
    concurrency: int
    errors: int
    duration_seconds: float
    requests_per_second: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one sample")
    ordered = sorted(values)
    rank = max(1, math.ceil((percentile_value / 100.0) * len(ordered)))
    return ordered[min(rank - 1, len(ordered) - 1)]


def require(response: requests.Response, expected: Iterable[int], label: str) -> dict | list:
    expected_set = set(expected)
    if response.status_code not in expected_set:
        raise RuntimeError(f"{label} failed: HTTP {response.status_code}: {response.text[:500]}")
    if not response.text:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise RuntimeError(f"{label} returned non-JSON response") from exc


def csrf(session: requests.Session, django_url: str, verify_tls: bool) -> str:
    response = session.get(f"{django_url}/auth/csrf/", timeout=15, verify=verify_tls)
    data = require(response, {200}, "CSRF bootstrap")
    token = data.get("csrfToken") if isinstance(data, dict) else None
    token = token or session.cookies.get("csrftoken")
    if not token:
        raise RuntimeError("CSRF token was not issued")
    return str(token)


def bootstrap(base_url: str, verify_tls: bool) -> tuple[dict[str, str], list[tuple[str, str]]]:
    base_url = base_url.rstrip("/")
    django_url = f"{base_url}/api/v1"
    api_v1 = f"{base_url}/api/v1"
    session = requests.Session()
    session.verify = verify_tls

    require(session.get(f"{base_url}/ready", timeout=15), {200}, "readiness")
    require(session.get(f"{base_url}/health", timeout=15), {200}, "health")

    unique = uuid.uuid4().hex[:12]
    email = os.getenv("AEGIS_PERF_EMAIL") or f"perf-{unique}@aegisscan.local"
    password = os.getenv("AEGIS_PERF_PASSWORD") or f"Aegis-Perf-{unique}-StrongPass!9"
    token = csrf(session, django_url, verify_tls)
    headers = {"X-CSRFToken": token, "Referer": f"{base_url}/"}

    if not (os.getenv("AEGIS_PERF_EMAIL") and os.getenv("AEGIS_PERF_PASSWORD")):
        require(
            session.post(
                f"{django_url}/auth/register/",
                json={
                    "email": email,
                    "first_name": "Performance",
                    "last_name": "Reality",
                    "password": password,
                    "password_confirm": password,
                },
                headers=headers,
                timeout=20,
            ),
            {201},
            "performance user registration",
        )

    token = csrf(session, django_url, verify_tls)
    headers["X-CSRFToken"] = token
    require(
        session.post(
            f"{django_url}/auth/login/",
            json={"email": email, "password": password},
            headers=headers,
            timeout=20,
        ),
        {200},
        "performance login",
    )

    project = require(
        session.post(
            f"{django_url}/projects/",
            json={
                "name": f"Performance Reality {unique}",
                "description": "Concurrent read-path performance fixture",
                "environment": "development",
            },
            headers=headers,
            timeout=20,
        ),
        {201},
        "performance project creation",
    )
    if not isinstance(project, dict) or not project.get("id"):
        raise RuntimeError("performance project did not return an id")

    organization = require(
        session.post(
            f"{api_v1}/enterprise/organizations",
            json={"name": f"Performance Reality {unique}", "slug": f"performance-reality-{unique}"},
            timeout=20,
        ),
        {201},
        "performance tenant creation",
    )
    if not isinstance(organization, dict) or not organization.get("id"):
        raise RuntimeError("performance tenant did not return an id")
    require(
        session.post(
            f"{api_v1}/enterprise/projects/{project['id']}/tenant",
            params={"organization_id": organization["id"]},
            timeout=20,
        ),
        {200},
        "performance tenant binding",
    )

    cookies = requests.utils.dict_from_cookiejar(session.cookies)
    endpoints = [
        ("readiness", f"{base_url}/ready"),
        ("django-projects-db", f"{django_url}/projects/"),
        ("fastapi-security-events-db", f"{api_v1}/security-events?limit=20"),
    ]
    return cookies, endpoints


def benchmark(
    name: str,
    url: str,
    *,
    cookies: dict[str, str],
    verify_tls: bool,
    requests_count: int,
    concurrency: int,
    timeout: float,
) -> BenchmarkResult:
    local = threading.local()

    def one() -> tuple[float, str | None]:
        if not hasattr(local, "session"):
            local.session = requests.Session()
            local.session.verify = verify_tls
            local.session.cookies.update(cookies)
        started = time.perf_counter()
        try:
            response = local.session.get(url, timeout=timeout)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if response.status_code != 200:
                return elapsed_ms, f"HTTP {response.status_code}"
            return elapsed_ms, None
        except requests.RequestException as exc:
            return (time.perf_counter() - started) * 1000.0, type(exc).__name__

    warmup = min(20, max(4, concurrency))
    for _ in range(warmup):
        latency, error = one()
        if error:
            raise RuntimeError(f"{name} warmup failed: {error} after {latency:.1f} ms")

    latencies: list[float] = []
    errors: list[str] = []
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one) for _ in range(requests_count)]
        for future in as_completed(futures):
            latency, error = future.result()
            latencies.append(latency)
            if error:
                errors.append(error)
    duration = time.perf_counter() - started
    return BenchmarkResult(
        name=name,
        requests=requests_count,
        concurrency=concurrency,
        errors=len(errors),
        duration_seconds=round(duration, 3),
        requests_per_second=round(requests_count / duration, 2),
        mean_ms=round(statistics.fmean(latencies), 2),
        p50_ms=round(percentile(latencies, 50), 2),
        p95_ms=round(percentile(latencies, 95), 2),
        p99_ms=round(percentile(latencies, 99), 2),
        max_ms=round(max(latencies), 2),
    )


def soak(
    url: str,
    *,
    cookies: dict[str, str],
    verify_tls: bool,
    seconds: int,
    concurrency: int,
    timeout: float,
) -> tuple[int, int]:
    deadline = time.monotonic() + seconds
    completed = 0
    errors = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal completed, errors
        session = requests.Session()
        session.verify = verify_tls
        session.cookies.update(cookies)
        local_completed = 0
        local_errors = 0
        while time.monotonic() < deadline:
            try:
                response = session.get(url, timeout=timeout)
                if response.status_code != 200:
                    local_errors += 1
            except requests.RequestException:
                local_errors += 1
            local_completed += 1
        with lock:
            completed += local_completed
            errors += local_errors

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(concurrency)]
        for future in futures:
            future.result()
    return completed, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=os.getenv("AEGIS_BASE_URL", "http://localhost"))
    parser.add_argument("--requests", type=int, default=int(os.getenv("AEGIS_PERF_REQUESTS", "300")))
    parser.add_argument("--concurrency", type=int, default=int(os.getenv("AEGIS_PERF_CONCURRENCY", "16")))
    parser.add_argument("--p95-ms", type=float, default=float(os.getenv("AEGIS_PERF_P95_MS", "1500")))
    parser.add_argument("--p99-ms", type=float, default=float(os.getenv("AEGIS_PERF_P99_MS", "2500")))
    parser.add_argument("--min-rps", type=float, default=float(os.getenv("AEGIS_PERF_MIN_RPS", "8")))
    parser.add_argument("--soak-seconds", type=int, default=int(os.getenv("AEGIS_PERF_SOAK_SECONDS", "20")))
    parser.add_argument("--timeout", type=float, default=float(os.getenv("AEGIS_PERF_TIMEOUT", "10")))
    parser.add_argument("--output", default=os.getenv("AEGIS_PERF_OUTPUT", "/tmp/aegis-performance-reality.json"))
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    if args.requests < 1 or args.concurrency < 1 or args.soak_seconds < 1:
        raise SystemExit("requests, concurrency and soak-seconds must be positive")
    if args.concurrency > args.requests:
        raise SystemExit("concurrency cannot exceed requests")

    verify_tls = not args.insecure
    cookies, endpoints = bootstrap(args.base_url, verify_tls)
    results = [
        benchmark(
            name,
            url,
            cookies=cookies,
            verify_tls=verify_tls,
            requests_count=args.requests,
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
        for name, url in endpoints
    ]

    soak_completed, soak_errors = soak(
        endpoints[-1][1],
        cookies=cookies,
        verify_tls=verify_tls,
        seconds=args.soak_seconds,
        concurrency=args.concurrency,
        timeout=args.timeout,
    )

    violations: list[str] = []
    for result in results:
        if result.errors:
            violations.append(f"{result.name}: {result.errors} request errors")
        if result.p95_ms > args.p95_ms:
            violations.append(f"{result.name}: p95 {result.p95_ms} ms > {args.p95_ms} ms")
        if result.p99_ms > args.p99_ms:
            violations.append(f"{result.name}: p99 {result.p99_ms} ms > {args.p99_ms} ms")
        if result.requests_per_second < args.min_rps:
            violations.append(f"{result.name}: {result.requests_per_second} rps < {args.min_rps} rps")
    if soak_errors:
        violations.append(f"soak: {soak_errors} errors across {soak_completed} requests")

    report = {
        "schema": "aegis.performance-reality.v1",
        "base_url": args.base_url,
        "thresholds": {
            "p95_ms": args.p95_ms,
            "p99_ms": args.p99_ms,
            "min_rps": args.min_rps,
            "zero_errors": True,
        },
        "benchmarks": [asdict(result) for result in results],
        "soak": {
            "seconds": args.soak_seconds,
            "concurrency": args.concurrency,
            "requests": soak_completed,
            "errors": soak_errors,
        },
        "violations": violations,
        "passed": not violations,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    if violations:
        raise SystemExit("PERFORMANCE_REALITY=FAIL: " + "; ".join(violations))
    print("PERFORMANCE_REALITY=PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
