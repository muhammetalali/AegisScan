from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx


SUPPORTED_ENGINE = "recon"


@dataclass(slots=True)
class ExecutionResult:
    status: str
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    metrics: dict[str, Any]
    error: str | None = None


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_target(target_type: str, target_value: str) -> str:
    value = target_value.strip()
    if target_type == "ip" and "://" not in value:
        return f"http://{value}"
    return value


async def execute_http_probe(target_type: str, target_value: str, timeout: float = 15.0) -> ExecutionResult:
    if target_type not in {"url", "ip", "api"}:
        return ExecutionResult(
            status="unsupported",
            findings=[],
            evidence=[],
            metrics={"engine": SUPPORTED_ENGINE},
            error="Real network execution is currently available for url, ip, and api targets only.",
        )

    target = normalize_target(target_type, target_value)
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ExecutionResult("failed", [], [], {}, "target_value must be a valid HTTP or HTTPS target")

    headers = {"User-Agent": "AegisScan/real-executor"}
    started = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers=headers, verify=True) as client:
            response = await client.get(target)
    except httpx.HTTPError as exc:
        return ExecutionResult("failed", [], [], {"target": target}, str(exc))

    finished = datetime.now(timezone.utc)
    duration_ms = round((finished - started).total_seconds() * 1000, 2)
    response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    evidence_id = f"ev-http-{abs(hash((target, response.status_code))) & 0xffffffff:08x}"

    evidence = [{
        "id": evidence_id,
        "type": "http_response",
        "engine": SUPPORTED_ENGINE,
        "created_at": _utc(),
        "data": {
            "requested_url": target,
            "final_url": str(response.url),
            "method": "GET",
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "elapsed_ms": duration_ms,
        },
    }]

    findings: list[dict[str, Any]] = []
    security_headers = [
        ("x-content-type-options", "Missing X-Content-Type-Options", "medium"),
        ("x-frame-options", "Missing X-Frame-Options", "medium"),
        ("referrer-policy", "Missing Referrer-Policy", "low"),
        ("content-security-policy", "Missing Content-Security-Policy", "medium"),
    ]
    if parsed.scheme == "https":
        security_headers.append(("strict-transport-security", "Missing Strict-Transport-Security", "medium"))

    for header, title, severity in security_headers:
        if header not in response_headers:
            findings.append({
                "id": f"finding-{abs(hash((target, header))) & 0xffffffff:08x}",
                "title": title,
                "severity": severity,
                "status": "open",
                "confidence": 96,
                "category": "security_headers",
                "asset": parsed.hostname,
                "evidence_ids": [evidence_id],
                "description": f"The live response from {response.url} did not include {header}.",
                "observed_at": _utc(),
            })

    return ExecutionResult(
        status="completed",
        findings=findings,
        evidence=evidence,
        metrics={
            "engine": SUPPORTED_ENGINE,
            "target": target,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "final_url": str(response.url),
            "findings_count": len(findings),
        },
    )
