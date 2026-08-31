from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

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


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _containerized() -> bool:
    return os.getenv("AEGIS_CONTAINERIZED", "0").strip().lower() in {"1", "true", "yes", "on"}


def _connect_target(target: str) -> tuple[str, str | None]:
    """Resolve browser-local loopback targets when execution happens in Docker."""
    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower()
    if not _containerized() or hostname not in {"localhost", "127.0.0.1", "::1"}:
        return target, None
    if parsed.username or parsed.password:
        raise ValueError("Credentials embedded in scan target URLs are not supported")

    host_gateway = os.getenv("AEGIS_HOST_GATEWAY", "host.docker.internal").strip() or "host.docker.internal"
    port = f":{parsed.port}" if parsed.port else ""
    connection_target = urlunparse(
        (parsed.scheme, f"{host_gateway}{port}", parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
    return connection_target, target


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

    try:
        connection_target, original_target = _connect_target(target)
    except ValueError as exc:
        return ExecutionResult("failed", [], [], {"target": target}, str(exc))

    connection_parsed = urlparse(connection_target)
    headers = {"User-Agent": "AegisScan/real-executor"}
    started = datetime.now(timezone.utc)
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers=headers, verify=True) as client:
            response = await client.get(connection_target)
    except httpx.ConnectError as exc:
        return ExecutionResult(
            "failed",
            [],
            [],
            {
                "target": target,
                "connection_target": connection_target,
                "connection_host": connection_parsed.hostname,
                "containerized_target_translation": bool(original_target),
            },
            f"Unable to connect to target {target} from the scan worker. Connection target: {connection_target}. {exc}",
        )
    except httpx.HTTPError as exc:
        return ExecutionResult(
            "failed",
            [],
            [],
            {
                "target": target,
                "connection_target": connection_target,
                "connection_host": connection_parsed.hostname,
                "containerized_target_translation": bool(original_target),
            },
            f"HTTP execution failed for {target}. {exc}",
        )

    finished = datetime.now(timezone.utc)
    duration_ms = round((finished - started).total_seconds() * 1000, 2)
    response_headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
    evidence_id = _stable_id("ev-http", target, response.status_code, response.url)

    evidence = [{
        "id": evidence_id,
        "type": "http_response",
        "engine": SUPPORTED_ENGINE,
        "created_at": _utc(),
        "data": {
            "requested_url": target,
            "connection_target": connection_target,
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
                "id": _stable_id("finding", target, header),
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
            "connection_target": connection_target,
            "containerized_target_translation": bool(original_target),
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "final_url": str(response.url),
            "findings_count": len(findings),
        },
    )
