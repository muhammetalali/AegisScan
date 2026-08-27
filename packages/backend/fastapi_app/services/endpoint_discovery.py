from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from .validation_executor import ExecutionResult, _utc, normalize_target

SUPPORTED_ENGINE = "endpoint_discovery"
MAX_ENDPOINTS = 24


def _same_origin(base: str, candidate: str) -> bool:
    left, right = urlparse(base), urlparse(candidate)
    return left.scheme == right.scheme and left.hostname == right.hostname and (left.port or (443 if left.scheme == "https" else 80)) == (right.port or (443 if right.scheme == "https" else 80))


def _extract_links(base: str, html: str) -> list[str]:
    import re
    raw = re.findall(r"(?:href|src)=[\"']([^\"'#>]+)", html, flags=re.IGNORECASE)
    endpoints: list[str] = []
    for value in raw:
        candidate = urljoin(base, value)
        if _same_origin(base, candidate) and candidate not in endpoints:
            endpoints.append(candidate)
        if len(endpoints) >= MAX_ENDPOINTS:
            break
    return endpoints


async def discover_endpoints(target_type: str, target_value: str, timeout: float = 15.0) -> ExecutionResult:
    if target_type not in {"url", "api"}:
        return ExecutionResult("unsupported", [], [], {"engine": SUPPORTED_ENGINE}, "Endpoint discovery requires a URL or API target")

    target = normalize_target(target_type, target_value)
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ExecutionResult("failed", [], [], {}, "target_value must be a valid HTTP or HTTPS target")

    started = _utc()
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers={"User-Agent": "AegisScan/endpoint-discovery"}, verify=True) as client:
            response = await client.get(target)
    except httpx.HTTPError as exc:
        return ExecutionResult("failed", [], [], {"engine": SUPPORTED_ENGINE, "target": target}, str(exc))

    endpoints = _extract_links(str(response.url), response.text)
    evidence_id = f"ev-endpoints-{abs(hash((target, tuple(endpoints)))) & 0xffffffff:08x}"
    evidence = [{
        "id": evidence_id,
        "type": "endpoint_discovery",
        "engine": SUPPORTED_ENGINE,
        "created_at": started,
        "data": {"target": target, "final_url": str(response.url), "method": "GET", "count": len(endpoints), "endpoints": endpoints},
    }]

    findings: list[dict[str, Any]] = []
    if not endpoints:
        findings.append({
            "id": f"finding-endpoint-empty-{abs(hash(target)) & 0xffffffff:08x}",
            "title": "No same-origin endpoints discovered from initial document",
            "severity": "informational",
            "status": "observed",
            "confidence": 82,
            "category": "endpoint_discovery",
            "asset": parsed.hostname,
            "evidence_ids": [evidence_id],
            "description": "No linked same-origin endpoints were observed in the initial HTML document; this is not evidence that the target has no additional routes.",
            "observed_at": _utc(),
        })

    return ExecutionResult(
        status="completed",
        findings=findings,
        evidence=evidence,
        metrics={"engine": SUPPORTED_ENGINE, "target": target, "endpoint_count": len(endpoints), "final_url": str(response.url)},
    )
