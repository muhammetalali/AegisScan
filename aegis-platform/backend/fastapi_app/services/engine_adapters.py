from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

from .validation_executor import ExecutionResult, execute_http_probe, normalize_target


SUPPORTED_REAL_ENGINES = {"recon", "evidence_collection", "control_validation"}


def _socket_evidence(hostname: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    evidence_id = f"ev-dns-{abs(hash(hostname)) & 0xffffffff:08x}"
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None) if item[4]})
        return [
            {"id": evidence_id, "type": "dns_resolution", "engine": "recon", "data": {"hostname": hostname, "addresses": addresses}}
        ], {"hostname": hostname, "resolved_addresses": addresses, "resolution_status": "resolved"}
    except OSError as exc:
        return [
            {"id": evidence_id, "type": "dns_resolution", "engine": "recon", "data": {"hostname": hostname, "error": str(exc)}}
        ], {"hostname": hostname, "resolution_status": "failed", "error": str(exc)}


async def execute_engine(engine: str, target_type: str, target_value: str) -> ExecutionResult:
    if engine not in SUPPORTED_REAL_ENGINES:
        return ExecutionResult(
            status="unavailable",
            findings=[],
            evidence=[],
            metrics={"engine": engine, "execution": "not_implemented"},
            error="No real executor is registered for this engine yet.",
        )

    target = normalize_target(target_type, target_value)
    hostname = urlparse(target).hostname
    if not hostname:
        return ExecutionResult("failed", [], [], {"engine": engine}, "Unable to determine target hostname")

    dns_evidence, dns_metrics = _socket_evidence(hostname)
    probe = await execute_http_probe(target_type, target_value)

    if engine == "recon":
        return ExecutionResult(
            status=probe.status,
            findings=probe.findings,
            evidence=dns_evidence + probe.evidence,
            metrics={"engine": engine, **dns_metrics, "http": probe.metrics},
            error=probe.error,
        )

    if engine == "evidence_collection":
        return ExecutionResult(
            status=probe.status,
            findings=[],
            evidence=dns_evidence + probe.evidence,
            metrics={"engine": engine, "evidence_count": len(dns_evidence) + len(probe.evidence), "http": probe.metrics},
            error=probe.error,
        )

    return ExecutionResult(
        status=probe.status,
        findings=[f for f in probe.findings if f.get("category") == "security_headers"],
        evidence=probe.evidence,
        metrics={"engine": engine, "validated_controls": ["security_headers"], "http": probe.metrics},
        error=probe.error,
    )
