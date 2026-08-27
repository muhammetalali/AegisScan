from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlparse

from .endpoint_discovery import discover_endpoints
from .validation_executor import ExecutionResult, execute_http_probe, normalize_target
from .vulnerability_intelligence import analyze_response


SUPPORTED_REAL_ENGINES = {"recon", "evidence_collection", "control_validation", "endpoint_discovery", "vuln_intelligence"}


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
        return ExecutionResult("unavailable", [], [], {"engine": engine, "execution": "not_implemented"}, "No real executor is registered for this engine yet.")

    target = normalize_target(target_type, target_value)
    hostname = urlparse(target).hostname
    if not hostname:
        return ExecutionResult("failed", [], [], {"engine": engine}, "Unable to determine target hostname")

    if engine == "endpoint_discovery":
        return await discover_endpoints(target_type, target_value)

    probe = await execute_http_probe(target_type, target_value)

    if engine == "recon":
        dns_evidence, dns_metrics = _socket_evidence(hostname)
        return ExecutionResult(probe.status, probe.findings, dns_evidence + probe.evidence, {"engine": engine, **dns_metrics, "http": probe.metrics}, probe.error)

    if engine == "evidence_collection":
        dns_evidence, dns_metrics = _socket_evidence(hostname)
        return ExecutionResult(probe.status, [], dns_evidence + probe.evidence, {"engine": engine, **dns_metrics, "evidence_count": len(dns_evidence) + len(probe.evidence), "http": probe.metrics}, probe.error)

    if engine == "vuln_intelligence":
        if probe.status != "completed" or not probe.evidence:
            return probe
        class ResponseView:
            status_code = probe.evidence[0]["data"]["status_code"]
            headers = probe.evidence[0]["data"]["headers"]
        return analyze_response(ResponseView(), target)

    return ExecutionResult(probe.status, [f for f in probe.findings if f.get("category") == "security_headers"], probe.evidence, {"engine": engine, "validated_controls": ["security_headers"], "http": probe.metrics}, probe.error)
