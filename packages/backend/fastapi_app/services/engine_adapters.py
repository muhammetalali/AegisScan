from __future__ import annotations

import hashlib
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .code_quality_executor import analyze_code
from .endpoint_discovery import discover_endpoints
from .manifest_discovery import discover_dependency_manifests
from .network_lab_executor import execute_network_tool
from .runtime_analysis_executor import analyze_runtime
from .security_intelligence import analyze_dependency_manifest, execute_tls_intelligence
from .validation_executor import ExecutionResult, execute_http_probe, normalize_target
from .vulnerability_intelligence import analyze_response

SUPPORTED_REAL_ENGINES = {
    "recon", "evidence_collection", "control_validation", "endpoint_discovery",
    "vuln_intelligence", "tls_intelligence", "dependency_risk", "code_quality",
    "runtime_analysis", "network_nmap", "network_masscan",
}


def _socket_evidence(hostname: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:12]
    evidence_id = f"ev-dns-{digest}"
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None) if item[4]})
        return [{"id": evidence_id, "type": "dns_resolution", "engine": "recon", "data": {"hostname": hostname, "addresses": addresses}}], {"hostname": hostname, "resolved_addresses": addresses, "resolution_status": "resolved"}
    except OSError as exc:
        return [{"id": evidence_id, "type": "dns_resolution", "engine": "recon", "data": {"hostname": hostname, "error": str(exc)}}], {"hostname": hostname, "resolution_status": "failed", "error": str(exc)}


async def execute_engine(engine: str, target_type: str, target_value: str, extra: dict[str, Any] | None = None) -> ExecutionResult:
    if engine not in SUPPORTED_REAL_ENGINES:
        return ExecutionResult("unavailable", [], [], {"engine": engine, "execution": "not_implemented"}, "No real executor is registered for this engine yet.")

    extra = extra or {}
    target = normalize_target(target_type, target_value) if target_type not in {"cidr", "hostname"} else target_value.strip()

    if engine in {"network_nmap", "network_masscan"}:
        return await execute_network_tool(engine, target_type, target_value, extra)

    if engine == "code_quality":
        return await analyze_code(extra)

    if engine == "runtime_analysis":
        return await analyze_runtime(extra)

    if engine == "dependency_risk":
        manifest = extra.get("dependency_manifest") or extra.get("manifest_content")
        filename = extra.get("dependency_filename") or extra.get("filename")
        if isinstance(manifest, str) and manifest.strip():
            return await analyze_dependency_manifest(manifest, str(filename or "dependency-manifest"))

        workspace = extra.get("workspace") or extra.get("workspace_path")
        if not workspace and target_type == "code":
            candidate = Path(target_value.strip()).expanduser()
            if candidate.exists() and candidate.is_dir():
                workspace = str(candidate)

        if isinstance(workspace, str) and workspace.strip():
            manifests = discover_dependency_manifests(
                workspace,
                max_bytes=int(extra.get("manifest_max_bytes", 2 * 1024 * 1024)),
                max_files=int(extra.get("manifest_max_files", 25)),
            )
            if not manifests:
                return ExecutionResult("unsupported", [], [], {"engine": engine, "reason": "dependency_manifest_missing", "workspace_discovery": True, "manifests_found": 0}, "No supported dependency manifest was discovered inside the authorized workspace.")
            combined_findings: list[dict[str, Any]] = []
            combined_evidence: list[dict[str, Any]] = []
            combined_metrics: list[dict[str, Any]] = []
            for manifest_item in manifests:
                result = await analyze_dependency_manifest(manifest_item["content"], manifest_item["filename"])
                combined_findings.extend(result.findings)
                combined_evidence.extend(result.evidence)
                combined_metrics.append({**result.metrics, "manifest_sha256": manifest_item["sha256"], "bytes": manifest_item["bytes"], "filename": manifest_item["filename"]})
                if result.error and result.status == "failed":
                    return ExecutionResult("failed", combined_findings, combined_evidence, {"engine": engine, "manifests_found": len(manifests), "manifests": combined_metrics}, result.error)
            return ExecutionResult("completed", combined_findings, combined_evidence, {"engine": engine, "workspace_discovery": True, "workspace": str(Path(workspace).expanduser().resolve()), "manifests_found": len(manifests), "manifests": combined_metrics, "vulnerability_matches": sum(int(m.get("vulnerability_matches", 0)) for m in combined_metrics), "cve_correlation": True})
        return ExecutionResult("unsupported", [], [], {"engine": engine, "reason": "dependency_manifest_missing", "workspace_discovery": True}, "Dependency risk requires manifest content or an authorized code workspace.")

    hostname = urlparse(target).hostname
    if not hostname:
        return ExecutionResult("failed", [], [], {"engine": engine}, "Unable to determine target hostname")
    if engine == "endpoint_discovery":
        return await discover_endpoints(target_type, target_value)
    if engine == "tls_intelligence":
        return await execute_tls_intelligence(target_type, target_value)

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
        if probe.metrics.get("access_limited"):
            return ExecutionResult("completed", [], probe.evidence, {"engine": engine, "access_limited": True, "access_limited_by": probe.metrics.get("access_limited_by"), "assessment_scope": "edge_response_only", "vulnerability_intelligence_skipped": True})
        class ResponseView:
            status_code = probe.evidence[0]["data"]["status_code"]
            headers = probe.evidence[0]["data"]["headers"]
        return analyze_response(ResponseView(), target)
    return ExecutionResult(probe.status, [f for f in probe.findings if f.get("category") == "security_headers"], probe.evidence, {"engine": engine, "validated_controls": ["security_headers"], "http": probe.metrics}, probe.error)
