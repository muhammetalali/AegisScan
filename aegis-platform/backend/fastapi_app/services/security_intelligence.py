from __future__ import annotations

import re
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .validation_executor import ExecutionResult, normalize_target


SUPPORTED_SECURITY_ENGINES = {"tls_intelligence", "dependency_risk"}


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence_id(prefix: str, value: str) -> str:
    return f"ev-{prefix}-{abs(hash(value)) & 0xffffffff:08x}"


def _parse_version(value: str) -> tuple[int, ...] | None:
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    if not match:
        return None
    return tuple(int(group or 0) for group in match.groups())


async def execute_tls_intelligence(target_type: str, target_value: str) -> ExecutionResult:
    target = normalize_target(target_type, target_value)
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname:
        return ExecutionResult(
            status="unsupported",
            findings=[],
            evidence=[],
            metrics={"engine": "tls_intelligence"},
            error="TLS intelligence requires an HTTPS target with a hostname.",
        )

    hostname = parsed.hostname
    port = parsed.port or 443
    evidence_id = _evidence_id("tls", f"{hostname}:{port}")
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        with ssl.create_connection((hostname, port), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                protocol = tls_socket.version()
                cipher = tls_socket.cipher()
                cert_subject = dict(item[0] for item in cert.get("subject", [])) if cert else {}
                cert_issuer = dict(item[0] for item in cert.get("issuer", [])) if cert else {}
                not_after = cert.get("notAfter") if cert else None
                evidence = [{
                    "id": evidence_id,
                    "type": "tls_handshake",
                    "engine": "tls_intelligence",
                    "created_at": _utc(),
                    "data": {
                        "hostname": hostname,
                        "port": port,
                        "protocol": protocol,
                        "cipher": cipher[0] if cipher else None,
                        "certificate_subject": cert_subject,
                        "certificate_issuer": cert_issuer,
                        "certificate_expires": not_after,
                    },
                }]
                findings: list[dict[str, Any]] = []
                if protocol in {"TLSv1", "TLSv1.1"}:
                    findings.append({
                        "id": f"finding-{abs(hash((hostname, protocol))) & 0xffffffff:08x}",
                        "title": f"Legacy TLS protocol negotiated: {protocol}",
                        "severity": "high",
                        "status": "open",
                        "confidence": 99,
                        "category": "tls",
                        "asset": hostname,
                        "evidence_ids": [evidence_id],
                        "observed_at": _utc(),
                    })
                return ExecutionResult(
                    status="completed",
                    findings=findings,
                    evidence=evidence,
                    metrics={"engine": "tls_intelligence", "protocol": protocol, "cipher": cipher[0] if cipher else None},
                )
    except (OSError, ssl.SSLError) as exc:
        return ExecutionResult(
            status="failed",
            findings=[],
            evidence=[{"id": evidence_id, "type": "tls_handshake", "engine": "tls_intelligence", "created_at": _utc(), "data": {"hostname": hostname, "port": port, "error": str(exc)}}],
            metrics={"engine": "tls_intelligence", "hostname": hostname, "port": port},
            error=str(exc),
        )


def analyze_dependency_manifest(content: str, filename: str) -> ExecutionResult:
    findings: list[dict[str, Any]] = []
    evidence_id = _evidence_id("dependency", filename)
    dependencies: list[dict[str, Any]] = []

    patterns = [
        re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|@|:)\s*([A-Za-z0-9_.+\-]+)\s*$"),
        re.compile(r'^\s*"?([A-Za-z0-9_.-]+)"?\s*[:=]\s*["\']?([A-Za-z0-9_.+\-^~*]+)')
    ]
    for line in content.splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("#", "//", "<!--")):
            continue
        match = next((pattern.search(raw) for pattern in patterns if pattern.search(raw)), None)
        if match:
            name, version = match.group(1), match.group(2)
            dependencies.append({"name": name, "version": version})
            parsed = _parse_version(version)
            if parsed and parsed[0] == 0:
                findings.append({
                    "id": f"finding-{abs(hash((filename, name, version))) & 0xffffffff:08x}",
                    "title": f"Pre-1.0 dependency: {name} {version}",
                    "severity": "low",
                    "status": "review",
                    "confidence": 72,
                    "category": "dependency_risk",
                    "asset": filename,
                    "evidence_ids": [evidence_id],
                    "observed_at": _utc(),
                    "description": "Version metadata suggests a pre-1.0 dependency; review stability and security posture. This is not a CVE finding.",
                })

    evidence = [{
        "id": evidence_id,
        "type": "dependency_manifest",
        "engine": "dependency_risk",
        "created_at": _utc(),
        "data": {"filename": filename, "dependency_count": len(dependencies), "dependencies": dependencies},
    }]
    return ExecutionResult(
        status="completed",
        findings=findings,
        evidence=evidence,
        metrics={"engine": "dependency_risk", "dependency_count": len(dependencies), "cve_correlation": False},
    )
