from __future__ import annotations

import hashlib
import json
import re
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from .validation_executor import ExecutionResult, normalize_target

SUPPORTED_SECURITY_ENGINES = {"tls_intelligence", "dependency_risk"}
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"ev-{prefix}-{digest}"


def _finding_id(*parts: str) -> str:
    return "finding-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]


def _parse_version(value: str) -> tuple[int, ...] | None:
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", value or "")
    if not match:
        return None
    return tuple(int(group or 0) for group in match.groups())


async def execute_tls_intelligence(target_type: str, target_value: str) -> ExecutionResult:
    target = normalize_target(target_type, target_value)
    parsed = urlparse(target)
    if parsed.scheme != "https" or not parsed.hostname:
        return ExecutionResult("unsupported", [], [], {"engine": "tls_intelligence"}, "TLS intelligence requires an HTTPS target with a hostname.")
    hostname = parsed.hostname
    port = parsed.port or 443
    evidence_id = _evidence_id("tls", f"{hostname}:{port}")
    context = ssl.create_default_context()
    try:
        with ssl.create_connection((hostname, port), timeout=10) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                protocol = tls_socket.version()
                cipher = tls_socket.cipher()
                cert_subject = dict(item[0] for item in cert.get("subject", [])) if cert else {}
                cert_issuer = dict(item[0] for item in cert.get("issuer", [])) if cert else {}
                evidence = [{"id": evidence_id, "type": "tls_handshake", "engine": "tls_intelligence", "created_at": _utc(), "data": {"hostname": hostname, "port": port, "protocol": protocol, "cipher": cipher[0] if cipher else None, "certificate_subject": cert_subject, "certificate_issuer": cert_issuer, "certificate_expires": cert.get("notAfter") if cert else None}}]
                findings = []
                if protocol in {"TLSv1", "TLSv1.1"}:
                    findings.append({"id": _finding_id(hostname, protocol), "title": f"Legacy TLS protocol negotiated: {protocol}", "severity": "high", "status": "open", "confidence": 99, "category": "tls", "asset": hostname, "evidence_ids": [evidence_id], "observed_at": _utc()})
                return ExecutionResult("completed", findings, evidence, {"engine": "tls_intelligence", "protocol": protocol, "cipher": cipher[0] if cipher else None})
    except (OSError, ssl.SSLError) as exc:
        return ExecutionResult("failed", [], [{"id": evidence_id, "type": "tls_handshake", "engine": "tls_intelligence", "created_at": _utc(), "data": {"hostname": hostname, "port": port, "error": str(exc)}}], {"engine": "tls_intelligence", "hostname": hostname, "port": port}, str(exc))


def _ecosystem_for_filename(filename: str) -> str | None:
    name = filename.replace("\\", "/").split("/")[-1].lower()
    return {"requirements.txt": "PyPI", "requirements-dev.txt": "PyPI", "requirements-dev.in": "PyPI", "pyproject.toml": "PyPI", "poetry.lock": "PyPI", "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm", "go.mod": "Go", "go.sum": "Go", "cargo.toml": "crates.io", "cargo.lock": "crates.io", "pom.xml": "Maven", "composer.lock": "Packagist", "gemfile.lock": "RubyGems"}.get(name)


def _parse_text_requirements(content: str) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    for line in content.splitlines():
        raw = line.strip()
        if not raw or raw.startswith(("#", "//", "<!--", "-r ", "--", "git+", "http://", "https://")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+\-]+)", raw)
        if match:
            dependencies.append({"name": match.group(1), "version": match.group(2)})
    return dependencies


def _parse_package_lock(content: str) -> list[dict[str, str]]:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return []
    dependencies: list[dict[str, str]] = []
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if isinstance(packages, dict):
        for path, item in packages.items():
            if not isinstance(item, dict) or not item.get("version") or "node_modules/" not in path:
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            if name:
                dependencies.append({"name": name, "version": str(item["version"])})
    legacy = payload.get("dependencies") if isinstance(payload, dict) else None
    if not dependencies and isinstance(legacy, dict):
        for name, item in legacy.items():
            if isinstance(item, dict) and item.get("version"):
                dependencies.append({"name": str(name), "version": str(item["version"])})
    return dependencies


def _parse_manifest(content: str, filename: str) -> tuple[str | None, list[dict[str, str]]]:
    lower = filename.replace("\\", "/").split("/")[-1].lower()
    ecosystem = _ecosystem_for_filename(filename)
    if lower in {"package-lock.json", "npm-shrinkwrap.json", "package.json"}:
        return ecosystem, _parse_package_lock(content)
    return ecosystem, _parse_text_requirements(content)


async def _query_osv(dependencies: list[dict[str, str]], ecosystem: str) -> list[dict[str, Any]]:
    if not dependencies:
        return []
    queries = [{"package": {"name": dep["name"], "ecosystem": ecosystem}, "version": dep["version"]} for dep in dependencies]
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
        response = await client.post(OSV_QUERYBATCH_URL, json={"queries": queries}, headers={"Accept": "application/json"})
        response.raise_for_status()
        payload = response.json()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    return results if isinstance(results, list) else []


async def analyze_dependency_manifest(content: str, filename: str) -> ExecutionResult:
    if not isinstance(content, str) or not content.strip():
        return ExecutionResult("unsupported", [], [], {"engine": "dependency_risk", "reason": "dependency_manifest_missing"}, "Dependency risk requires non-empty manifest content.")
    ecosystem, dependencies = _parse_manifest(content, filename)
    evidence_id = _evidence_id("dependency", f"{filename}:{hashlib.sha256(content.encode('utf-8')).hexdigest()}")
    if not ecosystem:
        return ExecutionResult("unsupported", [], [{"id": evidence_id, "type": "dependency_manifest", "engine": "dependency_risk", "created_at": _utc(), "data": {"filename": filename, "supported": False}}], {"engine": "dependency_risk", "dependency_count": 0, "cve_correlation": False}, "Unsupported dependency manifest format; no package or CVE data is fabricated.")

    try:
        osv_results = await _query_osv(dependencies, ecosystem)
    except Exception as exc:
        return ExecutionResult("completed", [], [{"id": evidence_id, "type": "dependency_manifest", "engine": "dependency_risk", "created_at": _utc(), "data": {"filename": filename, "ecosystem": ecosystem, "dependency_count": len(dependencies), "registry": "OSV", "registry_status": "error", "error": str(exc)}}], {"engine": "dependency_risk", "dependency_count": len(dependencies), "cve_correlation": False, "registry_status": "error"})

    findings: list[dict[str, Any]] = []
    osv_evidence: list[dict[str, Any]] = []
    vuln_count = 0
    for index, dep in enumerate(dependencies):
        result = osv_results[index] if index < len(osv_results) and isinstance(osv_results[index], dict) else {}
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict) or not vuln.get("id"):
                continue
            vuln_count += 1
            vuln_id = str(vuln["id"])
            vuln_evidence_id = _evidence_id("osv", f"{filename}:{dep['name']}:{dep['version']}:{vuln_id}")
            osv_evidence.append({"id": vuln_evidence_id, "type": "dependency_vulnerability_correlation", "engine": "dependency_risk", "created_at": _utc(), "data": {"registry": "OSV", "osv_id": vuln_id, "package": dep["name"], "version": dep["version"], "ecosystem": ecosystem, "query_index": index, "modified": vuln.get("modified")}})
            findings.append({"id": _finding_id(filename, dep["name"], dep["version"], vuln_id), "title": f"Known vulnerability in {dep['name']} {dep['version']}: {vuln_id}", "severity": "high", "status": "open", "confidence": 99, "category": "dependency_risk", "asset": filename, "package": dep["name"], "version": dep["version"], "vulnerability_id": vuln_id, "evidence_ids": [evidence_id, vuln_evidence_id], "observed_at": _utc(), "description": "The declared package version was correlated against the OSV vulnerability database."})

    base_evidence = {"id": evidence_id, "type": "dependency_manifest", "engine": "dependency_risk", "created_at": _utc(), "data": {"filename": filename, "ecosystem": ecosystem, "dependency_count": len(dependencies), "dependencies": dependencies, "registry": "OSV", "registry_status": "ok", "vulnerability_matches": vuln_count}}
    return ExecutionResult("completed", findings, [base_evidence, *osv_evidence], {"engine": "dependency_risk", "dependency_count": len(dependencies), "cve_correlation": True, "registry": "OSV", "registry_status": "ok", "vulnerability_matches": vuln_count})
