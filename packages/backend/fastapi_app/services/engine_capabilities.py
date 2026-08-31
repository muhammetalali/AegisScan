from __future__ import annotations

from typing import Any

from .engine_adapters import SUPPORTED_REAL_ENGINES

ALL_CONTRACT_ENGINES = [
    "recon", "evidence_collection", "code_quality", "runtime_analysis", "performance",
    "dependency_risk", "config_check", "vuln_intelligence", "tls_intelligence", "correlation", "validation",
    "control_validation", "coverage_gap", "endpoint_discovery", "attack_path", "evidence_graph", "knowledge",
    "ai_explain", "posture", "compliance", "digital_twin", "reporting", "network_nmap", "network_masscan",
]

CAPABILITY = {engine: {"status": "unavailable", "executor": None, "evidence": False} for engine in ALL_CONTRACT_ENGINES}

for engine in SUPPORTED_REAL_ENGINES:
    CAPABILITY[engine] = {"status": "implemented", "executor": "services.engine_adapters.execute_engine", "evidence": True}

CAPABILITY["vuln_intelligence"]["scope"] = "passive response intelligence; no exploitability proof or CVE/package correlation"
CAPABILITY["endpoint_discovery"]["scope"] = "bounded same-origin links discovered from the initial HTTP document"
CAPABILITY["tls_intelligence"]["scope"] = "live TLS handshake, certificate metadata, protocol and cipher observation"
CAPABILITY["dependency_risk"]["status"] = "implemented"
CAPABILITY["dependency_risk"]["executor"] = "services.security_intelligence.analyze_dependency_manifest"
CAPABILITY["dependency_risk"]["evidence"] = True
CAPABILITY["dependency_risk"]["scope"] = "resolved dependency manifest parsing plus live OSV package/version vulnerability correlation with evidence lineage"
CAPABILITY["code_quality"]["scope"] = "bounded static analysis of supplied code_content/code_files snapshots"
CAPABILITY["runtime_analysis"]["scope"] = "bounded pattern analysis of supplied runtime_logs; no host-level telemetry access"
CAPABILITY["network_nmap"]["scope"] = "isolated network lab execution; Nmap service/port observations only; authorization and exact target allowlist required"
CAPABILITY["network_masscan"]["scope"] = "isolated network lab execution; low-rate ports 1-1024 discovery only; authorization and exact target allowlist required"


def list_capabilities() -> list[dict[str, Any]]:
    return [{"engine": name, **data} for name, data in CAPABILITY.items()]


def capability_for(engine: str) -> dict[str, Any]:
    return {"engine": engine, **CAPABILITY.get(engine, {"status": "unknown", "executor": None, "evidence": False})}
