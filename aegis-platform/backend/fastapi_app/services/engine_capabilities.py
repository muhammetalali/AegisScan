from __future__ import annotations

from typing import Any

from .engine_adapters import SUPPORTED_REAL_ENGINES

ALL_CONTRACT_ENGINES = [
    "recon", "evidence_collection", "code_quality", "runtime_analysis", "performance",
    "dependency_risk", "config_check", "vuln_intelligence", "correlation", "validation",
    "control_validation", "coverage_gap", "attack_path", "evidence_graph", "knowledge",
    "ai_explain", "posture", "compliance", "digital_twin", "reporting",
]

CAPABILITY = {engine: {"status": "unavailable", "executor": None, "evidence": False} for engine in ALL_CONTRACT_ENGINES}

for engine in SUPPORTED_REAL_ENGINES:
    CAPABILITY[engine] = {"status": "implemented", "executor": "engine_adapters.execute_engine", "evidence": True}

CAPABILITY["vuln_intelligence"] = {
    "status": "partial",
    "executor": "validation_executor.execute_http_probe",
    "evidence": True,
    "scope": "response-level security observations; no CVE/package correlation yet",
}


def list_capabilities() -> list[dict[str, Any]]:
    return [{"engine": name, **data} for name, data in CAPABILITY.items()]


def capability_for(engine: str) -> dict[str, Any]:
    return {"engine": engine, **CAPABILITY.get(engine, {"status": "unknown", "executor": None, "evidence": False})}
