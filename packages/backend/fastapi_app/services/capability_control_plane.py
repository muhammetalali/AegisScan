from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .engine_capabilities import CAPABILITY
from .itsm_capability import all_provider_capabilities, provider_capability
from .itsm_configuration import validate_itsm_configuration
from .itsm_provider_health import check_all_providers, check_provider


@dataclass(frozen=True)
class CapabilityContract:
    engine: str
    status: str
    executor: str | None
    evidence: bool
    input_contract: dict[str, Any]
    output_contract: dict[str, Any]
    execution: dict[str, Any]
    safety: dict[str, Any]


_ENGINE_CONTRACTS: dict[str, CapabilityContract] = {
    "dependency_risk": CapabilityContract(
        engine="dependency_risk",
        status="implemented",
        executor="services.engine_adapters.execute_engine",
        evidence=True,
        input_contract={"target_types": ["code"], "sources": ["authorized_workspace", "dependency_manifest"]},
        output_contract={"findings": "dependency vulnerabilities correlated with registry provenance", "evidence": "manifest hash + OSV correlation lineage"},
        execution={"external_network": True, "deterministic": False, "timeout_seconds": 60},
        safety={"scope_required": True, "no_fabricated_cve_data": True},
    ),
    "vuln_intelligence": CapabilityContract(
        engine="vuln_intelligence",
        status="partial",
        executor="services.engine_adapters.execute_engine",
        evidence=True,
        input_contract={"target_types": ["url", "host"]},
        output_contract={"findings": "passive response intelligence", "evidence": "HTTP response observations"},
        execution={"external_network": True, "deterministic": False, "timeout_seconds": 30},
        safety={"scope_required": True, "no_exploit_execution": True},
    ),
}


def _contract_for(engine: str) -> CapabilityContract:
    base = CAPABILITY.get(engine, {"status": "unknown", "executor": None, "evidence": False})
    return _ENGINE_CONTRACTS.get(
        engine,
        CapabilityContract(
            engine=engine,
            status=str(base.get("status", "unknown")),
            executor=base.get("executor"),
            evidence=bool(base.get("evidence", False)),
            input_contract={"target_types": ["declared_by_executor"]},
            output_contract={"findings": "engine-defined", "evidence": "engine-defined"},
            execution={"external_network": False, "deterministic": None, "timeout_seconds": None},
            safety={"scope_required": True},
        ),
    )


def engine_contract(engine: str) -> dict[str, Any]:
    contract = _contract_for(engine)
    return {"engine": contract.engine, "status": contract.status, "executor": contract.executor, "evidence": contract.evidence, "input_contract": contract.input_contract, "output_contract": contract.output_contract, "execution": contract.execution, "safety": contract.safety}


def all_engine_contracts() -> list[dict[str, Any]]:
    return [engine_contract(engine) for engine in CAPABILITY]


async def engine_readiness(engine: str) -> dict[str, Any]:
    contract = engine_contract(engine)
    runtime_ready = contract["status"] in {"implemented", "partial"} and bool(contract["executor"])
    reason = "ready" if runtime_ready else "executor_not_ready"
    return {**contract, "readiness": "ready" if runtime_ready else "not_ready", "readiness_reason": reason}


async def provider_control_plane(provider: str) -> dict[str, Any]:
    capability = await provider_capability(provider)
    config = validate_itsm_configuration().get(provider)
    health = await check_provider(provider) if config and config.enabled and config.valid else {"provider": provider, "status": "not_checked", "reason": "configuration_not_ready"}
    return {"provider": provider, "capability": capability, "health": health, "configuration": {"enabled": bool(config and config.enabled), "valid": bool(config and config.valid), "errors": list(config.errors) if config else ["unsupported provider"]}}


async def all_provider_control_planes() -> list[dict[str, Any]]:
    return [await provider_control_plane(provider) for provider in ("jira", "servicenow")]


async def control_plane_snapshot() -> dict[str, Any]:
    return {"engines": all_engine_contracts(), "providers": await all_provider_control_planes()}
