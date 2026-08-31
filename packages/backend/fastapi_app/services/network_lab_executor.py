from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from .validation_executor import ExecutionResult

LAB_EXECUTOR_URL = os.getenv("AEGIS_LAB_EXECUTOR_URL", "http://aegisscan-network-lab:9000").rstrip("/")
LAB_EXECUTOR_TOKEN = os.getenv("AEGIS_LAB_EXECUTOR_TOKEN", "").strip()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_id(prefix: str, *parts: object) -> str:
    material = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(material.encode()).hexdigest()[:16]}"


def _authorized_target(target: str, extra: dict[str, Any]) -> bool:
    if extra.get("authorized") is not True:
        return False
    allowlist = extra.get("lab_target_allowlist") or extra.get("target_allowlist")
    return isinstance(allowlist, list) and target in {str(item).strip() for item in allowlist if str(item).strip()}


async def execute_network_tool(engine: str, target_type: str, target_value: str, extra: dict[str, Any]) -> ExecutionResult:
    tool = {"network_nmap": "nmap", "network_masscan": "masscan"}.get(engine)
    if not tool:
        return ExecutionResult("unsupported", [], [], {"engine": engine}, "No network executor registered for this engine")
    if target_type not in {"ip", "cidr", "hostname"} or not target_value.strip():
        return ExecutionResult("failed", [], [], {"engine": engine}, "Network lab requires a non-empty ip, cidr, or hostname target")
    target = target_value.strip()
    if not _authorized_target(target, extra):
        return ExecutionResult(
            "blocked", [], [], {"engine": engine, "tool": tool, "target": target, "authorization_required": True},
            "Network lab execution requires authorized=true and an exact target in lab_target_allowlist.",
        )
    if not LAB_EXECUTOR_TOKEN:
        return ExecutionResult("failed", [], [], {"engine": engine, "tool": tool}, "AEGIS_LAB_EXECUTOR_TOKEN is not configured")

    profile = str(extra.get("network_profile") or ("service-enumeration" if tool == "nmap" else "low-rate-discovery"))
    request = {"tool": tool, "target": target, "profile": profile, "requested_at": _utc()}
    try:
        async with httpx.AsyncClient(timeout=float(extra.get("network_tool_timeout", 180))) as client:
            response = await client.post(f"{LAB_EXECUTOR_URL}/v1/execute", json=request, headers={"Authorization": f"Bearer {LAB_EXECUTOR_TOKEN}"})
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return ExecutionResult("failed", [], [], {"engine": engine, "tool": tool, "target": target}, f"Lab executor request failed: {exc}")

    execution_id = str(payload.get("execution_id") or _stable_id("exec", engine, target))
    raw = str(payload.get("stdout") or "")
    stderr = str(payload.get("stderr") or "")
    output_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    evidence = [{
        "id": _stable_id("ev-net", execution_id, output_sha256),
        "type": "network_tool_execution",
        "engine": engine,
        "created_at": _utc(),
        "data": {
            "execution_id": execution_id,
            "tool": tool,
            "target": target,
            "profile": profile,
            "command": payload.get("command"),
            "return_code": payload.get("return_code"),
            "started_at": payload.get("started_at"),
            "completed_at": payload.get("completed_at"),
            "tool_version": payload.get("tool_version"),
            "executor_image": payload.get("executor_image"),
            "stdout": raw,
            "stderr": stderr,
            "stdout_sha256": output_sha256,
            "authorization": {"authorized": True, "allowlist_match": True, "target": target},
        },
    }]
    if payload.get("status") != "completed":
        return ExecutionResult(str(payload.get("status") or "failed"), [], evidence, {"engine": engine, "tool": tool, "target": target, "execution_id": execution_id}, payload.get("error") or "Network tool execution failed")

    findings = []
    for item in payload.get("observations") or []:
        port = item.get("port")
        protocol = str(item.get("protocol") or "tcp").lower()
        title = f"Open {protocol.upper()} port {port}"
        service = item.get("service")
        if service:
            title += f" ({service})"
        findings.append({
            "id": _stable_id("finding-net", engine, target, protocol, port, service),
            "title": title,
            "severity": "info",
            "status": "open",
            "confidence": 99,
            "category": "network_exposure",
            "asset": item.get("host") or target,
            "evidence_ids": [evidence[0]["id"]],
            "description": f"{tool} observed {protocol}/{port} as open.",
            "observed_at": _utc(),
        })
    return ExecutionResult("completed", findings, evidence, {
        "engine": engine, "tool": tool, "target": target, "execution_id": execution_id,
        "tool_version": payload.get("tool_version"), "executor_image": payload.get("executor_image"),
        "return_code": payload.get("return_code"), "observations_count": len(payload.get("observations") or []),
        "stdout_sha256": output_sha256, "provenance": "isolated-network-lab-executor",
    })
