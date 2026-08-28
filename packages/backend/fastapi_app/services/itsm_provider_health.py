from __future__ import annotations

import os
import time
from typing import Any

import httpx

from . import itsm_sandbox
from .itsm_configuration import validate_itsm_configuration


PROVIDERS = ("jira", "servicenow")


def _safe_origin(value: str) -> str:
    return value.strip().rstrip("/")


async def _check_jira(timeout: float) -> dict[str, Any]:
    base = _safe_origin(os.getenv("JIRA_BASE_URL", ""))
    email = os.getenv("JIRA_USER_EMAIL", "")
    token = os.getenv("JIRA_API_TOKEN", "")
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            auth=(email, token),
            headers={"Accept": "application/json"},
        ) as client:
            response = await client.get(f"{base}/rest/api/3/myself")
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        if response.status_code in {401, 403}:
            return {"status": "auth_failed", "http_status": response.status_code, "latency_ms": latency_ms}
        if response.status_code == 404:
            return {"status": "endpoint_invalid", "http_status": 404, "latency_ms": latency_ms}
        response.raise_for_status()
        data = response.json() if response.content else {}
        return {
            "status": "healthy",
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "account_id_present": bool(data.get("accountId")),
        }
    except httpx.TimeoutException:
        return {"status": "timeout", "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
    except httpx.HTTPError as exc:
        return {
            "status": "transport_error",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error_type": type(exc).__name__,
        }


async def _check_servicenow(timeout: float) -> dict[str, Any]:
    base = _safe_origin(os.getenv("SERVICENOW_BASE_URL", ""))
    token = os.getenv("SERVICENOW_API_TOKEN")
    username = os.getenv("SERVICENOW_USERNAME")
    password = os.getenv("SERVICENOW_PASSWORD")
    table = os.getenv("SERVICENOW_TABLE", "incident")
    headers = {"Accept": "application/json"}
    auth = None if token else (username, password)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            auth=auth,
            headers=headers,
        ) as client:
            response = await client.get(
                f"{base}/api/now/table/{table}",
                params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
            )
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        if response.status_code in {401, 403}:
            return {"status": "auth_failed", "http_status": response.status_code, "latency_ms": latency_ms}
        if response.status_code == 404:
            return {"status": "endpoint_invalid", "http_status": 404, "latency_ms": latency_ms}
        response.raise_for_status()
        return {"status": "healthy", "http_status": response.status_code, "latency_ms": latency_ms}
    except httpx.TimeoutException:
        return {"status": "timeout", "latency_ms": round((time.perf_counter() - started) * 1000, 2)}
    except httpx.HTTPError as exc:
        return {
            "status": "transport_error",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error_type": type(exc).__name__,
        }


async def check_provider(provider: str, timeout: float = 8.0) -> dict[str, Any]:
    provider = provider.strip().lower()
    if provider not in PROVIDERS:
        return {"provider": provider, "status": "unsupported", "configured": False, "errors": []}

    if itsm_sandbox.enabled():
        return {**itsm_sandbox.health(provider), "configured": True, "validated": True}

    state = validate_itsm_configuration()[provider]
    if not state.enabled:
        return {"provider": provider, "status": "not_configured", "configured": False, "errors": []}
    if not state.valid:
        return {
            "provider": provider,
            "status": "invalid_configuration",
            "configured": True,
            "errors": list(state.errors),
        }

    probe = await (_check_jira(timeout) if provider == "jira" else _check_servicenow(timeout))
    return {"provider": provider, "configured": True, "validated": True, **probe}


async def check_all_providers(timeout: float = 8.0) -> dict[str, Any]:
    results = {provider: await check_provider(provider, timeout) for provider in PROVIDERS}
    overall = all(item["status"] in {"healthy", "not_configured"} for item in results.values())
    return {"status": "healthy" if overall else "degraded", "providers": results}
