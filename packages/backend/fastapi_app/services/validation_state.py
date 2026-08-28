from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import redis

from ..core.config import settings

PHASES = [
    "queued",
    "initializing",
    "recon",
    "discovery",
    "enumeration",
    "analysis",
    "validation",
    "reporting",
    "completed",
]

ENGINE_PHASE = {
    "recon": "recon",
    "evidence_collection": "recon",
    "vuln_intelligence": "discovery",
    "validation": "discovery",
    "control_validation": "enumeration",
    "coverage_gap": "enumeration",
    "attack_path": "analysis",
    "evidence_graph": "analysis",
    "knowledge": "analysis",
    "posture": "analysis",
    "policy_compliance": "validation",
    "twin_engine": "validation",
    "scenarios": "validation",
    "dashboard": "reporting",
    "reporting": "reporting",
}

GROUPS = [
    {
        "id": "recon",
        "label": "Recon",
        "engines": ["recon", "evidence_collection"],
        "desc": "DNS • Subdomain • Port • Service Discovery",
    },
    {
        "id": "discovery",
        "label": "Discovery",
        "engines": ["vuln_intelligence", "validation"],
        "desc": "HTTP • Technology • Endpoint • Directory",
    },
    {
        "id": "enumeration",
        "label": "Enumeration",
        "engines": ["control_validation", "coverage_gap"],
        "desc": "Headers • TLS • Config • Vulnerability",
    },
    {
        "id": "analysis",
        "label": "Analysis",
        "engines": ["attack_path", "evidence_graph", "knowledge", "posture"],
        "desc": "Security Checks • Risk Analysis",
    },
    {
        "id": "reporting",
        "label": "Reporting",
        "engines": [
            "policy_compliance",
            "twin_engine",
            "scenarios",
            "dashboard",
            "reporting",
        ],
        "desc": "Findings • Report Generator",
    },
]

ALL_ENGINES = [
    "recon",
    "evidence_collection",
    "vuln_intelligence",
    "validation",
    "control_validation",
    "coverage_gap",
    "attack_path",
    "evidence_graph",
    "knowledge",
    "posture",
    "policy_compliance",
    "twin_engine",
    "scenarios",
    "dashboard",
    "reporting",
]

# Local memory is retained only by the executing worker as a short-lived
# working cache. Redis is the authoritative cross-process state store.
_store: dict[str, dict[str, Any]] = {}
_tasks: dict[str, asyncio.Task[Any]] = {}

_REDIS_PREFIX = "aegis:validation:"
_REDIS_TTL_SECONDS = 86400
_redis_client: redis.Redis | None = None


def _redis_key(validation_id: str) -> str:
    return f"{_REDIS_PREFIX}{validation_id}"


def _get_redis() -> redis.Redis:
    """Lazily create the Redis client inside the current worker process."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            health_check_interval=30,
        )
    return _redis_client


def _redis_get(validation_id: str) -> dict[str, Any] | None:
    """Return the value, None for a genuine cache miss, and raise on outages."""
    try:
        raw = _get_redis().get(_redis_key(validation_id))
    except (redis.RedisError, OSError) as exc:
        raise RuntimeError("Validation state store is unavailable") from exc

    if not raw:
        return None

    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Validation state store returned invalid data") from exc

    if not isinstance(value, dict):
        raise RuntimeError("Validation state store returned an invalid record")

    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def engine_state(
    status: str = "pending",
    progress: int = 0,
    findings: int = 0,
    duration: str = "—",
) -> dict[str, Any]:
    return {
        "status": status,
        "progress": progress,
        "findings": findings,
        "duration": duration,
    }


def make_live_event(
    event_type: str,
    message: str,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ts": now_iso(),
        "type": event_type,
        "message": message,
        "meta": meta or {},
    }


def get_validation(validation_id: str) -> dict[str, Any] | None:
    """Read authoritative validation state from Redis.

    A Redis outage is intentionally not treated as a cache miss. Returning a
    local per-process record here would make multi-worker behaviour divergent
    and could incorrectly report a real validation as "not found".
    """
    remote = _redis_get(validation_id)
    if remote is not None:
        _store[validation_id] = remote
    return remote


def put_validation(
    validation_id: str,
    value: dict[str, Any],
) -> None:
    _store[validation_id] = value
    persist_validation(validation_id)


def persist_validation(validation_id: str) -> bool:
    """Persist current validation state to the authoritative Redis store."""
    value = _store.get(validation_id)
    if value is None:
        return False

    try:
        _get_redis().set(
            _redis_key(validation_id),
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            ex=_REDIS_TTL_SECONDS,
        )
        return True
    except (redis.RedisError, OSError):
        return False


def validation_store_available() -> bool:
    """Return whether the authoritative Redis validation store is reachable."""
    try:
        _get_redis().ping()
        return True
    except (redis.RedisError, OSError):
        return False


def get_task(validation_id: str) -> asyncio.Task[Any] | None:
    return _tasks.get(validation_id)


def put_task(
    validation_id: str,
    task: asyncio.Task[Any],
) -> None:
    _tasks[validation_id] = task


def remove_task(validation_id: str) -> None:
    _tasks.pop(validation_id, None)
