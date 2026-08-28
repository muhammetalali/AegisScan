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
    {"id": "recon", "label": "Recon", "engines": ["recon", "evidence_collection"], "desc": "DNS • Subdomain • Port • Service Discovery"},
    {"id": "discovery", "label": "Discovery", "engines": ["vuln_intelligence", "validation"], "desc": "HTTP • Technology • Endpoint • Directory"},
    {"id": "enumeration", "label": "Enumeration", "engines": ["control_validation", "coverage_gap"], "desc": "Headers • TLS • Config • Vulnerability"},
    {"id": "analysis", "label": "Analysis", "engines": ["attack_path", "evidence_graph", "knowledge", "posture"], "desc": "Security Checks • Risk Analysis"},
    {"id": "reporting", "label": "Reporting", "engines": ["policy_compliance", "twin_engine", "scenarios", "dashboard", "reporting"], "desc": "Findings • Report Generator"},
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

_store: dict[str, dict[str, Any]] = {}
_tasks: dict[str, asyncio.Task[Any]] = {}

_REDIS_PREFIX = "aegis:validation:"
_REDIS_TTL_SECONDS = 86400
_redis_client: redis.Redis | None = None


def _redis_key(validation_id: str) -> str:
    return f"{_REDIS_PREFIX}{validation_id}"


def _get_redis() -> redis.Redis:
    """Create the Redis client lazily in the current worker process.

    Uvicorn/Gunicorn may fork worker processes. Creating a Redis client at
    module import time can inherit a connection pool across forks. Keeping
    construction lazy guarantees that each worker owns its own pool.
    """
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
    try:
        raw = _get_redis().get(_redis_key(validation_id))
    except (redis.RedisError, OSError):
        return None

    if not raw:
        return None

    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None

    return value if isinstance(value, dict) else None


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
    """Read shared validation state from Redis before local fallback."""
    remote = _redis_get(validation_id)
    if remote is not None:
        _store[validation_id] = remote
        return remote
    return _store.get(validation_id)


def put_validation(
    validation_id: str,
    value: dict[str, Any],
) -> None:
    _store[validation_id] = value
    persist_validation(validation_id)


def persist_validation(validation_id: str) -> bool:
    """Persist current validation state to the shared Redis store."""
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


def get_task(validation_id: str) -> asyncio.Task[Any] | None:
    return _tasks.get(validation_id)


def put_task(
    validation_id: str,
    task: asyncio.Task[Any],
) -> None:
    _tasks[validation_id] = task


def remove_task(validation_id: str) -> None:
    _tasks.pop(validation_id, None)
