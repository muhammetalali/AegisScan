from __future__ import annotations

import json
import time
from typing import Any

from redis import Redis

from ..core.config import settings

_IDEMPOTENCY_TTL = 24 * 60 * 60
_DLQ_PREFIX = "aegis:celery:dlq"


def redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=5, socket_connect_timeout=5)


def claim_idempotency(key: str, ttl: int = _IDEMPOTENCY_TTL) -> bool:
    """Atomically claim a task key. False means an equivalent execution is already active/completed."""
    return bool(redis_client().set(f"aegis:idempotency:{key}", str(time.time()), nx=True, ex=ttl))


def release_idempotency(key: str) -> None:
    redis_client().delete(f"aegis:idempotency:{key}")


def enqueue_dead_letter(task_name: str, task_id: str, args: Any, kwargs: Any, error: str) -> None:
    payload = {"task": task_name, "task_id": task_id, "args": args, "kwargs": kwargs, "error": error, "timestamp": time.time()}
    client = redis_client()
    client.rpush(f"{_DLQ_PREFIX}:{task_name}", json.dumps(payload, default=str))
    client.expire(f"{_DLQ_PREFIX}:{task_name}", 30 * 24 * 60 * 60)
