from __future__ import annotations

import time
from typing import Any

from celery.signals import task_failure, task_postrun, task_prerun
from redis import Redis

from ..core.config import settings

_PREFIX = "aegis:celery:metrics"
_START_TIMES: dict[str, float] = {}


def _redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def _key(name: str) -> str:
    return f"{_PREFIX}:{name}"


def _record_counter(name: str, amount: int = 1) -> None:
    try:
        client = _redis()
        client.incrby(_key(name), amount)
        client.expire(_key(name), 7 * 24 * 60 * 60)
    except Exception:
        # Telemetry must never break business tasks.
        return


def _record_duration(task_name: str, duration: float) -> None:
    try:
        client = _redis()
        key = _key("duration")
        client.lpush(key, f"{task_name}|{duration:.6f}")
        client.ltrim(key, 0, 999)
        client.expire(key, 7 * 24 * 60 * 60)
    except Exception:
        return


@task_prerun.connect(weak=False)
def record_task_start(task_id: str | None = None, task=None, **_: Any) -> None:
    if task_id:
        _START_TIMES[task_id] = time.monotonic()
    _record_counter("started")


@task_postrun.connect(weak=False)
def record_task_success(task_id: str | None = None, task=None, **_: Any) -> None:
    _record_counter("succeeded")
    if task_id:
        started = _START_TIMES.pop(task_id, None)
        if started is not None:
            _record_duration(getattr(task, "name", "unknown"), time.monotonic() - started)


@task_failure.connect(weak=False)
def record_task_failure(task_id: str | None = None, task=None, **_: Any) -> None:
    _record_counter("failed")
    if task_id:
        started = _START_TIMES.pop(task_id, None)
        if started is not None:
            _record_duration(getattr(task, "name", "unknown"), time.monotonic() - started)


def get_task_metrics() -> dict[str, Any]:
    client = _redis()
    counters = {
        name: int(client.get(_key(name)) or 0)
        for name in ("started", "succeeded", "failed")
    }
    durations = client.lrange(_key("duration"), 0, 999)
    parsed = []
    for item in durations:
        try:
            task_name, value = item.split("|", 1)
            parsed.append((task_name, float(value)))
        except ValueError:
            continue
    by_task: dict[str, list[float]] = {}
    for task_name, duration in parsed:
        by_task.setdefault(task_name, []).append(duration)
    task_stats = {
        task_name: {
            "samples": len(values),
            "avg_seconds": round(sum(values) / len(values), 4),
            "max_seconds": round(max(values), 4),
        }
        for task_name, values in by_task.items()
    }
    try:
        queue_depth = int(client.llen("celery"))
    except Exception:
        queue_depth = -1
    return {**counters, "queue_depth": queue_depth, "tasks": task_stats}
