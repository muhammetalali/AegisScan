from __future__ import annotations

import time
from typing import Any

from celery.signals import task_failure, task_postrun, task_prerun, task_retry
from redis import Redis

from ..core.config import settings

_PREFIX = "aegis:celery:metrics"
_QUEUES = ("default", "workflow", "reports", "health")
_START_TIMES: dict[str, float] = {}


def _redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def _key(name: str) -> str:
    return f"{_PREFIX}:{name}"


def _record_counter(name: str, amount: int = 1) -> None:
    try:
        client = _redis()
        key = _key(name)
        client.incrby(key, amount)
        client.expire(key, 7 * 24 * 60 * 60)
    except Exception:
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


def _queue_for(task: Any) -> str:
    name = getattr(task, "name", "") or ""
    if name.startswith("fastapi_app.tasks.workflow_tasks."):
        return "workflow"
    if name.startswith("fastapi_app.tasks.report_tasks."):
        return "reports"
    if name.startswith("fastapi_app.tasks.health_tasks."):
        return "health"
    return "default"


@task_prerun.connect(weak=False)
def record_task_start(task_id: str | None = None, task=None, **_: Any) -> None:
    if task_id:
        _START_TIMES[task_id] = time.monotonic()
    queue = _queue_for(task)
    _record_counter("started")
    _record_counter(f"queue:{queue}:started")


@task_postrun.connect(weak=False)
def record_task_success(task_id: str | None = None, task=None, **_: Any) -> None:
    queue = _queue_for(task)
    _record_counter("succeeded")
    _record_counter(f"queue:{queue}:succeeded")
    if task_id:
        started = _START_TIMES.pop(task_id, None)
        if started is not None:
            _record_duration(getattr(task, "name", "unknown"), time.monotonic() - started)


@task_failure.connect(weak=False)
def record_task_failure(task_id: str | None = None, task=None, **_: Any) -> None:
    queue = _queue_for(task)
    _record_counter("failed")
    _record_counter(f"queue:{queue}:failed")
    if task_id:
        started = _START_TIMES.pop(task_id, None)
        if started is not None:
            _record_duration(getattr(task, "name", "unknown"), time.monotonic() - started)


@task_retry.connect(weak=False)
def record_task_retry(task_id: str | None = None, task=None, **_: Any) -> None:
    _record_counter("retried")
    _record_counter(f"queue:{_queue_for(task)}:retried")


def get_task_metrics() -> dict[str, Any]:
    client = _redis()
    counters = {
        name: int(client.get(_key(name)) or 0)
        for name in ("started", "succeeded", "failed", "retried")
    }
    queues = {
        queue: {
            "started": int(client.get(_key(f"queue:{queue}:started")) or 0),
            "succeeded": int(client.get(_key(f"queue:{queue}:succeeded")) or 0),
            "failed": int(client.get(_key(f"queue:{queue}:failed")) or 0),
            "retried": int(client.get(_key(f"queue:{queue}:retried")) or 0),
            "depth": int(client.llen(queue)),
        }
        for queue in _QUEUES
    }
    durations = client.lrange(_key("duration"), 0, 999)
    parsed: list[tuple[str, float]] = []
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
    return {**counters, "queues": queues, "tasks": task_stats}
