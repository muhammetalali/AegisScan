from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import redis

from ..core.config import settings

CHANNEL = "aegisscan:workflow"


def _client() -> redis.Redis:
    return redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def publish_workflow_events(events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    client = _client()
    published = 0
    for event in events:
        payload = {
            "type": "workflow.sla",
            "at": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        try:
            client.publish(CHANNEL, json.dumps(payload, separators=(",", ":")))
            published += 1
        except redis.RedisError:
            # PostgreSQL remains authoritative; live fan-out is best-effort.
            continue
    return published
