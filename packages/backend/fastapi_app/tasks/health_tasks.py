from __future__ import annotations

from datetime import datetime, timezone

from ..celery_app import celery_app


@celery_app.task(name="fastapi_app.tasks.health_tasks.celery_health")
def celery_health() -> dict[str, str]:
    """Deterministic task used by Docker/CI to prove worker execution."""
    return {"status": "ok", "worker": "aegisscan", "timestamp": datetime.now(timezone.utc).isoformat()}
