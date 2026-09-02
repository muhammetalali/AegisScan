from __future__ import annotations

from typing import Any

from fastapi_app.celery_app import celery_app
from fastapi_app.services.workflow_events import publish_workflow_events
from fastapi_app.services.workflow_sla import evaluate_sla_actions


@celery_app.task(name="fastapi_app.tasks.workflow_tasks.evaluate_action_slas", bind=True, max_retries=3, default_retry_delay=30)
def evaluate_action_slas(self) -> dict[str, Any]:
    try:
        changed = evaluate_sla_actions()
        published = publish_workflow_events(changed)
        return {"changed": len(changed), "published": published, "items": changed}
    except Exception as exc:  # pragma: no cover - operational retry path
        raise self.retry(exc=exc)
