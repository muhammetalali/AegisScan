from fastapi_app.celery_app import celery_app


def test_production_queues_are_declared() -> None:
    queues = set(celery_app.conf.task_queues)
    assert {"default", "workflow", "reports", "health"}.issubset(queues)


def test_task_routes_are_isolated() -> None:
    routes = celery_app.conf.task_routes
    assert routes["fastapi_app.tasks.workflow_tasks.*"]["queue"] == "workflow"
    assert routes["fastapi_app.tasks.report_tasks.*"]["queue"] == "reports"
    assert routes["fastapi_app.tasks.health_tasks.*"]["queue"] == "health"


def test_beat_tasks_target_dedicated_queues() -> None:
    beat = celery_app.conf.beat_schedule
    assert beat["evaluate-action-slas-every-minute"]["options"]["queue"] == "workflow"
    assert beat["generate-scheduled-reports"]["options"]["queue"] == "reports"
