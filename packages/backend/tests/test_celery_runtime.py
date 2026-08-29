import pytest

from fastapi_app.celery_app import celery_app
from fastapi_app.tasks.health_tasks import celery_health


@pytest.mark.integration
@pytest.mark.timeout(30)
def test_celery_redis_live_round_trip():
    """Prove Redis broker + routed worker + Redis result backend end-to-end."""
    inspector = celery_app.control.inspect(timeout=3)
    ping = inspector.ping() or {}

    assert ping, "No live Celery workers responded to inspect ping"
    assert any(
        isinstance(response, dict) and response.get("ok") == "pong"
        for response in ping.values()
    ), f"Live Celery workers did not return pong: {ping!r}"

    result = celery_health.apply_async(queue="health", routing_key="health")
    payload = result.get(timeout=20, propagate=True)

    assert result.successful()
    assert payload["status"] == "ok"
    assert payload["worker"] == "aegisscan"
    assert result.backend is not None


def test_celery_runtime_routes_health_task_to_health_queue():
    route = celery_app.conf.task_routes["fastapi_app.tasks.health_tasks.*"]
    assert route["queue"] == "health"
    assert route["routing_key"] == "health"
