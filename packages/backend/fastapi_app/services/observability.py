from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    OTEL_AVAILABLE = False

REQUESTS = Counter("aegis_http_requests_total", "HTTP requests", ["method", "path", "status"])
REQUEST_LATENCY = Histogram("aegis_http_request_duration_seconds", "HTTP request latency", ["method", "path"])
CELERY_TASKS = Counter("aegis_celery_tasks_total", "Celery task outcomes", ["task", "queue", "state"])
CELERY_DURATION = Histogram("aegis_celery_task_duration_seconds", "Celery task duration", ["task", "queue"])
CELERY_QUEUE_DEPTH = Gauge("aegis_celery_queue_depth", "Celery queue depth", ["queue"])
INTELLIGENCE_REQUESTS = Counter("aegis_intelligence_requests_total", "Intelligence provider requests", ["provider", "state"])
INTELLIGENCE_LATENCY = Histogram("aegis_intelligence_request_duration_seconds", "Provider latency", ["provider"])


def configure_tracing() -> None:
    if not OTEL_AVAILABLE:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": "aegisscan-fastapi"}))
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)


def tracer():
    if OTEL_AVAILABLE:
        return trace.get_tracer("aegisscan")
    return None


def observe_http(method: str, path: str):
    @contextmanager
    def _observe() -> Iterator[None]:
        started = time.perf_counter()
        status = "500"
        try:
            yield
            status = "200"
        except Exception:
            raise
        finally:
            REQUESTS.labels(method, path, status).inc()
            REQUEST_LATENCY.labels(method, path).observe(time.perf_counter() - started)
    return _observe()


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
