from __future__ import annotations

import os

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
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
    if not OTEL_AVAILABLE or os.getenv("OTEL_ENABLED", "1").lower() not in {"1", "true", "yes"}:
        return
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return
    provider = TracerProvider(resource=Resource.create({"service.name": os.getenv("OTEL_SERVICE_NAME", "aegisscan-fastapi")}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)


def tracer():
    return trace.get_tracer("aegisscan") if OTEL_AVAILABLE else None


def metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
