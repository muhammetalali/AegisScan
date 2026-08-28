# Production Security & Observability Baseline

## Secrets

Production uses a secret-manager contract rather than committed credentials. `docker-compose.production.yml` requires `DJANGO_SECRET_KEY`, `JWT_SECRET_KEY`, database credentials and TLS Redis endpoints. In Kubernetes/managed platforms, inject these from Vault, cloud secret managers, or workload-identity-backed secret stores.

Never put production `.env` files in Git. Rotate JWT and application signing keys independently and record rotation events in the audit system.

## Redis TLS

Production Redis URLs must use `rediss://` and `REDIS_SSL_CERT_REQS=required`. Redis databases are separated for broker and result storage. Certificate verification is mandatory in production.

## Resource isolation

Application, workflow and report workers have independent CPU/memory limits. Scale queues independently instead of increasing one global worker pool.

## Prometheus

FastAPI exposes `/metrics` for an internal Prometheus scraper. Do not publish this endpoint directly to the public Internet; place it behind the private service network or an authenticated metrics gateway.

Recommended alerts:

- HTTP error rate > 2% for 5 minutes
- p95 API latency > 1 second for 5 minutes
- Celery queue depth continuously increasing for 10 minutes
- Celery failure rate > 5%
- task execution p95 above the task SLA
- Redis connection errors
- repeated circuit-breaker openings for intelligence providers

## OpenTelemetry

Set `OTEL_ENABLED=1`, `OTEL_SERVICE_NAME`, and `OTEL_EXPORTER_OTLP_ENDPOINT` to export traces to an internal OTLP collector. The application does not emit traces when no collector endpoint is configured.

## DLQ and idempotency

Failed tasks are routed to Redis-backed dead-letter lists only after their configured retry budget is exhausted. Idempotency keys use atomic Redis `SET NX` with a bounded TTL. DLQ consumers must replay only after inspecting the failure reason and ensuring the operation is safe to repeat.

## Production deployment gate

Before promotion:

1. Validate the production Compose configuration.
2. Build every image from a clean cache.
3. Verify FastAPI `/health` and `/ready`.
4. Verify `/metrics` is reachable only from the monitoring network.
5. Verify every Celery worker responds to `inspect ping`.
6. Submit a deterministic health task and verify completion.
7. Confirm TLS Redis connectivity.
8. Execute migration checks.
9. Run backend/frontend tests and static checks.
10. Record the exact Git commit SHA as the deployment artifact.
