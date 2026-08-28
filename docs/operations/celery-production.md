# AegisScan Celery Production Operations

## Runtime contract

Celery is started from the backend image with an explicit application path:

```text
celery -A fastapi_app.celery_app worker
celery -A fastapi_app.celery_app beat
```

The application registers workflow, report, and deterministic health tasks from `fastapi_app.tasks.*`. Docker health checks use `celery inspect ping`, while CI additionally verifies the exact registered task names and executes `celery_health` through the Redis broker.

## Worker safety defaults

The Celery application enables:

- late acknowledgements (`task_acks_late`)
- worker-lost rejection (`task_reject_on_worker_lost`)
- prefetch multiplier of one for fair work distribution
- broker retry on startup
- bounded broker reconnect attempts
- task hard/soft time limits
- JSON-only serialization
- one-day result retention
- UTC scheduling

These defaults are intended to make retries and horizontal worker scaling predictable.

## Horizontal scaling

Increase worker replicas rather than increasing concurrency without a capacity measurement. The Compose worker concurrency is configurable with `CELERY_WORKER_CONCURRENCY` and defaults to `4`.

For a production scheduler, run **one active beat instance per schedule domain**. Run multiple workers behind the same Redis broker; tasks should remain idempotent and database state transitions should use transactions/row locks where required.

Capacity signals to watch:

- queue depth
- task success/failure count
- average and maximum task duration
- database connection saturation
- Redis memory and latency
- worker CPU and memory

FastAPI exposes staff-only Celery telemetry at `/metrics/celery` backed by Redis. Telemetry failures are intentionally non-fatal to business tasks.

## Secrets

The repository keeps local-development fallbacks for convenience, but production deployments must inject unique secrets through the deployment platform. Do not commit production credentials.

Recommended progression:

1. CI uses short-lived environment-scoped secrets.
2. Production uses a managed secret store or HashiCorp Vault/KMS-backed provider.
3. Rotate Django, JWT, database, SMTP, and external intelligence credentials independently.
4. Audit secret access and never expose secret values through task arguments, logs, or Celery results.

## CI release gate

`.github/workflows/celery-production-gate.yml` validates:

1. Compose syntax.
2. PostgreSQL and Redis readiness.
3. Worker image build.
4. Django migrations.
5. Worker health.
6. Exact task registration.
7. Real task execution through Redis.
8. Beat startup.
9. Container runtime state and logs.

A release is not considered Celery-ready until this gate passes.
