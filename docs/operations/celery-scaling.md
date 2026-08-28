# Celery workload isolation and scaling

AegisScan uses Redis as the Celery broker and separates workloads by queue so slow report generation cannot starve workflow/SLA processing.

## Queues

| Queue | Workload | Default workers |
| --- | --- | ---: |
| `default` | fallback tasks | 2 |
| `health` | liveness/diagnostic tasks | 2 |
| `workflow` | SLA evaluation and workflow events | 2 |
| `reports` | report generation and scheduled reports | 2 |

The Compose deployment keeps a core worker for `default,health` and dedicated worker pools for `workflow` and `reports`.

## Horizontal scaling

Increase replicas per workload independently. For example, add workflow workers when queue depth or workflow latency grows without increasing report workers. Keep `CELERY_*_WORKER_CONCURRENCY` aligned with available CPU and memory rather than treating concurrency as a fixed constant.

## Operational signals

The protected Celery metrics endpoint exposes:

- started/succeeded/failed/retried counters
- per-queue depth and outcome counters
- task average and maximum execution duration

Scale based on sustained queue depth, p95/p99 task latency, retry rate, and worker CPU/memory. A transient queue spike alone is not sufficient evidence for scaling.

## Reliability rules

- Tasks use late acknowledgement and reject-on-worker-loss so a worker crash does not silently acknowledge work.
- JSON is the only accepted task serialization format.
- Workflow and report tasks have explicit rate limits.
- Beat publishes scheduled tasks directly to their dedicated queues.
- Telemetry failures are deliberately non-blocking and must never fail a business task.

## Production hardening

Use managed Redis/TLS, non-default credentials, secret management, resource limits, and a durable monitoring backend in production. Redis telemetry in this repository is an operational baseline, not a replacement for Prometheus/OpenTelemetry.
