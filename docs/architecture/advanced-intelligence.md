# Advanced Intelligence & Assurance

AegisScan now exposes governed building blocks for advanced enterprise assurance:

- **BTE / Behavioral Terrain:** baseline-vs-observed fingerprints and anomaly signals for asset behavior.
- **ADI boundary:** provider interface for authorized external threat intelligence. The default dark-intelligence provider is deliberately disabled; no anonymous-market scraping or illicit data collection is part of the platform.
- **Correlation Intelligence:** evidence grouping, cross-source agreement, conflicts, and confidence.
- **Controlled AePEX:** represented as reviewable validation/remediation proposals. Production changes are never executed by this API; validation belongs in an isolated twin/sandbox with approval and rollback evidence.
- **AADA:** autonomous-assurance proposal loop: evidence -> candidate remediation -> isolated validation -> before/after risk -> approval -> audited action.
- **Slack/Teams:** webhook adapters using `SLACK_WEBHOOK_URL` and `TEAMS_WEBHOOK_URL`.
- **Vault:** production secret provider using `VAULT_ADDR`, `VAULT_TOKEN`, and optional `VAULT_TLS_VERIFY`; CI can continue using ephemeral secrets.
- **Observability:** existing Prometheus/OpenTelemetry foundation remains the metrics/tracing layer for these services.
- **Horizontal scaling:** services remain stateless at the API layer; Redis is the broker/cache and PostgreSQL is the durable state. Add Celery workers horizontally and partition queues by workload.

## Production controls

1. Every external provider has a bounded timeout/retry/circuit-breaker boundary.
2. Every finding carries source/provenance information before correlation.
3. Confidence is explicit and conflicts are surfaced instead of silently merged.
4. Autonomous remediation is proposal-only until an authorized execution path is added.
5. Notifications are outbound adapters and never contain credentials in source control.
6. Vault is a production secret source; CI ephemeral injection is the non-production verification mechanism.
7. Scaling changes must be validated with queue-depth, task-latency, failure-rate, and recovery metrics.
