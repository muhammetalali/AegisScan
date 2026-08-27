# AegisScan

AegisScan is a defensive security-validation platform with a Python analysis core and a web platform.

## Repository map

- `aegis/` — the reusable Python core, CLI, models, evidence engines, correlation, remediation, and analytical attack-path graph.
- `aegis-platform/backend/` — Django is the authority for identity, users, projects, reports, and durable application data; FastAPI is the operational API for high-throughput validation and live progress; Celery runs asynchronous work.
- `aegis-platform/frontend/` — the React/TypeScript user interface. Its production bundle in `dist/` is a tracked deployment artifact.
- `tests/` — core and integration tests. Backend migration and endpoint checks run from the repository root through `manage.py`.
- `docs/reports/` — retained generated reports used as audit examples; runtime output is ignored under `aegis-platform/backend/runtime/reports/`.

## API contract

The canonical Django authentication routes are `/api/v1/auth/*`, the authenticated self-service route is `/api/v1/users/me/`, durable reports are served by Django at `/api/v1/reports/`, and persisted compliance is served at `/api/v1/compliance/`. FastAPI remains the operational API for high-throughput validation, live progress, and assurance workflows; it does not maintain second in-memory report or compliance stores.

Optional passive intelligence adapters for Shodan, Censys, AlienVault OTX, and URLScan are available in the core. They are disabled without explicit credentials, never perform active probing, and isolate provider failures from the primary scan.

## Quality checks

```text
python -m pytest -q
python manage.py check
python manage.py makemigrations --check --dry-run
cd aegis-platform/frontend && npm ci && npm run build
```

The platform is intentionally defensive: analytical attack paths and validation twins are isolated and auditable. Any active test requires explicit operator authorization and safety checks.
