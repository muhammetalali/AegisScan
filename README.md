# AegisScan

AegisScan is a defensive security-validation platform with a Python analysis core and a web platform.

## Repository map

- `packages/core/` — the reusable Python core, CLI, models, evidence engines, correlation, remediation, and analytical attack-path graph.
- `packages/backend/` — Django is the authority for identity, users, projects, reports, compliance, and durable application data; FastAPI is the operational API for high-throughput validation and live progress; Celery runs asynchronous work.
- `packages/web/` — the React/TypeScript user interface. Its production bundle in `dist/` is a tracked deployment artifact.
- `packages/platform/` — Docker Compose and Windows platform operations.
- `tests/` — core and integration tests. Backend migration and endpoint checks run from the repository root through `manage.py`.
- `docs/reports/` — retained generated reports used as audit examples; runtime output is ignored under `packages/backend/runtime/reports/`.

## API contract

The canonical Django authentication routes are `/api/v1/auth/*`, the authenticated self-service route is `/api/v1/users/me/`, durable reports are served by Django at `/api/v1/reports/`, and persisted compliance is served at `/api/v1/compliance/`. FastAPI remains the operational API for high-throughput validation, live progress, and assurance workflows; it does not maintain second in-memory report or compliance stores.

Optional passive intelligence adapters for Shodan, Censys, AlienVault OTX, and URLScan are available in the core. They are disabled without explicit credentials, never perform active probing, and isolate provider failures from the primary scan.

Plugin distribution is opt-in and verified: entries in `packages/core/aegis/plugins/registry.json` must use HTTPS and provide a SHA-256 digest. The sync API downloads into an isolated versioned directory, rejects oversized or unsafe archives, and never imports or executes downloaded code automatically. See `docs/plugins.md`.

Exploit-generation and stealth/evasion payloads are intentionally not part of AegisScan. The platform provides a non-executing defensive adversary simulator that measures control coverage and produces remediation gaps inside the analytical twin. See `docs/defensive-simulation.md`.

## Quality checks

```text
python -m pytest -q
python manage.py check
python manage.py makemigrations --check --dry-run
cd packages/web && npm ci && npm run build
```

The platform is intentionally defensive: analytical attack paths and validation twins are isolated and auditable. Any active test requires explicit operator authorization and safety checks.
