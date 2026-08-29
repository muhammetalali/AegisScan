# AegisScan — Reality Audit

**Branch:** `main`  
**Audit date:** 2026-08-29  
**Scope:** repository structure, Frontend, Django/FastAPI backend, authentication, persistence, async execution, security configuration, deployment configuration, and mock/fake behavior.

## Executive verdict

AegisScan has a substantial Enterprise Security Validation UI and a broad backend/domain structure, but **`main` is not yet a real end-to-end production security platform**. Several critical paths are explicitly simulated or in-memory, and there are structural/runtime blockers that must be resolved before production deployment.

### Current maturity

- Frontend architecture/UI: **SUBSTANTIAL / PARTIAL**
- Protected routing: **PRESENT, but auth bootstrap is incomplete**
- API layer: **PRESENT, but split/duplicated between Django and FastAPI**
- PostgreSQL persistence: **CONFIGURED, not proven operational from repository alone**
- Django migrations: **MISSING from the audited app directories**
- JWT issuance: **PRESENT**
- Refresh rotation: **CONFIGURED**
- Refresh-token blacklist: **CONFIGURED IN CODE BUT REQUIRED APP IS NOT INSTALLED**
- Logout revocation: **PARTIAL / LIKELY BROKEN until blacklist app+migrations are added**
- RBAC: **PRESENT at Django permission layer, requires endpoint/tenant verification**
- Rate limiting / brute-force protection: **NOT IMPLEMENTED in audited configuration**
- CORS: **DEVELOPMENT-PERMITTED; production requires strict environment values**
- Cookie-based auth: **NOT IMPLEMENTED**; JWTs are persisted in browser `localStorage`
- Validation workflow: **EXPLICITLY SIMULATED / IN-MEMORY**
- Scan orchestration: **EXPLICITLY SIMULATED / IN-MEMORY**
- Dashboard metrics: **EXPLICITLY RANDOM / FAKE**
- Celery: **CONFIGURED, but real security work is not wired to the validation simulator**
- Nmap/Nuclei adapters: **NOT demonstrated in the audited platform path**
- Intelligence/Fusion: **architecture exists; real provider-to-platform persistence must be verified and completed**
- Production deployment: **NOT READY**

## Critical findings

### CRITICAL-01 — Validation endpoint is a simulator

`aegis-platform/backend/fastapi_app/routers/validations.py` stores validations in `_store` and advances them using `_simulate_validation()`. It uses `asyncio.sleep()` and `random` to generate progress/findings. This means the UI can display completed validation activity without executing a real security test or persisting the execution to PostgreSQL.

**Required action:** replace the simulator with a persisted ValidationRun model + Celery task + real provider execution + evidence recording.

### CRITICAL-02 — Scan orchestrator is a simulator

`aegis-platform/backend/fastapi_app/services/scan_orchestrator.py` explicitly simulates engine execution. It sleeps for shortened demo intervals and emits a hardcoded final result (`security_score=85.5`, `findings_count=12`, etc.).

**Required action:** replace `_run_engine()` with real provider adapters and persist scan/job state and results.

### CRITICAL-03 — Dashboard returns random fake security data

`aegis-platform/backend/fastapi_app/routers/dashboard.py` imports `random` and returns randomized project/asset/validation/risk/security/compliance metrics. Recent validations are also fabricated from fixed project names and synthetic IDs; trend data is generated randomly.

**Required action:** all dashboard queries must aggregate real PostgreSQL data. If no data exists, the API must return zero/empty states rather than fabricated values.

### CRITICAL-04 — Django project module names are inconsistent

`aegis-platform/backend/django_project/settings.py` declares `ROOT_URLCONF = 'aegis_core.urls'`, `WSGI_APPLICATION = 'aegis_core.wsgi.application'`, and `ASGI_APPLICATION = 'aegis_core.asgi.application'`, while the repository contains `django_project/urls.py`, `django_project/asgi.py`, and `django_project/wsgi.py`. The ASGI/WSGI files also set `DJANGO_SETTINGS_MODULE` to `aegis_core.settings`.

**Required action:** normalize the Django project package name and all entrypoints before runtime validation.

### CRITICAL-05 — Django settings reference an app that is absent from the audited tree

`settings.py` contains `'reports'` in `INSTALLED_APPS` and `urls.py` includes `reports.urls`, but the audited `django_project` tree has no `reports` package. A direct repository path lookup for `aegis-platform/backend/django_project/reports` returns Not Found.

**Required action:** either implement the Django reports app or remove the stale Django references and use the intended FastAPI report service. Do not leave broken imports in production settings.

### CRITICAL-06 — `users.management_urls` is referenced but absent

`django_project/urls.py` includes `users.management_urls`, but `django_project/users/management_urls.py` is absent from the repository path audited.

**Required action:** implement the module or remove the include and route management endpoints through the existing user URLs.

### CRITICAL-07 — Django migrations are absent from the audited application tree

The application directories contain model files but no `migrations` directories in the audited paths. A direct lookup of `django_project/assets/migrations` returns Not Found.

**Required action:** create and commit initial migrations for every Django app, including the custom user model and any required SimpleJWT blacklist models.

### HIGH-01 — Refresh-token blacklist is not fully installed

`settings.py` enables `BLACKLIST_AFTER_ROTATION=True` and the user logout view calls `RefreshToken(...).blacklist()`, but `rest_framework_simplejwt.token_blacklist` is not present in `INSTALLED_APPS` in the audited settings. Without that app and migrations, blacklist persistence cannot be considered operational.

**Required action:** add the blacklist app, migrate it, and add integration tests for rotation/replay/revocation.

### HIGH-02 — JWTs are persisted in `localStorage`

The frontend `authStore.ts` uses Zustand `persist` with `createJSONStorage(() => localStorage)` and stores `accessToken` and `refreshToken`. This is not an HttpOnly-cookie design and increases exposure to token theft through XSS.

**Required action:** for the production architecture, prefer a secure HttpOnly refresh-token cookie (with appropriate SameSite/Secure/CSRF controls) and keep short-lived access state out of persistent localStorage where practical.

### HIGH-03 — Auth bootstrap is incomplete

`App.tsx` uses `isAuthenticated` for route protection, but `main.tsx` does not call `initAuth()`. The persisted Zustand state can therefore influence the initial route decision before a server-side `/me` validation has completed.

**Required action:** implement a deterministic auth bootstrap before rendering protected application routes.

### HIGH-04 — Frontend and backend route topology is inconsistent

The frontend API client defaults to `http://localhost:8000/api/v1`. The Django auth routes are mounted under `/api/v1/auth/`, while the frontend calls `/users/me/`, `/users/me/change_password/`, etc. Django's root URLs also reference a separate `users.management_urls` module. This needs endpoint-by-endpoint contract testing.

**Required action:** establish one canonical API contract and test every frontend call against it.

### HIGH-05 — FastAPI readiness endpoint is not a dependency readiness check

`fastapi_app/main.py` returns `{ "ready": true }` from `/ready` without checking PostgreSQL, Redis, Celery, or external providers.

**Required action:** readiness must fail when required dependencies are unavailable.

### HIGH-06 — FastAPI WebSocket scan/validation state is not persisted

Scan and validation state is held in Python dictionaries and asyncio tasks. A process restart loses active state, and multiple workers cannot safely share it.

**Required action:** persist job state in PostgreSQL/Redis and use Celery as the durable execution mechanism.

### HIGH-07 — Celery is configured but not the source of truth for validation execution

The repository has Celery configuration and tasks, but the validation route directly creates asyncio background tasks. This bypasses the intended worker architecture.

**Required action:** API request -> durable DB job -> Celery -> provider -> DB/evidence -> WebSocket event.

### HIGH-08 — `django-redis` is referenced but absent from requirements

Django settings configure `django_redis.cache.RedisCache`, but the audited `aegis-platform/backend/requirements.txt` does not list `django-redis`.

**Required action:** add the dependency or change the cache backend to a dependency actually installed and tested.

### HIGH-09 — CORS is permissive in development and production safety depends entirely on env

Django settings use explicit origins by default but also set `CORS_ALLOW_ALL_ORIGINS = DEBUG`. FastAPI uses `settings.CORS_ORIGINS` and allows credentials/methods/headers broadly. This is acceptable only with strict production configuration and reverse-proxy policy.

**Required action:** define production-only allowed origins, credentials policy, trusted hosts, CSRF origins, and proxy behavior; add automated configuration tests.

### HIGH-10 — Cookie security is not currently implemented

The frontend sets Axios `withCredentials=true`, but the actual JWTs are stored in localStorage and sent in the Authorization header. Therefore `withCredentials` does not make the authentication cookie-secure; there is no HttpOnly refresh cookie in the audited implementation.

**Required action:** explicitly choose and implement either a secure cookie architecture or a documented bearer-token architecture with its security controls. Do not rely on `withCredentials` alone.

### HIGH-11 — Brute-force/rate limiting is not visible in the audited auth path

Login attempts are logged, but no actual throttling/rate-limit policy was found in the audited Django REST configuration or user login view.

**Required action:** add IP/account-aware login throttling, exponential backoff or temporary lockout, and tests.

### HIGH-12 — `defusedxml` is absent

The audited backend requirements do not include `defusedxml`. If AegisScan parses untrusted XML anywhere, XML processing must use a safe parser strategy.

**Required action:** add `defusedxml` where XML is accepted/parsed and audit all XML parsing call sites.

## Frontend checklist

| Check | Result | Evidence / action |
|---|---|---|
| `mocks`/`fixtures`/`sample-data` directories | No such path found in recursive `main` tree | Keep automated scan in CI |
| `localStorage` as primary business data source | Not observed for domain data; auth tokens are persisted there | Remove persistent refresh token for production cookie architecture |
| `setTimeout`/sleep demo success | Validation uses `asyncio.sleep`; scan uses `asyncio.sleep` | Critical simulator removal required |
| localhost API defaults | **YES** | `frontend/src/services/api.ts` defaults to localhost:8000 |
| localhost WebSocket default | **YES** | `frontend/src/services/api.ts` defaults to ws://localhost:8000 |
| TODO/COMING SOON | Needs content-level scan of all source blobs | Add CI grep/code-search job |
| Protected routes | **YES, present** | `App.tsx` has `ProtectedRoute`/`PublicRoute` |
| Auth bootstrap | **INCOMPLETE** | `main.tsx` does not invoke `initAuth()` |

## Backend checklist

| Check | Result |
|---|---|
| Hardcoded/random API data | **YES — critical** in dashboard |
| In-memory endpoints | **YES — critical** in validations and scan orchestration |
| Models | Extensive Django models present |
| Migrations | **Missing in audited app tree** |
| Celery | Configured, but validation path bypasses it |
| Beat | Configured via Django Celery Beat; operational schedule requires DB-backed configuration/verification |
| Secrets in code | Dangerous default secrets exist in settings (`django-insecure-change-me-in-production`, `jwt-secret-change-me`) — defaults must be forbidden in production |

## Database checklist

### Model domains present in repository

The Django tree includes domains for users, projects, scans, vulnerabilities, assets, audit, compliance, knowledge, notifications, and system. The repository also contains separate platform/domain models under `aegis/models`.

### Missing proof

The repository alone cannot prove that PostgreSQL/Redis are currently running. Docker Compose defines PostgreSQL 16 and Redis 7 services, but operational connectivity must be tested in a running environment.

### Required production data model

At minimum, the production persistence layer must cover:

- Organization / Tenant
- User
- Role / Permission
- Project
- Asset
- Assessment / Scan
- ValidationRun
- Finding / Vulnerability
- Evidence / Artifact
- Intelligence source data
- Risk assessment
- Remediation action
- Re-validation result
- Report
- Audit event

## Authentication & authorization checklist

- JWT access/refresh issuance: **present**
- Refresh rotation: **configured**
- Blacklist after rotation: **configured but blacklist app absent**
- Logout: **partial; depends on blacklist infrastructure**
- Profile endpoint: **frontend contract needs correction/verification**
- API RBAC: **Django permission classes are present**
- Tenant isolation: **not established as a first-class Organization boundary in the audited models**
- Brute-force protection: **missing**
- CORS: **needs production hardening**
- Cookies: **not implemented as secure HttpOnly auth mechanism**
- XML safety: **defusedxml absent**

## Deployment checklist

The committed `docker-compose.yml` defines PostgreSQL, Redis, Django, FastAPI, Celery worker, Celery beat, frontend, and nginx. However, the audited backend directory listing contains only `celery_app`, `django_project`, `fastapi_app`, and `requirements.txt`; the compose file references `Dockerfile.django`, `Dockerfile.fastapi`, frontend `Dockerfile`, nginx configuration, and SSL material that must all be verified to exist and build successfully.

Production must additionally require:

1. Real secrets supplied through deployment secret management.
2. No insecure defaults.
3. TLS.
4. Strict `ALLOWED_HOSTS`.
5. Strict CORS/CSRF origins.
6. Database backups and restore testing.
7. Durable Celery/Redis configuration.
8. Security worker isolation for scanner execution.
9. Scope authorization before network scanning.
10. Dependency and image vulnerability scanning.
11. CI tests and migration checks.
12. Real end-to-end validation against an authorized test target.

## Required implementation sequence

1. Normalize Django project package/entrypoints and eliminate broken imports.
2. Create/verify all Django apps and migrations.
3. Add SimpleJWT blacklist app + migrations.
4. Add `django-redis` or replace its backend.
5. Implement real auth bootstrap and canonical API contracts.
6. Implement Organization/Tenant isolation and API-level RBAC tests.
7. Remove all fake/random/in-memory dashboard and validation/scan paths.
8. Introduce durable ValidationRun/ScanJob persistence.
9. Move long-running work to Celery.
10. Implement real scanner adapters with strict target-scope authorization.
11. Persist raw outputs and hashed evidence.
12. Implement real NVD/OSV/CISA KEV/EPSS ingestion and FusionEngine persistence.
13. Recalculate real risk/posture from stored facts.
14. Implement remediation + proof-of-fix revalidation.
15. Implement real reports from persisted data.
16. Add WebSocket events backed by durable job state.
17. Add security, integration, and end-to-end tests.
18. Build and verify Docker/production deployment.

## Definition of done

AegisScan must not display a successful scan, validation, finding, risk score, evidence item, posture score, or report unless the underlying result is traceable to a real persisted execution or a clearly identified external intelligence source.

The production golden path is:

`Login -> Organization -> Asset -> Authorized Scope -> Assessment -> Celery Job -> Real Provider -> Raw Evidence -> Normalized Finding -> Intelligence Fusion -> Risk -> Remediation -> Re-validation -> Verified Result -> Audit Event -> Report`

Anything outside that chain must be explicitly labeled as configuration, empty state, or unavailable — never as a fabricated security result.
