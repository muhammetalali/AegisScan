# AegisScan — Reality Audit (Latest Remediation Pass)

Date: 2026-08-29
Branch: `main`

## Audit scope

This pass audits the repository from the root with priority:

1. Database / Django migrations
2. Authentication / JWT
3. Frontend / mock-data sweep

Only repository evidence is treated as fact. A feature is not marked operational merely because a file or UI exists.

## Database / Django findings

### Confirmed real

- The active Django project is `aegis-platform/backend/django_project` and `ROOT_URLCONF`, WSGI and ASGI paths consistently use `django_project`.
- `rest_framework_simplejwt.token_blacklist` is present in `INSTALLED_APPS`.
- Django apps have committed migration files, including `users`, `projects`, `scans`, `vulnerabilities`, `assets`, `compliance`, `knowledge`, `notifications`, `audit`, `system` and `evidence`.
- The repository contains an automated migration consistency workflow that runs Django checks, migration generation/checks, applies migrations to clean PostgreSQL, verifies the `users_user` table, and checks for pending migrations.
- `Evidence` is a real Django model with persisted raw output, SHA-256, metadata, collection timestamp and relationships to scan/asset/finding.
- PostgreSQL and Redis are configured through environment variables rather than being simulated in application code.

### Important verification boundary

The repository proves that migration files exist and that CI is designed to validate them. It does **not** by itself prove that a live institutional PostgreSQL instance has been migrated successfully. That requires an actual runtime/CI result. No live database claim is made here without that evidence.

## Authentication / JWT findings

### Confirmed real

- Access and refresh JWTs are issued by Django SimpleJWT.
- Refresh-token rotation and blacklist-after-rotation are enabled.
- `CookieJWTAuthentication` reads the access token from an HttpOnly cookie.
- Login and refresh endpoints are rate-limited with `django-ratelimit`, which is present in backend requirements.
- CORS credentials are enabled with an explicit origin allow-list and wildcard CORS is disabled.
- Session/auth cookies use HttpOnly and SameSite=Lax; Secure is enabled automatically when `DEBUG=False`.
- The frontend Axios client uses `withCredentials: true` and CSRF cookie/header configuration.

### Fixed in this pass

- Removed the refresh-token request-body fallback. Refresh now requires the HttpOnly refresh cookie.
- Removed the logout request-body refresh-token fallback. Logout now uses the HttpOnly refresh cookie.
- Fixed an authentication bootstrap race: `initAuth()` now sets the store to loading before the first async request and clears loading in `finally`, preventing protected routes from redirecting before server-side authentication initialization finishes.
- Production startup now fails closed when `DEBUG=False` and `SECRET_KEY` or `JWT_SECRET_KEY` is missing or still set to known placeholder values.

## Celery / execution findings

- The canonical Celery configuration is under `fastapi_app/celery_app.py`.
- The legacy `celery_app` compatibility entrypoint was unified with the canonical configuration.
- Legacy simulated Celery tasks were removed; real security tasks are kept under `fastapi_app.tasks.security_scan`.
- Real Nmap/Nuclei execution is asynchronous through Celery and is protected by server-side scope authorization.

## Frontend reality findings

### Confirmed real architecture

- The frontend has a real Axios API client with credentials and CSRF configuration.
- Authentication state is not persisted as access/refresh tokens in localStorage; the store keeps token fields null and relies on cookies.
- `initAuth()` is called from `main.tsx`.
- Protected routes are enforced by a React route guard.

### Still requiring the dedicated sweep

The repository is large and contains both source and generated `dist` output. The remaining frontend pass must inspect source files endpoint-by-endpoint for mock arrays, hardcoded metrics, random values, artificial timers, placeholder states and unused/orphaned screens. Generated `dist` files are not treated as source-of-truth for this audit.

## Current remediation commits

- `b9af0f0b6ecefab06eb8c7f927566c7ce3864ea6` — removed legacy simulated Celery task implementations.
- `867f1312dc0ccfe8083e01223cd3c48e47401590` — enforced HttpOnly cookie-only refresh/logout handling.
- `45e7d6de0a4d2621c2f84b545998a1ac582834d0` — fixed authentication initialization race.
- `6976e819b66d92bf586c44960fe6d5d427374839` — fail-closed production signing-secret validation.

## Remaining gates

1. Obtain a successful runtime/CI result for the migration workflow against clean PostgreSQL and Redis.
2. Verify every Django model has no pending migration with `makemigrations --check --dry-run` in CI/runtime.
3. Complete the source-level frontend mock/fake sweep.
4. Verify API-level tenant isolation and RBAC on every protected resource.
5. Verify real scanner output normalization into persisted findings.
6. Verify real intelligence ingestion and FusionEngine persistence.
7. Verify remediation proof-of-fix and report generation from persisted evidence.

## Reality rule

`Code exists != operational`.

`Configuration is valid != external service is connected`.

`Sandbox output != real output`.

`A success state is valid only when backed by a persisted database result, external provider response, or persisted evidence.`

Unsupported capabilities must fail explicitly instead of returning simulated success.
