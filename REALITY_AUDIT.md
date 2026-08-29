# AegisScan — Reality Audit

**Branch:** `main`  
**Audit date:** 2026-08-29  
**Audit basis:** current repository tree, current source files, and commit history on `main`.  
**Rule:** a feature is only classified as real when the repository shows an actual implementation path; repository inspection cannot prove that PostgreSQL/Redis/scanner binaries are currently running on a developer machine.

## Executive verdict

`main` has materially advanced since the earlier audit. The major simulator paths identified previously have been replaced or constrained: dashboard metrics now aggregate Django models; validation is persisted and dispatched to Celery; scan execution is persisted and routed through real Nmap/Nuclei adapters; authorization gates are explicit; HttpOnly auth cookies and CSRF bootstrapping are implemented; login/refresh rate limiting is present; `defusedxml` is installed; and CI now provisions PostgreSQL/Redis and performs Django/frontend verification.

However, **AegisScan is still not production-complete**. The biggest remaining blockers are migration/runtime proof, first-class tenant/scope authorization, complete finding normalization, Nuclei result persistence into findings, intelligence ingestion/FusionEngine integration, robust worker lifecycle semantics, and end-to-end verification against an authorized test target.

## Current status

| Domain | Reality status | Evidence / conclusion |
|---|---|---|
| Frontend UI | 🟢 Substantial | Enterprise platform UI exists and builds through CI configuration |
| Mock business data | 🟢 Major simulator paths removed | Dashboard now queries DB; scan/validation paths no longer use demo sleep/random results |
| Protected routing | 🟢 Present | Auth bootstrap is invoked from `main.tsx` |
| API client | 🟢 Present | Axios uses environment API URL, credentials, CSRF settings, refresh handling |
| PostgreSQL | 🟡 Configured | Django DB points to `DATABASE_URL`; operational connectivity still requires runtime execution |
| Redis | 🟡 Configured | cache/channel/Celery URLs are configured; runtime connectivity still requires execution |
| Django migrations | 🔴 Blocker | No `users/migrations/0001_initial.py` or `assets/migrations/0001_initial.py` found at audited paths |
| JWT access/refresh | 🟢 Implemented | Login and refresh endpoints issue cookies; SimpleJWT rotation enabled |
| Refresh blacklist | 🟢 Configured | `token_blacklist` is installed and blacklist-after-rotation is enabled |
| Logout revocation | 🟢 Implemented | Logout reads refresh cookie, blacklists it, and clears auth cookies |
| HttpOnly cookies | 🟢 Implemented | Access/refresh cookies are HttpOnly with configurable Secure/SameSite |
| Rate limiting | 🟢 Present | Login and refresh are IP-rate-limited with django-ratelimit |
| CORS | 🟢 Strict by configuration | Explicit origins only; credentials enabled; production values must remain strict |
| CSRF | 🟢 Present | CSRF cookie endpoint + Axios X-CSRFToken + trusted origins configuration |
| RBAC | 🟡 Partial | Django permission layer exists; tenant-wide isolation still needs proof/tests |
| Validation execution | 🟢 Real worker path | Persisted `ValidationRun` -> Celery -> Nmap -> evidence/result |
| Scan execution | 🟢 Real worker path | Persisted `Scan` -> Celery -> Nmap/Nuclei -> evidence/result |
| Nmap | 🟢 Real adapter | Safe argv execution and XML parsing are implemented |
| Nuclei | 🟢 Real adapter exists | Binary execution is real, but finding normalization is incomplete |
| Evidence | 🟢 Real persistence | Raw output, SHA-256, metadata and collection timestamp are persisted |
| Dashboard | 🟢 DB-backed | No random metrics in current dashboard implementation |
| Intelligence | 🟡 Partial | Architecture/providers require full ingestion + persistence + Fusion verification |
| Attack Path | 🟡 Partial | UI/domain direction exists; real graph calculation requires verification |
| Remediation | 🟡 Partial | Workflow exists in platform architecture; proof-of-fix needs full provider-backed implementation |
| Reports | 🟡 Partial | Must verify every report path is DB-derived and executable |
| Production | 🔴 Not ready | Runtime, migrations, tenant isolation, scanner scope, end-to-end tests and deployment verification remain |

## Checklist — Frontend

| Check | Result |
|---|---|
| `mocks` / `dummy` / `sample-data` directories | No matching path was found in the current recursive `main` tree inspected |
| `localStorage` as business-data source | Not found in the inspected current auth store; auth tokens are no longer persisted in localStorage |
| `setTimeout` demo success | No repository search hit in current indexed source; validation/scan code uses Celery rather than simulated sleep |
| Hardcoded localhost API | **Development fallback only:** `api.ts` defaults to `http://localhost:8000/api/v1` when `VITE_API_URL` is absent |
| Hardcoded localhost WebSocket | **Development fallback only:** `api.ts` defaults to `ws://localhost:8000` when `VITE_WS_URL` is absent |
| TODO/COMING SOON | No indexed search hit for `TODO`; continue enforcing this in CI |
| Protected routes | Present |
| Auth bootstrap | Present: `main.tsx` invokes `initAuth()` |

### Frontend security conclusion

The frontend now uses `withCredentials`, CSRF cookie/header configuration, and does not persist JWTs in localStorage. This is a materially safer architecture than the previous bearer-token/localStorage design. The remaining requirement is to verify the production deployment uses HTTPS and `AUTH_COOKIE_SECURE=True`.

## Checklist — Backend

### Hardcoded/fake results

The previous dashboard implementation that imported `random` and fabricated scores is gone. The current dashboard aggregates `Project`, `Asset`, `Scan`, and `Vulnerability` records and returns zero/empty values when there is no data.

The previous validation simulator is gone. The current endpoint creates a persisted `ValidationRun` and dispatches `validate_finding_task` to Celery.

The previous scan simulator is gone. `ScanOrchestrator` queues a persisted scan and dispatches `run_nmap_scan`.

Unsupported engine categories are explicitly marked `provider-required`/inactive and fail rather than pretending to have executed. This is correct behavior for a no-fake-data platform.

### Celery

Celery is configured with JSON serialization, Redis broker/result backend, one-minute SLA evaluation, and autodiscovery. The real Nmap/validation tasks are Celery tasks. Runtime worker connectivity still requires execution in Docker/local environment.

### Secrets

The repository no longer needs real secrets committed. `.env.example` contains replacement placeholders. **Production must reject insecure fallback secrets** currently present as development defaults in Django/FastAPI settings.

## Database reality

### Models verified in current tree

The repository contains model domains for at least:

- Users
- Projects
- Scans
- Vulnerabilities
- Assets
- Evidence / ValidationRun
- Compliance
- Knowledge
- Notifications
- Audit
- System

### Remaining blocker: migrations

Direct checks of `django_project/users/migrations/0001_initial.py` and `django_project/assets/migrations/0001_initial.py` return Not Found. Therefore the repository cannot currently be certified as migration-complete.

The CI workflow attempts `makemigrations --check --dry-run && migrate`, which is useful, but it does **not** substitute for committed migration files in a production repository. Initial migrations must be generated, reviewed, committed, and tested from a clean PostgreSQL database.

## Authentication / Authorization

### Verified implementation

- `/auth/login/` exists.
- `/auth/refresh/` exists.
- `/auth/logout/` exists.
- `/auth/csrf/` exists.
- Access and refresh JWTs are placed in HttpOnly cookies.
- Refresh rotation and blacklist-after-rotation are enabled.
- Logout blacklists the refresh token and deletes both auth cookies.
- Login is rate-limited to 10 POST requests/minute/IP.
- Refresh is rate-limited to 20 POST requests/minute/IP.
- DRF defaults to authenticated requests.
- Cookie JWT authentication is implemented.
- `defusedxml` is present in requirements.

### Remaining authorization issue

The current validation API accepts `authorized: true` from the request itself and the Nmap task then treats that flag as sufficient authorization. The target validator prevents malformed targets but does **not** establish that the target belongs to an organization-owned authorized scope.

This is a **security-critical architectural gap**. A production security platform must derive authorization from persisted scope/asset policy, not trust a client-supplied boolean.

Required flow:

`Authenticated User -> Organization/Tenant -> Asset -> Authorized Scope Policy -> Job -> Provider`

A request must be rejected if the target is not contained in a persisted authorized scope, regardless of the submitted `authorized` flag.

## CORS and Cookies — explicit answer

**CORS is configured, but production hardening is still required.** Django sets explicit `CORS_ALLOWED_ORIGINS`, disables `CORS_ALLOW_ALL_ORIGINS`, enables credentials, and uses the same configured origins for CSRF trusted origins. FastAPI also loads allowed origins from environment. Production must provide the exact HTTPS frontend origin(s), not development localhost values.

**Cookies are now implemented correctly at the application layer.** Access and refresh JWTs are issued as HttpOnly cookies; `SameSite=Lax` is configured; `Secure` is environment-controlled. Production must set `AUTH_COOKIE_SECURE=True` and use HTTPS. `withCredentials=true` is present in the frontend.

A remaining cleanup is to separate `CSRF_TRUSTED_ORIGINS` from `CORS_ALLOWED_ORIGINS` so operators cannot accidentally make the CSRF trust set broader than intended.

## Scanner reality

### Nmap

A real Nmap adapter exists and executes the binary through an argument list rather than shell interpolation. The output is parsed as XML and persisted as Evidence. The parser is intended to use `defusedxml`.

### Nuclei

A real Nuclei adapter exists and executes JSONL output. The current task persists raw Nuclei output as Evidence, but it does not yet normalize every Nuclei finding into the Vulnerability/Finding domain. Therefore Nuclei execution is real, while the full `scan -> normalized finding -> risk` pipeline is incomplete.

### Scope enforcement

Target syntax validation is **not equivalent to authorization**. This must be fixed before exposing scanning to untrusted tenants/users.

## Evidence reality

Evidence has:

- raw output
- SHA-256 digest calculated on save
- source/tool
- evidence type
- metadata
- collection timestamp
- collecting user
- optional scan/asset/finding references

This satisfies the basic provenance requirement, but evidence integrity should additionally be covered by tests and immutable/controlled storage policy in production.

## Intelligence / FusionEngine

The target architecture remains:

`NVD + OSV + CISA KEV + EPSS -> normalize -> correlate -> conflict detection -> confidence -> risk -> explanation`.

Current repository inspection does not provide enough proof that all providers are fully ingested, persisted, deduplicated, scheduled, and connected to dashboard/risk calculations. Therefore this area remains **PARTIAL**, not complete.

## Required next implementation sequence

1. **Generate and commit Django migrations for every model app.**
2. **Create first-class Organization/Tenant + persisted authorized-scope model and enforce it server-side.**
3. **Add endpoint-level RBAC and tenant-isolation integration tests.**
4. **Separate CSRF trusted origins from CORS allowed origins and add production configuration validation.**
5. **Add Nuclei finding normalization and vulnerability persistence.**
6. **Complete real NVD/OSV/CISA KEV/EPSS ingestion, persistence, scheduling and FusionEngine.**
7. **Connect risk/posture to persisted findings and intelligence rather than derived placeholders.**
8. **Complete remediation + proof-of-fix revalidation.**
9. **Verify report generation exclusively from persisted data.**
10. **Add durable WebSocket job events from DB/Celery state.**
11. **Run clean PostgreSQL/Redis/Celery/Nmap/Nuclei end-to-end tests against an explicitly authorized test target.**
12. **Verify Docker production stack, TLS, secrets, backups, restore, monitoring and dependency/image security scanning.**

## Definition of Done

AegisScan is complete only when this chain works with real data:

`Login -> Organization -> Asset -> Authorized Scope -> Assessment -> Celery Job -> Real Provider -> Raw Evidence -> Normalized Finding -> Intelligence Fusion -> Risk -> Remediation -> Re-validation -> Verified Result -> Audit Event -> Report`

No UI, API or worker may manufacture a successful security result. Unsupported functionality must return an explicit unavailable/provider-not-configured state.
