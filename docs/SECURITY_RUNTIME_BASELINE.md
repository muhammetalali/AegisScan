# AegisScan Security Runtime Baseline

## Purpose

This document records the verified runtime security configuration and integration state for the `feature/enterprise-platform-ui-v2` branch. It contains configuration behavior and test expectations only; no secrets, passwords, tokens, or signing keys are stored here.

## Authentication / JWT

- Django is the authentication authority for JWT issuance.
- Access tokens are short-lived by design.
- Refresh tokens are rotated.
- Rotated refresh tokens are blacklisted.
- JWT signing algorithm: HS256.
- JWT user identifier claim: `user_id`.
- JWT token type claim: `token_type`.
- Access tokens include `session_version`.
- FastAPI validates the JWT with the shared effective JWT signing secret and algorithm.
- FastAPI re-checks the active Django user and the user's current `session_version` before authorizing protected requests.

## Session Version / Revocation

Session invalidation is version-based:

1. Django increments `User.session_version`.
2. Previously issued access tokens contain the older version.
3. FastAPI compares the token claim with the current Django value.
4. A mismatch rejects the token as invalid.
5. Refresh-token rotation/blacklisting prevents reuse of revoked refresh tokens.

## RBAC

- Authorization is enforced server-side in Django for management APIs.
- Example verified behavior: a `viewer` attempting a privileged `DELETE` operation receives HTTP `403` with `You do not have permission to perform this action.`
- Role permissions are represented by the centralized `ROLE_PERMISSIONS` mapping.
- The canonical role/permission contract is documented in `docs/RBAC_MATRIX.md`.

### RBAC Matrix Regression Baseline — Verified 2026-08-29

The dedicated Django regression suite was executed successfully with:

`docker exec aegis-django python manage.py test users.test_rbac_matrix -v 2`

Result:

- 7 tests collected.
- 7 tests passed.
- 0 failures.

The verified guarantees include:

1. Every declared role has a permission set.
2. The matrix contains only declared permissions.
3. `super_admin` retains every declared permission.
4. `viewer` is read-only for protected domains.
5. `security_analyst` has no administrative user/system permissions.
6. `admin` does not receive the reserved destructive/system privileges.
7. `auditor` cannot modify protected security state.

## FastAPI Integration

Verified endpoints/runtime:

- `GET /health` -> HTTP 200.
- `GET /openapi.json` -> HTTP 200.
- Protected FastAPI requests accept valid Django-issued JWTs.
- Invalid/revoked JWTs are rejected with HTTP 401.

## WebSocket Authentication

Workflow WebSocket endpoint:

- `ws://<host>:8001/ws/workflow`

Authentication contract:

- Bearer token is supplied through WebSocket subprotocols.
- Valid JWT -> connection accepted and `workflow.connected` event is emitted.
- Missing token -> rejected without an internal server error.
- Invalid token -> rejected with HTTP 403.

## Live WebSocket Revocation — Verified E2E

A real runtime test was completed using the Dockerized FastAPI process and the real PostgreSQL-backed Django user model:

1. Create an active `security_analyst` test user.
2. Issue a Django JWT containing `session_version=1`.
3. Open a real WebSocket connection.
4. Receive `workflow.connected`.
5. Increment Django `session_version` from `1` to `2` while the socket remains open.
6. FastAPI detects the version mismatch.
7. Server sends:
   `{"type":"auth.revoked","reason":"session_revoked"}`
8. Server closes the socket with close code `4001` and reason `Authentication revoked`.
9. Test user is deleted.

Observed result:

- `LIVE REVOCATION EVENT: PASS`
- `CLOSE CODE: 4001`
- `CLOSE REASON: Authentication revoked`
- `LIVE DISCONNECT: PASS`
- `TEST USER CLEANED`

## Celery / Redis Runtime

Celery is deployed as dedicated runtime services for core, workflow, and reports processing, using Redis as the broker/result infrastructure.

### Routing Regression Baseline — Verified 2026-08-29

The routing and runtime test suite was executed successfully with:

`docker exec aegis-fastapi pytest tests/test_celery_routing.py tests/test_celery_runtime.py -v`

Result:

- 5 tests collected.
- 5 tests passed.
- Production queues are declared.
- Task routes remain isolated by dedicated queue.
- Beat tasks target dedicated queues.
- Live Celery/Redis round-trip succeeds.
- Health task is routed to the health queue.

### Live Worker Health — Verified 2026-08-29

Direct worker inspection was also executed:

`docker exec aegis-celery-worker celery -A fastapi_app.celery_app inspect ping`

Observed live workers:

- `core` -> `pong`
- `workflow` -> `pong`
- `reports` -> `pong`
- 3 nodes online.

This confirms that the Dockerized Celery workers are reachable through the configured broker/control plane in the current runtime.

## Known Test-Harness Issue

The integration test `test_workflow_websocket_is_revoked_after_session_version_bump` previously failed during WebSocket handshake when run through the Django/Starlette test harness because the test database transaction/isolation model prevented the WebSocket-side database connection from seeing the newly created test user. This is a test-harness isolation issue, not evidence that the real Docker runtime revocation flow is broken.

The real live E2E runtime test described above succeeded.

## Current Security Baseline

- Django system checks: passing.
- Migration drift check: passing.
- Migrations: applied.
- PostgreSQL: healthy.
- Redis: healthy.
- Django: healthy.
- FastAPI: healthy.
- Celery worker/workflow/report services: healthy in Docker runtime.
- Celery routing regression suite: 5/5 passing.
- Celery/Redis live round-trip: passing.
- Live Celery workers: 3/3 responding to `inspect ping`.
- JWT cross-service validation: verified.
- RBAC 403 enforcement: verified.
- RBAC matrix regression suite: 7/7 passing.
- Access-token session-version revocation: verified.
- Refresh-token blacklist: verified.
- WebSocket authentication: verified.
- Live WebSocket revocation: verified end-to-end.

## Baseline Acceptance Criteria

This baseline is considered verified for the tested local Docker runtime when all of the following remain true:

- `users.test_rbac_matrix` reports 7/7 passing.
- `tests/test_celery_routing.py tests/test_celery_runtime.py` reports 5/5 passing.
- Celery `inspect ping` reports `core`, `workflow`, and `reports` as online with `pong`.
- Protected FastAPI API access with a valid Django JWT returns a successful response.
- Session-version mismatch invalidates the old JWT.
- Revoked refresh tokens are rejected.
- Valid WebSocket authentication succeeds.
- Missing/invalid WebSocket authentication is rejected without a 500 error.
- Live session-version revocation emits `auth.revoked` and closes the socket with code `4001`.

## Secrets Policy

Never commit real values for:

- `DJANGO_SECRET_KEY`
- `JWT_SECRET_KEY`
- `FASTAPI_SECRET_KEY`
- production database credentials
- real account passwords
- live access/refresh tokens

Keep these values in the local environment, Docker/CI secret store, or production secret manager.
