# AegisScan API Contract

## Purpose

Django is the source of truth for durable identity, authorization, and CRUD resources. FastAPI is the execution/runtime layer for high-throughput security operations and live workflows.

## Authentication contract

- Login: `POST /api/v1/auth/login/` — Django.
- Refresh: `POST /api/v1/auth/refresh/` — Django SimpleJWT.
- Logout: `POST /api/v1/users/logout/` — Django; refresh tokens are blacklisted when the blacklist app is migrated.
- Current user: `GET /api/v1/users/me/` — Django.
- 2FA enrollment/verification/disable: `/api/v1/auth/2fa/*` — Django.
- Frontend sends the same Bearer access token to both Django and FastAPI.
- FastAPI must never become a second source of truth for user roles or permissions. It resolves the active user from Django before authorizing requests.

## Ownership

| Domain | Owner | Contract |
|---|---|---|
| Users / identity | Django | `/api/v1/users/*` |
| JWT issue/refresh | Django | `/api/v1/auth/*` |
| Teams / memberships | Django | `/api/v1/teams/*` |
| Projects | Django | `/api/v1/projects/*` |
| Assets | Django | `/api/v1/assets/*` |
| Findings / vulnerabilities | Django | `/api/v1/vulnerabilities/*` |
| Reports | Django | `/api/v1/reports/*` |
| Compliance | Django | `/api/v1/compliance/*` |
| Knowledge | Django + FastAPI runtime where explicitly documented | `/api/v1/knowledge/*` |
| Scan execution actions | FastAPI | `/api/v1/scans/{scan_id}/start|pause|resume|cancel|progress` |
| Security validation runtime | FastAPI | `/api/v1/*` router-specific runtime endpoints |
| Live WebSockets | FastAPI | `/ws/*` |

## Authorization rules

1. Authentication is required by default.
2. A valid JWT is not sufficient for privileged actions; the endpoint permission is checked server-side.
3. Resource ownership/project membership is checked in addition to the permission for scoped resources.
4. FastAPI uses Django's current `is_active`, role, and permission state when validating a token.
5. Frontend route guards are UX controls only; they are not security boundaries.

## Routing/deployment requirement

Django and FastAPI both expose `/api/v1`. A production reverse proxy must route requests by the documented ownership rules; the two services must not be exposed behind an ambiguous catch-all rule. WebSocket traffic under `/ws/*` is routed to FastAPI.

## Token lifecycle

- Access tokens are bounded by the configured `JWT_ACCESS_TOKEN_LIFETIME` and should not be treated as revocable durable credentials.
- Refresh tokens use rotation and blacklist-after-rotation.
- The SimpleJWT blacklist application must be migrated in every environment before refresh-token revocation is considered operational.
- Password changes, account deactivation, and disabling 2FA trigger refresh-token revocation through the Users pre-save security signal.
- Clients must discard local access/refresh tokens on logout or failed refresh.

## Required integration tests

The minimum cross-service contract tests are:

1. Django issues a JWT accepted by FastAPI.
2. FastAPI rejects a token for an inactive Django user.
3. A current Django role/permission change is reflected by FastAPI without reissuing the old token.
4. A blacklisted refresh token cannot be refreshed.
5. Password change/deactivation/2FA disable invalidates outstanding refresh tokens.
6. A user without project membership cannot access another project's scoped FastAPI operation.
7. Django CRUD and FastAPI runtime actions use consistent resource identifiers and HTTP error semantics.
