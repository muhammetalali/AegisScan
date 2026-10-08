# AegisScan — Manual scan and asset-scan idempotency acceptance

Status: isolated branch only, **not approved for production**.
Baseline: `main@a0a883bbf44c8d2b83d509e343307bca9262a08b`.

## Behavior

- Manual `POST /scans/` supports optional `idempotency_key` in its JSON request.
- `POST /api/v1/assets/{id}/scan` supports optional `idempotency_key` query argument.
- Identical same-actor/project/key requests reuse the persisted Scan without sending a second Celery message.
- Same key but materially changed scan name, type, asset, configuration, engine, depth or authorization snapshot is a conflict (HTTP 409).
- Repeat requests continue to validate current asset authorization and tenant/project access before replay.
- Keys are opt-in; absent keys continue to mean intentional new scans, including explicit rescans. Do not silently collapse separate user-authorized assessments.
- The existing unique PostgreSQL constraint `scans_scan_exec_idem_uq` and project row locking serialize concurrent requests. No duplicate storage mechanism or schema migration.
- Governed capability execution has its own established idempotency contract; preserve it without competing keys.

## Evidence

Run focused `fastapi_app/routers/test_scans.py` using PostgreSQL isolated from production:
8/8 tests passed (3 baseline, 5 new: replay, changed payload, revoked authority, asset route, invalid key).
Wire the same module into the existing `Domain Contract Reality` workflow; full exact-SHA CI and production acceptance remain mandatory.

## Outstanding reliability work (explicit limitations)

- Keyed replay does not itself establish at-least-once broker delivery: a database insert may commit before the Celery publish fails. The existing scan recovery/outbox strategy must resolve broker failure and uncertain acknowledgements before promising exactly-once execution.
- This is a first protected entrypoint improvement, not replacement of native capability, scheduled-assessment or continuous-assurance dispatch.
- Full dispatcher unification requires end-to-end retry, outage, worker crash, and evidence lineage tests.
- Security blockers #343 (password recovery, SMTP and approved legal policy) and #345 (real enforced 2FA) remain open.

## Production Firefox public-route observation

The read-only Firefox smoke script `aegis-platform/frontend/scripts/public-auth-browser-smoke.py`
checks /login, /register, /forgot-password, /terms, /privacy and unauthorized /dashboard:
login (2 inputs), register (6 inputs), dashboard redirects to login. Password
recovery explicitly indicates unavailable service, and /terms and /privacy
redirect to login rather than returning approved documents. This must not be
misrepresented as legal, email or MFA acceptance.
