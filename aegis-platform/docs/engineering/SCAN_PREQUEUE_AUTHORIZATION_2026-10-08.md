# AegisScan pending-scan activation — bounded security correction

Baseline: production `main@eebef52a95477f83f1cb50504316e88f7d37945b`.

The existing `ScanOrchestrator._queue_scan` checked project membership, pending state and real engine selection, but it did not validate the scan's currently bound immutable asset authorization before marking it queued. The worker has a separate authoritative guard, so this is primarily a fail-closed entrypoint/telemetry correction: revoke, asset identity/target drift and inactive asset must be rejected **before** broker publish or a queued state transition.

The same service contained three legacy `from scans.models import Scan` imports. They can create a second Django model namespace outside registered `django_project.scans`; change all three to the authoritative Django app path.

The corrected pending-scan path reuses `require_bound_scan_authorization` from the existing worker security service, including scope and destination policy, without creating a second authorization engine.

## Real isolated PostgreSQL regression

Five focused tests, all passed: missing bound decision, newer revocation, asset target drift, inactive asset, authorized queue contract with mocked broker. Included in existing Domain Contract Reality job rather than introducing a new CI workflow.

## Explicit remaining limits

- This does not itself make Celery publish atomic with PostgreSQL state. Broker outage or missing publish acknowledgement remains a scanner-outbox recovery task and must be tested before claiming exactly-once delivery.
- Worker checks still independently enforce authorization and dynamic egress when execution starts.
- The branch is not production until required PR checks, protected merge, exact-main CI and governed deployment have passed.

## Bounded manual/asset dispatch consolidation

The manual `POST /scans/` and asset `POST /api/v1/assets/{id}/scan` launchers previously maintained duplicate local engine-to-Celery task dictionaries. They now share the existing scan router's `_dispatch_primary_scan` registry, preserving the same engine-task mapping and existing Celery routing. Existing tests for idempotent replay, target authorization, explicit rescans and old Semgrep path must pass unchanged. Native capability, scheduled execution, and enterprise entrypoints are deliberately excluded pending a separately governed broker-outbox/uncertain-ack design.

## ZIP safety regressions (not production ZIP end-to-end proof)

Extended the existing Assessment Launcher ZIP unit-contract suite with symlink rejection, declared expanded-size limit and empty-directory archive rejection. The existing 21/21 `test_assessment_launcher.py` tests passed against isolated PostgreSQL. The existing Burp MCP reality workflow already executes this test module, so no redundant CI workflow was created. A real production upload -> authorization -> Semgrep scan -> finding/evidence flow for an actual ZIP archive remains an acceptance obligation; `file_acceptance=true` currently tests a standalone Python file rather than ZIP.

## Mandatory CI connection for ZIP regression tests

The existing Burp MCP Gateway workflow has narrower path triggers and did not fire for this PR; to avoid untested ZIP regressions, the existing `Domain Contract Reality` job now also runs `fastapi_app/routers/test_assessment_launcher.py` beside the scan and prequeue security regressions. This changes no workflow IDs, triggers, security gates or required job names.
