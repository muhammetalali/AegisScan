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
