from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

from django.db import close_old_connections
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.audit.services import verify_audit_chain
from django_project.evidence.models import Evidence
from django_project.projects.models import Project, ScheduledScanExecution
from django_project.scans.models import Scan
from django_project.users.models import User, UserRole

from fastapi_app.services.scheduled_execution import (
    claim_due_schedule,
    create_canonical_schedule,
)
from fastapi_app.tasks.scheduled_scans import (
    dispatch_due_scheduled_scans,
    run_scheduled_scan_execution,
)


TARGET = 'http://127.0.0.1:18081/'


def _claim(schedule_id: str, due_time):
    close_old_connections()
    try:
        execution, created = claim_due_schedule(schedule_id, now=due_time)
        return str(execution.id) if execution else None, created
    finally:
        close_old_connections()


def _wait_for_scan(execution_id: str, timeout: int = 120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        execution = ScheduledScanExecution.objects.select_related('scan').get(pk=execution_id)
        if execution.scan_id:
            scan = Scan.objects.get(pk=execution.scan_id)
            if scan.status in {
                Scan.Status.COMPLETED,
                Scan.Status.PARTIAL,
                Scan.Status.FAILED,
                Scan.Status.CANCELLED,
            }:
                return execution, scan
        time.sleep(1)
    raise AssertionError('Scheduled scan did not reach a terminal scanner state')


def main() -> int:
    user = User.objects.create_user(
        email='scheduled-reality@example.invalid',
        password='Scheduled-Reality-Only-123!',
        first_name='Scheduled',
        last_name='Reality',
        role=UserRole.SECURITY_ANALYST,
    )
    project = Project.objects.create(
        name='Scheduled Canonical Reality',
        slug=f'scheduled-canonical-{str(user.id)[:8]}',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Scheduled Reality HTTP Target',
        slug='scheduled-reality-http-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': TARGET},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot=TARGET,
        reason='scheduled canonical runtime reality',
        expires_at=timezone.now() + timedelta(minutes=30),
    )

    first_due = timezone.now() + timedelta(seconds=2)
    schedule = create_canonical_schedule(
        actor_id=str(user.id),
        project_id=str(project.id),
        asset_id=str(asset.id),
        name='Scheduled HTTP method policy',
        capability_id='web.http-method-policy',
        depth='standard',
        options={},
        credential_refs=[],
        frequency='daily',
        cron_expression='',
        timezone_name='UTC',
        first_run_at=first_due,
    )
    assert schedule.template_id is None
    assert schedule.capability_id == 'web.http-method-policy'

    # Two PostgreSQL transactions race for the same due occurrence. Row locking
    # plus the unique occurrence constraint must yield exactly one durable claim.
    claim_time = first_due + timedelta(seconds=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _claim(str(schedule.id), claim_time), range(2)))
    claimed_ids = [item[0] for item in results if item[0]]
    assert len(claimed_ids) == 1, results
    execution_id = claimed_ids[0]
    assert ScheduledScanExecution.objects.filter(schedule=schedule).count() == 1

    dispatch_result = dispatch_due_scheduled_scans.apply_async(
        kwargs={'limit': 20},
        task_id=f'scheduled-reality-dispatch-{execution_id}',
    ).get(timeout=60)
    assert dispatch_result['queued'] >= 1, dispatch_result

    execution, scan = _wait_for_scan(execution_id)
    assert execution.status == ScheduledScanExecution.Status.DISPATCHED
    assert scan.status == Scan.Status.COMPLETED
    assert scan.scheduled_scan_id == schedule.id
    assert scan.asset_id == asset.id
    assert scan.authorization_decision_id == authorization.id
    assert scan.execution_idempotency_key == execution.idempotency_key
    assert scan.execution_correlation_id == execution.correlation_id
    assert scan.execution_contract_fingerprint == execution.execution_contract_fingerprint
    assert len(scan.execution_contract_fingerprint) == 64
    assert scan.execution_contract['capability_id'] == 'web.http-method-policy'
    assert scan.execution_contract['policy_version'] == 'scheduled-capability.v1'
    assert scan.execution_contract['authorization_ref'] == f'authorization:{authorization.id}'
    assert scan.execution_contract['project_ref'] == f'project:{project.id}'
    assert scan.execution_contract['asset_ref'] == f'asset:{asset.id}'
    assert execution.policy_fingerprint == scan.execution_contract['policy_fingerprint']

    evidence = Evidence.objects.get(
        scan=scan,
        source='aegis-internal-wstg',
        evidence_type='scanner_output',
    )
    assert len(evidence.sha256) == 64
    assert evidence.metadata['capability_id'] == 'web.http-method-policy'
    normalized = evidence.metadata['normalized']
    assert normalized['count'] >= 1
    assert normalized['observations'][0]['unsafe_methods_sent'] is False

    replay = run_scheduled_scan_execution.apply_async(
        args=[execution_id],
        task_id=f'scheduled-reality-replay-{execution_id}',
    ).get(timeout=60)
    assert replay['status'] == 'dispatched'
    assert replay['replayed'] is True
    assert Scan.objects.filter(scheduled_scan=schedule).count() == 1
    assert Evidence.objects.filter(scan=scan, source='aegis-internal-wstg').count() == 1

    # A claimed occurrence is not authority. Superseding the asset grant before
    # execution must block it and disable the schedule without creating a Scan.
    second_due = timezone.now() + timedelta(seconds=2)
    second = create_canonical_schedule(
        actor_id=str(user.id),
        project_id=str(project.id),
        asset_id=str(asset.id),
        name='Scheduled authorization drift proof',
        capability_id='web.http-method-policy',
        depth='standard',
        options={},
        credential_refs=[],
        frequency='weekly',
        cron_expression='',
        timezone_name='UTC',
        first_run_at=second_due,
    )
    blocked_execution, created = claim_due_schedule(
        str(second.id),
        now=second_due + timedelta(seconds=1),
    )
    assert created is True and blocked_execution is not None

    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot=TARGET,
        reason='revoke before scheduled dispatch',
        supersedes=authorization,
    )
    blocked = run_scheduled_scan_execution.apply_async(
        args=[str(blocked_execution.id)],
        task_id=f'scheduled-reality-blocked-{blocked_execution.id}',
    ).get(timeout=60)
    assert blocked['status'] == 'blocked'
    blocked_execution.refresh_from_db()
    second.refresh_from_db()
    assert blocked_execution.status == ScheduledScanExecution.Status.BLOCKED
    assert second.is_active is False
    assert Scan.objects.filter(scheduled_scan=second).count() == 0

    audit_ok, audit_tip = verify_audit_chain()
    assert audit_ok is True
    assert audit_tip
    assert AuditLog.objects.filter(
        resource_type='ScheduledScanExecution',
        metadata__event='scheduled_scan_dispatched',
    ).exists()
    assert AuditLog.objects.filter(
        resource_type='ScheduledScanExecution',
        metadata__event='scheduled_scan_blocked',
    ).exists()

    report = {
        'schema': 'aegis.scheduled-scan-canonical-reality.v1',
        'schedule_id': str(schedule.id),
        'execution_id': execution_id,
        'scan_id': str(scan.id),
        'capability_id': scan.execution_contract['capability_id'],
        'execution_contract_fingerprint': scan.execution_contract_fingerprint,
        'policy_fingerprint': execution.policy_fingerprint,
        'evidence_id': str(evidence.id),
        'evidence_sha256': evidence.sha256,
        'concurrent_claim_count': len(claimed_ids),
        'scan_count_after_replay': Scan.objects.filter(scheduled_scan=schedule).count(),
        'authorization_drift_result': blocked['status'],
        'audit_chain': 'verified',
        'legacy_template_authority': False,
    }
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
