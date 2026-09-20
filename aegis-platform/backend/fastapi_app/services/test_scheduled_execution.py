from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project, ScheduledScan, ScheduledScanExecution
from django_project.scans.models import Scan
from django_project.users.models import User
from fastapi_app.services.scheduled_execution import (
    ScheduledExecutionError,
    claim_due_schedule,
    create_canonical_schedule,
    execute_scheduled_occurrence,
    next_schedule_run,
    update_canonical_schedule,
)


pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture
def scheduled_fixture():
    user = User.objects.create_user(
        email='scheduled-runtime@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='Scheduled',
        last_name='Runtime',
    )
    project = Project.objects.create(
        name='Scheduled Runtime',
        slug='scheduled-runtime',
        owner=user,
    )
    asset = Asset.objects.create(
        project=project,
        owner=user,
        name='Scheduled web target',
        slug='scheduled-web-target',
        type=Asset.Type.WEBSITE,
        configuration={'url': 'https://scheduled.example.test/'},
    )
    authorization = AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=True,
        target_snapshot='https://scheduled.example.test/',
        reason='scheduled execution test',
        expires_at=timezone.now() + timedelta(hours=1),
    )
    return user, project, asset, authorization


def _schedule(user, project, asset, *, first_run=None, frequency='daily', cron_expression=''):
    return create_canonical_schedule(
        actor_id=str(user.id),
        project_id=str(project.id),
        asset_id=str(asset.id),
        name='Canonical scheduled validation',
        capability_id='web.http-method-policy',
        depth='standard',
        options={},
        credential_refs=[],
        frequency=frequency,
        cron_expression=cron_expression,
        timezone_name='UTC',
        first_run_at=first_run or (timezone.now() + timedelta(seconds=5)),
    )


def test_schedule_creation_is_capability_bound_not_template_authority(scheduled_fixture):
    user, project, asset, _authorization = scheduled_fixture
    schedule = _schedule(user, project, asset)

    assert schedule.template_id is None
    assert schedule.asset_id == asset.id
    assert schedule.capability_id == 'web.http-method-policy'
    assert schedule.policy_version == 'scheduled-capability.v1'
    assert schedule.version == 1
    assert schedule.is_active is True


def test_claim_snapshots_one_deterministic_occurrence_and_advances_schedule(scheduled_fixture):
    user, project, asset, _authorization = scheduled_fixture
    now = timezone.now()
    schedule = _schedule(user, project, asset, first_run=now)
    original_next = schedule.next_run

    execution, created = claim_due_schedule(str(schedule.id), now=now + timedelta(seconds=1))
    assert created is True
    assert execution is not None
    assert execution.schedule_version == 1
    assert execution.asset_id == asset.id
    assert execution.capability_id == 'web.http-method-policy'
    assert execution.request_fingerprint
    assert execution.idempotency_key.startswith('sched:')
    assert execution.correlation_id.startswith('schedexec:')

    schedule.refresh_from_db()
    assert schedule.next_run > original_next
    assert ScheduledScanExecution.objects.filter(
        schedule=schedule,
        scheduled_for=original_next,
    ).count() == 1

    second, created_second = claim_due_schedule(str(schedule.id), now=now + timedelta(seconds=1))
    assert second is None
    assert created_second is False


def test_scheduled_execution_uses_governed_contract_and_replays_without_duplicate_scan(
    scheduled_fixture,
):
    user, project, asset, authorization = scheduled_fixture
    now = timezone.now()
    schedule = _schedule(user, project, asset, first_run=now)
    execution, _ = claim_due_schedule(str(schedule.id), now=now + timedelta(seconds=1))
    assert execution is not None

    result = SimpleNamespace(id='scheduled-native-task-1')
    with patch(
        'fastapi_app.tasks.native_capabilities.run_native_capability_scan.apply_async',
        return_value=result,
    ) as dispatch:
        first = execute_scheduled_occurrence(str(execution.id))
        second = execute_scheduled_occurrence(str(execution.id))

    assert first['status'] == 'dispatched'
    assert first['replayed'] is False
    assert second['status'] == 'dispatched'
    assert second['replayed'] is True
    assert dispatch.call_count == 1

    execution.refresh_from_db()
    scan = Scan.objects.get(pk=execution.scan_id)
    assert Scan.objects.filter(scheduled_scan=schedule).count() == 1
    assert scan.authorization_decision_id == authorization.id
    assert scan.execution_idempotency_key == execution.idempotency_key
    assert scan.execution_correlation_id == execution.correlation_id
    assert scan.execution_contract_fingerprint == execution.execution_contract_fingerprint
    assert len(scan.execution_contract_fingerprint) == 64
    assert scan.execution_contract['policy_version'] == 'scheduled-capability.v1'
    assert scan.execution_contract['capability_id'] == 'web.http-method-policy'
    assert scan.execution_contract['authorization_ref'] == f'authorization:{authorization.id}'
    assert scan.execution_contract['project_ref'] == f'project:{project.id}'
    assert scan.execution_contract['asset_ref'] == f'asset:{asset.id}'
    assert execution.policy_fingerprint == scan.execution_contract['policy_fingerprint']
    assert execution.status == ScheduledScanExecution.Status.DISPATCHED


def test_execution_revalidates_current_authorization_and_disables_drifted_schedule(
    scheduled_fixture,
):
    user, project, asset, authorization = scheduled_fixture
    now = timezone.now()
    schedule = _schedule(user, project, asset, first_run=now)
    execution, _ = claim_due_schedule(str(schedule.id), now=now + timedelta(seconds=1))
    assert execution is not None

    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot='https://scheduled.example.test/',
        reason='revoked before scheduled execution',
        supersedes=authorization,
    )

    result = execute_scheduled_occurrence(str(execution.id))
    assert result['status'] == 'blocked'
    execution.refresh_from_db()
    schedule.refresh_from_db()
    assert execution.status == ScheduledScanExecution.Status.BLOCKED
    assert schedule.is_active is False
    assert Scan.objects.filter(scheduled_scan=schedule).count() == 0


def test_schedule_version_change_after_claim_blocks_old_occurrence(scheduled_fixture):
    user, project, asset, _authorization = scheduled_fixture
    now = timezone.now()
    schedule = _schedule(user, project, asset, first_run=now)
    execution, _ = claim_due_schedule(str(schedule.id), now=now + timedelta(seconds=1))
    assert execution is not None

    updated = update_canonical_schedule(
        actor_id=str(user.id),
        schedule_id=str(schedule.id),
        expected_version=schedule.version,
        name='Updated canonical schedule',
        next_run_at=timezone.now() + timedelta(hours=1),
    )
    assert updated.version == 2

    result = execute_scheduled_occurrence(str(execution.id))
    assert result['status'] == 'blocked'
    assert 'changed after this occurrence was claimed' in result['reason']
    assert Scan.objects.filter(scheduled_scan=schedule).count() == 0


def test_custom_cron_and_monthly_recurrence_are_timezone_aware():
    current = datetime(2026, 1, 31, 9, 15, tzinfo=dt_timezone.utc)
    monthly = next_schedule_run(
        frequency=ScheduledScan.Frequency.MONTHLY,
        cron_expression='',
        timezone_name='UTC',
        scheduled_for=current,
    )
    assert monthly == datetime(2026, 2, 28, 9, 15, tzinfo=dt_timezone.utc)

    custom = next_schedule_run(
        frequency=ScheduledScan.Frequency.CUSTOM,
        cron_expression='*/15 * * * *',
        timezone_name='UTC',
        scheduled_for=datetime(2026, 1, 1, 10, 7, tzinfo=dt_timezone.utc),
    )
    assert custom == datetime(2026, 1, 1, 10, 15, tzinfo=dt_timezone.utc)


def test_custom_schedule_rejects_invalid_cron(scheduled_fixture):
    user, project, asset, _authorization = scheduled_fixture
    with pytest.raises(ScheduledExecutionError) as caught:
        _schedule(
            user,
            project,
            asset,
            frequency='custom',
            cron_expression='not-a-cron',
        )
    assert caught.value.code == 'invalid_cron_expression'
