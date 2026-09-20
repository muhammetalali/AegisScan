from __future__ import annotations

import calendar
import hashlib
import json
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Any, Mapping
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from django_project.assets.models import Asset
from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit
from django_project.projects.models import Project, ScheduledScan, ScheduledScanExecution
from django_project.scans.models import Scan
from django_project.system.credential_vault import CredentialVaultDenied
from django_project.users.models import User

from .authorization_guard import asset_target, current_asset_authorization
from .capability_registry import RetiredCapabilityError, get_capability, validate_capability_options
from .credential_execution import (
    authorize_credential_refs_for_execution,
    empty_credential_context,
    normalize_credential_refs,
)
from .governed_execution_contract import (
    finalize_governed_execution_contract,
    prepare_governed_execution_draft,
)
from .native_packaging import is_packaged_native_capability
from .native_tool_runtime import NATIVE_TOOL_SPECS


SCHEDULE_POLICY_VERSION = 'scheduled-capability.v1'
SCHEDULE_NAMESPACE = UUID('2e21bb6c-88db-4ccf-90c6-6ed728ecfbce')
_MAX_EXECUTION_ATTEMPTS = 3


class ScheduledExecutionError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 409):
        self.code = code
        self.status_code = status_code
        super().__init__(message)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)


def _sha256(value: Any) -> str:
    raw = value if isinstance(value, str) else _canonical_json(value)
    return hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()


def _zone(name: str) -> ZoneInfo:
    normalized = str(name or '').strip()
    if not normalized or len(normalized) > 64:
        raise ScheduledExecutionError('invalid_timezone', 'A valid IANA timezone is required.', 422)
    try:
        return ZoneInfo(normalized)
    except ZoneInfoNotFoundError as exc:
        raise ScheduledExecutionError('invalid_timezone', 'Unknown IANA timezone.', 422) from exc


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ScheduledExecutionError(name, f'{name} must include a timezone offset.', 422)
    return value


def _validate_cron(expression: str) -> str:
    value = ' '.join(str(expression or '').split())
    if len(value) > 100 or len(value.split()) != 5 or not croniter.is_valid(value):
        raise ScheduledExecutionError(
            'invalid_cron_expression',
            'Custom schedules require one valid five-field cron expression.',
            422,
        )
    return value


def validate_schedule_timing(
    *,
    frequency: str,
    cron_expression: str,
    timezone_name: str,
    first_run_at: datetime,
) -> tuple[str, str, str, datetime]:
    if frequency not in set(ScheduledScan.Frequency.values):
        raise ScheduledExecutionError('invalid_frequency', 'Unsupported schedule frequency.', 422)
    zone = _zone(timezone_name)
    first = _aware(first_run_at, 'first_run_at').astimezone(dt_timezone.utc)
    cron_value = _validate_cron(cron_expression) if frequency == ScheduledScan.Frequency.CUSTOM else ''
    if frequency != ScheduledScan.Frequency.CUSTOM and str(cron_expression or '').strip():
        raise ScheduledExecutionError(
            'unexpected_cron_expression',
            'cron_expression is allowed only when frequency=custom.',
            422,
        )
    # Round-trip through the selected timezone so invalid offsets are never used
    # as schedule authority.
    first_local = first.astimezone(zone)
    return frequency, cron_value, zone.key, first_local.astimezone(dt_timezone.utc)


def next_schedule_run(
    *,
    frequency: str,
    cron_expression: str,
    timezone_name: str,
    scheduled_for: datetime,
) -> datetime:
    zone = _zone(timezone_name)
    current = _aware(scheduled_for, 'scheduled_for').astimezone(zone)

    if frequency == ScheduledScan.Frequency.CUSTOM:
        expression = _validate_cron(cron_expression)
        candidate = croniter(expression, current).get_next(datetime)
        if candidate.tzinfo is None:
            candidate = candidate.replace(tzinfo=zone)
    elif frequency == ScheduledScan.Frequency.DAILY:
        candidate = current + timedelta(days=1)
    elif frequency == ScheduledScan.Frequency.WEEKLY:
        candidate = current + timedelta(days=7)
    elif frequency == ScheduledScan.Frequency.MONTHLY:
        year = current.year + (1 if current.month == 12 else 0)
        month = 1 if current.month == 12 else current.month + 1
        day = min(current.day, calendar.monthrange(year, month)[1])
        candidate = current.replace(year=year, month=month, day=day)
    else:
        raise ScheduledExecutionError('invalid_frequency', 'Unsupported schedule frequency.', 422)

    # For a nonexistent DST wall-clock value, the UTC round-trip selects a real
    # instant deterministically. Ambiguous instants retain the existing fold.
    candidate = candidate.astimezone(dt_timezone.utc).astimezone(zone)
    if candidate <= current:
        raise ScheduledExecutionError('invalid_recurrence', 'Schedule did not advance monotonically.', 409)
    return candidate.astimezone(dt_timezone.utc)


def _actor_project(actor_id: str, project_id: str, *, lock: bool = False) -> tuple[User, Project]:
    users = User.objects.filter(pk=actor_id, is_active=True)
    actor = users.select_for_update().first() if lock else users.first()
    if actor is None:
        raise ScheduledExecutionError('actor_unavailable', 'Schedule actor is no longer active.', 403)

    projects = Project.objects.filter(pk=project_id)
    project = projects.select_for_update().first() if lock else projects.first()
    if project is None or project.status != Project.Status.ACTIVE:
        raise ScheduledExecutionError('project_unavailable', 'Scheduled project is not active.', 409)
    if str(project.owner_id) != str(actor.id) and not project.members.filter(pk=actor.id).exists():
        raise ScheduledExecutionError('project_access_revoked', 'Schedule actor no longer has project access.', 403)
    return actor, project


def _normalize_binding(
    *,
    actor_id: str,
    project_id: str,
    asset_id: str,
    capability_id: str,
    depth: str,
    options: Mapping[str, Any] | None,
    credential_refs: list[str] | tuple[str, ...] | None,
    purpose: str,
) -> dict[str, Any]:
    actor, project = _actor_project(actor_id, project_id)
    asset = Asset.objects.filter(pk=asset_id, project=project, is_active=True).first()
    if asset is None:
        raise ScheduledExecutionError('asset_unavailable', 'Scheduled asset is not active in the project.', 409)

    try:
        capability = get_capability(str(capability_id or '').strip())
        normalized_options = validate_capability_options(capability, dict(options or {}))
    except RetiredCapabilityError as exc:
        raise ScheduledExecutionError('capability_retired', str(exc), 410) from exc
    except ValueError as exc:
        raise ScheduledExecutionError('capability_invalid', str(exc), 409) from exc

    if asset.type not in capability.asset_types:
        raise ScheduledExecutionError(
            'asset_type_mismatch',
            f'Capability {capability.id} does not support asset type {asset.type}.',
            409,
        )
    if capability.id in NATIVE_TOOL_SPECS and not is_packaged_native_capability(capability.id):
        raise ScheduledExecutionError(
            'capability_not_packaged',
            f'Capability {capability.id} is not part of the proven scanner image.',
            409,
        )
    if depth not in set(ScheduledScan.Depth.values):
        raise ScheduledExecutionError('invalid_depth', 'Unsupported scheduled scan depth.', 422)

    target = asset_target(asset)
    if not target:
        raise ScheduledExecutionError('target_unavailable', 'Scheduled asset has no executable target.', 409)
    authorization, reason = current_asset_authorization(asset, target)
    if authorization is None:
        raise ScheduledExecutionError('authorization_invalid', reason, 403)

    try:
        refs = normalize_credential_refs(credential_refs)
    except ValueError as exc:
        raise ScheduledExecutionError('credential_refs_invalid', str(exc), 422) from exc

    if capability.credential_required and len(refs) != 1:
        raise ScheduledExecutionError(
            'credential_required',
            f'Capability {capability.id} requires exactly one credential reference.',
            409,
        )
    if refs and capability.credential_mode == 'none':
        raise ScheduledExecutionError(
            'credentials_not_supported',
            f'Capability {capability.id} does not support credential-bound execution.',
            409,
        )

    identity_ref = str(normalized_options.get('identity_ref') or '').strip()
    try:
        credential_context = (
            authorize_credential_refs_for_execution(
                project_id=project.id,
                actor_id=actor.id,
                refs=refs,
                capability_id=capability.id,
                allowed_kinds=capability.credential_kinds,
                purpose=purpose,
                target=target,
                identity_ref=identity_ref,
            )
            if refs
            else empty_credential_context()
        )
    except CredentialVaultDenied as exc:
        raise ScheduledExecutionError('credential_denied', str(exc), 403) from exc

    if capability.id == 'browser.spa-discovery':
        if refs:
            bindings = credential_context.get('credential_refs')
            bound_identity = (
                str(bindings[0].get('browser_identity_ref') or '').strip()
                if isinstance(bindings, list) and bindings and isinstance(bindings[0], dict)
                else ''
            )
            if not bound_identity:
                raise ScheduledExecutionError(
                    'browser_identity_missing',
                    'Browser credential has no durable identity binding.',
                    409,
                )
            if identity_ref not in {'', 'anonymous', bound_identity}:
                raise ScheduledExecutionError(
                    'browser_identity_mismatch',
                    'Requested browser identity does not match the bound credential identity.',
                    409,
                )
            normalized_options = {**normalized_options, 'identity_ref': bound_identity}
        else:
            if identity_ref not in {'', 'anonymous'}:
                raise ScheduledExecutionError(
                    'browser_identity_requires_credential',
                    'Non-anonymous browser identity requires a bound browser credential.',
                    409,
                )
            normalized_options = {**normalized_options, 'identity_ref': 'anonymous'}

    return {
        'actor': actor,
        'project': project,
        'asset': asset,
        'capability': capability,
        'options': normalized_options,
        'credential_refs': refs,
        'credential_context': credential_context,
        'target': target,
        'authorization': authorization,
    }


@transaction.atomic
def create_canonical_schedule(
    *,
    actor_id: str,
    project_id: str,
    asset_id: str,
    name: str,
    capability_id: str,
    depth: str,
    options: Mapping[str, Any] | None,
    credential_refs: list[str] | tuple[str, ...] | None,
    frequency: str,
    cron_expression: str,
    timezone_name: str,
    first_run_at: datetime,
) -> ScheduledScan:
    title = str(name or '').strip()
    if not title or len(title) > 200:
        raise ScheduledExecutionError('invalid_name', 'Schedule name must be 1-200 characters.', 422)

    frequency, cron_value, timezone_value, first_run = validate_schedule_timing(
        frequency=frequency,
        cron_expression=cron_expression,
        timezone_name=timezone_name,
        first_run_at=first_run_at,
    )
    if first_run < timezone.now() - timedelta(minutes=1):
        raise ScheduledExecutionError(
            'first_run_in_past',
            'first_run_at cannot be more than one minute in the past.',
            422,
        )
    binding = _normalize_binding(
        actor_id=actor_id,
        project_id=project_id,
        asset_id=asset_id,
        capability_id=capability_id,
        depth=depth,
        options=options,
        credential_refs=credential_refs,
        purpose=f'scheduled-scan:create:{project_id}',
    )
    schedule = ScheduledScan.objects.create(
        name=title,
        project=binding['project'],
        asset=binding['asset'],
        template=None,
        capability_id=binding['capability'].id,
        depth=depth,
        options=binding['options'],
        credential_refs=binding['credential_refs'],
        policy_version=SCHEDULE_POLICY_VERSION,
        timezone=timezone_value,
        frequency=frequency,
        cron_expression=cron_value,
        next_run=first_run,
        is_active=True,
        disabled_reason='',
        version=1,
        created_by=binding['actor'],
    )
    append_audit(
        user=binding['actor'],
        action=AuditLog.Action.SCAN_SCHEDULE,
        result=AuditLog.Result.SUCCESS,
        resource_type='ScheduledScan',
        resource_id=str(schedule.id),
        resource_repr=title,
        changes={'created': True},
        metadata={
            'event': 'scheduled_scan_created',
            'project_id': str(schedule.project_id),
            'asset_id': str(schedule.asset_id),
            'capability_id': schedule.capability_id,
            'schedule_version': schedule.version,
            'next_run': schedule.next_run.isoformat(),
            'policy_version': schedule.policy_version,
        },
        ip_address='0.0.0.0',
    )
    return schedule


@transaction.atomic
def update_canonical_schedule(
    *,
    actor_id: str,
    schedule_id: str,
    expected_version: int,
    name: str | None = None,
    asset_id: str | None = None,
    capability_id: str | None = None,
    depth: str | None = None,
    options: Mapping[str, Any] | None = None,
    credential_refs: list[str] | tuple[str, ...] | None = None,
    frequency: str | None = None,
    cron_expression: str | None = None,
    timezone_name: str | None = None,
    next_run_at: datetime | None = None,
    is_active: bool | None = None,
) -> ScheduledScan:
    schedule = (
        ScheduledScan.objects.select_for_update(of=('self',))
        .select_related('project', 'asset', 'created_by')
        .filter(pk=schedule_id)
        .first()
    )
    if schedule is None:
        raise ScheduledExecutionError('schedule_not_found', 'Scheduled scan not found.', 404)
    actor, project = _actor_project(actor_id, str(schedule.project_id), lock=True)
    if project.id != schedule.project_id:
        raise ScheduledExecutionError('schedule_not_found', 'Scheduled scan not found.', 404)
    if int(expected_version) != int(schedule.version):
        raise ScheduledExecutionError(
            'schedule_version_conflict',
            'Scheduled scan was modified by another request.',
            409,
        )

    desired_active = schedule.is_active if is_active is None else bool(is_active)
    desired_name = str(name if name is not None else schedule.name).strip()
    if not desired_name or len(desired_name) > 200:
        raise ScheduledExecutionError('invalid_name', 'Schedule name must be 1-200 characters.', 422)

    if not desired_active:
        schedule.name = desired_name
        schedule.is_active = False
        schedule.disabled_reason = 'Disabled by an authorized schedule update.'
        schedule.version += 1
        schedule.created_by = actor
        schedule.save(update_fields=[
            'name', 'is_active', 'disabled_reason', 'version', 'created_by', 'updated_at',
        ])
        append_audit(
            user=actor,
            action=AuditLog.Action.SCAN_SCHEDULE,
            result=AuditLog.Result.SUCCESS,
            resource_type='ScheduledScan',
            resource_id=str(schedule.id),
            resource_repr=schedule.name,
            changes={'is_active': False, 'version': schedule.version},
            metadata={
                'event': 'scheduled_scan_disabled',
                'project_id': str(schedule.project_id),
                'schedule_version': schedule.version,
            },
            ip_address='0.0.0.0',
        )
        return schedule

    desired_asset_id = str(asset_id or schedule.asset_id or '')
    desired_capability_id = str(capability_id or schedule.capability_id)
    desired_depth = str(depth or schedule.depth)
    desired_options = dict(schedule.options or {}) if options is None else dict(options)
    desired_refs = list(schedule.credential_refs or []) if credential_refs is None else list(credential_refs)
    desired_frequency = str(frequency or schedule.frequency)
    desired_cron = schedule.cron_expression if cron_expression is None else str(cron_expression)
    desired_timezone = str(timezone_name or schedule.timezone)
    desired_next = next_run_at or schedule.next_run

    desired_frequency, desired_cron, desired_timezone, desired_next = validate_schedule_timing(
        frequency=desired_frequency,
        cron_expression=desired_cron,
        timezone_name=desired_timezone,
        first_run_at=desired_next,
    )
    if desired_next < timezone.now() - timedelta(minutes=1):
        raise ScheduledExecutionError(
            'next_run_in_past',
            'next_run_at cannot be more than one minute in the past.',
            422,
        )
    binding = _normalize_binding(
        actor_id=str(actor.id),
        project_id=str(project.id),
        asset_id=desired_asset_id,
        capability_id=desired_capability_id,
        depth=desired_depth,
        options=desired_options,
        credential_refs=desired_refs,
        purpose=f'scheduled-scan:update:{schedule.id}',
    )

    schedule.name = desired_name
    schedule.asset = binding['asset']
    schedule.template = None
    schedule.capability_id = binding['capability'].id
    schedule.depth = desired_depth
    schedule.options = binding['options']
    schedule.credential_refs = binding['credential_refs']
    schedule.policy_version = SCHEDULE_POLICY_VERSION
    schedule.timezone = desired_timezone
    schedule.frequency = desired_frequency
    schedule.cron_expression = desired_cron
    schedule.next_run = desired_next
    schedule.is_active = True
    schedule.disabled_reason = ''
    schedule.version += 1
    schedule.created_by = actor
    schedule.save(update_fields=[
        'name', 'asset', 'template', 'capability_id', 'depth', 'options',
        'credential_refs', 'policy_version', 'timezone', 'frequency',
        'cron_expression', 'next_run', 'is_active', 'disabled_reason',
        'version', 'created_by', 'updated_at',
    ])
    append_audit(
        user=actor,
        action=AuditLog.Action.SCAN_SCHEDULE,
        result=AuditLog.Result.SUCCESS,
        resource_type='ScheduledScan',
        resource_id=str(schedule.id),
        resource_repr=schedule.name,
        changes={'updated': True, 'version': schedule.version, 'is_active': True},
        metadata={
            'event': 'scheduled_scan_updated',
            'project_id': str(schedule.project_id),
            'asset_id': str(schedule.asset_id),
            'capability_id': schedule.capability_id,
            'schedule_version': schedule.version,
            'next_run': schedule.next_run.isoformat(),
            'policy_version': schedule.policy_version,
        },
        ip_address='0.0.0.0',
    )
    return schedule


def _occurrence_payload(schedule: ScheduledScan, scheduled_for: datetime) -> dict[str, Any]:
    return {
        'schedule_id': str(schedule.id),
        'schedule_version': schedule.version,
        'scheduled_for': scheduled_for.astimezone(dt_timezone.utc).isoformat(),
        'actor_id': str(schedule.created_by_id or ''),
        'project_id': str(schedule.project_id),
        'asset_id': str(schedule.asset_id or ''),
        'capability_id': schedule.capability_id,
        'depth': schedule.depth,
        'options': schedule.options if isinstance(schedule.options, dict) else {},
        'credential_refs': list(schedule.credential_refs or []),
        'policy_version': schedule.policy_version,
    }


@transaction.atomic
def claim_due_schedule(schedule_id: str, *, now: datetime | None = None) -> tuple[ScheduledScanExecution | None, bool]:
    current_time = (now or timezone.now()).astimezone(dt_timezone.utc)
    schedule = (
        ScheduledScan.objects.select_for_update(of=('self',))
        .select_related('project', 'asset', 'created_by')
        .filter(pk=schedule_id)
        .first()
    )
    if schedule is None or not schedule.is_active or schedule.next_run > current_time:
        return None, False

    if schedule.created_by_id is None or schedule.asset_id is None or not schedule.capability_id:
        schedule.is_active = False
        schedule.disabled_reason = 'Canonical schedule binding is incomplete.'
        schedule.save(update_fields=['is_active', 'disabled_reason', 'updated_at'])
        return None, False

    scheduled_for = schedule.next_run.astimezone(dt_timezone.utc)
    payload = _occurrence_payload(schedule, scheduled_for)
    request_fingerprint = _sha256(payload)
    occurrence_id = uuid5(SCHEDULE_NAMESPACE, f"{schedule.id}:{scheduled_for.isoformat()}")
    idempotency_key = f'sched:{occurrence_id}'
    correlation_id = f'schedexec:{occurrence_id}'

    execution, created = ScheduledScanExecution.objects.get_or_create(
        schedule=schedule,
        scheduled_for=scheduled_for,
        defaults={
            'id': occurrence_id,
            'schedule_version': schedule.version,
            'actor_id_snapshot': str(schedule.created_by_id),
            'project_id': schedule.project_id,
            'asset_id': schedule.asset_id,
            'capability_id': schedule.capability_id,
            'depth_snapshot': schedule.depth,
            'options_snapshot': payload['options'],
            'credential_refs_snapshot': payload['credential_refs'],
            'policy_version_snapshot': schedule.policy_version,
            'request_fingerprint': request_fingerprint,
            'idempotency_key': idempotency_key,
            'correlation_id': correlation_id,
        },
    )
    if execution.request_fingerprint != request_fingerprint:
        schedule.is_active = False
        schedule.disabled_reason = 'Scheduled occurrence identity no longer matches its persisted snapshot.'
        schedule.save(update_fields=['is_active', 'disabled_reason', 'updated_at'])
        raise ScheduledExecutionError(
            'occurrence_identity_conflict',
            'Scheduled occurrence fingerprint conflict detected.',
            409,
        )

    schedule.next_run = next_schedule_run(
        frequency=schedule.frequency,
        cron_expression=schedule.cron_expression,
        timezone_name=schedule.timezone,
        scheduled_for=scheduled_for,
    )
    schedule.save(update_fields=['next_run', 'updated_at'])
    return execution, created


def _block_execution(execution: ScheduledScanExecution, reason: str, *, disable_schedule: bool = True) -> dict[str, Any]:
    now = timezone.now()
    with transaction.atomic():
        current = (
            ScheduledScanExecution.objects.select_for_update(of=('self',))
            .select_related('schedule')
            .get(pk=execution.pk)
        )
        current.status = ScheduledScanExecution.Status.BLOCKED
        current.reason = str(reason)[:4000]
        current.dispatched_at = None
        current.save(update_fields=['status', 'reason', 'dispatched_at', 'updated_at'])
        if disable_schedule and current.schedule.is_active:
            current.schedule.is_active = False
            current.schedule.disabled_reason = str(reason)[:4000]
            current.schedule.save(update_fields=['is_active', 'disabled_reason', 'updated_at'])
    append_audit(
        user=None,
        action=AuditLog.Action.SCAN_SCHEDULE,
        result=AuditLog.Result.FAILURE,
        resource_type='ScheduledScanExecution',
        resource_id=str(execution.id),
        resource_repr='Blocked scheduled scan occurrence',
        changes={'blocked': True},
        metadata={
            'event': 'scheduled_scan_blocked',
            'schedule_id': str(execution.schedule_id),
            'actor_id_snapshot': execution.actor_id_snapshot,
            'reason_sha256': _sha256(str(reason)),
        },
        error_message=str(reason)[:2000],
        ip_address='0.0.0.0',
    )
    return {'status': 'blocked', 'execution_id': str(execution.id), 'reason': str(reason)}


def execute_scheduled_occurrence(execution_id: str) -> dict[str, Any]:
    with transaction.atomic():
        execution = (
            ScheduledScanExecution.objects.select_for_update(of=('self',))
            .select_related('schedule', 'project', 'asset', 'scan')
            .get(pk=execution_id)
        )
        if execution.status == ScheduledScanExecution.Status.DISPATCHED and execution.scan_id:
            return {
                'status': 'dispatched',
                'execution_id': str(execution.id),
                'scan_id': str(execution.scan_id),
                'task_id': execution.scanner_task_id,
                'replayed': True,
            }
        if execution.status == ScheduledScanExecution.Status.BLOCKED:
            return {
                'status': 'blocked',
                'execution_id': str(execution.id),
                'reason': execution.reason,
                'replayed': True,
            }
        lease_cutoff = timezone.now() - timedelta(minutes=2)
        if (
            execution.status == ScheduledScanExecution.Status.RUNNING
            and execution.updated_at >= lease_cutoff
        ):
            return {
                'status': 'running',
                'execution_id': str(execution.id),
                'scan_id': str(execution.scan_id) if execution.scan_id else None,
                'replayed': True,
            }
        if execution.attempts >= _MAX_EXECUTION_ATTEMPTS:
            return _block_execution(execution, 'Scheduled execution retry limit reached.')

        schedule = ScheduledScan.objects.select_for_update(of=('self',)).get(pk=execution.schedule_id)
        if not schedule.is_active:
            return _block_execution(execution, schedule.disabled_reason or 'Schedule is disabled.', disable_schedule=False)
        if schedule.version != execution.schedule_version:
            return _block_execution(execution, 'Schedule changed after this occurrence was claimed.', disable_schedule=False)
        if execution.policy_version_snapshot != SCHEDULE_POLICY_VERSION:
            return _block_execution(
                execution,
                'Scheduled execution policy version is stale and requires an explicit schedule update.',
            )

        execution.status = ScheduledScanExecution.Status.RUNNING
        execution.attempts += 1
        execution.started_at = execution.started_at or timezone.now()
        execution.reason = ''
        execution.save(update_fields=['status', 'attempts', 'started_at', 'reason', 'updated_at'])

    try:
        binding = _normalize_binding(
            actor_id=execution.actor_id_snapshot,
            project_id=str(execution.project_id),
            asset_id=str(execution.asset_id),
            capability_id=execution.capability_id,
            depth=execution.depth_snapshot,
            options=execution.options_snapshot,
            credential_refs=execution.credential_refs_snapshot,
            purpose=f'scheduled-scan:execute:{execution.id}',
        )
        capability = binding['capability']
        options = binding['options']
        refs = binding['credential_refs']

        draft = prepare_governed_execution_draft(
            policy_version=execution.policy_version_snapshot,
            actor_id=execution.actor_id_snapshot,
            project_id=str(execution.project_id),
            asset_id=str(execution.asset_id),
            requested_capability_id=capability.id,
            capability=capability,
            allowed_options=options,
            credential_refs=refs,
            depth=execution.depth_snapshot,
            idempotency_key=execution.idempotency_key,
            correlation_id=execution.correlation_id,
        )
        envelope, contract_fingerprint = finalize_governed_execution_contract(
            draft,
            authorization_id=str(binding['authorization'].id),
        )

        expected_request = {
            'schedule_id': str(execution.schedule_id),
            'schedule_version': execution.schedule_version,
            'scheduled_for': execution.scheduled_for.astimezone(dt_timezone.utc).isoformat(),
            'actor_id': execution.actor_id_snapshot,
            'project_id': str(execution.project_id),
            'asset_id': str(execution.asset_id),
            'capability_id': execution.capability_id,
            'depth': execution.depth_snapshot,
            'options': execution.options_snapshot,
            'credential_refs': list(execution.credential_refs_snapshot or []),
            'policy_version': execution.policy_version_snapshot,
        }
        if _sha256(expected_request) != execution.request_fingerprint:
            return _block_execution(execution, 'Scheduled execution snapshot integrity check failed.')

        with transaction.atomic():
            locked = ScheduledScanExecution.objects.select_for_update(of=('self',)).get(pk=execution.id)
            if locked.scan_id:
                scan = Scan.objects.select_for_update().get(pk=locked.scan_id)
                if scan.execution_contract_fingerprint != contract_fingerprint:
                    return _block_execution(locked, 'Existing scheduled scan contract fingerprint changed.')
            else:
                config = {
                    'target': binding['target'],
                    'capability_options': options,
                    **options,
                    'credential_refs': refs,
                    'credential_context': binding['credential_context'],
                    'capability_id': capability.id,
                    'delegate_capability_id': None,
                    'plugin_capability': None,
                    'capability_category': capability.category,
                    'capability_risk': capability.risk,
                    'capability_policy_version': execution.policy_version_snapshot,
                    'capability_source': capability.source,
                    'capability_adapter': capability.adapter,
                    'credential_mode': capability.credential_mode,
                    'credential_required': capability.credential_required,
                    'scheduled_execution_id': str(execution.id),
                    'scheduled_for': execution.scheduled_for.isoformat(),
                }
                scan = Scan.objects.create(
                    project=binding['project'],
                    name=f'Scheduled {capability.id} for {binding["asset"].name}',
                    scan_type=capability.scan_type,
                    asset=binding['asset'],
                    authorization_decision=binding['authorization'],
                    engines=[capability.tool],
                    depth=execution.depth_snapshot,
                    config=config,
                    initiated_by=binding['actor'],
                    status=Scan.Status.QUEUED,
                    scheduled_scan=locked.schedule,
                    execution_contract=envelope,
                    execution_contract_fingerprint=contract_fingerprint,
                    execution_idempotency_key=draft.idempotency_key,
                    execution_idempotency_fingerprint=draft.idempotency_fingerprint,
                    execution_correlation_id=draft.correlation_id,
                )
                locked.scan = scan

            locked.authorization_decision = binding['authorization']
            locked.target_snapshot = binding['target']
            locked.policy_fingerprint = str(envelope.get('policy_fingerprint') or '')
            locked.execution_contract_fingerprint = contract_fingerprint
            locked.save(update_fields=[
                'scan',
                'authorization_decision',
                'target_snapshot',
                'policy_fingerprint',
                'execution_contract_fingerprint',
                'updated_at',
            ])

        task_id = f'scheduled-scan-{execution.id}'
        from fastapi_app.celery_app import BROWSER_QUEUE
        from fastapi_app.services.wstg_native_capabilities import is_wstg_internal_capability
        from fastapi_app.tasks.advanced_scans import run_masscan_scan, run_semgrep_scan
        from fastapi_app.tasks.native_capabilities import run_native_capability_scan
        from fastapi_app.tasks.security_scan import run_nmap_scan, run_nuclei_scan

        specialized = {
            'nmap': run_nmap_scan,
            'nuclei': run_nuclei_scan,
            'masscan': run_masscan_scan,
            'semgrep': run_semgrep_scan,
        }
        if capability.id in NATIVE_TOOL_SPECS or is_wstg_internal_capability(capability.id):
            if capability.id == 'browser.spa-discovery':
                result = run_native_capability_scan.apply_async(
                    args=[str(scan.id)],
                    task_id=task_id,
                    queue=BROWSER_QUEUE,
                    routing_key=BROWSER_QUEUE,
                )
            else:
                result = run_native_capability_scan.apply_async(args=[str(scan.id)], task_id=task_id)
        else:
            task = specialized.get(capability.tool)
            if task is None:
                return _block_execution(
                    execution,
                    f'Capability {capability.id} has no canonical scheduled dispatcher.',
                )
            result = task.apply_async(args=[str(scan.id)], task_id=task_id)

        now = timezone.now()
        with transaction.atomic():
            locked = ScheduledScanExecution.objects.select_for_update(of=('self',)).get(pk=execution.id)
            scan = Scan.objects.select_for_update().get(pk=locked.scan_id)
            scan.celery_task_id = result.id
            scan.save(update_fields=['celery_task_id', 'updated_at'])
            locked.status = ScheduledScanExecution.Status.DISPATCHED
            locked.scanner_task_id = result.id
            locked.dispatched_at = now
            locked.reason = ''
            locked.save(update_fields=['status', 'scanner_task_id', 'dispatched_at', 'reason', 'updated_at'])
            ScheduledScan.objects.filter(pk=locked.schedule_id).update(last_run=locked.scheduled_for)

        append_audit(
            user=binding['actor'],
            action=AuditLog.Action.SCAN_SCHEDULE,
            result=AuditLog.Result.SUCCESS,
            resource_type='ScheduledScanExecution',
            resource_id=str(execution.id),
            resource_repr=f'Scheduled {capability.id}',
            changes={'dispatched': True},
            metadata={
                'event': 'scheduled_scan_dispatched',
                'schedule_id': str(execution.schedule_id),
                'scan_id': str(scan.id),
                'project_id': str(execution.project_id),
                'asset_id': str(execution.asset_id),
                'authorization_decision_id': str(binding['authorization'].id),
                'capability_id': capability.id,
                'execution_contract_fingerprint': contract_fingerprint,
                'policy_fingerprint': envelope['policy_fingerprint'],
                'correlation_id': execution.correlation_id,
            },
            ip_address='0.0.0.0',
        )
        return {
            'status': 'dispatched',
            'execution_id': str(execution.id),
            'scan_id': str(scan.id),
            'task_id': result.id,
            'replayed': False,
        }
    except ScheduledExecutionError as exc:
        return _block_execution(execution, str(exc))
    except (RetiredCapabilityError, CredentialVaultDenied, ValueError) as exc:
        return _block_execution(execution, str(exc))
    except Exception as exc:
        with transaction.atomic():
            failed = ScheduledScanExecution.objects.select_for_update(of=('self',)).get(pk=execution.id)
            failed.status = ScheduledScanExecution.Status.FAILED
            failed.reason = str(exc)[:4000]
            failed.save(update_fields=['status', 'reason', 'updated_at'])
        raise


def due_schedule_ids(*, now: datetime | None = None, limit: int = 100) -> list[str]:
    current_time = now or timezone.now()
    return [
        str(value)
        for value in ScheduledScan.objects.filter(
            is_active=True,
            next_run__lte=current_time,
        )
        .order_by('next_run', 'id')
        .values_list('id', flat=True)[: max(1, min(int(limit), 500))]
    ]


def retryable_execution_ids(*, limit: int = 100) -> list[str]:
    stale_before = timezone.now() - timedelta(minutes=2)
    retry_state = (
        Q(
            status=ScheduledScanExecution.Status.CLAIMED,
            celery_task_id='',
        )
        | Q(
            status=ScheduledScanExecution.Status.CLAIMED,
            updated_at__lt=stale_before,
        )
        | Q(
            status=ScheduledScanExecution.Status.FAILED,
            updated_at__lt=stale_before,
        )
        | Q(
            status=ScheduledScanExecution.Status.RUNNING,
            updated_at__lt=stale_before,
        )
    )
    return [
        str(value)
        for value in ScheduledScanExecution.objects.filter(
            retry_state,
            attempts__lt=_MAX_EXECUTION_ATTEMPTS,
            schedule__is_active=True,
        )
        .order_by('updated_at', 'id')
        .values_list('id', flat=True)[: max(1, min(int(limit), 500))]
    ]


__all__ = [
    'SCHEDULE_POLICY_VERSION',
    'ScheduledExecutionError',
    'claim_due_schedule',
    'create_canonical_schedule',
    'due_schedule_ids',
    'execute_scheduled_occurrence',
    'next_schedule_run',
    'retryable_execution_ids',
    'update_canonical_schedule',
    'validate_schedule_timing',
]
