from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Callable

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence, ValidationRun
from fastapi_app.services.nmap_parser import parse_nmap_xml
from fastapi_app.services.authorization_guard import authorization_snapshot, require_bound_validation_authorization
from fastapi_app.services.evidence_identity import evidence_id
from fastapi_app.services.kali_nmap_provider import execute_kali_nmap, nmap_provider_decision
from fastapi_app.services.nmap_execution_provider import legacy_nmap_disabled


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ''


def _first_expected_port(raw_data: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if isinstance(raw_data.get('port'), (int, str)):
        candidates.append(raw_data)
    parsed = raw_data.get('parsed')
    if isinstance(parsed, dict):
        for host in parsed.get('hosts', []):
            if not isinstance(host, dict):
                continue
            for port in host.get('ports', []):
                if isinstance(port, dict) and port.get('port') is not None:
                    candidates.append(port)
    for candidate in candidates:
        value = candidate.get('port', candidate.get('portid'))
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            return port, candidate
    raise ValueError('Nmap finding has no valid port for exact re-validation')


def _expected_signature(raw_data: dict[str, Any]) -> tuple[int, dict[str, str]]:
    port, source = _first_expected_port(raw_data)
    signature = {
        'protocol': _string(source.get('protocol') or raw_data.get('protocol')).lower() or 'tcp',
        'state': _string(source.get('state') or raw_data.get('state')).lower(),
        'service': _string(source.get('service') or raw_data.get('service')).lower(),
        'product': _string(source.get('product') or raw_data.get('product')).lower(),
        'version': _string(source.get('version') or raw_data.get('version')).lower(),
    }
    if not signature['state']:
        raise ValueError('Nmap finding has no state for exact re-validation')
    return port, signature


def _run_nmap_exact(
    target: str,
    port: int,
    timeout: int,
    *,
    authorization_ref: str,
    scope_ref: str,
    execution_ref: str,
    state_getter: Callable[[], str],
) -> tuple[int, str, str, dict[str, Any]]:
    """Use the EXISTING attested Kali Nmap provider, never an unpinned worker binary."""
    decision = nmap_provider_decision(routing_key=execution_ref)
    if not legacy_nmap_disabled() or decision.mode != 'default-kali' or decision.selected_provider != 'kali':
        raise RuntimeError('Exact finding validation requires governed default-kali Nmap and legacy retirement')
    result = execute_kali_nmap(
        target=target,
        timeout_seconds=timeout,
        execution_ref=execution_ref,
        authorization_ref=authorization_ref,
        scope_ref=scope_ref,
        state_getter=state_getter,
        validation_port=port,
    )
    return int(result['exit_code']), str(result['stdout']), str(result['stderr']), dict(result['runtime'])


def _exact_port_covered(parsed: dict[str, Any], port: int, protocol: str) -> bool:
    """A missing/ambiguous target port is INDETERMINATE, never proof of a fix."""
    return any(
        isinstance(observed, dict)
        and str(observed.get('port', observed.get('portid', ''))) == str(port)
        and _string(observed.get('protocol')).lower() == protocol
        for host in parsed.get('hosts', []) if isinstance(host, dict)
        for observed in host.get('ports', [])
    )


def _matches_signature(parsed: dict[str, Any], expected_port: int, signature: dict[str, str]) -> tuple[bool, dict[str, Any] | None]:
    for host in parsed.get('hosts', []):
        if not isinstance(host, dict):
            continue
        for observed in host.get('ports', []):
            if not isinstance(observed, dict) or int(observed.get('port') or 0) != expected_port:
                continue
            if _string(observed.get('protocol')).lower() != signature['protocol']:
                continue
            if _string(observed.get('state')).lower() != signature['state']:
                continue
            for field in ('service', 'product', 'version'):
                expected = signature[field]
                if expected and expected != _string(observed.get(field)).lower():
                    return False, observed
            return True, observed
    return False, None


def _fail_validation(validation: ValidationRun, message: str, status: str = 'failed') -> dict[str, Any]:
    # Cancellation is terminal: even a preflight rejection must not erase it.
    updated = ValidationRun.objects.filter(
        pk=validation.pk, status=ValidationRun.Status.RUNNING,
    ).update(
        status=ValidationRun.Status.FAILED,
        progress=100,
        current_phase=status,
        error_message=message,
        completed_at=datetime.now(timezone.utc),
    )
    if not updated:
        return {'status': ValidationRun.Status.CANCELLED, 'validation_id': str(validation.id)}
    return {'status': status, 'validation_id': str(validation.id)}


@shared_task(bind=True, name='fastapi_app.tasks.nmap_finding_validation.validate_nmap_finding_e2e', max_retries=1, default_retry_delay=30)
def validate_nmap_finding_e2e(self, validation_id: str) -> dict[str, Any]:
    validation = ValidationRun.objects.select_related('finding', 'finding__asset', 'finding__scan', 'user').get(pk=validation_id)
    finding = validation.finding
    if not finding:
        raise ValueError('Nmap finding validation requires validation.finding')
    existing_result = validation.result if isinstance(validation.result, dict) else {}
    existing_evidence_id = existing_result.get('evidence_id')
    if validation.status == ValidationRun.Status.COMPLETED and existing_evidence_id and Evidence.objects.filter(pk=existing_evidence_id, finding=finding).exists():
        return {
            'status': validation.status,
            'validation_id': validation_id,
            'finding_id': str(finding.id),
            'tool': 'nmap',
            'target': existing_result.get('target'),
            'finding_present': existing_result.get('finding_present'),
            'evidence_id': str(existing_evidence_id),
            'redelivered': True,
        }

    # Compare-and-update is essential: a queued Celery delivery cannot revive
    # a run cancelled (or completed) between the initial read and this claim.
    claimed = ValidationRun.objects.filter(
        pk=validation_id, status=ValidationRun.Status.QUEUED,
    ).update(
        status=ValidationRun.Status.RUNNING,
        progress=10,
        current_phase='preflight',
        started_at=datetime.now(timezone.utc),
        error_message='',
    )
    if not claimed:
        current_status = ValidationRun.objects.get(pk=validation_id).status
        return {
            'status': current_status,
            'validation_id': validation_id,
            'redelivered': True,
        }
    validation.status = ValidationRun.Status.RUNNING

    try:
        asset, target, authorization = require_bound_validation_authorization(validation)
        if authorization is None:
            return _fail_validation(validation, target, 'blocked')
        asset_config = asset.configuration or {}

        engine = (validation.engines or [finding.source_engine])[0].strip().lower()
        if engine != 'nmap' or (finding.source_engine or '').strip().lower() != 'nmap':
            raise ValueError('Nmap finding validation requires source engine nmap and validation engine nmap')

        port, signature = _expected_signature(finding.raw_data or {})
        # Do not revert a concurrent cancellation's terminal progress/phase.
        phase_updated = ValidationRun.objects.filter(
            pk=validation_id, status=ValidationRun.Status.RUNNING,
        ).update(current_phase='nmap', progress=20)
        if not phase_updated:
            return {'status': ValidationRun.objects.get(pk=validation_id).status,
                    'validation_id': validation_id}

        exit_code, evidence_raw, stderr, provider_runtime = _run_nmap_exact(
            target, port, timeout=300,
            authorization_ref=str(authorization.id),
            scope_ref=f'project:{finding.project_id}:asset:{finding.asset_id}',
            execution_ref=f'validation:{validation_id}:nmap',
            state_getter=lambda: (
                'cancelled' if ValidationRun.objects.filter(
                    pk=validation_id, status=ValidationRun.Status.CANCELLED
                ).exists() else 'running'
            ),
        )
        parsed = parse_nmap_xml(evidence_raw) if evidence_raw.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
        if exit_code == 0 and not _exact_port_covered(parsed, port, signature['protocol']):
            raise ValueError('Exact Nmap target port was not observed: remediation verdict is indeterminate')
        finding_present, observed = _matches_signature(parsed, port, signature)
        result = {
            'tool': 'nmap',
            'target': target,
            'exit_code': exit_code,
            'port': port,
            'expected': signature,
            'observed': observed,
            'parsed': parsed,
            'finding_present': finding_present,
            'runtime_provenance': provider_runtime,
        }

        now = datetime.now(timezone.utc)
        _, authorization_reason, current_authorization = require_bound_validation_authorization(validation)
        if current_authorization is None:
            raise ValueError(authorization_reason)
        with transaction.atomic():
            # Serialize cancellation against evidence and remediation-verdict
            # persistence. A late Nmap response must never revive a cancelled run.
            current = ValidationRun.objects.select_for_update().get(pk=validation_id)
            if current.status == ValidationRun.Status.CANCELLED:
                return {'status': ValidationRun.Status.CANCELLED, 'validation_id': validation_id}
            if current.status != ValidationRun.Status.RUNNING:
                raise ValueError('Validation state changed before evidence persistence')
            validation = current
            evidence, _ = Evidence.objects.update_or_create(
                id=evidence_id('validation', validation_id, 'nmap', 'validation_output', str(finding.id)),
                defaults={
                    'scan': finding.scan,
                    'asset': finding.asset,
                    'finding': finding,
                    'source': 'nmap',
                    'evidence_type': 'validation_output',
                    'raw_output': evidence_raw,
                    'metadata': {
                        'format': 'xml',
                        'stderr': stderr,
                        'target': target,
                        'exit_code': exit_code,
                        'validation_run_id': validation_id,
                        'validation_id': validation_id,
                        'finding_present': finding_present,
                        'port': port,
                        'expected': signature,
                        'observed': observed,
                        'runtime_provenance': provider_runtime,
                        **authorization_snapshot(authorization),
                    },
                    'collected_by': validation.user,
                },
            )
            result['evidence_id'] = str(evidence.id)
            existing_result = dict(validation.result) if isinstance(validation.result, dict) else {}
            validation.result = {**existing_result, **result}
            validation.status = ValidationRun.Status.COMPLETED if exit_code == 0 else ValidationRun.Status.FAILED
            validation.progress = 100
            validation.current_phase = 'completed' if exit_code == 0 else 'failed'
            validation.completed_at = now
            validation.save(update_fields=['status', 'progress', 'current_phase', 'result', 'completed_at'])

            finding.evidence_count = finding.evidence_records.count()
            if exit_code == 0 and finding_present is False:
                finding.validation_status = 'verified'
                finding.validated_at = now
                finding.validated_by = validation.user
                finding.verified_evidence_count = finding.evidence_records.filter(
                    evidence_type='validation_output',
                    metadata__finding_present=False,
                ).count()
                finding.save(update_fields=['validation_status', 'validated_at', 'validated_by', 'verified_evidence_count', 'evidence_count', 'updated_at'])
            else:
                finding.validation_status = 'unverified'
                finding.validated_at = now
                finding.validated_by = validation.user
                finding.verified_evidence_count = finding.evidence_records.filter(
                    evidence_type='validation_output',
                    metadata__finding_present=False,
                ).count()
                finding.save(update_fields=['validation_status', 'validated_at', 'validated_by', 'verified_evidence_count', 'evidence_count', 'updated_at'])

        return {
            'status': validation.status,
            'validation_id': validation_id,
            'finding_id': str(finding.id),
            'tool': 'nmap',
            'target': target,
            'port': port,
            'finding_present': finding_present,
            'evidence_id': result['evidence_id'],
        }
    except Exception as exc:
        # The provider may observe cancellation and raise. Keep CANCELLED as
        # the terminal result; neither the exception nor a queued retry may
        # rewrite the user's explicit decision.
        updated = ValidationRun.objects.filter(
            pk=validation_id, status=ValidationRun.Status.RUNNING,
        ).update(
            status=ValidationRun.Status.FAILED,
            progress=100,
            current_phase='failed',
            error_message=str(exc),
            completed_at=datetime.now(timezone.utc),
        )
        if not updated:
            return {'status': ValidationRun.objects.get(pk=validation_id).status,
                    'validation_id': validation_id}
        raise
