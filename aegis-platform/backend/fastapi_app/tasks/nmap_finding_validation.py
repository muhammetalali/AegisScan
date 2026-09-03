from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from celery import shared_task
from django.db import transaction

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.nmap_parser import parse_nmap_xml
from fastapi_app.services.scope_authorization import is_target_authorized


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ''


def _finding_port_signature(raw_data: dict[str, Any]) -> tuple[int, dict[str, str]]:
    candidates: list[dict[str, Any]] = []
    if isinstance(raw_data.get('port'), (int, str)):
        candidates.append(raw_data)
    parsed = raw_data.get('parsed')
    if isinstance(parsed, dict):
        for host in parsed.get('hosts', []):
            if isinstance(host, dict):
                candidates.extend(p for p in host.get('ports', []) if isinstance(p, dict))
    for candidate in candidates:
        try:
            port = int(candidate.get('port', candidate.get('portid')))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        signature = {
            'protocol': _string(candidate.get('protocol') or raw_data.get('protocol')).lower() or 'tcp',
            'state': _string(candidate.get('state') or raw_data.get('state')).lower(),
            'service': _string(candidate.get('service') or raw_data.get('service')).lower(),
            'product': _string(candidate.get('product') or raw_data.get('product')).lower(),
            'version': _string(candidate.get('version') or raw_data.get('version')).lower(),
        }
        if signature['state']:
            return port, signature
    raise ValueError('Nmap finding has no valid port/state signature for exact re-validation')


def _run_nmap_exact(target: str, port: int, timeout: int = 300) -> tuple[int, str, str]:
    executable = shutil.which('nmap')
    if not executable:
        raise RuntimeError('Nmap is not installed on the validation worker')
    completed = subprocess.run(
        [executable, '-sV', '-p', str(port), '-oX', '-', '--', target],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _matches(parsed: dict[str, Any], expected_port: int, signature: dict[str, str]) -> tuple[bool, dict[str, Any] | None]:
    for host in parsed.get('hosts', []):
        if not isinstance(host, dict):
            continue
        for observed in host.get('ports', []):
            if not isinstance(observed, dict):
                continue
            try:
                if int(observed.get('port') or 0) != expected_port:
                    continue
            except (TypeError, ValueError):
                continue
            if _string(observed.get('protocol')).lower() != signature['protocol']:
                continue
            if _string(observed.get('state')).lower() != signature['state']:
                continue
            for field in ('service', 'product', 'version'):
                expected = signature[field]
                if expected and _string(observed.get(field)).lower() != expected:
                    return False, observed
            return True, observed
    return False, None


def _fail(validation: ValidationRun, message: str, phase: str = 'blocked') -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    validation.status = ValidationRun.Status.FAILED
    validation.progress = 100
    validation.current_phase = phase
    validation.error_message = message
    validation.completed_at = now
    validation.save(update_fields=['status', 'progress', 'current_phase', 'error_message', 'completed_at'])
    return {'status': phase, 'validation_id': str(validation.id), 'error': message}


def _load_bound_context(validation_id: str) -> tuple[ValidationRun, Vulnerability, Asset, AssetAuthorization]:
    with transaction.atomic():
        validation = ValidationRun.objects.select_for_update().select_related('finding', 'user').get(pk=validation_id)
        finding = validation.finding
        if not finding:
            raise ValueError('Validation must be bound to a persisted finding')
        if validation.finding_identity_snapshot != finding.id:
            raise ValueError('Validation finding identity does not match the persisted finding')
        asset = Asset.objects.select_for_update().get(pk=finding.asset_id)
        decision = AssetAuthorization.objects.select_for_update().get(pk=validation.authorization_decision_id)
        if finding.scan.authorization_decision_id != decision.id:
            raise ValueError('Validation authorization does not match the originating scan authorization decision')
        latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
        if latest is None or latest.id != decision.id:
            raise ValueError('Validation authorization is no longer the latest asset decision')
        if decision.authorized is not True or not decision.is_currently_valid:
            raise ValueError('Validation authorization is no longer currently valid')
        if decision.asset_identity_snapshot != asset.id:
            raise ValueError('Validation authorization asset identity mismatch')
        target = _string(decision.target_snapshot)
        asset_config = asset.configuration or {}
        asset_target = _string(asset_config.get('host') or asset_config.get('ip') or asset_config.get('domain'))
        if not target or target != asset_target:
            raise ValueError('Validation target no longer matches immutable authorization target')
        if not is_target_authorized(target):
            raise ValueError('Validation target is outside the server-side authorized scan scope')
        if validation.target_value != target or validation.scope != target:
            raise ValueError('Validation target/scope does not exactly match the authorized target')
        if (finding.source_engine or '').strip().lower() != 'nmap':
            raise ValueError('Only Nmap findings can use the real Nmap validation worker')
        if not validation.engines or [str(v).lower() for v in validation.engines] != ['nmap']:
            raise ValueError('Validation engine binding must be exactly nmap')
        return validation, finding, asset, decision


@shared_task(bind=True, name='fastapi_app.tasks.nmap_finding_validation.validate_nmap_finding_e2e', max_retries=0)
def validate_nmap_finding_e2e(self, validation_id: str) -> dict[str, Any]:
    validation, finding, asset, decision = _load_bound_context(validation_id)
    now = datetime.now(timezone.utc)
    validation.status = ValidationRun.Status.RUNNING
    validation.progress = 10
    validation.current_phase = 'preflight'
    validation.started_at = now
    validation.error_message = ''
    validation.save(update_fields=['status', 'progress', 'current_phase', 'started_at', 'error_message'])

    try:
        if validation.authorized is not True:
            return _fail(validation, 'Execution blocked: validation is not explicitly authorized')
        port, expected = _finding_port_signature(finding.raw_data or {})
        validation.current_phase = 'nmap'
        validation.progress = 20
        validation.save(update_fields=['current_phase', 'progress'])

        exit_code, raw_output, stderr = _run_nmap_exact(decision.target_snapshot, port)
        parsed = parse_nmap_xml(raw_output) if raw_output.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
        finding_present, observed = _matches(parsed, port, expected)
        completed = datetime.now(timezone.utc)

        with transaction.atomic():
            # Re-check the immutable decision immediately before persisting evidence so revocation cannot be bypassed by a queued worker.
            locked_decision = AssetAuthorization.objects.select_for_update().get(pk=decision.id)
            latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
            if latest is None or latest.id != decision.id or locked_decision.authorized is not True or not locked_decision.is_currently_valid:
                raise ValueError('Validation authorization was revoked or superseded during execution')
            evidence = Evidence.objects.create(
                scan=finding.scan,
                asset=asset,
                finding=finding,
                source='nmap',
                evidence_type='validation_output',
                raw_output=raw_output,
                metadata={
                    'format': 'xml',
                    'stderr': stderr,
                    'target': decision.target_snapshot,
                    'exit_code': exit_code,
                    'validation_id': validation_id,
                    'finding_id': str(finding.id),
                    'finding_present': finding_present,
                    'port': port,
                    'expected': expected,
                    'observed': observed,
                    'authorization_decision_id': str(decision.id),
                },
                collected_by=validation.user,
            )
            validation.result = {
                'tool': 'nmap', 'target': decision.target_snapshot, 'exit_code': exit_code,
                'finding_id': str(finding.id), 'port': port, 'expected': expected,
                'observed': observed, 'finding_present': finding_present,
                'parsed': parsed, 'evidence_id': str(evidence.id),
                'authorization_decision_id': str(decision.id),
            }
            validation.status = ValidationRun.Status.COMPLETED if exit_code == 0 else ValidationRun.Status.FAILED
            validation.progress = 100
            validation.current_phase = 'completed' if exit_code == 0 else 'failed'
            validation.completed_at = completed
            validation.save(update_fields=['result', 'status', 'progress', 'current_phase', 'completed_at'])

            evidence_qs = finding.evidence_records.filter(evidence_type='validation_output', metadata__finding_present=False)
            finding.evidence_count = finding.evidence_records.count()
            finding.verified_evidence_count = evidence_qs.count()
            finding.validation_status = 'verified' if exit_code == 0 and not finding_present else 'unverified'
            finding.validated_at = completed
            finding.validated_by = validation.user
            finding.save(update_fields=['evidence_count', 'verified_evidence_count', 'validation_status', 'validated_at', 'validated_by', 'updated_at'])

        return {
            'status': validation.status,
            'validation_id': validation_id,
            'finding_id': str(finding.id),
            'target': decision.target_snapshot,
            'finding_present': finding_present,
            'evidence_id': str(evidence.id),
            'authorization_decision_id': str(decision.id),
        }
    except Exception as exc:
        validation.status = ValidationRun.Status.FAILED
        validation.progress = 100
        validation.current_phase = 'failed'
        validation.error_message = str(exc)
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'progress', 'current_phase', 'error_message', 'completed_at'])
        raise
