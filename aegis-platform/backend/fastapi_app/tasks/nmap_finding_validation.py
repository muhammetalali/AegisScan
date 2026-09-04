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

from django_project.evidence.models import Evidence, ValidationRun
from fastapi_app.services.nmap_parser import parse_nmap_xml
from fastapi_app.services.scope_authorization import is_target_authorized
from fastapi_app.services.evidence_identity import evidence_id


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


def _run_nmap_exact(target: str, port: int, timeout: int) -> tuple[int, str, str]:
    executable = shutil.which('nmap')
    if not executable:
        raise RuntimeError('Nmap is not installed on the worker')
    completed = subprocess.run(
        [executable, '-sV', '-p', str(port), '-oX', '-', '--', target],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


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
    validation.status = ValidationRun.Status.FAILED
    validation.progress = 100
    validation.current_phase = status
    validation.error_message = message
    validation.completed_at = datetime.now(timezone.utc)
    validation.save(update_fields=['status', 'progress', 'current_phase', 'error_message', 'completed_at'])
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

    validation.status = ValidationRun.Status.RUNNING
    validation.progress = 10
    validation.current_phase = 'preflight'
    validation.started_at = datetime.now(timezone.utc)
    validation.error_message = ''
    validation.save(update_fields=['status', 'progress', 'current_phase', 'started_at', 'error_message'])

    try:
        if not validation.authorized:
            return _fail_validation(validation, 'Execution blocked: validation is not explicitly authorized.', 'blocked')

        asset = finding.asset
        asset_config = (asset.configuration or {}) if asset else {}
        if asset_config.get('authorized') is not True:
            return _fail_validation(validation, 'Execution blocked: finding asset is not explicitly marked authorized.', 'blocked')

        engine = (validation.engines or [finding.source_engine])[0].strip().lower()
        if engine != 'nmap' or (finding.source_engine or '').strip().lower() != 'nmap':
            raise ValueError('Nmap finding validation requires source engine nmap and validation engine nmap')

        target = _string(asset_config.get('host') or asset_config.get('ip') or asset_config.get('domain'))
        if not target:
            raise ValueError('Finding asset does not contain an authorized host/ip/domain for Nmap validation')
        if validation.target_value.strip() != target:
            raise ValueError('Nmap finding validation target must exactly match the finding asset host')
        if not is_target_authorized(validation.scope or validation.target_value):
            raise ValueError('Execution blocked: target is outside the server-side authorized scan scope.')

        port, signature = _expected_signature(finding.raw_data or {})
        validation.current_phase = 'nmap'
        validation.progress = 20
        validation.save(update_fields=['current_phase', 'progress'])

        exit_code, evidence_raw, stderr = _run_nmap_exact(target, port, timeout=300)
        parsed = parse_nmap_xml(evidence_raw) if evidence_raw.strip() else {'hosts': [], 'host_count': 0, 'open_ports': 0}
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
        }

        now = datetime.now(timezone.utc)
        with transaction.atomic():
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
                        'validation_id': validation_id,
                        'finding_present': finding_present,
                        'port': port,
                        'expected': signature,
                        'observed': observed,
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
        validation.status = ValidationRun.Status.FAILED
        validation.progress = 100
        validation.current_phase = 'failed'
        validation.error_message = str(exc)
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'progress', 'current_phase', 'error_message', 'completed_at'])
        raise
