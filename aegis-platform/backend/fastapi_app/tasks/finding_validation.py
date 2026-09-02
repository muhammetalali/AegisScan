from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence, ValidationRun
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services.scope_authorization import is_target_authorized


_DEFAULT_NUCLEI_TEMPLATES = '/opt/nuclei-templates'


def _authorized_web_url(asset_config: dict[str, Any]) -> str:
    value = str(asset_config.get('url') or '').strip()
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('Finding asset does not contain an authorized http/https URL')
    return value


def _authorized_host(asset_config: dict[str, Any]) -> str:
    value = str(asset_config.get('host') or asset_config.get('ip') or asset_config.get('domain') or '').strip()
    if not value:
        raise ValueError('Finding asset does not contain an authorized host/ip/domain')
    return value


def _run_nuclei_template(target: str, template_path: str, timeout: int) -> tuple[int, str, str]:
    executable = shutil.which('nuclei')
    if not executable:
        raise RuntimeError('Nuclei is not installed on the worker')
    templates_dir = Path(os.getenv('NUCLEI_TEMPLATES_DIR', _DEFAULT_NUCLEI_TEMPLATES)).resolve()
    candidate = Path(template_path).resolve()
    try:
        candidate.relative_to(templates_dir)
    except ValueError as exc:
        raise ValueError('Finding template path is outside the configured Nuclei templates directory') from exc
    if not candidate.is_file():
        raise ValueError(f'Finding template file is missing: {candidate}')
    completed = subprocess.run(
        [executable, '-u', target, '-t', str(candidate), '-jsonl', '-silent', '-no-color'],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _jsonl_records(raw_output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


@shared_task(bind=True, name='fastapi_app.tasks.finding_validation.validate_finding_e2e', max_retries=1, default_retry_delay=30)
def validate_finding_e2e(self, validation_id: str) -> dict[str, Any]:
    validation = ValidationRun.objects.select_related('finding', 'finding__asset', 'finding__scan', 'user').get(pk=validation_id)
    finding = validation.finding
    if not finding:
        raise ValueError('Finding-specific validation requires validation.finding')

    validation.status = ValidationRun.Status.RUNNING
    validation.progress = 10
    validation.current_phase = finding.source_engine or 'validation'
    validation.started_at = datetime.now(timezone.utc)
    validation.error_message = ''
    validation.save(update_fields=['status', 'progress', 'current_phase', 'started_at', 'error_message'])

    if not validation.authorized:
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = 'Execution blocked: validation is not explicitly authorized.'
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'status': 'blocked', 'validation_id': validation_id}

    asset_config = (finding.asset.configuration or {}) if finding.asset else {}
    if asset_config.get('authorized') is not True:
        validation.status = ValidationRun.Status.FAILED
        validation.error_message = 'Execution blocked: finding asset is not explicitly marked authorized.'
        validation.completed_at = datetime.now(timezone.utc)
        validation.save(update_fields=['status', 'error_message', 'completed_at'])
        return {'status': 'blocked', 'validation_id': validation_id}

    engine = (validation.engines or [finding.source_engine])[0]
    if engine != finding.source_engine:
        raise ValueError(f'Validation engine must match finding source engine: {finding.source_engine}')

    try:
        if not is_target_authorized(validation.scope or validation.target_value):
            raise ValueError('Execution blocked: target is outside the server-side authorized scan scope.')

        result: dict[str, Any]
        evidence_raw: str
        stderr = ''
        exit_code = 0

        if engine == 'nuclei':
            target = _authorized_web_url(asset_config)
            raw_data = finding.raw_data or {}
            template_path = str(raw_data.get('template-path') or '').strip()
            template_id = str(raw_data.get('template-id') or '').strip()
            matcher_name = str(raw_data.get('matcher-name') or '').strip()
            if not template_path:
                raise ValueError('Nuclei finding has no template-path for exact re-validation')
            if validation.target_value.strip() != target:
                raise ValueError('Validation target must exactly match the finding asset URL')
            exit_code, evidence_raw, stderr = _run_nuclei_template(target, template_path, timeout=600)
            records = _jsonl_records(evidence_raw)
            matching_records = [
                record for record in records
                if str(record.get('template-id') or '').strip() == template_id
                and (not matcher_name or str(record.get('matcher-name') or '').strip() == matcher_name)
            ]
            finding_present = bool(matching_records)
            result = {
                'tool': 'nuclei',
                'target': target,
                'exit_code': exit_code,
                'template_id': template_id,
                'matcher_name': matcher_name,
                'finding_present': finding_present,
                'result_count': len(matching_records),
            }
        elif engine == 'nmap':
            raise ValueError('Finding-specific Nmap verification is handled by the dedicated Nmap validator')
        else:
            raise ValueError(f'Unsupported finding validation engine: {engine}')

        now = datetime.now(timezone.utc)
        with transaction.atomic():
            evidence = Evidence.objects.create(
                scan=finding.scan,
                asset=finding.asset,
                finding=finding,
                source=engine,
                evidence_type='validation_output',
                raw_output=evidence_raw,
                metadata={
                    'format': 'jsonl',
                    'stderr': stderr,
                    'target': result['target'],
                    'exit_code': result['exit_code'],
                    'validation_id': validation_id,
                    'finding_present': result['finding_present'],
                    'template_id': result.get('template_id', ''),
                    'matcher_name': result.get('matcher_name', ''),
                },
                collected_by=validation.user,
            )
            result['evidence_id'] = str(evidence.id)
            existing_result = dict(validation.result) if isinstance(validation.result, dict) else {}
            validation.result = {**existing_result, **result}
            validation.status = ValidationRun.Status.COMPLETED if exit_code == 0 else ValidationRun.Status.FAILED
            validation.progress = 100
            validation.current_phase = 'completed' if exit_code == 0 else 'failed'
            validation.completed_at = now
            validation.save(update_fields=['status', 'progress', 'current_phase', 'result', 'completed_at'])

            if exit_code == 0 and result.get('finding_present') is False:
                finding.validation_status = 'validated'
                finding.validated_at = now
                finding.validated_by = validation.user
                finding.verified_evidence_count = finding.evidence_records.filter(
                    evidence_type='validation_output',
                    metadata__finding_present=False,
                ).count()
                finding.evidence_count = finding.evidence_records.count()
                finding.save(update_fields=['validation_status', 'validated_at', 'validated_by', 'verified_evidence_count', 'evidence_count', 'updated_at'])
            else:
                finding.validation_status = 'unverified'
                finding.validated_at = now
                finding.validated_by = validation.user
                finding.evidence_count = finding.evidence_records.count()
                finding.save(update_fields=['validation_status', 'validated_at', 'validated_by', 'evidence_count', 'updated_at'])

        return {
            'status': validation.status,
            'validation_id': validation_id,
            'finding_id': str(finding.id),
            'tool': engine,
            'target': result['target'],
            'finding_present': result.get('finding_present'),
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
