from __future__ import annotations

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from fastapi_app.celery_app import SCANNER_QUEUE
from fastapi_app.services.authorization_guard import require_bound_scan_authorization
from fastapi_app.services.burp_mcp_capability import CAPABILITY_ID, validate_burp_probe_options
from fastapi_app.services.burp_mcp_execution import resolve_probe_provider
from fastapi_app.services.burp_mcp_gateway import start_burp_mcp_session, invoke_burp_mcp
from fastapi_app.services.scanner_delivery import terminal_scan_delivery
from fastapi_app.services.governed_execution_contract import _fingerprint
from .native_capabilities import _engine, _execution, _fail, _cancelled


@shared_task(bind=True, name='fastapi_app.tasks.burp_mcp.run_burp_mcp_probe', max_retries=0)
def run_burp_mcp_probe(self, scan_id: str) -> dict:
    terminal = terminal_scan_delivery(scan_id, 'burp-mcp')
    if terminal:
        return terminal
    persisted = Scan.objects.select_related('asset', 'project', 'initiated_by').get(pk=scan_id)
    engine = _engine('burp-mcp', ScanEngine.EngineCategory.ANALYSIS, 30)
    execution = _execution(persisted, engine)
    if persisted.status == Scan.Status.CANCELLED:
        return _cancelled(persisted, execution)
    if persisted.status == Scan.Status.PAUSED:
        execution.status = ScanEngineExecution.ExecutionStatus.PENDING
        execution.save(update_fields=['status', 'updated_at'])
        return {'status': 'paused', 'scan_id': scan_id, 'lab_solved': False}
    delivery = getattr(self.request, 'delivery_info', None) or {}
    if not getattr(self.request, 'called_directly', False) and delivery.get('routing_key') != SCANNER_QUEUE:
        return _fail(persisted, execution, 'توقّف فحص Burp: وصلت المهمة إلى طابور غير معتمد.')
    config = persisted.config if isinstance(persisted.config, dict) else {}
    envelope = persisted.execution_contract if isinstance(persisted.execution_contract, dict) else {}
    refs = config.get('credential_refs', [])
    if not isinstance(refs, list) or len(refs) > 1 or any(not isinstance(ref, str) for ref in refs):
        return _fail(persisted, execution, 'فحص الاتصال يقبل مرجع سر مزود واحدًا كحد أقصى.')
    if (config.get('capability_id') != CAPABILITY_ID
            or not persisted.execution_contract_fingerprint
            or _fingerprint(envelope) != persisted.execution_contract_fingerprint
            or envelope.get('capability_id') != CAPABILITY_ID
            or envelope.get('project_ref') != f'project:{persisted.project_id}'
            or envelope.get('asset_ref') != f'asset:{persisted.asset_id}'
            or envelope.get('actor_ref') != f'user:{persisted.initiated_by_id}'
            or envelope.get('authorization_ref') != f'authorization:{persisted.authorization_decision_id}'
            or envelope.get('allowed_options') != config.get('capability_options')
            or envelope.get('credential_bindings') != sorted(refs)):
        return _fail(persisted, execution, 'توقّف فحص Burp: عقد التنفيذ الحالي غير مطابق.')
    try:
        options = validate_burp_probe_options(config.get('capability_options', {}))
        scan, target, authorization = require_bound_scan_authorization(scan_id)
        if scan is None or authorization is None:
            return _fail(persisted, execution, 'توقّف فحص Burp: التفويض المرتبط أو نطاق الهدف غير صالح.')
        refs = config.get('credential_refs', [])
        if not isinstance(refs, list) or len(refs) > 1:
            return _fail(scan, execution, 'فحص الاتصال يقبل مرجع سر مزود واحدًا كحد أقصى.')
        provider = resolve_probe_provider(project_id=str(scan.project_id),
                                          decision_ref=options['provider_decision_ref'], target=target)
        scan.status, scan.current_phase, scan.current_engine = Scan.Status.RUNNING, 'burp-conformance', 'burp-mcp'
        scan.started_at = scan.started_at or timezone.now()
        scan.save(update_fields=['status', 'current_phase', 'current_engine', 'started_at', 'updated_at'])
        ScanLog.objects.create(scan=scan, engine_execution=execution, level=ScanLog.Level.INFO,
                               message='بدأ التحقق من دورة اتصال Burp ومخطط أداة HTTP ثم طلب صحة الهدف المحلي.',
                               context={'capability_id': CAPABILITY_ID, 'lab_solved': False})
        session = start_burp_mcp_session(
            project_id=str(scan.project_id), asset_id=str(scan.asset_id), scan_id=str(scan.id),
            authorization_id=str(authorization.id), actor_id=str(scan.initiated_by_id),
            provider_name=provider.provider_name, provider_version=provider.provider_version,
            requested_operations=['burp.http_request'], idempotency_key=f'probe-session:{scan.id}',
            credential_ref=refs[0] if refs else None, max_invocations=1,
            rate_limit_per_minute=1, ttl_seconds=120,
        ).session
        invocation = invoke_burp_mcp(session_id=str(session.id), actor_id=str(scan.initiated_by_id),
                                     operation='burp.http_request', arguments={'path': '/health'},
                                     idempotency_key=f'probe-health:{scan.id}').invocation
        summary = invocation.result_summary
        with transaction.atomic():
            current = Scan.objects.select_for_update().get(pk=scan_id)
            if current.status == Scan.Status.CANCELLED:
                return _cancelled(current, execution)
            if current.status == Scan.Status.PAUSED:
                execution.status = ScanEngineExecution.ExecutionStatus.PENDING
                execution.save(update_fields=['status', 'updated_at'])
                return {'status': 'paused', 'scan_id': scan_id, 'lab_solved': False}
            success = summary.get('transport_probe_passed') is True
            now = timezone.now()
            execution.status = ScanEngineExecution.ExecutionStatus.COMPLETED if success else ScanEngineExecution.ExecutionStatus.FAILED
            execution.progress, execution.completed_at, execution.evidences_collected = 100, now, 1
            execution.result_data = {**summary, 'target': target, 'capability_id': CAPABILITY_ID,
                                     'session_ref': str(session.id), 'invocation_ref': str(invocation.id),
                                     'evidence_ref': str(invocation.evidence_id), 'finding_ids': [],
                                     'message_ar': 'نجح اتصال HTTP عبر Burp إلى علامة صحة الهدف؛ لم يتحقق حل اللاب أو بصمة النسخة الحية.'
                                     if success else 'تم الاستدعاء لكن علامة صحة الهدف أو حالته لا تطابق التعريف؛ لم ينجح فحص الاتصال.'}
            execution.error_message = '' if success else execution.result_data['message_ar']
            execution.save(update_fields=['status', 'progress', 'completed_at', 'evidences_collected',
                                          'result_data', 'error_message', 'updated_at'])
            current.status, current.progress, current.completed_at = (
                Scan.Status.COMPLETED if success else Scan.Status.FAILED), 100, now
            current.current_phase = 'burp-probe-completed' if success else 'failed'
            current.engine_results = {**(current.engine_results or {}), 'burp-mcp': execution.result_data}
            current.error_message = execution.error_message
            current.save(update_fields=['status', 'progress', 'completed_at', 'current_phase',
                                        'engine_results', 'error_message', 'updated_at'])
        return {'status': current.status, 'scan_id': scan_id, 'evidence_ref': str(invocation.evidence_id),
                'transport_probe_passed': success, 'lab_solved': False}
    except Exception as exc:
        # Do not record raw provider bodies, endpoint query/session IDs or credential material.
        return _fail(persisted, execution, 'تعذر إكمال فحص اتصال Burp؛ راجع قبول المزود والتوافق والهدف المرتبط.',
                     {'error_type': type(exc).__name__, 'transport_error_code': getattr(exc, 'code', ''),
                      'lab_solved': False})
