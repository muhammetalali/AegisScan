from __future__ import annotations

import csv
import io
import json
from datetime import timedelta, timezone
from typing import List, Optional

from asgiref.sync import sync_to_async
from django.core.files.base import ContentFile
from django.core.signing import BadSignature, SignatureExpired, dumps, loads
from django.http import FileResponse
from django.utils import timezone as django_timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user, require_permission
from audit.models import DataExport
from projects.models import Project
from scans.models import Scan
from vulnerabilities.models import Vulnerability
from evidence.models import Evidence
from django_project.users.models import Permission

router = APIRouter()
SUPPORTED_FORMATS = {'json', 'csv', 'pdf'}
SUPPORTED_REPORT_TYPES = {'full', 'findings', 'evidence', 'scan'}

class ReportCreate(BaseModel):
    project_id: str
    scan_id: Optional[str] = None
    title: str
    description: str = ''
    report_type: str = 'full'
    format: str = 'pdf'
    template_id: Optional[str] = None

class ReportResponse(BaseModel):
    id: str
    project_id: str
    scan_id: Optional[str] = None
    title: str
    report_type: str
    format: str
    status: str
    file_size: int = 0
    generated_by: str
    created_at: str
    completed_at: Optional[str] = None

class ReportScheduleCreate(BaseModel):
    project_id: str
    template_id: str
    frequency: str
    recipients: List[str]
    formats: List[str]

@sync_to_async
def _project_access(project_id: str, user_id: str):
    from django.db.models import Q
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project

def _report_queryset(user_id: str):
    return DataExport.objects.filter(resource_type='project_report', user_id=user_id).order_by('-created_at')

@sync_to_async
def _serialize(report: DataExport):
    filters = report.filters if isinstance(report.filters, dict) else {}
    return ReportResponse(id=str(report.id), project_id=str(filters.get('project_id', '')), scan_id=str(filters['scan_id']) if filters.get('scan_id') else None,
                          title=report.name, report_type=filters.get('report_type', 'full'), format=report.format, status=report.status,
                          file_size=report.file_size, generated_by=str(report.user_id), created_at=report.created_at.astimezone(timezone.utc).isoformat(),
                          completed_at=report.completed_at.astimezone(timezone.utc).isoformat() if report.completed_at else None)

@sync_to_async
def _build_payload(project_id: str, scan_id: Optional[str], report_type: str):
    project = Project.objects.filter(id=project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found')
    scans = Scan.objects.filter(project=project)
    findings = Vulnerability.objects.filter(project=project)
    evidence = Evidence.objects.filter(scan__project=project)
    if scan_id:
        scan = scans.filter(id=scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail='Scan not found for project')
        findings = findings.filter(scan=scan)
        evidence = evidence.filter(scan=scan)
    else:
        scan = scans.order_by('-created_at').first()
    payload = {
        'project': {'id': str(project.id), 'name': project.name, 'environment': project.environment},
        'scan': {'id': str(scan.id), 'name': scan.name, 'status': scan.status, 'findings_count': scan.findings_count} if scan else None,
        'findings': [{'id': str(f.id), 'title': f.title, 'severity': f.severity, 'status': f.status, 'confidence': f.confidence, 'risk_score': f.risk_score, 'source_engine': f.source_engine, 'scan_id': str(f.scan_id), 'asset_id': str(f.asset_id) if f.asset_id else None} for f in findings.order_by('-risk_score', '-created_at')],
        'evidence': [{'id': str(e.id), 'finding_id': str(e.finding_id) if e.finding_id else None, 'scan_id': str(e.scan_id) if e.scan_id else None, 'source': e.source, 'evidence_type': e.evidence_type, 'sha256': e.sha256, 'collected_at': e.collected_at.astimezone(timezone.utc).isoformat()} for e in evidence.order_by('-collected_at')],
    }
    if report_type == 'findings': payload['evidence'] = []
    elif report_type == 'evidence': payload['findings'] = []
    elif report_type == 'scan' and scan: payload = {'project': payload['project'], 'scan': payload['scan']}
    return payload

def _make_csv(payload: dict) -> bytes:
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['kind', 'id', 'title', 'severity', 'status', 'risk_score', 'source_engine', 'scan_id', 'asset_id'])
    for item in payload.get('findings', []): writer.writerow(['finding', item['id'], item['title'], item['severity'], item['status'], item['risk_score'], item['source_engine'], item['scan_id'], item['asset_id']])
    writer.writerow([]); writer.writerow(['kind', 'id', 'finding_id', 'source', 'evidence_type', 'sha256', 'collected_at'])
    for item in payload.get('evidence', []): writer.writerow(['evidence', item['id'], item['finding_id'], item['source'], item['evidence_type'], item['sha256'], item['collected_at']])
    return output.getvalue().encode('utf-8')

def _make_pdf(payload: dict, title: str) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise HTTPException(status_code=503, detail='PDF reporting is unavailable because reportlab is not installed') from exc
    buffer = io.BytesIO(); pdf = canvas.Canvas(buffer, pagesize=A4); width, height = A4; y = height - 45; pdf.setTitle(title); pdf.setFont('Helvetica-Bold', 14); pdf.drawString(40, y, title); y -= 30; pdf.setFont('Helvetica', 9)
    lines = [f"Project: {payload['project']['name']} ({payload['project']['id']})", f"Scan: {payload.get('scan', {}).get('name', 'n/a') if payload.get('scan') else 'n/a'}", f"Findings: {len(payload.get('findings', []))}", f"Evidence records: {len(payload.get('evidence', []))}", '']
    lines.extend(f"[{f['severity']}] {f['title']} | {f['status']} | risk={f['risk_score']}" for f in payload.get('findings', [])[:200])
    lines.extend(f"Evidence {e['id']} | {e['source']} | {e['evidence_type']} | sha256={e['sha256']}" for e in payload.get('evidence', [])[:200])
    for line in lines:
        if y < 45: pdf.showPage(); y = height - 45; pdf.setFont('Helvetica', 9)
        pdf.drawString(40, y, line[:150]); y -= 13
    pdf.save(); return buffer.getvalue()

@sync_to_async
def _create_report(body: ReportCreate, user_id: str, payload: dict):
    if body.format not in SUPPORTED_FORMATS: raise HTTPException(status_code=400, detail=f'Unsupported report format: {body.format}')
    if body.report_type not in SUPPORTED_REPORT_TYPES: raise HTTPException(status_code=400, detail=f'Unsupported report type: {body.report_type}')
    report = DataExport.objects.create(user_id=user_id, name=body.title, format=body.format, status=DataExport.Status.PROCESSING,
                                       resource_type='project_report', filters={'project_id': body.project_id, 'scan_id': body.scan_id, 'report_type': body.report_type, 'description': body.description, 'template_id': body.template_id},
                                       fields=['project', 'scan', 'findings', 'evidence'], expires_at=django_timezone.now() + timedelta(days=7))
    if body.format == 'json': content, ext = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8'), 'json'
    elif body.format == 'csv': content, ext = _make_csv(payload), 'csv'
    else: content, ext = _make_pdf(payload, body.title), 'pdf'
    report.file.save(f'{report.id}.{ext}', ContentFile(content), save=False); report.file_size = len(content); report.record_count = len(payload.get('findings', [])) + len(payload.get('evidence', [])); report.status = DataExport.Status.COMPLETED; report.completed_at = django_timezone.now(); report.save(update_fields=['file', 'file_size', 'record_count', 'status', 'completed_at']); return report

@sync_to_async
def _get_report(report_id: str, user_id: str):
    report = DataExport.objects.filter(id=report_id, resource_type='project_report', user_id=user_id).first()
    if not report: raise HTTPException(status_code=404, detail='Report not found')
    return report

@router.get('/', response_model=List[ReportResponse])
async def list_reports(project_id: Optional[str] = None, report_type: Optional[str] = None, status: Optional[str] = None, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), current_user=Depends(require_permission(Permission.REPORT_READ))):
    qs = _report_queryset(str(current_user.get('user_id')))
    if project_id: qs = qs.filter(filters__project_id=project_id)
    if report_type: qs = qs.filter(filters__report_type=report_type)
    if status: qs = qs.filter(status=status)
    return [await _serialize(item) for item in list(qs[offset:offset + limit])]

@router.post('/', response_model=ReportResponse, status_code=201)
async def create_report(report: ReportCreate, current_user=Depends(require_permission(Permission.REPORT_CREATE))):
    await _project_access(report.project_id, str(current_user.get('user_id'))); payload = await _build_payload(report.project_id, report.scan_id, report.report_type)
    return await _serialize(await _create_report(report, str(current_user.get('user_id')), payload))

@router.get('/{report_id}', response_model=ReportResponse)
async def get_report(report_id: str, current_user=Depends(require_permission(Permission.REPORT_READ))):
    return await _serialize(await _get_report(report_id, str(current_user.get('user_id'))))

@router.get('/{report_id}/download')
async def download_report(report_id: str, current_user=Depends(require_permission(Permission.REPORT_DOWNLOAD))):
    report = await _get_report(report_id, str(current_user.get('user_id')))
    if report.status != DataExport.Status.COMPLETED or not report.file: raise HTTPException(status_code=409, detail='Report is not ready for download')
    report.downloaded_at = django_timezone.now(); await sync_to_async(report.save)(update_fields=['downloaded_at'])
    return FileResponse(report.file.path, media_type='application/octet-stream', filename=report.file.name.rsplit('/', 1)[-1])

@router.get('/shared/{share_token}/download')
async def download_shared_report(share_token: str):
    try: payload = loads(share_token, salt='aegisscan-report-share', max_age=30 * 24 * 3600)
    except (BadSignature, SignatureExpired): raise HTTPException(status_code=401, detail='Invalid or expired report share token')
    report = await sync_to_async(lambda: DataExport.objects.filter(id=payload.get('report_id'), resource_type='project_report', status=DataExport.Status.COMPLETED).first())()
    if not report or not report.file or payload.get('permission') not in {'view', 'download'}: raise HTTPException(status_code=404, detail='Shared report not found')
    return FileResponse(report.file.path, media_type='application/octet-stream', filename=report.file.name.rsplit('/', 1)[-1])

@router.delete('/{report_id}')
async def delete_report(report_id: str, current_user=Depends(require_permission(Permission.REPORT_CREATE))):
    report = await _get_report(report_id, str(current_user.get('user_id'))); report.file.delete(save=False); report.delete(); return {'deleted': True, 'report_id': report_id}

@router.post('/{report_id}/share')
async def share_report(report_id: str, email: str, permission: str = 'view', expires_in_days: int = Query(7, ge=1, le=30), current_user=Depends(require_permission(Permission.REPORT_SHARE))):
    if permission not in {'view', 'download'}: raise HTTPException(status_code=400, detail='permission must be view or download')
    report = await _get_report(report_id, str(current_user.get('user_id')))
    token = dumps({'report_id': str(report.id), 'permission': permission, 'recipient': email}, salt='aegisscan-report-share')
    return {'report_id': str(report.id), 'recipient': email, 'permission': permission, 'expires_in_days': expires_in_days, 'share_token': token, 'download_path': f'/reports/shared/{token}/download'}

@router.post('/compare')
async def compare_reports(report_id_a: str, report_id_b: str, current_user=Depends(require_permission(Permission.REPORT_COMPARE))):
    first, second = await _get_report(report_id_a, str(current_user.get('user_id'))), await _get_report(report_id_b, str(current_user.get('user_id')))
    a = {'id': str(first.id), 'project_id': first.filters.get('project_id'), 'scan_id': first.filters.get('scan_id'), 'record_count': first.record_count, 'file_size': first.file_size, 'created_at': first.created_at.astimezone(timezone.utc).isoformat()}
    b = {'id': str(second.id), 'project_id': second.filters.get('project_id'), 'scan_id': second.filters.get('scan_id'), 'record_count': second.record_count, 'file_size': second.file_size, 'created_at': second.created_at.astimezone(timezone.utc).isoformat()}
    return {'report_a': a, 'report_b': b, 'record_count_delta': b['record_count'] - a['record_count'], 'file_size_delta': b['file_size'] - a['file_size']}

@router.post('/schedules', response_model=dict)
async def create_schedule(schedule: ReportScheduleCreate, current_user=Depends(require_permission(Permission.REPORT_CREATE))):
    await _project_access(schedule.project_id, str(current_user.get('user_id'))); raise HTTPException(status_code=501, detail='Report scheduling requires a persisted report schedule model and Celery Beat registration; no placeholder schedule is created')

@router.get('/schedules/', response_model=List[dict])
async def list_schedules(project_id: Optional[str] = None, current_user=Depends(require_permission(Permission.REPORT_READ))):
    raise HTTPException(status_code=501, detail='Report scheduling is not enabled until persisted schedules are configured')

@router.get('/templates/', response_model=List[dict])
async def list_templates(report_type: Optional[str] = None, current_user=Depends(require_permission(Permission.REPORT_READ))):
    templates = [
        {'id': 'full', 'name': 'Full security report', 'report_type': 'full', 'formats': sorted(SUPPORTED_FORMATS)},
        {'id': 'findings', 'name': 'Findings report', 'report_type': 'findings', 'formats': sorted(SUPPORTED_FORMATS)},
        {'id': 'evidence', 'name': 'Evidence report', 'report_type': 'evidence', 'formats': sorted(SUPPORTED_FORMATS)},
        {'id': 'scan', 'name': 'Scan summary report', 'report_type': 'scan', 'formats': sorted(SUPPORTED_FORMATS)},
    ]
    return [item for item in templates if not report_type or item['report_type'] == report_type]
