from __future__ import annotations

import json
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

from asgiref.sync import sync_to_async
from django.core.files.base import ContentFile
from django.db.models import Count, Q
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from django_project.projects.models import Project
from django_project.reporting.models import Report, ReportSchedule
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability

from ..core.dependencies import get_current_user

router = APIRouter()


class ReportCreate(BaseModel):
    project_id: str
    scan_id: Optional[str] = None
    title: str
    description: str = ""
    report_type: str = "security"
    format: str = "json"


class ReportScheduleCreate(BaseModel):
    project_id: str
    title: str
    report_type: str = "security"
    format: str = "json"
    frequency: str
    recipients: list[str] = Field(default_factory=list)
    next_run: datetime
    cron_expression: str = ""


@sync_to_async
def _project_access(project_id: str, user_id: str):
    return Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()


@sync_to_async
def _build_snapshot(project_id: str, scan_id: str | None, report_type: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    scan = None
    if scan_id:
        scan = Scan.objects.filter(id=scan_id, project=project).first()
        if not scan:
            raise HTTPException(status_code=404, detail='Scan not found')
    findings = Vulnerability.objects.filter(project=project)
    if scan:
        findings = findings.filter(scan=scan)
    counts = findings.aggregate(
        total=Count('id'),
        critical=Count('id', filter=Q(severity=Vulnerability.Severity.CRITICAL)),
        high=Count('id', filter=Q(severity=Vulnerability.Severity.HIGH)),
        medium=Count('id', filter=Q(severity=Vulnerability.Severity.MEDIUM)),
        low=Count('id', filter=Q(severity=Vulnerability.Severity.LOW)),
        info=Count('id', filter=Q(severity=Vulnerability.Severity.INFO)),
        open=Count('id', filter=Q(status=Vulnerability.Status.OPEN)),
        fixed=Count('id', filter=Q(status=Vulnerability.Status.FIXED)),
        accepted=Count('id', filter=Q(status=Vulnerability.Status.ACCEPTED_RISK)),
    )
    assets_count = project.assets.filter(is_active=True).count()
    scans_count = project.scans.count()
    risk = sum(float(v.risk_score or 0) for v in findings.only('risk_score'))
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'project': {'id': str(project.id), 'name': project.name, 'environment': project.environment},
        'scan': {'id': str(scan.id), 'name': scan.name, 'status': scan.status} if scan else None,
        'report_type': report_type,
        'coverage': {'active_assets': assets_count, 'scans': scans_count},
        'findings': {k: int(v or 0) for k, v in counts.items()},
        'risk': {'aggregate_risk_score': round(risk, 2)},
    }


def _render_html(snapshot: dict) -> str:
    project = snapshot['project']
    f = snapshot['findings']
    return '<!doctype html><html><head><meta charset="utf-8"><title>AegisScan Report</title></head><body>' + \
        f"<h1>AegisScan Security Report</h1><h2>{project['name']}</h2>" + \
        f"<p>Generated: {snapshot['generated_at']}</p>" + \
        '<h3>Coverage</h3>' + f"<p>Active assets: {snapshot['coverage']['active_assets']} | Scans: {snapshot['coverage']['scans']}</p>" + \
        '<h3>Findings</h3>' + f"<p>Total: {f['total']} | Critical: {f['critical']} | High: {f['high']} | Medium: {f['medium']} | Low: {f['low']} | Info: {f['info']}</p>" + \
        f"<p>Open: {f['open']} | Fixed: {f['fixed']} | Accepted risk: {f['accepted']}</p>" + \
        f"<p>Aggregate risk score: {snapshot['risk']['aggregate_risk_score']}</p>" + '</body></html>'


@sync_to_async
def _create_report(body: ReportCreate, user_id: str):
    if body.format not in {Report.Format.JSON, Report.Format.HTML}:
        raise HTTPException(status_code=501, detail='Requested report format is not implemented')
    snapshot = _build_snapshot_sync(body.project_id, body.scan_id, body.report_type, user_id)
    report = Report.objects.create(
        project_id=body.project_id,
        scan_id=body.scan_id,
        title=body.title,
        description=body.description,
        report_type=body.report_type,
        format=body.format,
        snapshot=snapshot,
        status=Report.Status.COMPLETED,
        completed_at=datetime.now(timezone.utc),
        generated_by_id=user_id,
    )
    payload = json.dumps(snapshot, sort_keys=True, ensure_ascii=False, indent=2).encode('utf-8')
    if body.format == Report.Format.HTML:
        payload = _render_html(snapshot).encode('utf-8')
    report.file.save(f'{report.id}.{body.format}', ContentFile(payload), save=True)
    return report


def _build_snapshot_sync(project_id: str, scan_id: str | None, report_type: str, user_id: str):
    project = Project.objects.filter(id=project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    scan = Scan.objects.filter(id=scan_id, project=project).first() if scan_id else None
    if scan_id and not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    findings = Vulnerability.objects.filter(project=project)
    if scan:
        findings = findings.filter(scan=scan)
    counts = findings.aggregate(
        total=Count('id'), critical=Count('id', filter=Q(severity=Vulnerability.Severity.CRITICAL)),
        high=Count('id', filter=Q(severity=Vulnerability.Severity.HIGH)), medium=Count('id', filter=Q(severity=Vulnerability.Severity.MEDIUM)),
        low=Count('id', filter=Q(severity=Vulnerability.Severity.LOW)), info=Count('id', filter=Q(severity=Vulnerability.Severity.INFO)),
        open=Count('id', filter=Q(status=Vulnerability.Status.OPEN)), fixed=Count('id', filter=Q(status=Vulnerability.Status.FIXED)),
        accepted=Count('id', filter=Q(status=Vulnerability.Status.ACCEPTED_RISK)),
    )
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'project': {'id': str(project.id), 'name': project.name, 'environment': project.environment},
        'scan': {'id': str(scan.id), 'name': scan.name, 'status': scan.status} if scan else None,
        'report_type': report_type,
        'coverage': {'active_assets': project.assets.filter(is_active=True).count(), 'scans': project.scans.count()},
        'findings': {k: int(v or 0) for k, v in counts.items()},
        'risk': {'aggregate_risk_score': round(sum(float(v.risk_score or 0) for v in findings.only('risk_score')), 2)},
    }


@sync_to_async
def _list_reports(project_id: str | None, report_type: str | None, status: str | None, user_id: str, limit: int, offset: int):
    qs = Report.objects.filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id)).distinct().order_by('-created_at')
    if project_id: qs = qs.filter(project_id=project_id)
    if report_type: qs = qs.filter(report_type=report_type)
    if status: qs = qs.filter(status=status)
    rows = list(qs[offset:offset+limit])
    return [
        {'id': str(r.id), 'project_id': str(r.project_id), 'scan_id': str(r.scan_id) if r.scan_id else None, 'title': r.title,
         'report_type': r.report_type, 'format': r.format, 'status': r.status, 'file_size': r.file.size if r.file else 0,
         'generated_by': str(r.generated_by_id), 'created_at': r.created_at.isoformat(), 'completed_at': r.completed_at.isoformat() if r.completed_at else None}
        for r in rows
    ]


@sync_to_async
def _get_report(report_id: str, user_id: str):
    r = Report.objects.filter(id=report_id).filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id)).first()
    if not r: raise HTTPException(status_code=404, detail='Report not found')
    return r


@router.get('/')
async def list_reports(project_id: Optional[str] = None, report_type: Optional[str] = None, status: Optional[str] = None,
                       limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(get_current_user)):
    rows = await _list_reports(project_id, report_type, status, str(user.get('user_id')), limit, offset)
    return rows


@router.post('/', status_code=201)
async def create_report(report: ReportCreate, user=Depends(get_current_user)):
    r = await _create_report(report, str(user.get('user_id')))
    return {'id': str(r.id), 'project_id': str(r.project_id), 'scan_id': str(r.scan_id) if r.scan_id else None, 'title': r.title,
            'report_type': r.report_type, 'format': r.format, 'status': r.status, 'file_size': r.file.size if r.file else 0,
            'generated_by': str(r.generated_by_id), 'created_at': r.created_at.isoformat(), 'completed_at': r.completed_at.isoformat() if r.completed_at else None}


@router.get('/{report_id}')
async def get_report(report_id: str, user=Depends(get_current_user)):
    r = await _get_report(report_id, str(user.get('user_id')))
    return {'id': str(r.id), 'project_id': str(r.project_id), 'scan_id': str(r.scan_id) if r.scan_id else None, 'title': r.title,
            'report_type': r.report_type, 'format': r.format, 'status': r.status, 'snapshot': r.snapshot,
            'snapshot_sha256': r.snapshot_sha256, 'file_url': r.file.url if r.file else None}


@router.get('/{report_id}/download')
async def download_report(report_id: str, user=Depends(get_current_user)):
    r = await _get_report(report_id, str(user.get('user_id')))
    if not r.file:
        raise HTTPException(status_code=404, detail='Report file not found')
    content = await sync_to_async(r.file.read)()
    media_type = 'text/html' if r.format == Report.Format.HTML else 'application/json'
    return StreamingResponse(BytesIO(content), media_type=media_type, headers={'Content-Disposition': f'attachment; filename="{r.id}.{r.format}"'})


@sync_to_async
def _delete_report(report_id: str, user_id: str):
    r = Report.objects.filter(id=report_id).filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id)).first()
    if not r: raise HTTPException(status_code=404, detail='Report not found')
    r.file.delete(save=False)
    r.delete()


@router.delete('/{report_id}')
async def delete_report(report_id: str, user=Depends(get_current_user)):
    await _delete_report(report_id, str(user.get('user_id')))
    return {'deleted': True, 'id': report_id}


@sync_to_async
def _create_schedule(body: ReportScheduleCreate, user_id: str):
    if body.format not in {Report.Format.JSON, Report.Format.HTML}:
        raise HTTPException(status_code=501, detail='Requested report format is not implemented')
    if body.frequency == ReportSchedule.Frequency.CRON and not body.cron_expression:
        raise HTTPException(status_code=400, detail='cron_expression is required for cron schedules')
    project = Project.objects.filter(id=body.project_id).filter(Q(owner_id=user_id) | Q(members__id=user_id)).first()
    if not project: raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return ReportSchedule.objects.create(project=project, title=body.title, report_type=body.report_type, format=body.format,
        frequency=body.frequency, cron_expression=body.cron_expression, recipients=body.recipients, next_run=body.next_run, created_by_id=user_id)


@router.post('/schedules', status_code=201)
async def create_schedule(schedule: ReportScheduleCreate, user=Depends(get_current_user)):
    r = await _create_schedule(schedule, str(user.get('user_id')))
    return {'id': str(r.id), 'project_id': str(r.project_id), 'title': r.title, 'report_type': r.report_type, 'format': r.format,
            'frequency': r.frequency, 'recipients': r.recipients, 'is_active': r.is_active, 'next_run': r.next_run.isoformat()}


@sync_to_async
def _list_schedules(project_id: str | None, user_id: str):
    qs = ReportSchedule.objects.filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id)).distinct().order_by('next_run')
    if project_id: qs = qs.filter(project_id=project_id)
    return [{'id': str(r.id), 'project_id': str(r.project_id), 'title': r.title, 'report_type': r.report_type, 'format': r.format,
             'frequency': r.frequency, 'recipients': r.recipients, 'is_active': r.is_active, 'next_run': r.next_run.isoformat()} for r in qs]


@router.get('/schedules')
async def list_schedules(project_id: Optional[str] = None, user=Depends(get_current_user)):
    return await _list_schedules(project_id, str(user.get('user_id')))


@router.get('/templates')
async def list_templates(user=Depends(get_current_user)):
    return [{'id': t.value, 'name': t.label, 'formats': [f.value for f in Report.Format]} for t in Report.ReportType]
