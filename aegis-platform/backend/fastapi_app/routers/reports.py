"""Report projection API.

The durable report domain belongs to Django. This router is a small operational
projection used by the FastAPI UI; it never fabricates a successful lookup for
an unknown report and can be replaced by a repository-backed adapter.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()
_reports: dict[str, 'ReportResponse'] = {}
_schedules: list[dict[str, Any]] = []


class ReportCreate(BaseModel):
    project_id: str = Field(min_length=1)
    scan_id: str | None = None
    title: str = Field(min_length=1, max_length=300)
    description: str = ''
    report_type: str = 'full'
    format: str = 'pdf'
    template_id: str | None = None


class ReportResponse(BaseModel):
    id: str
    project_id: str
    scan_id: str | None = None
    title: str
    report_type: str
    format: str
    status: str
    file_size: int = 0
    generated_by: str
    created_at: str
    completed_at: str | None = None


class ReportScheduleCreate(BaseModel):
    project_id: str = Field(min_length=1)
    template_id: str = Field(min_length=1)
    frequency: str
    recipients: list[str]
    formats: list[str]


@router.get('/', response_model=list[ReportResponse])
async def list_reports(
    project_id: str | None = None,
    report_type: str | None = None,
    status: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    items = list(_reports.values())
    if project_id:
        items = [item for item in items if item.project_id == project_id]
    if report_type:
        items = [item for item in items if item.report_type == report_type]
    if status:
        items = [item for item in items if item.status == status]
    return items[offset:offset + limit]


@router.post('/', response_model=ReportResponse, status_code=201)
async def create_report(report: ReportCreate):
    item = ReportResponse(
        id=f'report_{uuid4().hex[:12]}',
        project_id=report.project_id,
        scan_id=report.scan_id,
        title=report.title,
        report_type=report.report_type,
        format=report.format,
        status='generating',
        generated_by='current-user',
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _reports[item.id] = item
    return item


@router.post('/compare')
async def compare_reports(report_id_a: str, report_id_b: str):
    if report_id_a not in _reports or report_id_b not in _reports:
        raise HTTPException(status_code=404, detail='One or both reports not found')
    return {'comparison_id': f'comparison_{uuid4().hex[:12]}', 'report_id_a': report_id_a, 'report_id_b': report_id_b}


@router.post('/schedules', response_model=dict)
async def create_schedule(schedule: ReportScheduleCreate):
    item = {'id': f'schedule_{uuid4().hex[:12]}', **schedule.model_dump(), 'is_active': True}
    _schedules.append(item)
    return item


@router.get('/schedules/', response_model=list[dict])
async def list_schedules(project_id: str | None = None):
    if project_id:
        return [item for item in _schedules if item['project_id'] == project_id]
    return list(_schedules)


@router.get('/templates/', response_model=list[dict])
async def list_templates(report_type: str | None = None):
    # Templates are owned by Django; an empty projection is honest until synced.
    return []


@router.get('/{report_id}', response_model=ReportResponse)
async def get_report(report_id: str):
    item = _reports.get(report_id)
    if not item:
        raise HTTPException(status_code=404, detail='Report not found')
    return item


@router.get('/{report_id}/download')
async def download_report(report_id: str):
    item = _reports.get(report_id)
    if not item:
        raise HTTPException(status_code=404, detail='Report not found')
    raise HTTPException(status_code=409, detail=f'Report is not ready (status: {item.status})')


@router.delete('/{report_id}')
async def delete_report(report_id: str):
    if _reports.pop(report_id, None) is None:
        raise HTTPException(status_code=404, detail='Report not found')
    return {'message': 'Report deleted', 'id': report_id}


@router.post('/{report_id}/share')
async def share_report(report_id: str, email: str, permission: str = 'view', expires_in_days: int = 7):
    if report_id not in _reports:
        raise HTTPException(status_code=404, detail='Report not found')
    if permission not in {'view', 'download', 'comment'}:
        raise HTTPException(status_code=422, detail='Invalid sharing permission')
    return {'message': 'Report share recorded', 'report_id': report_id, 'email': email, 'permission': permission, 'expires_in_days': expires_in_days}
