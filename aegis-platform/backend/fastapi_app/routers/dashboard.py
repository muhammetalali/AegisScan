import os
from datetime import datetime, timedelta, timezone
from typing import List

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from asgiref.sync import sync_to_async
from django.db.models import Avg, Count, Q
from fastapi import APIRouter, Query
from pydantic import BaseModel

from assets.models import Asset
from projects.models import Project
from scans.models import Scan
from vulnerabilities.models import Vulnerability

router = APIRouter()


class DashboardSummary(BaseModel):
    total_projects: int
    total_assets: int
    total_validations: int
    critical: int
    high: int
    medium: int
    low: int
    security_score: int
    compliance_score: int


class RiskDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class RecentValidation(BaseModel):
    id: str
    project_name: str
    status: str
    risk_level: str
    progress: int
    created_at: str
    security_score: int


class TrendPoint(BaseModel):
    date: str
    score: int
    validations: int


@sync_to_async
def _summary():
    counts = Vulnerability.objects.values('severity').annotate(count=Count('id'))
    by_severity = {row['severity']: row['count'] for row in counts}
    avg_score = Scan.objects.filter(status=Scan.Status.COMPLETED).aggregate(value=Avg('security_score'))['value']
    return DashboardSummary(
        total_projects=Project.objects.count(),
        total_assets=Asset.objects.filter(is_active=True).count(),
        total_validations=Scan.objects.count(),
        critical=by_severity.get(Vulnerability.Severity.CRITICAL, 0),
        high=by_severity.get(Vulnerability.Severity.HIGH, 0),
        medium=by_severity.get(Vulnerability.Severity.MEDIUM, 0),
        low=by_severity.get(Vulnerability.Severity.LOW, 0),
        security_score=round(avg_score or 0),
        compliance_score=0,
    )


@router.get('/dashboard/summary', response_model=DashboardSummary)
async def dashboard_summary():
    return await _summary()


@sync_to_async
def _risk_distribution():
    rows = Vulnerability.objects.values('severity').annotate(count=Count('id'))
    counts = {row['severity']: row['count'] for row in rows}
    return RiskDistribution(
        critical=counts.get(Vulnerability.Severity.CRITICAL, 0),
        high=counts.get(Vulnerability.Severity.HIGH, 0),
        medium=counts.get(Vulnerability.Severity.MEDIUM, 0),
        low=counts.get(Vulnerability.Severity.LOW, 0),
        informational=counts.get(Vulnerability.Severity.INFO, 0),
    )


@router.get('/dashboard/risk-distribution', response_model=RiskDistribution)
async def dashboard_risk_distribution():
    return await _risk_distribution()


@sync_to_async
def _recent(limit: int):
    scans = Scan.objects.select_related('project').order_by('-created_at')[:limit]
    return [RecentValidation(
        id=str(scan.id),
        project_name=scan.project.name,
        status=scan.status,
        risk_level=scan.risk_level or 'unknown',
        progress=round(scan.progress),
        created_at=scan.created_at.astimezone(timezone.utc).isoformat(),
        security_score=round(scan.security_score),
    ) for scan in scans]


@router.get('/dashboard/recent-validations', response_model=List[RecentValidation])
async def dashboard_recent_validations(limit: int = Query(10, le=50)):
    return await _recent(limit)


@sync_to_async
def _trends(days: int):
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)
    scans = Scan.objects.filter(created_at__gte=start).values('created_at', 'security_score')
    buckets = {}
    for row in scans:
        day = row['created_at'].astimezone(timezone.utc).date().isoformat()
        bucket = buckets.setdefault(day, {'scores': [], 'count': 0})
        bucket['scores'].append(row['security_score'])
        bucket['count'] += 1
    result = []
    for i in range(days):
        day = (start + timedelta(days=i)).date().isoformat()
        bucket = buckets.get(day, {'scores': [], 'count': 0})
        result.append(TrendPoint(
            date=day,
            score=round(sum(bucket['scores']) / len(bucket['scores'])) if bucket['scores'] else 0,
            validations=bucket['count'],
        ))
    return result


@router.get('/dashboard/trends', response_model=List[TrendPoint])
async def dashboard_trends(days: int = Query(30, ge=7, le=90)):
    return await _trends(days)
