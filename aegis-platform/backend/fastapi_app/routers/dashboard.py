import os
from datetime import datetime, timedelta, timezone
from typing import List

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django

django.setup()

from asgiref.sync import sync_to_async
from django.db.models import Avg, Count, Q
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from assets.models import Asset
from compliance.models import ComplianceAssessment
from projects.models import Project
from scans.models import Scan
from vulnerabilities.models import Vulnerability
from ..core.config import settings
from ..core.security import verify_token

router = APIRouter()
security = HTTPBearer(auto_error=False)


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


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    token = credentials.credentials if credentials else request.cookies.get(settings.AUTH_ACCESS_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    user = await verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid token')
    return user


@sync_to_async
def _user_project_ids(user_id: str):
    return list(
        Project.objects.filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .values_list('id', flat=True)
        .distinct()
    )


@sync_to_async
def _summary(project_ids):
    project_filter = Q(project_id__in=project_ids)
    counts = Vulnerability.objects.filter(project_filter).values('severity').annotate(count=Count('id'))
    by_severity = {row['severity']: row['count'] for row in counts}
    avg_score = Scan.objects.filter(project_id__in=project_ids, status=Scan.Status.COMPLETED).aggregate(value=Avg('security_score'))['value']
    compliance = ComplianceAssessment.objects.filter(project_id__in=project_ids).aggregate(
        compliant=Count('id', filter=Q(status=ComplianceAssessment.Status.COMPLIANT)),
        partial=Count('id', filter=Q(status=ComplianceAssessment.Status.PARTIAL)),
        non_compliant=Count('id', filter=Q(status=ComplianceAssessment.Status.NON_COMPLIANT)),
    )
    assessed = compliance['compliant'] + compliance['partial'] + compliance['non_compliant']
    compliance_score = round(((compliance['compliant'] + (compliance['partial'] * 0.5)) / assessed) * 100) if assessed else 0
    return DashboardSummary(
        total_projects=len(project_ids),
        total_assets=Asset.objects.filter(project_id__in=project_ids, is_active=True).count(),
        total_validations=Scan.objects.filter(project_id__in=project_ids).count(),
        critical=by_severity.get(Vulnerability.Severity.CRITICAL, 0),
        high=by_severity.get(Vulnerability.Severity.HIGH, 0),
        medium=by_severity.get(Vulnerability.Severity.MEDIUM, 0),
        low=by_severity.get(Vulnerability.Severity.LOW, 0),
        security_score=round(avg_score or 0),
        compliance_score=compliance_score,
    )


@router.get('/dashboard/summary', response_model=DashboardSummary)
async def dashboard_summary(user=Depends(get_current_user)):
    return await _summary(await _user_project_ids(str(user['user_id'])))


@sync_to_async
def _risk_distribution(project_ids):
    rows = Vulnerability.objects.filter(project_id__in=project_ids).values('severity').annotate(count=Count('id'))
    counts = {row['severity']: row['count'] for row in rows}
    return RiskDistribution(
        critical=counts.get(Vulnerability.Severity.CRITICAL, 0),
        high=counts.get(Vulnerability.Severity.HIGH, 0),
        medium=counts.get(Vulnerability.Severity.MEDIUM, 0),
        low=counts.get(Vulnerability.Severity.LOW, 0),
        informational=counts.get(Vulnerability.Severity.INFO, 0),
    )


@router.get('/dashboard/risk-distribution', response_model=RiskDistribution)
async def dashboard_risk_distribution(user=Depends(get_current_user)):
    return await _risk_distribution(await _user_project_ids(str(user['user_id'])))


@sync_to_async
def _recent(limit: int, project_ids):
    scans = Scan.objects.filter(project_id__in=project_ids).select_related('project').order_by('-created_at')[:limit]
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
async def dashboard_recent_validations(limit: int = Query(10, ge=1, le=50), user=Depends(get_current_user)):
    return await _recent(limit, await _user_project_ids(str(user['user_id'])))


@sync_to_async
def _trends(days: int, project_ids):
    start = datetime.now(timezone.utc) - timedelta(days=days - 1)
    scans = Scan.objects.filter(project_id__in=project_ids, created_at__gte=start).values('created_at', 'security_score')
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
async def dashboard_trends(days: int = Query(30, ge=7, le=90), user=Depends(get_current_user)):
    return await _trends(days, await _user_project_ids(str(user['user_id'])))
