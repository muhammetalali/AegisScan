from __future__ import annotations

from datetime import timedelta
from typing import List

from asgiref.sync import sync_to_async
from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from ..core.security import verify_token

router = APIRouter()
OPEN_STATUSES = ("open", "confirmed", "in_progress")


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


def _access_cookie_name() -> str:
    from django.conf import settings
    return settings.AUTH_ACCESS_COOKIE


async def current_user_id(request: Request) -> str:
    token = request.cookies.get(_access_cookie_name())
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = await verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return str(payload["user_id"])


@sync_to_async
def _dashboard_snapshot(user_id: str, days: int = 30, limit: int = 5) -> dict:
    from projects.models import Project
    from scans.models import Scan
    from assets.models import Asset
    from vulnerabilities.models import Vulnerability
    from compliance.models import ComplianceAssessment

    projects = Project.objects.filter(Q(owner_id=user_id) | Q(memberships__user_id=user_id)).distinct()
    scans = Scan.objects.filter(project__in=projects)
    completed = scans.filter(status=Scan.Status.COMPLETED)
    scores = list(completed.order_by("-created_at").values_list("security_score", flat=True)[:10])

    vulnerabilities = Vulnerability.objects.filter(project__in=projects, status__in=OPEN_STATUSES)
    risk = vulnerabilities.aggregate(
        critical=Count("id", filter=Q(severity=Vulnerability.Severity.CRITICAL)),
        high=Count("id", filter=Q(severity=Vulnerability.Severity.HIGH)),
        medium=Count("id", filter=Q(severity=Vulnerability.Severity.MEDIUM)),
        low=Count("id", filter=Q(severity=Vulnerability.Severity.LOW)),
        informational=Count("id", filter=Q(severity=Vulnerability.Severity.INFO)),
    )

    compliance = ComplianceAssessment.objects.filter(project__in=projects).aggregate(
        compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.COMPLIANT)),
        non_compliant=Count("id", filter=Q(status=ComplianceAssessment.Status.NON_COMPLIANT)),
        partial=Count("id", filter=Q(status=ComplianceAssessment.Status.PARTIAL)),
    )
    assessed_controls = compliance["compliant"] + compliance["non_compliant"] + compliance["partial"]
    compliance_score = round((compliance["compliant"] / assessed_controls) * 100) if assessed_controls else None

    days = min(max(int(days), 7), 90)
    start = timezone.now() - timedelta(days=days - 1)
    trends = (
        completed.filter(created_at__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(score=Avg("security_score"), validations=Count("id"))
        .order_by("day")
    )

    recent = scans.select_related("project", "asset").order_by("-created_at")[:limit]
    latest_score = round(sum(float(v) for v in scores) / len(scores)) if scores else None

    return {
        "summary": {
            "security_score": latest_score,
            "total_projects": projects.count(),
            "total_assets": Asset.objects.filter(project__in=projects).count(),
            "total_validations": scans.count(),
            "critical": risk["critical"] or 0,
            "high": risk["high"] or 0,
            "medium": risk["medium"] or 0,
            "low": risk["low"] or 0,
            "compliance_score": compliance_score,
        },
        "risk_distribution": {key: value or 0 for key, value in risk.items()},
        "trends": [
            {"date": row["day"].isoformat(), "score": round(float(row["score"])), "validations": row["validations"]}
            for row in trends
            if row["day"] is not None and row["score"] is not None
        ],
        "recent_validations": [
            {
                "id": str(scan.id),
                "project_name": scan.project.name,
                "status": scan.status,
                "risk_level": scan.risk_level or "unrated",
                "progress": int(scan.progress),
                "created_at": scan.created_at.isoformat(),
                "security_score": round(float(scan.security_score or 0)),
            }
            for scan in recent
        ],
    }


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def dashboard_summary(user_id: str = Depends(current_user_id)):
    summary = (await _dashboard_snapshot(user_id))["summary"]
    return DashboardSummary(**summary)


@router.get("/dashboard/risk-distribution", response_model=RiskDistribution)
async def dashboard_risk_distribution(user_id: str = Depends(current_user_id)):
    return RiskDistribution(**(await _dashboard_snapshot(user_id))["risk_distribution"])


@router.get("/dashboard/recent-validations", response_model=List[RecentValidation])
async def dashboard_recent_validations(limit: int = Query(5, ge=1, le=20), user_id: str = Depends(current_user_id)):
    return [RecentValidation(**item) for item in (await _dashboard_snapshot(user_id, limit=limit))["recent_validations"]]


@router.get("/dashboard/trends", response_model=List[TrendPoint])
async def dashboard_trends(days: int = Query(30, ge=7, le=90), user_id: str = Depends(current_user_id)):
    return [TrendPoint(**item) for item in (await _dashboard_snapshot(user_id, days=days))["trends"]]
