from datetime import timedelta

from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset
from projects.models import Project
from scans.models import Scan
from vulnerabilities.models import Vulnerability


OPEN_STATUSES = [
    Vulnerability.Status.OPEN,
    Vulnerability.Status.CONFIRMED,
    Vulnerability.Status.IN_PROGRESS,
]


def visible_projects(user):
    return Project.objects.filter(Q(owner=user) | Q(members=user)).distinct()


def build_dashboard_snapshot(user, days=30, limit=5):
    """Build one tenant-scoped dashboard payload for HTTP and WebSocket consumers."""
    projects = visible_projects(user)
    scans = Scan.objects.filter(project__in=projects)
    completed = scans.filter(status=Scan.Status.COMPLETED)
    scores = [
        float(value)
        for value in completed.order_by("-created_at").values_list("security_score", flat=True)[:10]
        if value is not None
    ]
    vulnerabilities = Vulnerability.objects.filter(project__in=projects, status__in=OPEN_STATUSES)
    risk = vulnerabilities.aggregate(
        critical=Count("id", filter=Q(severity=Vulnerability.Severity.CRITICAL)),
        high=Count("id", filter=Q(severity=Vulnerability.Severity.HIGH)),
        medium=Count("id", filter=Q(severity=Vulnerability.Severity.MEDIUM)),
        low=Count("id", filter=Q(severity=Vulnerability.Severity.LOW)),
        informational=Count("id", filter=Q(severity=Vulnerability.Severity.INFO)),
    )
    days = min(max(int(days), 7), 90)
    start = timezone.now() - timedelta(days=days - 1)
    trends = (
        completed.filter(created_at__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(score=Avg("security_score"))
        .order_by("day")
    )
    recent = scans.select_related("project", "asset").order_by("-created_at")[:limit]
    return {
        "summary": {
            "security_score": round(sum(scores) / len(scores), 1) if scores else None,
            "total_projects": projects.count(),
            "total_assets": Asset.objects.filter(project__in=projects).count(),
            "total_validations": scans.count(),
            "critical": risk["critical"] or 0,
            "high": risk["high"] or 0,
        },
        "risk_distribution": {key: value or 0 for key, value in risk.items()},
        "trends": [
            {"date": row["day"].isoformat(), "score": round(float(row["score"]), 1)}
            for row in trends
            if row["day"] is not None and row["score"] is not None
        ],
        "recent_validations": [
            {
                "id": str(scan.id),
                "validation_id": str(scan.id),
                "target_value": scan.asset.name if scan.asset else scan.project.name,
                "target": scan.name,
                "project_name": scan.project.name,
                "status": scan.status,
                "security_score": scan.security_score,
                "findings_count": scan.findings_count,
                "created_at": scan.created_at.isoformat(),
            }
            for scan in recent
        ],
    }


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(build_dashboard_snapshot(request.user)["summary"])


class DashboardRiskDistributionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(build_dashboard_snapshot(request.user)["risk_distribution"])


class DashboardTrendsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            days = min(max(int(request.query_params.get("days", 30)), 7), 90)
        except (TypeError, ValueError):
            days = 30
        return Response(build_dashboard_snapshot(request.user, days=days)["trends"])


class DashboardRecentValidationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            limit = min(max(int(request.query_params.get("limit", 5)), 1), 20)
        except (TypeError, ValueError):
            limit = 5
        return Response(build_dashboard_snapshot(request.user, limit=limit)["recent_validations"])
