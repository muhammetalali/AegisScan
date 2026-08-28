from datetime import timedelta

from django.db.models import Count, Q
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


class DashboardSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        projects = visible_projects(request.user)
        scans = Scan.objects.filter(project__in=projects)
        completed = scans.filter(status=Scan.Status.COMPLETED)
        scores = [float(v) for v in completed.order_by('-created_at').values_list('security_score', flat=True)[:10] if v is not None]
        vulnerabilities = Vulnerability.objects.filter(project__in=projects, status__in=OPEN_STATUSES)
        risk = vulnerabilities.aggregate(
            critical=Count('id', filter=Q(severity=Vulnerability.Severity.CRITICAL)),
            high=Count('id', filter=Q(severity=Vulnerability.Severity.HIGH)),
        )
        return Response({
            'security_score': round(sum(scores) / len(scores), 1) if scores else None,
            'total_projects': projects.count(),
            'total_assets': Asset.objects.filter(project__in=projects).count(),
            'total_validations': scans.count(),
            'critical': risk['critical'] or 0,
            'high': risk['high'] or 0,
        })


class DashboardRiskDistributionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        projects = visible_projects(request.user)
        queryset = Vulnerability.objects.filter(project__in=projects, status__in=OPEN_STATUSES)
        result = queryset.aggregate(
            critical=Count('id', filter=Q(severity=Vulnerability.Severity.CRITICAL)),
            high=Count('id', filter=Q(severity=Vulnerability.Severity.HIGH)),
            medium=Count('id', filter=Q(severity=Vulnerability.Severity.MEDIUM)),
            low=Count('id', filter=Q(severity=Vulnerability.Severity.LOW)),
            informational=Count('id', filter=Q(severity=Vulnerability.Severity.INFO)),
        )
        return Response({key: value or 0 for key, value in result.items()})


class DashboardTrendsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            days = min(max(int(request.query_params.get('days', 30)), 7), 90)
        except (TypeError, ValueError):
            days = 30
        projects = visible_projects(request.user)
        start = timezone.now() - timedelta(days=days - 1)
        scans = Scan.objects.filter(project__in=projects, status=Scan.Status.COMPLETED, created_at__gte=start)
        points = []
        for offset in range(days):
            day = (start + timedelta(days=offset)).date()
            scores = [float(v) for v in scans.filter(created_at__date=day).values_list('security_score', flat=True) if v is not None]
            if scores:
                points.append({'date': day.isoformat(), 'score': round(sum(scores) / len(scores), 1)})
        return Response(points)


class DashboardRecentValidationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            limit = min(max(int(request.query_params.get('limit', 5)), 1), 20)
        except (TypeError, ValueError):
            limit = 5
        projects = visible_projects(request.user)
        scans = Scan.objects.filter(project__in=projects).select_related('project', 'asset').order_by('-created_at')[:limit]
        return Response([
            {
                'id': str(scan.id),
                'validation_id': str(scan.id),
                'target_value': scan.asset.name if scan.asset else scan.project.name,
                'target': scan.name,
                'project_name': scan.project.name,
                'status': scan.status,
                'security_score': scan.security_score,
                'findings_count': scan.findings_count,
                'created_at': scan.created_at.isoformat(),
            }
            for scan in scans
        ])
