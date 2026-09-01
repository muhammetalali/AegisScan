from django.db.models import Q
from django.utils.text import slugify
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from django_project.assets.models import Asset
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from .models import Project
from .serializers import ProjectSerializer, ProjectCreateUpdateSerializer
from django_project.users.permissions import HasPermission


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    permission_classes = [permissions.IsAuthenticated, HasPermission]
    required_permissions = {
        'list': 'project.read',
        'retrieve': 'project.read',
        'create': 'project.create',
        'update': 'project.update',
        'partial_update': 'project.update',
        'destroy': 'project.delete',
    }

    def get_serializer_class(self):
        return ProjectCreateUpdateSerializer if self.action in {'create', 'update', 'partial_update'} else ProjectSerializer

    def get_queryset(self):
        return Project.objects.filter(
            Q(owner=self.request.user) | Q(members=self.request.user)
        ).distinct().select_related('owner').prefetch_related('assets', 'scans', 'vulnerabilities')

    def _unique_slug(self, name: str) -> str:
        base = slugify(name) or 'project'
        slug = base[:220]
        suffix = 2
        while Project.objects.filter(slug=slug).exists():
            tail = f'-{suffix}'
            slug = f'{base[:220-len(tail)]}{tail}'
            suffix += 1
        return slug

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user, slug=self._unique_slug(serializer.validated_data['name']))

    def perform_update(self, serializer):
        instance = self.get_object()
        serializer.save()

    def retrieve(self, request, *args, **kwargs):
        project = self.get_object()
        project_data = ProjectSerializer(project, context={'request': request}).data

        assets = [
            {
                'id': str(asset.id),
                'name': asset.name,
                'type': asset.type,
                'environment': asset.environment,
                'criticality': asset.criticality,
                'is_active': asset.is_active,
                'scan_count': asset.scan_count,
                'last_scanned_at': asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
            }
            for asset in project.assets.all().order_by('-created_at')
        ]
        validations = [
            {
                'id': str(scan.id),
                'name': scan.name,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'progress': round(scan.progress),
                'security_score': round(scan.security_score),
                'risk_level': scan.risk_level or 'unknown',
                'findings_count': scan.findings_count,
                'created_at': scan.created_at.isoformat(),
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            }
            for scan in project.scans.all().order_by('-created_at')[:50]
        ]
        findings = [
            {
                'id': str(finding.id),
                'title': finding.title,
                'severity': finding.severity,
                'status': finding.status,
                'confidence': finding.confidence,
                'cvss': finding.cvss_score,
                'asset': finding.asset.name if finding.asset else None,
                'scan_id': str(finding.scan_id),
                'created_at': finding.created_at.isoformat(),
            }
            for finding in project.vulnerabilities.select_related('asset').all().order_by('-risk_score', '-created_at')[:100]
        ]

        return Response({
            'project': project_data,
            'assets': assets,
            'validations': validations,
            'findings': findings,
        }, status=status.HTTP_200_OK)
