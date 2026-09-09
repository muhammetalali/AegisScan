from __future__ import annotations

from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from django_project.projects.models import Project, ProjectMembership
from django_project.system.credential_models import CredentialSecret
from django_project.system.credential_serializers import (
    CredentialRotateSerializer,
    CredentialSecretCreateSerializer,
    CredentialSecretSerializer,
    CredentialUseSerializer,
)
from django_project.system.credential_vault import (
    CredentialVaultDenied,
    authorize_credential_use,
    create_credential_secret,
    revoke_credential_secret,
    rotate_credential_secret,
)
from django_project.users.permissions import HasPermission


class CredentialSecretViewSet(viewsets.ModelViewSet):
    """Project-scoped credential references. API responses never return secret material."""

    queryset = CredentialSecret.objects.select_related('project', 'created_by', 'last_used_by')
    permission_classes = [permissions.IsAuthenticated, HasPermission]
    required_permissions = {
        'list': 'project.read',
        'retrieve': 'project.read',
        'create': 'api_key.manage',
        'destroy': 'api_key.manage',
        'rotate': 'api_key.manage',
        'revoke': 'api_key.manage',
        'authorize_use': 'scan.create',
    }

    def get_serializer_class(self):
        if self.action == 'create':
            return CredentialSecretCreateSerializer
        if self.action == 'rotate':
            return CredentialRotateSerializer
        if self.action == 'authorize_use':
            return CredentialUseSerializer
        return CredentialSecretSerializer

    def _visible_projects(self):
        if self.request.user.is_superuser:
            return Project.objects.all()
        return Project.objects.filter(Q(owner=self.request.user) | Q(members=self.request.user)).distinct()

    def _manageable_projects(self):
        if self.request.user.is_superuser:
            return Project.objects.all()
        return Project.objects.filter(
            Q(owner=self.request.user)
            | Q(memberships__user=self.request.user, memberships__role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN])
        ).distinct()

    def get_queryset(self):
        queryset = super().get_queryset().filter(project__in=self._visible_projects())
        project_id = self.request.query_params.get('project')
        if project_id:
            queryset = queryset.filter(project_id=project_id)
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        kind = self.request.query_params.get('kind')
        if kind:
            queryset = queryset.filter(kind=kind)
        return queryset.order_by('-created_at', '-id')

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = get_object_or_404(self._manageable_projects(), pk=serializer.validated_data['project'])
        credential = create_credential_secret(
            project=project,
            actor=request.user,
            name=serializer.validated_data['name'],
            kind=serializer.validated_data['kind'],
            secret=serializer.validated_data['secret'],
            scope=serializer.validated_data.get('scope', {}),
            request=request,
        )
        return Response(CredentialSecretSerializer(credential, context={'request': request}).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=['post'], url_path='rotate')
    def rotate(self, request, *args, **kwargs):
        credential = self.get_object()
        get_object_or_404(self._manageable_projects(), pk=credential.project_id)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        credential = rotate_credential_secret(
            credential=credential,
            actor=request.user,
            secret=serializer.validated_data['secret'],
            request=request,
        )
        return Response(CredentialSecretSerializer(credential, context={'request': request}).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='revoke')
    def revoke(self, request, *args, **kwargs):
        credential = self.get_object()
        get_object_or_404(self._manageable_projects(), pk=credential.project_id)
        credential = revoke_credential_secret(
            credential=credential,
            actor=request.user,
            request=request,
            reason=str(request.data.get('reason', ''))[:500] if isinstance(request.data, dict) else '',
        )
        return Response(CredentialSecretSerializer(credential, context={'request': request}).data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='authorize-use')
    def authorize_use(self, request, *args, **kwargs):
        credential = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            credential = authorize_credential_use(
                credential=credential,
                actor=request.user,
                purpose=serializer.validated_data['purpose'],
                request=request,
            )
        except CredentialVaultDenied as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(
            {
                'credential_ref': str(credential.id),
                'project_id': str(credential.project_id),
                'kind': credential.kind,
                'status': credential.status,
                'version': credential.version,
                'secret_available': True,
            },
            status=status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        credential = self.get_object()
        get_object_or_404(self._manageable_projects(), pk=credential.project_id)
        revoke_credential_secret(credential=credential, actor=request.user, request=request, reason='destroy-mapped-to-revoke')
        return Response(status=status.HTTP_204_NO_CONTENT)
