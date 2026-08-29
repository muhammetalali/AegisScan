from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Q
import logging

from .models import User, Team, TeamMembership, APIKey, UserSession, LoginAttempt
from .serializers import (
    UserSerializer, UserListSerializer, UserCreateSerializer, UserUpdateSerializer,
    ChangePasswordSerializer, TeamSerializer, TeamCreateSerializer, TeamMembershipSerializer,
    APIKeySerializer, APIKeyCreateSerializer, UserSessionSerializer, LoginAttemptSerializer
)
from .permissions import IsOwnerOrReadOnly, HasPermission, IsTeamAdmin

User = get_user_model()
logger = logging.getLogger(__name__)


class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200:
            user = User.objects.get(email=request.data.get('email'))
            user.last_login_ip = self.get_client_ip(request)
            user.last_activity = timezone.now()
            user.save(update_fields=['last_login_ip', 'last_activity'])

            LoginAttempt.objects.create(
                email=request.data.get('email'),
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True,
            )
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated, HasPermission]
    required_permissions = {
        'list': 'user.read',
        'retrieve': 'user.read',
        'create': 'user.create',
        'update': 'user.update',
        'partial_update': 'user.update',
        'destroy': 'user.delete',
    }

    def get_serializer_class(self):
        if self.action == 'list':
            return UserListSerializer
        elif self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.has_permission('user.read'):
            return User.objects.all()
        return User.objects.filter(id=user.id)

    @action(detail=False, methods=['get'])
    def me(self, request):
        serializer = UserSerializer(request.user, context={'request': request})
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'message': 'Password changed successfully'})

    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
        except Exception:
            pass
        return Response({'message': 'Logged out successfully'})

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, HasPermission], required_permissions=['user.update'])
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save(update_fields=['is_active'])
        return Response({'message': 'User activated'})

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, HasPermission], required_permissions=['user.update'])
    def deactivate(self, request, pk=None):
        user = self.get_object()
        if user == request.user:
            return Response({'error': 'Cannot deactivate yourself'}, status=status.HTTP_400_BAD_REQUEST)
        user.is_active = False
        user.save(update_fields=['is_active'])
        return Response({'message': 'User deactivated'})


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    permission_classes = [permissions.IsAuthenticated, HasPermission]
    required_permissions = {
        'list': 'user.read',
        'retrieve': 'user.read',
        'create': 'user.create',
        'update': 'user.update',
        'partial_update': 'user.update',
        'destroy': 'user.delete',
    }

    def get_serializer_class(self):
        if self.action == 'create':
            return TeamCreateSerializer
        return TeamSerializer

    def get_queryset(self):
        return Team.objects.filter(members=self.request.user).distinct()

    def perform_create(self, serializer):
        team = serializer.save(owner=self.request.user)
        TeamMembership.objects.create(team=team, user=self.request.user, role=TeamMembership.Role.OWNER)

    @action(
        detail=True,
        methods=['post'],
        permission_classes=[permissions.IsAuthenticated, HasPermission, IsTeamAdmin],
        required_permissions=['user.update'],
    )
    def add_member(self, request, pk=None):
        team = self.get_object()
        user_id = request.data.get('user_id')
        role = request.data.get('role', TeamMembership.Role.MEMBER)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        membership, created = TeamMembership.objects.get_or_create(
            team=team, user=user,
            defaults={'role': role}
        )
        if not created:
            membership.role = role
            membership.save()

        return Response(TeamMembershipSerializer(membership).data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    @action(
        detail=True,
        methods=['delete'],
        permission_classes=[permissions.IsAuthenticated, HasPermission, IsTeamAdmin],
        required_permissions=['user.update'],
    )
    def remove_member(self, request, pk=None):
        team = self.get_object()
        user_id = request.data.get('user_id')

        try:
            membership = TeamMembership.objects.get(team=team, user_id=user_id)
            if membership.role == TeamMembership.Role.OWNER:
                return Response({'error': 'Cannot remove owner'}, status=status.HTTP_400_BAD_REQUEST)
            membership.delete()
            return Response({'message': 'Member removed'})
        except TeamMembership.DoesNotExist:
            return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(
        detail=True,
        methods=['patch'],
        permission_classes=[permissions.IsAuthenticated, HasPermission, IsTeamAdmin],
        required_permissions=['user.update'],
    )
    def update_member_role(self, request, pk=None):
        team = self.get_object()
        user_id = request.data.get('user_id')
        role = request.data.get('role')

        if role not in TeamMembership.Role.values:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            membership = TeamMembership.objects.get(team=team, user_id=user_id)
            if membership.role == TeamMembership.Role.OWNER:
                return Response({'error': 'Cannot change owner role'}, status=status.HTTP_400_BAD_REQUEST)
            membership.role = role
            membership.save()
            return Response(TeamMembershipSerializer(membership).data)
        except TeamMembership.DoesNotExist:
            return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)


class APIKeyViewSet(viewsets.ModelViewSet):
    queryset = APIKey.objects.all()
    permission_classes = [permissions.IsAuthenticated, HasPermission]
    required_permissions = {
        'list': 'api_key.manage',
        'retrieve': 'api_key.manage',
        'create': 'api_key.manage',
        'destroy': 'api_key.manage',
    }

    def get_serializer_class(self):
        if self.action == 'create':
            return APIKeyCreateSerializer
        return APIKeySerializer

    def get_queryset(self):
        return APIKey.objects.filter(user=self.request.user)

    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()


class UserSessionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserSession.objects.filter(user=self.request.user)

    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        session = self.get_object()
        session.delete()
        return Response({'message': 'Session revoked'})

    @action(detail=False, methods=['post'])
    def revoke_all_others(self, request):
        current_session_key = request.session.session_key
        UserSession.objects.filter(user=request.user).exclude(session_key=current_session_key).delete()
        return Response({'message': 'All other sessions revoked'})
