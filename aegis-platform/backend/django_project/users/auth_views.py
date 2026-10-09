from django.conf import settings
from django.contrib.auth import authenticate
from django.middleware.csrf import get_token
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.db import transaction
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.exceptions import APIException, Throttled
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit, client_ip_from_request
from .auth_audit import record_login_event
from .serializers import UserSerializer
from .models import User


def _set_auth_cookies(response, access: str, refresh: str | None = None) -> None:
    response.set_cookie(
        settings.AUTH_ACCESS_COOKIE,
        access,
        httponly=settings.AUTH_COOKIE_HTTPONLY,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        path='/',
    )
    if refresh is not None:
        response.set_cookie(
            settings.AUTH_REFRESH_COOKIE,
            refresh,
            httponly=settings.AUTH_COOKIE_HTTPONLY,
            secure=settings.AUTH_COOKIE_SECURE,
            samesite=settings.AUTH_COOKIE_SAMESITE,
            max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()),
            path='/',
        )


class LoginView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='ip', rate='10/m', method='POST', block=False))
    def post(self, request):
        email = str(request.data.get('email') or '')
        if getattr(request, 'limited', False):
            record_login_event(request, email=email, success=False, failure_reason='rate_limited')
            raise Throttled(detail='Too many login attempts.')
        # A password alone MUST NOT issue JWTs when the persistent MFA flag is
        # enabled. Enrollment/challenge verification is not implemented yet:
        # fail closed before TokenObtainPairSerializer mints an outstanding token.
        if (
            email
            and User.objects.filter(email__iexact=email, is_active=True, two_factor_enabled=True).exists()
        ):
            candidate = authenticate(
                request=request,
                email=email,
                password=str(request.data.get('password') or ''),
            )
            if candidate is not None and candidate.two_factor_enabled:
                record_login_event(
                    request, email=email, success=False,
                    failure_reason='second_factor_unavailable',
                )
                return Response(
                    {'detail': 'Second-factor verification is required but is not configured. Contact an administrator.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
        serializer = TokenObtainPairSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except APIException as exc:
            record_login_event(
                request,
                email=email,
                success=False,
                failure_reason=str(getattr(exc, 'default_code', 'authentication_failed')),
            )
            raise
        data = serializer.validated_data
        user = serializer.user
        user.last_login_ip = client_ip_from_request(request)
        user.last_activity = timezone.now()
        user.save(update_fields=['last_login_ip', 'last_activity'])
        record_login_event(request, email=email, success=True, user=user)
        response = Response({
            'user': UserSerializer(user, context={'request': request}).data,
            'authenticated': True,
        })
        _set_auth_cookies(response, data['access'], data['refresh'])
        return response


class RegisterView(APIView):
    """Company-only: public registration is permanently unavailable."""

    permission_classes = [AllowAny]

    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='ip', rate='5/h', method='POST', block=True))
    def post(self, request):
        # Company-only service: public callers may not create active accounts.
        # CI/production E2E identities use the existing protected server-side
        # one-run fixture provisioner, never this public endpoint.
        return Response(
            {'detail': 'Accounts are created and activated by the primary company owner.'},
            status=status.HTTP_403_FORBIDDEN,
        )


class RefreshView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='ip', rate='20/m', method='POST', block=True))
    def post(self, request):
        refresh = request.COOKIES.get(settings.AUTH_REFRESH_COOKIE)
        if not refresh:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = TokenRefreshSerializer(data={'refresh': refresh})
        serializer.is_valid(raise_exception=True)
        access = serializer.validated_data['access']
        rotated_refresh = serializer.validated_data.get('refresh')
        response = Response({'authenticated': True})
        _set_auth_cookies(response, access, rotated_refresh)
        return response


class LogoutView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_protect)
    def post(self, request):
        refresh = request.COOKIES.get(settings.AUTH_REFRESH_COOKIE)
        if refresh:
            try:
                RefreshToken(refresh).blacklist()
            except Exception:
                # Logout remains idempotent even when the token is already expired/blacklisted.
                pass
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie(settings.AUTH_ACCESS_COOKIE, path='/')
        response.delete_cookie(settings.AUTH_REFRESH_COOKIE, path='/')
        return response


class DeactivateSelfView(APIView):
    """Deactivate the authenticated account while preserving audit and ownership lineage."""

    permission_classes = [IsAuthenticated]

    @method_decorator(csrf_protect)
    def post(self, request):
        if request.user.is_company_owner:
            return Response({'detail': 'The primary company owner account cannot self-deactivate.'}, status=status.HTTP_403_FORBIDDEN)
        password = str(request.data.get('password') or '')
        if not password or not request.user.check_password(password):
            return Response({'detail': 'Current password is invalid.'}, status=status.HTTP_400_BAD_REQUEST)

        refresh = request.COOKIES.get(settings.AUTH_REFRESH_COOKIE)
        if refresh:
            try:
                RefreshToken(refresh).blacklist()
            except Exception:
                pass
        with transaction.atomic():
            request.user.is_active = False
            request.user.save(update_fields=['is_active'])
            append_audit(
                user=request.user,
                action=AuditLog.Action.USER_UPDATE,
                result=AuditLog.Result.SUCCESS,
                resource_type='User',
                resource_id=str(request.user.id),
                resource_repr=request.user.email,
                changes={'is_active': {'from': True, 'to': False}},
                metadata={'event': 'self_deactivation'},
                ip_address=client_ip_from_request(request),
                user_agent=str(request.META.get('HTTP_USER_AGENT', ''))[:2000],
            )
        response = Response({'deactivated': True})
        response.delete_cookie(settings.AUTH_ACCESS_COOKIE, path='/')
        response.delete_cookie(settings.AUTH_REFRESH_COOKIE, path='/')
        return response


@ensure_csrf_cookie
def csrf_view(request):
    return JsonResponse({'csrfToken': get_token(request)})
