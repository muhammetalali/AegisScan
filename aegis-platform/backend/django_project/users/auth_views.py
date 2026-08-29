from django.conf import settings
from django.middleware.csrf import get_token
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import UserSerializer


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

    @method_decorator(ratelimit(key='ip', rate='10/m', method='POST', block=True))
    def post(self, request):
        serializer = TokenObtainPairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user = serializer.user
        response = Response({
            'user': UserSerializer(user, context={'request': request}).data,
            'authenticated': True,
        })
        _set_auth_cookies(response, data['access'], data['refresh'])
        return response


class RefreshView(APIView):
    permission_classes = [AllowAny]

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


@ensure_csrf_cookie
def csrf_view(request):
    return JsonResponse({'csrfToken': get_token(request)})
