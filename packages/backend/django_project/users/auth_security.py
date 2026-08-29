from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import uuid
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import AccessToken

from .audit import record_user_audit
from .models import ROLE_PERMISSIONS, User
from .serializers import UserSerializer


def _totp(secret: str, timestamp: int | None = None, period: int = 30, digits: int = 6) -> str:
    counter = int((timestamp if timestamp is not None else time.time()) // period)
    key = base64.b32decode(secret + ('=' * ((8 - len(secret) % 8) % 8)), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return f'{code:0{digits}d}'


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    normalized = ''.join(ch for ch in str(code) if ch.isdigit())
    if not secret or len(normalized) != 6:
        return False
    now = int(time.time())
    return any(hmac.compare_digest(_totp(secret, now + offset * 30), normalized) for offset in range(-window, window + 1))


def _send_message(subject: str, body: str, recipient: str) -> None:
    send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [recipient], fail_silently=True)


def _apply_identity_claims(token, user: User) -> None:
    token['email'] = user.email
    token['role'] = user.role
    token['is_staff'] = user.is_staff
    token['is_superuser'] = user.is_superuser
    token['session_version'] = user.session_version
    token['permissions'] = [p.value if hasattr(p, 'value') else p for p in ROLE_PERMISSIONS.get(user.role, [])]


class AegisTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Issue short-lived access tokens with a revocable session-version claim."""

    @classmethod
    def get_token(cls, user: User):
        token = super().get_token(user)
        _apply_identity_claims(token, user)
        return token


class AegisTokenRefreshSerializer(TokenRefreshSerializer):
    """Reject stale sessions and mint refreshed access tokens from current identity state."""

    def validate(self, attrs):
        data = super().validate(attrs)
        user = User.objects.filter(pk=self.user_id).first()
        if not user or not user.is_active:
            raise AuthenticationFailed('User account is inactive or unavailable')
        if int(self.token.get('session_version', 1)) != user.session_version:
            raise AuthenticationFailed('Refresh token has been revoked')

        access = AccessToken(data['access'])
        _apply_identity_claims(access, user)
        data['access'] = str(access)
        return data


class SecureTokenObtainPairView(TokenObtainPairView):
    serializer_class = AegisTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        started = time.monotonic()
        email = str(request.data.get('email', '')).strip().lower()
        password = request.data.get('password', '')
        user = User.objects.filter(email__iexact=email).first()

        if user and not user.check_password(password):
            response = super().post(request, *args, **kwargs)
            record_user_audit(request=request, action='auth.login', result='failure', user=user, resource_id=user.pk, metadata={'reason': 'invalid_credentials'}, start=started)
            return response

        if user and user.two_factor_enabled:
            otp = request.data.get('otp')
            if not otp:
                response = Response({'detail': 'Two-factor authentication code required', 'two_factor_required': True}, status=status.HTTP_401_UNAUTHORIZED)
                record_user_audit(request=request, action='auth.login_2fa', result='failure', user=user, resource_id=user.pk, metadata={'reason': 'otp_required'}, start=started)
                return response
            if not verify_totp(user.two_factor_secret, otp):
                response = Response({'detail': 'Invalid two-factor authentication code', 'two_factor_required': True}, status=status.HTTP_401_UNAUTHORIZED)
                record_user_audit(request=request, action='auth.login_2fa', result='failure', user=user, resource_id=user.pk, metadata={'reason': 'invalid_otp'}, start=started)
                return response

        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK and user:
            user.last_login_ip = request.META.get('REMOTE_ADDR')
            user.last_activity = timezone.now()
            user.save(update_fields=['last_login_ip', 'last_activity'])
            response.data['user'] = UserSerializer(user, context={'request': request}).data
            record_user_audit(request=request, action='auth.login', result='success', user=user, resource_id=user.pk, metadata={'two_factor': bool(user.two_factor_enabled)}, start=started)
        elif response.status_code != status.HTTP_200_OK:
            record_user_audit(request=request, action='auth.login', result='failure', user=user, resource_id=user.pk if user else '', metadata={'reason': 'authentication_failed'}, start=started)
        return response


class SecureTokenRefreshView(TokenRefreshView):
    serializer_class = AegisTokenRefreshSerializer


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def request_password_reset(request):
    email = str(request.data.get('email', '')).strip().lower()
    user = User.objects.filter(email__iexact=email).first()
    if user:
        user.password_reset_token = uuid.uuid4()
        user.password_reset_expires = timezone.now() + timezone.timedelta(hours=1)
        user.save(update_fields=['password_reset_token', 'password_reset_expires'])
        link = f"{settings.FRONTEND_URL}/reset-password?token={quote(str(user.password_reset_token))}"
        _send_message('AegisScan password reset', f'Reset your password: {link}\n\nThis link expires in 1 hour.', user.email)
        record_user_audit(request=request, action='auth.password_reset.request', result='success', user=user, resource_id=user.pk)
    else:
        record_user_audit(request=request, action='auth.password_reset.request', result='success', metadata={'account_exists': False})
    return Response({'message': 'If the account exists, a password reset email has been sent.'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def confirm_password_reset(request):
    token = str(request.data.get('token', '')).strip()
    password = request.data.get('password', '')
    if len(password) < 8:
        return Response({'detail': 'Password must be at least 8 characters'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        token_uuid = uuid.UUID(token)
    except (ValueError, AttributeError):
        return Response({'detail': 'Invalid or expired reset token'}, status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.filter(password_reset_token=token_uuid, password_reset_expires__gt=timezone.now()).first()
    if not user:
        record_user_audit(request=request, action='auth.password_reset.confirm', result='failure', metadata={'reason': 'invalid_or_expired_token'})
        return Response({'detail': 'Invalid or expired reset token'}, status=status.HTTP_400_BAD_REQUEST)
    user.set_password(password)
    user.password_reset_token = uuid.uuid4()
    user.password_reset_expires = None
    user.save(update_fields=['password', 'password_reset_token', 'password_reset_expires'])
    record_user_audit(request=request, action='auth.password_reset.confirm', result='success', user=user, resource_id=user.pk)
    return Response({'message': 'Password reset successfully'})


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    token = str(request.data.get('token', '')).strip()
    try:
        token_uuid = uuid.UUID(token)
    except (ValueError, AttributeError):
        return Response({'detail': 'Invalid or expired verification token'}, status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.filter(email_verification_token=token_uuid, email_verification_expires__gt=timezone.now()).first()
    if not user:
        record_user_audit(request=request, action='auth.email_verification', result='failure', metadata={'reason': 'invalid_or_expired_token'})
        return Response({'detail': 'Invalid or expired verification token'}, status=status.HTTP_400_BAD_REQUEST)
    user.is_verified = True
    user.email_verification_token = uuid.uuid4()
    user.email_verification_expires = None
    user.save(update_fields=['is_verified', 'email_verification_token', 'email_verification_expires'])
    record_user_audit(request=request, action='auth.email_verification', result='success', user=user, resource_id=user.pk)
    return Response({'message': 'Email verified successfully'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resend_verification(request):
    if request.user.is_verified:
        return Response({'message': 'Email is already verified'})
    request.user.email_verification_token = uuid.uuid4()
    request.user.email_verification_expires = timezone.now() + timezone.timedelta(hours=24)
    request.user.save(update_fields=['email_verification_token', 'email_verification_expires'])
    link = f"{settings.FRONTEND_URL}/verify-email?token={quote(str(request.user.email_verification_token))}"
    _send_message('Verify your AegisScan email', f'Verify your account: {link}\n\nThis link expires in 24 hours.', request.user.email)
    record_user_audit(request=request, action='auth.email_verification.resend', result='success', user=request.user, resource_id=request.user.pk)
    return Response({'message': 'Verification email sent'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def enable_2fa(request):
    raw_secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')
    request.user.two_factor_secret = raw_secret
    request.user.two_factor_enabled = False
    request.user.save(update_fields=['two_factor_secret', 'two_factor_enabled'])
    label = quote(f'AegisScan:{request.user.email}')
    issuer = quote('AegisScan')
    uri = f'otpauth://totp/{label}?secret={raw_secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30'
    record_user_audit(request=request, action='auth.2fa.enable.begin', result='success', user=request.user, resource_id=request.user.pk)
    return Response({'secret': raw_secret, 'qrCode': uri, 'otpauthUri': uri, 'message': 'Add this account to your authenticator app and verify the generated code.'})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def verify_2fa(request):
    if not verify_totp(request.user.two_factor_secret, request.data.get('code', '')):
        record_user_audit(request=request, action='auth.2fa.enable', result='failure', user=request.user, resource_id=request.user.pk, metadata={'reason': 'invalid_code'})
        return Response({'detail': 'Invalid or expired two-factor authentication code'}, status=status.HTTP_400_BAD_REQUEST)
    request.user.two_factor_enabled = True
    request.user.save(update_fields=['two_factor_enabled'])
    record_user_audit(request=request, action='auth.2fa.enable', result='success', user=request.user, resource_id=request.user.pk)
    return Response({'message': 'Two-factor authentication enabled', 'two_factor_enabled': True})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def disable_2fa(request):
    if not request.user.check_password(str(request.data.get('password', ''))):
        record_user_audit(request=request, action='auth.2fa.disable', result='failure', user=request.user, resource_id=request.user.pk, metadata={'reason': 'invalid_password'})
        return Response({'detail': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
    if not verify_totp(request.user.two_factor_secret, request.data.get('code', '')):
        record_user_audit(request=request, action='auth.2fa.disable', result='failure', user=request.user, resource_id=request.user.pk, metadata={'reason': 'invalid_code'})
        return Response({'detail': 'Valid two-factor authentication code required'}, status=status.HTTP_400_BAD_REQUEST)
    request.user.two_factor_enabled = False
    request.user.two_factor_secret = ''
    request.user.save(update_fields=['two_factor_enabled', 'two_factor_secret'])
    record_user_audit(request=request, action='auth.2fa.disable', result='success', user=request.user, resource_id=request.user.pk)
    return Response({'message': 'Two-factor authentication disabled', 'two_factor_enabled': False})
