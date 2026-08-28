import uuid
from urllib.parse import quote
from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .audit import record_user_audit
from .models import User
from .serializers import UserCreateSerializer, UserSerializer


def issue_verification(user, request=None):
    user.email_verification_token = uuid.uuid4()
    user.email_verification_expires = timezone.now() + timezone.timedelta(hours=24)
    user.save(update_fields=['email_verification_token', 'email_verification_expires'])
    if request is not None:
        link = request.build_absolute_uri(f'/api/v1/auth/verify-email/?token={quote(str(user.email_verification_token))}')
    else:
        link = f"{settings.FRONTEND_URL}/login?verified=1"
    send_mail('Verify your AegisScan email', f'Verify your account: {link}\n\nThis link expires in 24 hours.', settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_user(request):
    serializer = UserCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    issue_verification(user, request)
    refresh = RefreshToken.for_user(user)
    record_user_audit(request=request, action='auth.register', result='success', user=user, resource_id=user.pk)
    return Response({'access': str(refresh.access_token), 'refresh': str(refresh), 'user': UserSerializer(user, context={'request': request}).data, 'verification_required': True}, status=201)


@api_view(['GET', 'POST'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    token = request.query_params.get('token') if request.method == 'GET' else request.data.get('token')
    try:
        token_uuid = uuid.UUID(str(token))
    except (ValueError, AttributeError):
        record_user_audit(request=request, action='auth.email_verification', result='failure', metadata={'reason': 'invalid_token'})
        if request.method == 'GET': return HttpResponseRedirect(f'{settings.FRONTEND_URL}/login?verification=invalid')
        return Response({'detail': 'Invalid or expired verification token'}, status=status.HTTP_400_BAD_REQUEST)
    user = User.objects.filter(email_verification_token=token_uuid, email_verification_expires__gt=timezone.now()).first()
    if not user:
        record_user_audit(request=request, action='auth.email_verification', result='failure', metadata={'reason': 'invalid_or_expired_token'})
        if request.method == 'GET': return HttpResponseRedirect(f'{settings.FRONTEND_URL}/login?verification=invalid')
        return Response({'detail': 'Invalid or expired verification token'}, status=status.HTTP_400_BAD_REQUEST)
    user.is_verified = True
    user.email_verification_token = uuid.uuid4()
    user.email_verification_expires = None
    user.save(update_fields=['is_verified', 'email_verification_token', 'email_verification_expires'])
    record_user_audit(request=request, action='auth.email_verification', result='success', user=user, resource_id=user.pk)
    if request.method == 'GET': return HttpResponseRedirect(f'{settings.FRONTEND_URL}/login?verification=success')
    return Response({'message': 'Email verified successfully', 'is_verified': True})


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def resend_verification(request):
    if request.user.is_verified:
        return Response({'message': 'Email is already verified'})
    issue_verification(request.user, request)
    record_user_audit(request=request, action='auth.email_verification.resend', result='success', user=request.user, resource_id=request.user.pk)
    return Response({'message': 'Verification email sent'})
