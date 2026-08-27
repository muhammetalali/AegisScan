from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import UserViewSet, TeamViewSet, APIKeyViewSet, UserSessionViewSet
from .auth_security import SecureTokenObtainPairView, request_password_reset, confirm_password_reset, verify_email, resend_verification, enable_2fa, verify_2fa, disable_2fa

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'teams', TeamViewSet, basename='team')
router.register(r'api-keys', APIKeyViewSet, basename='api-key')
router.register(r'sessions', UserSessionViewSet, basename='session')

urlpatterns = [
    path('auth/login/', SecureTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/register/', UserViewSet.as_view({'post': 'create'}), name='register'),
    path('auth/password/reset/', request_password_reset, name='password_reset'),
    path('auth/password/reset/confirm/', confirm_password_reset, name='password_reset_confirm'),
    path('auth/verify-email/', verify_email, name='verify_email'),
    path('auth/resend-verification/', resend_verification, name='resend_verification'),
    path('auth/2fa/enable/', enable_2fa, name='enable_2fa'),
    path('auth/2fa/verify/', verify_2fa, name='verify_2fa'),
    path('auth/2fa/disable/', disable_2fa, name='disable_2fa'),
    path('', include(router.urls)),
]
