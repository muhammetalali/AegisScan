from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, TeamViewSet, APIKeyViewSet, UserSessionViewSet
from .auth_security import enable_2fa, verify_2fa, disable_2fa

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='management-user')
router.register(r'teams', TeamViewSet, basename='management-team')
router.register(r'api-keys', APIKeyViewSet, basename='management-api-key')
router.register(r'sessions', UserSessionViewSet, basename='management-session')

urlpatterns = [
    path('me/2fa/enable/', enable_2fa, name='me-2fa-enable'),
    path('me/2fa/verify/', verify_2fa, name='me-2fa-verify'),
    path('me/2fa/disable/', disable_2fa, name='me-2fa-disable'),
    path('', include(router.urls)),
]
