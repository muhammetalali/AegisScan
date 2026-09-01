from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .auth_views import LoginView, RegisterView, RefreshView, LogoutView, csrf_view
from .views import UserViewSet, TeamViewSet, APIKeyViewSet, UserSessionViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'teams', TeamViewSet, basename='team')
router.register(r'api-keys', APIKeyViewSet, basename='api-key')
router.register(r'sessions', UserSessionViewSet, basename='session')

urlpatterns = [
    path('login/', LoginView.as_view(), name='token_obtain_pair'),
    path('refresh/', RefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('csrf/', csrf_view, name='csrf'),
    path('register/', RegisterView.as_view(), name='register'),
    path('', include(router.urls)),
]
