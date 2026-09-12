from rest_framework.routers import DefaultRouter

from django_project.system.credential_views import CredentialSecretViewSet

router = DefaultRouter()
router.register(r'credentials', CredentialSecretViewSet, basename='credential')

urlpatterns = router.urls
