from rest_framework.routers import DefaultRouter

from .views import AssetRelationshipViewSet, AssetViewSet, TechnologyFingerprintViewSet

router = DefaultRouter()
router.register("", AssetViewSet, basename="asset")
router.register("relationships", AssetRelationshipViewSet, basename="asset-relationship")
router.register("technologies", TechnologyFingerprintViewSet, basename="technology")

urlpatterns = router.urls
