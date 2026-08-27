from rest_framework.routers import DefaultRouter

from .views import ScanEngineExecutionViewSet, ScanEngineViewSet, ScanViewSet

router = DefaultRouter()
router.register("", ScanViewSet, basename="scan")
router.register("engines", ScanEngineViewSet, basename="scan-engine")
router.register("engine-executions", ScanEngineExecutionViewSet, basename="scan-engine-execution")

urlpatterns = router.urls
