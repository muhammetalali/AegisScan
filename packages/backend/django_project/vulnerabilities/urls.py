from rest_framework.routers import DefaultRouter

from .views import VulnerabilityEvidenceViewSet, VulnerabilityNoteViewSet, VulnerabilityViewSet

router = DefaultRouter()
router.register("", VulnerabilityViewSet, basename="vulnerability")
router.register("evidences", VulnerabilityEvidenceViewSet, basename="vulnerability-evidence")
router.register("notes", VulnerabilityNoteViewSet, basename="vulnerability-note")

urlpatterns = router.urls
