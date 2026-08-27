from rest_framework.routers import DefaultRouter

from .views import (
    ComplianceAssessmentViewSet,
    ComplianceControlViewSet,
    ComplianceFrameworkViewSet,
    ComplianceReportViewSet,
)

router = DefaultRouter()
router.register(r"frameworks", ComplianceFrameworkViewSet, basename="compliance-framework")
router.register(r"controls", ComplianceControlViewSet, basename="compliance-control")
router.register(r"assessments", ComplianceAssessmentViewSet, basename="compliance-assessment")
router.register(r"reports", ComplianceReportViewSet, basename="compliance-report")

urlpatterns = router.urls
