from rest_framework.routers import DefaultRouter

from .views import KnowledgeArticleViewSet

router = DefaultRouter()
router.register(r"articles", KnowledgeArticleViewSet, basename="knowledge-article")

urlpatterns = router.urls
