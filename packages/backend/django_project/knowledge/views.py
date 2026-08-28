from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ReadOnlyModelViewSet

from .models import KnowledgeArticle
from .serializers import KnowledgeArticleSerializer


class KnowledgeArticleViewSet(ReadOnlyModelViewSet):
    serializer_class = KnowledgeArticleSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [SearchFilter, OrderingFilter]
    search_fields = ["title", "summary", "content", "tags"]
    ordering_fields = ["published_at", "created_at", "view_count"]

    def get_queryset(self):
        return (
            KnowledgeArticle.objects
            .filter(status=KnowledgeArticle.Status.PUBLISHED)
            .select_related("category")
            .prefetch_related("related_vulnerabilities", "related_controls")
            .order_by("-published_at", "-created_at")
        )
