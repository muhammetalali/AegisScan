from rest_framework import serializers

from .models import KnowledgeArticle


class KnowledgeArticleSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source="category.name", read_only=True)
    related_vulnerability_count = serializers.IntegerField(source="related_vulnerabilities.count", read_only=True)
    related_control_count = serializers.IntegerField(source="related_controls.count", read_only=True)

    class Meta:
        model = KnowledgeArticle
        fields = (
            "id", "title", "slug", "type", "difficulty", "category_name", "tags",
            "summary", "content", "version", "published_at", "view_count",
            "related_vulnerability_count", "related_control_count",
        )
