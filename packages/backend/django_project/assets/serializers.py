from rest_framework import serializers

from .models import Asset, AssetRelationship, TechnologyFingerprint


class AssetSerializer(serializers.ModelSerializer):
    # The API generates a project-scoped slug in AssetViewSet.perform_create().
    # Keep the field writable for explicit slugs, but do not require clients to
    # provide one so validation reaches the centralized slug-generation logic.
    slug = serializers.SlugField(required=False, allow_blank=False, max_length=220)

    class Meta:
        model = Asset
        fields = "__all__"
        read_only_fields = ("id", "owner", "scan_count", "last_scanned_at", "created_at", "updated_at")


class AssetRelationshipSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetRelationship
        fields = "__all__"
        read_only_fields = ("id", "project", "created_at")


class TechnologyFingerprintSerializer(serializers.ModelSerializer):
    class Meta:
        model = TechnologyFingerprint
        fields = "__all__"
        read_only_fields = ("id", "detected_at")
