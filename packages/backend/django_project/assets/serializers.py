from rest_framework import serializers

from .models import Asset, AssetRelationship, TechnologyFingerprint


class AssetSerializer(serializers.ModelSerializer):
    # Slugs are owned by the API and generated per project in AssetViewSet.
    # Clients must not provide or override this server-managed identifier.
    slug = serializers.SlugField(read_only=True, max_length=220)

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
