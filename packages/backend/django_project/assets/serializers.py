from rest_framework import serializers

from .models import Asset, AssetRelationship, TechnologyFingerprint


class AssetSerializer(serializers.ModelSerializer):
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
