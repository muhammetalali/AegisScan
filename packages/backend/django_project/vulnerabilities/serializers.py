from rest_framework import serializers

from .models import Vulnerability, VulnerabilityEvidence, VulnerabilityNote


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = "__all__"
        read_only_fields = (
            "id", "project", "created_at", "updated_at", "first_seen", "last_seen",
            "validated_at", "validated_by", "fixed_at", "fixed_by", "assigned_at",
        )


class VulnerabilityEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityEvidence
        fields = "__all__"
        read_only_fields = ("id", "verified_at", "verified_by", "collected_at")


class VulnerabilityNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityNote
        fields = "__all__"
        read_only_fields = ("id", "author", "created_at", "updated_at")
