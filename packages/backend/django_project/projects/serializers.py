from rest_framework import serializers

from .models import Project


class ProjectSerializer(serializers.ModelSerializer):
    owner = serializers.UUIDField(source="owner_id", read_only=True)
    member_count = serializers.IntegerField(source="get_member_count", read_only=True)

    class Meta:
        model = Project
        fields = [
            "id", "name", "slug", "description", "status", "environment", "owner",
            "tags", "settings", "default_scan_config", "member_count", "created_at",
            "updated_at", "archived_at",
        ]
        read_only_fields = ["id", "owner", "member_count", "created_at", "updated_at", "archived_at"]

    def validate_slug(self, value):
        value = value.strip().lower()
        if not value:
            raise serializers.ValidationError("Slug cannot be empty.")
        return value

    def validate_status(self, value):
        if value == Project.Status.ARCHIVED:
            raise serializers.ValidationError("Use the archive action to archive a project.")
        return value

    def validate_tags(self, value):
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise serializers.ValidationError("Tags must be a list of strings.")
        return value

    def validate_settings(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Settings must be an object.")
        return value

    def validate_default_scan_config(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError("Default scan config must be an object.")
        return value
