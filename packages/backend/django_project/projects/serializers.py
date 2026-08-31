from __future__ import annotations

import logging
import re
import uuid

from django.utils.text import slugify
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from users.models import Permission

from .models import Project

logger = logging.getLogger(__name__)


class ProjectSerializer(serializers.ModelSerializer):
    # SlugField performs Django's ASCII slug validation before validate_slug(),
    # which caused valid project creation requests to fail before our custom
    # normalization could run. Treat the API boundary as the canonical place
    # to normalize an optional client-provided slug.
    slug = serializers.CharField(required=False, allow_blank=True, max_length=220)
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

    def validate(self, attrs):
        attrs = super().validate(attrs)
        request = self.context.get("request")
        if self.instance is None and request is not None:
            user = request.user
            logger.info(
                "PROJECT_CREATE_AUTH user_id=%s role=%s superuser=%s staff=%s project_create=%s authenticated=%s",
                getattr(user, "pk", None),
                getattr(user, "role", None),
                getattr(user, "is_superuser", False),
                getattr(user, "is_staff", False),
                bool(getattr(user, "has_permission", lambda _permission: False)(Permission.PROJECT_CREATE)),
                bool(getattr(user, "is_authenticated", False)),
            )
            if not user.has_permission(Permission.PROJECT_CREATE):
                raise PermissionDenied("You do not have permission to create projects.")

        raw_slug = str(attrs.get("slug") or "").strip()
        name = str(attrs.get("name") or "").strip()
        normalized_slug = slugify(raw_slug, allow_unicode=False) if raw_slug else slugify(name, allow_unicode=False)

        if not normalized_slug:
            normalized_slug = f"project-{uuid.uuid4().hex[:12]}"

        normalized_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", normalized_slug).strip("-_").lower()
        normalized_slug = normalized_slug[:220].strip("-_")
        if not normalized_slug:
            normalized_slug = f"project-{uuid.uuid4().hex[:12]}"

        candidate = normalized_slug
        suffix = 1
        while Project.objects.filter(slug=candidate).exclude(pk=getattr(self.instance, "pk", None)).exists():
            suffix_text = f"-{suffix}"
            candidate = f"{normalized_slug[:220 - len(suffix_text)]}{suffix_text}"
            suffix += 1

        attrs["slug"] = candidate
        return attrs

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
