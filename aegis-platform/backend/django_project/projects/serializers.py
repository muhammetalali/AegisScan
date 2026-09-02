from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Project

User = get_user_model()


class ProjectSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField()
    assets = serializers.SerializerMethodField()
    validations = serializers.SerializerMethodField()
    findings = serializers.SerializerMethodField()
    security_score = serializers.SerializerMethodField()
    risk = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            'id', 'name', 'slug', 'description', 'status', 'environment',
            'owner', 'assets', 'validations', 'findings', 'security_score',
            'risk', 'tags', 'settings', 'default_scan_config',
            'created_at', 'updated_at', 'archived_at',
        ]
        read_only_fields = [
            'id', 'slug', 'owner', 'assets', 'validations', 'findings',
            'security_score', 'risk', 'created_at', 'updated_at', 'archived_at',
        ]

    def get_owner(self, obj):
        return obj.owner.get_full_name() or obj.owner.email if obj.owner else None

    def get_assets(self, obj):
        return obj.assets.filter(is_active=True).count()

    def get_validations(self, obj):
        return obj.scans.count()

    def get_findings(self, obj):
        return obj.vulnerabilities.count()

    def get_security_score(self, obj):
        from django.db.models import Avg
        value = obj.scans.filter(status='completed').aggregate(value=Avg('security_score'))['value']
        return round(value) if value is not None else None

    def get_risk(self, obj):
        severities = set(
            obj.vulnerabilities.filter(status__in=['open', 'confirmed', 'in_progress']).values_list('severity', flat=True)
        )
        if 'critical' in severities:
            return 'critical'
        if 'high' in severities:
            return 'high'
        if 'medium' in severities:
            return 'medium'
        if 'low' in severities:
            return 'low'
        return None


class ProjectCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = [
            'id', 'name', 'description', 'status', 'environment', 'tags',
            'settings', 'default_scan_config',
        ]
        read_only_fields = ['id']

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError('Project name is required.')
        return value
