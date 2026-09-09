from __future__ import annotations

from rest_framework import serializers

from django_project.system.credential_models import CredentialSecret


class CredentialSecretSerializer(serializers.ModelSerializer):
    credential_ref = serializers.UUIDField(source='id', read_only=True)
    project_id = serializers.UUIDField(read_only=True)
    created_by_id = serializers.UUIDField(read_only=True)
    last_used_by_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = CredentialSecret
        fields = [
            'id', 'credential_ref', 'project_id', 'name', 'kind', 'status', 'scope', 'version',
            'created_by_id', 'last_used_by_id', 'created_at', 'updated_at', 'rotated_at',
            'revoked_at', 'last_used_at',
        ]
        read_only_fields = fields


class CredentialSecretCreateSerializer(serializers.Serializer):
    project = serializers.UUIDField()
    name = serializers.CharField(max_length=200, trim_whitespace=True)
    kind = serializers.ChoiceField(choices=CredentialSecret.Kind.choices, default=CredentialSecret.Kind.GENERIC)
    secret = serializers.CharField(write_only=True, trim_whitespace=False, min_length=1, max_length=65536)
    scope = serializers.DictField(required=False, default=dict)

    def validate_name(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError('Credential name cannot be blank.')
        return value.strip()


class CredentialRotateSerializer(serializers.Serializer):
    secret = serializers.CharField(write_only=True, trim_whitespace=False, min_length=1, max_length=65536)


class CredentialUseSerializer(serializers.Serializer):
    purpose = serializers.CharField(max_length=200, trim_whitespace=True)

    def validate_purpose(self, value: str) -> str:
        if not value.strip():
            raise serializers.ValidationError('Credential use requires a purpose.')
        return value.strip()
