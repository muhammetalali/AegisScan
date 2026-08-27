from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import User, Team, TeamMembership, APIKey, UserSession, LoginAttempt, UserRole, Permission, ROLE_PERMISSIONS

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone', 'avatar', 'avatar_url', 'role', 'is_active',
            'is_verified', 'last_login_ip', 'last_activity',
            'language', 'theme', 'timezone', 'two_factor_enabled',
            'permissions', 'date_joined', 'last_login',
        ]
        read_only_fields = ['id', 'date_joined', 'last_login', 'is_verified', 'last_login_ip', 'last_activity']

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_permissions(self, obj):
        return ROLE_PERMISSIONS.get(obj.role, [])

    def get_avatar_url(self, obj):
        if obj.avatar:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.avatar.url)
        return None


class UserListSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'role', 'is_active', 'is_verified', 'last_activity', 'date_joined']

    def get_full_name(self, obj):
        return obj.get_full_name()


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password_confirm', 'role', 'phone', 'language', 'theme', 'timezone']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Passwords do not match'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'role', 'language', 'theme', 'timezone', 'is_active']
        read_only_fields = ['email']


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    new_password_confirm = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({'new_password_confirm': 'Passwords do not match'})
        return attrs


class TeamMembershipSerializer(serializers.ModelSerializer):
    user = UserListSerializer(read_only=True)
    user_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = TeamMembership
        fields = ['id', 'user', 'user_id', 'role', 'joined_at']
        read_only_fields = ['id', 'joined_at']


class TeamSerializer(serializers.ModelSerializer):
    owner = UserListSerializer(read_only=True)
    owner_id = serializers.UUIDField(write_only=True)
    members = TeamMembershipSerializer(source='memberships', many=True, read_only=True)
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Team
        fields = ['id', 'name', 'description', 'owner', 'owner_id', 'members', 'member_count', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_member_count(self, obj):
        return obj.members.count()


class TeamCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ['name', 'description', 'owner_id']


class APIKeySerializer(serializers.ModelSerializer):
    user = UserListSerializer(read_only=True)
    team = serializers.StringRelatedField(read_only=True)
    key = serializers.CharField(read_only=True)  # Only shown on create

    class Meta:
        model = APIKey
        fields = ['id', 'name', 'key', 'key_prefix', 'user', 'team', 'permissions', 'expires_at', 'last_used_at', 'is_active', 'created_at']
        read_only_fields = ['id', 'key', 'key_prefix', 'last_used_at', 'created_at']


class APIKeyCreateSerializer(serializers.ModelSerializer):
    key = serializers.CharField(read_only=True)

    class Meta:
        model = APIKey
        fields = ['id', 'name', 'key', 'permissions', 'expires_at', 'team']

    def create(self, validated_data):
        import secrets
        import hashlib
        key = f"aegis_{secrets.token_urlsafe(32)}"
        validated_data['key_hash'] = hashlib.sha256(key.encode()).hexdigest()
        validated_data['key_prefix'] = key[:12]
        validated_data['user'] = self.context['request'].user
        api_key = super().create(validated_data)
        api_key.key = key  # Only for response
        return api_key


class UserSessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSession
        fields = ['id', 'ip_address', 'user_agent', 'location', 'is_current', 'expires_at', 'created_at', 'last_activity']
        read_only_fields = fields


class LoginAttemptSerializer(serializers.ModelSerializer):
    class Meta:
        model = LoginAttempt
        fields = ['id', 'email', 'ip_address', 'success', 'failure_reason', 'created_at']
        read_only_fields = fields