from rest_framework import serializers
from .permissions import can_manage_account
from django.contrib.auth import get_user_model
from .models import User, Team, TeamMembership, APIKey, UserSession, LoginAttempt, UserRole, Permission, ROLE_PERMISSIONS

User = get_user_model()


def validate_delegated_scope_allowlists(actor, attrs):
    """Prevent delegated scan/page allowlists from exceeding the actor's own."""
    if 'enabled_scan_types' in attrs and actor.enabled_scan_types is not None:
        if not set(attrs['enabled_scan_types']).issubset(set(actor.enabled_scan_types)):
            raise serializers.ValidationError({
                'enabled_scan_types': 'Cannot delegate scan types outside your own allowlist.'
            })
    if 'enabled_pages' in attrs and actor.enabled_pages is not None:
        if not set(attrs['enabled_pages']).issubset(set(actor.enabled_pages)):
            raise serializers.ValidationError({
                'enabled_pages': 'Cannot delegate pages outside your own allowlist.'
            })


class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()
    avatar_url = serializers.SerializerMethodField()
    is_company_owner = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone', 'avatar', 'avatar_url', 'role', 'is_active',
            'is_verified', 'last_login_ip', 'last_activity',
            'language', 'theme', 'timezone', 'two_factor_enabled',
            'permissions', 'granted_permissions', 'enabled_scan_types', 'enabled_pages',
            'is_company_owner', 'date_joined', 'last_login',
        ]
        read_only_fields = ['id', 'date_joined', 'last_login', 'is_verified', 'last_login_ip', 'last_activity']

    def get_full_name(self, obj):
        return obj.get_full_name()

    def get_permissions(self, obj):
        return obj.get_effective_permissions()

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
        fields = ['id', 'email', 'first_name', 'last_name', 'full_name', 'role', 'is_active', 'is_verified', 'last_activity', 'date_joined', 'granted_permissions', 'enabled_scan_types', 'enabled_pages', 'is_company_owner']

    def get_full_name(self, obj):
        return obj.get_full_name()


class UserCreateSerializer(serializers.ModelSerializer):
    granted_permissions = serializers.ListField(child=serializers.ChoiceField(choices=Permission.values), required=False)
    enabled_scan_types = serializers.ListField(child=serializers.ChoiceField(choices=('code', 'url', 'ip', 'api', 'file', 'docker', 'network', 'full_validation')), required=False)
    enabled_pages = serializers.ListField(child=serializers.RegexField(r'^/[a-z0-9][a-z0-9/-]{0,100}$'), required=False)
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'is_active', 'email', 'first_name', 'last_name', 'password', 'password_confirm', 'role', 'phone', 'language', 'theme', 'timezone', 'granted_permissions', 'enabled_scan_types', 'enabled_pages']
        read_only_fields = ['id', 'is_active']

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({'password_confirm': 'Passwords do not match'})
        role = attrs.get('role', UserRole.VIEWER)
        allowed = {str(p) for p in ROLE_PERMISSIONS[role]}
        grants = attrs.get('granted_permissions', [])
        if not set(grants).issubset(allowed):
            raise serializers.ValidationError({'granted_permissions': 'Selected permissions exceed role limits.'})
        actor = self.context.get('request').user if self.context.get('request') else None
        if actor and not actor.is_company_owner:
            if role == UserRole.SUPER_ADMIN:
                raise serializers.ValidationError({'role': 'Only the primary owner can assign the super admin role.'})
            if role != UserRole.VIEWER and not actor.has_permission('user.manage_roles'):
                raise serializers.ValidationError({'role': 'Role management permission required.'})
            if grants and not actor.has_permission('user.manage_permissions'):
                raise serializers.ValidationError({'granted_permissions': 'Permission management grant required.'})
            if not set(grants).issubset(set(actor.get_effective_permissions())):
                raise serializers.ValidationError({'granted_permissions': 'Cannot delegate permissions you do not hold.'})
            validate_delegated_scope_allowlists(actor, attrs)
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        # New company accounts are inert until the owner explicitly activates them.
        validated_data.setdefault('granted_permissions', [])
        validated_data.setdefault('enabled_scan_types', [])
        validated_data.setdefault('enabled_pages', [])
        validated_data['is_active'] = False
        return User.objects.create_user(password=password, **validated_data)


class UserUpdateSerializer(serializers.ModelSerializer):
    granted_permissions = serializers.ListField(child=serializers.ChoiceField(choices=Permission.values), required=False)
    enabled_scan_types = serializers.ListField(child=serializers.ChoiceField(choices=('code', 'url', 'ip', 'api', 'file', 'docker', 'network', 'full_validation')), required=False)
    enabled_pages = serializers.ListField(child=serializers.RegexField(r'^/[a-z0-9][a-z0-9/-]{0,100}$'), required=False)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone', 'role', 'language', 'theme', 'timezone', 'granted_permissions', 'enabled_scan_types', 'enabled_pages']

    def validate(self, attrs):
        role = attrs.get('role', self.instance.role)
        # Legacy NULL means role defaults. A delegated super admin must never
        # inherit every capability merely because an old account had NULL.
        if role == UserRole.SUPER_ADMIN and attrs.get('granted_permissions', self.instance.granted_permissions) is None:
            attrs['granted_permissions'] = []
        grants = attrs.get('granted_permissions', self.instance.granted_permissions)
        if grants is not None and not set(grants).issubset({str(p) for p in ROLE_PERMISSIONS[role]}):
            raise serializers.ValidationError({'granted_permissions': 'Selected permissions exceed role limits.'})
        actor = self.context.get('request').user if self.context.get('request') else None
        if actor and not actor.is_company_owner:
            if not can_manage_account(actor, self.instance):
                raise serializers.ValidationError({'role': 'Only the primary owner can manage privileged accounts.'})
            if 'role' in attrs and attrs['role'] != self.instance.role and not actor.has_permission('user.manage_roles'):
                raise serializers.ValidationError({'role': 'Role management permission required.'})
            if role == UserRole.SUPER_ADMIN and role != self.instance.role:
                raise serializers.ValidationError({'role': 'Only the primary owner can assign the super admin role.'})
            if 'granted_permissions' in attrs:
                if not actor.has_permission('user.manage_permissions'):
                    raise serializers.ValidationError({'granted_permissions': 'Permission management grant required.'})
                if not set(attrs['granted_permissions']).issubset(set(actor.get_effective_permissions())):
                    raise serializers.ValidationError({'granted_permissions': 'Cannot delegate permissions you do not hold.'})
            validate_delegated_scope_allowlists(actor, attrs)
        return attrs


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

    def validate_permissions(self, value):
        # A scoped API key cannot exceed the authenticating operator's RBAC grants.
        user = self.context['request'].user
        if not isinstance(value, list) or not value or not all(
            isinstance(permission, str) and user.has_permission(permission) for permission in value
        ):
            raise serializers.ValidationError('Key permissions must be a nonempty subset of your own grants.')
        return sorted(set(value))

    def validate_team(self, value):
        if value and not TeamMembership.objects.filter(team=value, user=self.context['request'].user).exists():
            raise serializers.ValidationError('You are not a member of this team.')
        return value

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