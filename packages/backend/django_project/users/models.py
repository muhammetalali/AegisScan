from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        if settings.DEBUG and not extra_fields.get('role'):
            extra_fields['role'] = UserRole.ADMIN
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', UserRole.ADMIN)
        return self.create_user(email, password, **extra_fields)


class UserRole(models.TextChoices):
    SUPER_ADMIN = 'super_admin', _('Super Admin')
    ADMIN = 'admin', _('Admin')
    SECURITY_MANAGER = 'security_manager', _('Security Manager')
    SECURITY_ANALYST = 'security_analyst', _('Security Analyst')
    DEVELOPER = 'developer', _('Developer')
    AUDITOR = 'auditor', _('Auditor')
    VIEWER = 'viewer', _('Viewer')


class Permission(models.TextChoices):
    # Project permissions
    PROJECT_CREATE = 'project.create', _('Create Project')
    PROJECT_READ = 'project.read', _('Read Project')
    PROJECT_UPDATE = 'project.update', _('Update Project')
    PROJECT_DELETE = 'project.delete', _('Delete Project')
    PROJECT_ARCHIVE = 'project.archive', _('Archive Project')
    PROJECT_CLONE = 'project.clone', _('Clone Project')
    # Asset permissions
    ASSET_CREATE = 'asset.create', _('Create Asset')
    ASSET_READ = 'asset.read', _('Read Asset')
    ASSET_UPDATE = 'asset.update', _('Update Asset')
    ASSET_DELETE = 'asset.delete', _('Delete Asset')
    # Scan permissions
    SCAN_CREATE = 'scan.create', _('Create Scan')
    SCAN_READ = 'scan.read', _('Read Scan')
    SCAN_CANCEL = 'scan.cancel', _('Cancel Scan')
    SCAN_RESTART = 'scan.restart', _('Restart Scan')
    SCAN_SCHEDULE = 'scan.schedule', _('Schedule Scan')
    # Vulnerability permissions
    VULN_READ = 'vulnerability.read', _('Read Vulnerability')
    VULN_UPDATE = 'vulnerability.update', _('Update Vulnerability')
    VULN_ASSIGN = 'vulnerability.assign', _('Assign Vulnerability')
    VULN_CHANGE_STATUS = 'vulnerability.change_status', _('Change Vulnerability Status')
    VULN_ADD_NOTE = 'vulnerability.add_note', _('Add Note to Vulnerability')
    # Report permissions
    REPORT_CREATE = 'report.create', _('Create Report')
    REPORT_READ = 'report.read', _('Read Report')
    REPORT_DOWNLOAD = 'report.download', _('Download Report')
    REPORT_COMPARE = 'report.compare', _('Compare Reports')
    REPORT_SHARE = 'report.share', _('Share Reports')
    # Compliance permissions
    COMPLIANCE_READ = 'compliance.read', _('Read Compliance')
    COMPLIANCE_UPDATE = 'compliance.update', _('Update Compliance')
    # Knowledge permissions
    KNOWLEDGE_CREATE = 'knowledge.create', _('Create Knowledge')
    KNOWLEDGE_READ = 'knowledge.read', _('Read Knowledge')
    KNOWLEDGE_UPDATE = 'knowledge.update', _('Update Knowledge')
    # Digital Twin permissions
    TWIN_READ = 'digital_twin.read', _('Read Digital Twin')
    TWIN_SIMULATE = 'digital_twin.simulate', _('Simulate Digital Twin')
    # User Management permissions
    USER_CREATE = 'user.create', _('Create User')
    USER_READ = 'user.read', _('Read User')
    USER_UPDATE = 'user.update', _('Update User')
    USER_DELETE = 'user.delete', _('Delete User')
    USER_MANAGE_ROLES = 'user.manage_roles', _('Manage Roles')
    USER_MANAGE_PERMISSIONS = 'user.manage_permissions', _('Manage Permissions')
    # System permissions
    SYSTEM_SETTINGS = 'system.settings', _('System Settings')
    SYSTEM_MONITOR = 'system.monitor', _('System Monitor')
    SYSTEM_BACKUP = 'system.backup', _('System Backup')
    API_KEY_MANAGE = 'api_key.manage', _('Manage API Keys')
    AUDIT_READ = 'audit.read', _('Read Audit Logs')


ROLE_PERMISSIONS = {
    UserRole.SUPER_ADMIN: [p.value for p in Permission],
    UserRole.ADMIN: [
        Permission.PROJECT_CREATE, Permission.PROJECT_READ, Permission.PROJECT_UPDATE,
        Permission.PROJECT_DELETE, Permission.PROJECT_ARCHIVE, Permission.PROJECT_CLONE,
        Permission.ASSET_CREATE, Permission.ASSET_READ, Permission.ASSET_UPDATE, Permission.ASSET_DELETE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_CANCEL, Permission.SCAN_RESTART, Permission.SCAN_SCHEDULE,
        Permission.VULN_READ, Permission.VULN_UPDATE, Permission.VULN_ASSIGN, Permission.VULN_CHANGE_STATUS, Permission.VULN_ADD_NOTE,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_DOWNLOAD, Permission.REPORT_COMPARE, Permission.REPORT_SHARE,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_UPDATE,
        Permission.KNOWLEDGE_CREATE, Permission.KNOWLEDGE_READ, Permission.KNOWLEDGE_UPDATE,
        Permission.TWIN_READ, Permission.TWIN_SIMULATE,
        Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, Permission.USER_MANAGE_ROLES,
        Permission.SYSTEM_SETTINGS, Permission.SYSTEM_MONITOR, Permission.API_KEY_MANAGE, Permission.AUDIT_READ,
    ],
    UserRole.SECURITY_MANAGER: [
        Permission.PROJECT_CREATE, Permission.PROJECT_READ, Permission.PROJECT_UPDATE, Permission.PROJECT_ARCHIVE, Permission.PROJECT_CLONE,
        Permission.ASSET_CREATE, Permission.ASSET_READ, Permission.ASSET_UPDATE,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_CANCEL, Permission.SCAN_RESTART, Permission.SCAN_SCHEDULE,
        Permission.VULN_READ, Permission.VULN_UPDATE, Permission.VULN_ASSIGN, Permission.VULN_CHANGE_STATUS, Permission.VULN_ADD_NOTE,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_DOWNLOAD, Permission.REPORT_COMPARE, Permission.REPORT_SHARE,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_UPDATE,
        Permission.KNOWLEDGE_CREATE, Permission.KNOWLEDGE_READ, Permission.KNOWLEDGE_UPDATE,
        Permission.TWIN_READ, Permission.TWIN_SIMULATE,
        Permission.USER_READ, Permission.API_KEY_MANAGE,
    ],
    UserRole.SECURITY_ANALYST: [
        Permission.PROJECT_READ, Permission.PROJECT_CLONE,
        Permission.ASSET_READ,
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_RESTART,
        Permission.VULN_READ, Permission.VULN_UPDATE, Permission.VULN_ADD_NOTE,
        Permission.REPORT_READ, Permission.REPORT_DOWNLOAD,
        Permission.COMPLIANCE_READ,
        Permission.KNOWLEDGE_READ,
        Permission.TWIN_READ,
    ],
    UserRole.DEVELOPER: [
        Permission.PROJECT_READ, Permission.ASSET_READ, Permission.SCAN_READ,
        Permission.VULN_READ, Permission.VULN_ADD_NOTE, Permission.REPORT_READ, Permission.KNOWLEDGE_READ,
    ],
    UserRole.AUDITOR: [
        Permission.PROJECT_READ, Permission.ASSET_READ, Permission.SCAN_READ, Permission.VULN_READ,
        Permission.REPORT_READ, Permission.REPORT_DOWNLOAD, Permission.COMPLIANCE_READ,
        Permission.KNOWLEDGE_READ, Permission.TWIN_READ, Permission.AUDIT_READ,
    ],
    UserRole.VIEWER: [
        Permission.PROJECT_READ, Permission.ASSET_READ, Permission.SCAN_READ, Permission.VULN_READ,
        Permission.REPORT_READ, Permission.COMPLIANCE_READ, Permission.KNOWLEDGE_READ, Permission.TWIN_READ,
    ],
}


class User(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=150)
    last_name = models.CharField(_('last name'), max_length=150)
    phone = models.CharField(_('phone'), max_length=20, blank=True)
    avatar = models.ImageField(_('avatar'), upload_to='avatars/', blank=True, null=True)
    role = models.CharField(_('role'), max_length=30, choices=UserRole.choices, default=UserRole.VIEWER)
    is_active = models.BooleanField(_('active'), default=True)
    is_verified = models.BooleanField(_('verified'), default=False)
    last_login_ip = models.GenericIPAddressField(_('last login IP'), blank=True, null=True)
    last_activity = models.DateTimeField(_('last activity'), blank=True, null=True)
    language = models.CharField(_('language'), max_length=10, default='ar')
    theme = models.CharField(_('theme'), max_length=10, choices=[('dark', 'Dark'), ('light', 'Light')], default='dark')
    timezone = models.CharField(_('timezone'), max_length=50, default='UTC')
    two_factor_enabled = models.BooleanField(_('2FA enabled'), default=False)
    two_factor_secret = models.CharField(_('2FA secret'), max_length=32, blank=True)
    session_version = models.PositiveBigIntegerField(_('session version'), default=1, editable=False)
    password_reset_token = models.UUIDField(_('password reset token'), default=uuid.uuid4, editable=False)
    password_reset_expires = models.DateTimeField(_('password reset expires'), blank=True, null=True)
    email_verification_token = models.UUIDField(_('email verification token'), default=uuid.uuid4, editable=False)
    email_verification_expires = models.DateTimeField(_('email verification expires'), blank=True, null=True)
    objects = UserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        ordering = ['-date_joined']
        indexes = [models.Index(fields=['email']), models.Index(fields=['role']), models.Index(fields=['is_active'])]

    def __str__(self): return self.email

    def get_full_name(self): return f"{self.first_name} {self.last_name}".strip()

    def has_permission(self, permission: str) -> bool:
        if self.is_superuser: return True
        role_perms = ROLE_PERMISSIONS.get(self.role, [])
        return permission in role_perms

    def has_any_permission(self, *permissions: str) -> bool: return any(self.has_permission(p) for p in permissions)
    def has_all_permissions(self, *permissions: str) -> bool: return all(self.has_permission(p) for p in permissions)


class Team(models.Model):
    class Role(models.TextChoices):
        OWNER = 'owner', _('Owner'); ADMIN = 'admin', _('Admin'); MEMBER = 'member', _('Member'); VIEWER = 'viewer', _('Viewer')
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100)
    description = models.TextField(_('description'), blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_teams')
    members = models.ManyToManyField(User, through='TeamMembership', related_name='teams')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    def __str__(self): return self.name


class TeamMembership(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='team_memberships')
    role = models.CharField(max_length=20, choices=Team.Role.choices, default=Team.Role.MEMBER)
    joined_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ['team', 'user']


class APIKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(_('name'), max_length=100)
    key_hash = models.CharField(_('key hash'), max_length=255)
    key_prefix = models.CharField(_('key prefix'), max_length=20)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    team = models.ForeignKey(Team, on_delete=models.SET_NULL, null=True, blank=True, related_name='api_keys')
    permissions = models.JSONField(_('permissions'), default=list)
    expires_at = models.DateTimeField(_('expires at'), blank=True, null=True)
    last_used_at = models.DateTimeField(_('last used at'), blank=True, null=True)
    last_used_ip = models.GenericIPAddressField(_('last used IP'), blank=True, null=True)
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self): return f"{self.name} ({self.key_prefix}...)"


class UserSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key = models.CharField(_('session key'), max_length=255)
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('user agent'))
    location = models.CharField(_('location'), max_length=100, blank=True)
    is_current = models.BooleanField(_('current'), default=False)
    expires_at = models.DateTimeField(_('expires at'))
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)


class LoginAttempt(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email'))
    ip_address = models.GenericIPAddressField(_('IP address'))
    user_agent = models.TextField(_('user agent'), blank=True)
    success = models.BooleanField(_('success'), default=False)
    failure_reason = models.CharField(_('failure reason'), max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
