from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
import uuid


class CredentialSecretQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Credential secrets must be rotated or revoked through the vault service.')

    def delete(self):
        raise ValidationError('Credential secrets cannot be bulk deleted; revoke them instead.')

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError('Credential secrets must be rotated or revoked through the vault service.')


class CredentialSecretManager(models.Manager.from_queryset(CredentialSecretQuerySet)):
    pass


class CredentialSecret(models.Model):
    """Encrypted, project-scoped secret material addressed only by reference."""

    class Kind(models.TextChoices):
        PASSWORD = 'password', _('Password')
        API_KEY = 'api_key', _('API Key')
        TOKEN = 'token', _('Token')
        SSH_PRIVATE_KEY = 'ssh_private_key', _('SSH Private Key')
        CLOUD_ACCESS_KEY = 'cloud_access_key', _('Cloud Access Key')
        GENERIC = 'generic', _('Generic Secret')

    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        REVOKED = 'revoked', _('Revoked')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey('projects.Project', on_delete=models.CASCADE, related_name='credential_secrets')
    name = models.CharField(_('name'), max_length=200)
    kind = models.CharField(_('kind'), max_length=30, choices=Kind.choices, default=Kind.GENERIC)
    status = models.CharField(_('status'), max_length=20, choices=Status.choices, default=Status.ACTIVE)
    scope = models.JSONField(_('scope'), default=dict, blank=True)
    encrypted_secret = models.TextField(_('encrypted secret'))
    secret_fingerprint = models.CharField(_('secret fingerprint'), max_length=64)
    version = models.PositiveIntegerField(_('version'), default=1)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_credential_secrets')
    rotated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='rotated_credential_secrets')
    revoked_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='revoked_credential_secrets')
    last_used_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='used_credential_secrets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    rotated_at = models.DateTimeField(_('rotated at'), null=True, blank=True)
    revoked_at = models.DateTimeField(_('revoked at'), null=True, blank=True)
    last_used_at = models.DateTimeField(_('last used at'), null=True, blank=True)

    objects = CredentialSecretManager()

    class Meta:
        verbose_name = _('Credential Secret')
        verbose_name_plural = _('Credential Secrets')
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['project', 'status', 'kind'], name='sys_cred_prj_status_kind_idx'),
            models.Index(fields=['project', 'name'], name='sys_cred_prj_name_idx'),
            models.Index(fields=['secret_fingerprint'], name='sys_cred_fp_idx'),
            models.Index(fields=['last_used_at'], name='sys_cred_last_used_idx'),
        ]
        constraints = [
            models.UniqueConstraint(fields=['project', 'name'], name='sys_cred_project_name_uniq'),
        ]

    def __str__(self):
        return f'{self.project_id}:{self.name}:{self.kind}:{self.status}'

    def delete(self, *args, **kwargs):
        raise ValidationError('Credential secrets cannot be deleted; revoke them instead.')


class CredentialAccessQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValidationError('Credential access records are append-only and cannot be updated.')

    def delete(self):
        raise ValidationError('Credential access records are append-only and cannot be deleted.')

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError('Credential access records are append-only and cannot be updated.')


class CredentialAccess(models.Model):
    """Append-only vault access ledger that never stores secret material."""

    class Operation(models.TextChoices):
        CREATE = 'create', _('Create')
        ROTATE = 'rotate', _('Rotate')
        REVOKE = 'revoke', _('Revoke')
        AUTHORIZE_USE = 'authorize_use', _('Authorize Use')
        RESOLVE_INTERNAL = 'resolve_internal', _('Resolve Internal')

    class Result(models.TextChoices):
        SUCCESS = 'success', _('Success')
        DENIED = 'denied', _('Denied')
        FAILURE = 'failure', _('Failure')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(CredentialSecret, on_delete=models.PROTECT, related_name='access_events')
    project = models.ForeignKey('projects.Project', on_delete=models.PROTECT, related_name='credential_access_events')
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='credential_access_events')
    operation = models.CharField(_('operation'), max_length=30, choices=Operation.choices)
    result = models.CharField(_('result'), max_length=20, choices=Result.choices)
    purpose = models.CharField(_('purpose'), max_length=200)
    reason = models.CharField(_('reason'), max_length=500, blank=True)
    metadata = models.JSONField(_('metadata'), default=dict, blank=True)
    request_id = models.UUIDField(_('request ID'), default=uuid.uuid4)
    ip_address = models.GenericIPAddressField(_('IP address'), default='127.0.0.1')
    user_agent = models.TextField(_('user agent'), blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = CredentialAccessQuerySet.as_manager()

    class Meta:
        verbose_name = _('Credential Access')
        verbose_name_plural = _('Credential Access Events')
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['credential', '-created_at'], name='sys_ca_cred_created_idx'),
            models.Index(fields=['project', '-created_at'], name='sys_ca_project_created_idx'),
            models.Index(fields=['actor', '-created_at'], name='sys_ca_actor_created_idx'),
            models.Index(fields=['operation', 'result', '-created_at'], name='sys_ca_op_result_idx'),
            models.Index(fields=['request_id'], name='sys_ca_request_idx'),
        ]

    def __str__(self):
        return f'{self.credential_id}:{self.operation}:{self.result}'

    def save(self, *args, **kwargs):
        if self.pk and type(self).objects.filter(pk=self.pk).exists():
            raise ValidationError('Credential access records are append-only and cannot be updated.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError('Credential access records are append-only and cannot be deleted.')
