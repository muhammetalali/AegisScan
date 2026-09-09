from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from django_project.audit.services import client_ip_from_request
from django_project.system.credential_models import CredentialAccess, CredentialSecret


class CredentialVaultError(Exception):
    """Base exception for governed credential vault operations."""


class CredentialVaultUnavailable(CredentialVaultError):
    """Raised when vault keys are missing or malformed."""


class CredentialVaultDenied(CredentialVaultError):
    """Raised when a credential reference cannot be used."""


_SECRET_FIELD_NAMES = {
    'secret', 'password', 'token', 'api_key', 'apikey', 'authorization', 'private_key',
    'access_key', 'secret_key', 'credential', 'credentials', 'bearer', 'cookie',
}
_MISSING = object()


def _explicit_setting(name: str) -> object:
    return getattr(settings, name, _MISSING)


def _setting_preferred_value(name: str) -> str:
    configured = _explicit_setting(name)
    if configured is _MISSING:
        return os.environ.get(name, '')
    return str(configured or '')


def _derive_development_key() -> bytes:
    seed = f"aegis-development-credential-vault:{settings.SECRET_KEY}".encode('utf-8')
    return base64.urlsafe_b64encode(hashlib.sha256(seed).digest())


def _configured_vault_keys() -> list[bytes]:
    configured = _setting_preferred_value('CREDENTIAL_VAULT_KEYS')
    if not configured:
        if getattr(settings, 'DEBUG', False):
            return [_derive_development_key()]
        raise CredentialVaultUnavailable('CREDENTIAL_VAULT_KEYS must be configured before credential secrets can be used.')

    keys: list[bytes] = []
    for raw in configured.split(','):
        value = raw.strip()
        if not value:
            continue
        try:
            # Fernet validates key shape at construction time.
            Fernet(value.encode('utf-8'))
        except Exception as exc:  # pragma: no cover - exact cryptography exception is version dependent
            raise CredentialVaultUnavailable('CREDENTIAL_VAULT_KEYS contains an invalid Fernet key.') from exc
        keys.append(value.encode('utf-8'))
    if not keys:
        raise CredentialVaultUnavailable('CREDENTIAL_VAULT_KEYS did not contain any usable keys.')
    return keys


def _fernet() -> MultiFernet:
    return MultiFernet([Fernet(key) for key in _configured_vault_keys()])


def _fingerprint_key() -> bytes:
    configured = _setting_preferred_value('CREDENTIAL_FINGERPRINT_KEY')
    if configured:
        return configured.encode('utf-8')
    fallback = getattr(settings, 'JWT_SECRET_KEY', '') or getattr(settings, 'SECRET_KEY', '')
    if fallback:
        return fallback.encode('utf-8')
    return _configured_vault_keys()[0]


def credential_fingerprint(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValidationError('Credential secret must be a non-empty string.')
    return hmac.new(_fingerprint_key(), secret.encode('utf-8'), hashlib.sha256).hexdigest()


def encrypt_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValidationError('Credential secret must be a non-empty string.')
    return _fernet().encrypt(secret.encode('utf-8')).decode('ascii')


def decrypt_secret(encrypted_secret: str) -> str:
    try:
        return _fernet().decrypt(encrypted_secret.encode('ascii')).decode('utf-8')
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise CredentialVaultUnavailable('Credential secret cannot be decrypted with the configured vault keys.') from exc


def _request_context(request: Any | None) -> dict[str, str]:
    if request is None:
        return {'ip_address': '127.0.0.1', 'user_agent': ''}
    return {
        'ip_address': client_ip_from_request(request),
        'user_agent': getattr(request, 'META', {}).get('HTTP_USER_AGENT', ''),
    }


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(marker in key_text for marker in _SECRET_FIELD_NAMES):
                redacted[key] = '[redacted]'
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _append_access(
    *,
    credential: CredentialSecret,
    actor: Any,
    operation: str,
    result: str,
    purpose: str,
    reason: str = '',
    metadata: Mapping[str, Any] | None = None,
    request: Any | None = None,
) -> CredentialAccess:
    context = _request_context(request)
    return CredentialAccess.objects.create(
        credential=credential,
        project=credential.project,
        actor=actor,
        operation=operation,
        result=result,
        purpose=purpose[:200],
        reason=reason[:500],
        metadata=_redact(dict(metadata or {})),
        ip_address=context['ip_address'],
        user_agent=context['user_agent'],
    )


def assert_no_secret_material(secret: str, *payloads: Any) -> None:
    for payload in payloads:
        rendered = json.dumps(payload, default=str, sort_keys=True) if not isinstance(payload, str) else payload
        if secret and secret in rendered:
            raise AssertionError('Secret material leaked into a non-secret payload.')


@transaction.atomic
def create_credential_secret(
    *,
    project: Any,
    actor: Any,
    name: str,
    kind: str,
    secret: str,
    scope: Mapping[str, Any] | None = None,
    request: Any | None = None,
) -> CredentialSecret:
    encrypted = encrypt_secret(secret)
    credential = CredentialSecret.objects.create(
        project=project,
        name=name.strip(),
        kind=kind,
        scope=dict(scope or {}),
        encrypted_secret=encrypted,
        secret_fingerprint=credential_fingerprint(secret),
        created_by=actor,
    )
    access = _append_access(
        credential=credential,
        actor=actor,
        operation=CredentialAccess.Operation.CREATE,
        result=CredentialAccess.Result.SUCCESS,
        purpose='credential-create',
        metadata={'scope_keys': sorted((scope or {}).keys()), 'kind': kind},
        request=request,
    )
    assert_no_secret_material(secret, credential.encrypted_secret, access.metadata, access.reason, access.user_agent)
    return credential


def rotate_credential_secret(*, credential: CredentialSecret, actor: Any, secret: str, request: Any | None = None) -> CredentialSecret:
    with transaction.atomic():
        credential = CredentialSecret.objects.select_for_update().get(pk=credential.pk)
        if credential.status == CredentialSecret.Status.ACTIVE:
            credential.encrypted_secret = encrypt_secret(secret)
            credential.secret_fingerprint = credential_fingerprint(secret)
            credential.version += 1
            credential.rotated_by = actor
            credential.rotated_at = timezone.now()
            credential.save(update_fields=['encrypted_secret', 'secret_fingerprint', 'version', 'rotated_by', 'rotated_at', 'updated_at'])
            access = _append_access(
                credential=credential,
                actor=actor,
                operation=CredentialAccess.Operation.ROTATE,
                result=CredentialAccess.Result.SUCCESS,
                purpose='credential-rotate',
                metadata={'version': credential.version},
                request=request,
            )
            assert_no_secret_material(secret, credential.encrypted_secret, access.metadata, access.reason)
            return credential
        _append_access(
            credential=credential,
            actor=actor,
            operation=CredentialAccess.Operation.ROTATE,
            result=CredentialAccess.Result.DENIED,
            purpose='credential-rotate',
            reason='revoked credentials cannot be rotated',
            request=request,
        )
    # Exit the transaction normally before raising, so the denial is retained.
    raise CredentialVaultDenied('Revoked credentials cannot be rotated.')


@transaction.atomic
def revoke_credential_secret(*, credential: CredentialSecret, actor: Any, request: Any | None = None, reason: str = '') -> CredentialSecret:
    credential = CredentialSecret.objects.select_for_update().get(pk=credential.pk)
    if credential.status != CredentialSecret.Status.REVOKED:
        credential.status = CredentialSecret.Status.REVOKED
        credential.revoked_by = actor
        credential.revoked_at = timezone.now()
        credential.save(update_fields=['status', 'revoked_by', 'revoked_at', 'updated_at'])
    _append_access(
        credential=credential,
        actor=actor,
        operation=CredentialAccess.Operation.REVOKE,
        result=CredentialAccess.Result.SUCCESS,
        purpose='credential-revoke',
        reason=reason,
        request=request,
    )
    return credential


def _authorize_credential_use_locked(
    *, credential: CredentialSecret, actor: Any, purpose: str, request: Any | None = None
) -> bool:
    """Record an authorization decision while the caller holds the row lock.

    Return a denial instead of raising inside the caller's transaction. The
    public service raises only after that transaction has exited successfully.
    """
    if credential.status != CredentialSecret.Status.ACTIVE:
        _append_access(
            credential=credential,
            actor=actor,
            operation=CredentialAccess.Operation.AUTHORIZE_USE,
            result=CredentialAccess.Result.DENIED,
            purpose=purpose,
            reason='credential revoked',
            request=request,
        )
        return False
    credential.last_used_by = actor
    credential.last_used_at = timezone.now()
    credential.save(update_fields=['last_used_by', 'last_used_at', 'updated_at'])
    _append_access(
        credential=credential,
        actor=actor,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.SUCCESS,
        purpose=purpose,
        metadata={'credential_ref': str(credential.id), 'kind': credential.kind, 'version': credential.version},
        request=request,
    )
    return True


def authorize_credential_use(
    *, credential: CredentialSecret, actor: Any, purpose: str, request: Any | None = None
) -> CredentialSecret:
    with transaction.atomic():
        credential = CredentialSecret.objects.select_for_update().get(pk=credential.pk)
        if _authorize_credential_use_locked(credential=credential, actor=actor, purpose=purpose, request=request):
            return credential
    raise CredentialVaultDenied('Credential is revoked.')


def resolve_credential_secret(
    *, credential: CredentialSecret, actor: Any, purpose: str, request: Any | None = None
) -> str:
    with transaction.atomic():
        # Resolve the current database version under the same lock used by
        # rotation/revocation; a cached model instance cannot bypass revocation.
        credential = CredentialSecret.objects.select_for_update().get(pk=credential.pk)
        if _authorize_credential_use_locked(credential=credential, actor=actor, purpose=purpose, request=request):
            plaintext = decrypt_secret(credential.encrypted_secret)
            access = _append_access(
                credential=credential,
                actor=actor,
                operation=CredentialAccess.Operation.RESOLVE_INTERNAL,
                result=CredentialAccess.Result.SUCCESS,
                purpose=purpose,
                metadata={'credential_ref': str(credential.id), 'version': credential.version},
                request=request,
            )
            assert_no_secret_material(plaintext, access.metadata, access.reason, access.user_agent)
            return plaintext
    raise CredentialVaultDenied('Credential is revoked.')
