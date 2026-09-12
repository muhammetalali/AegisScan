from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from django.contrib.auth import get_user_model

from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import (
    CredentialVaultDenied,
    assert_no_secret_material,
    authorize_credential_use,
    resolve_credential_secret,
)
from fastapi_app.services.cloud_target import parse_cloud_target

_POLICY_VERSION = 'credential-execution.v4'
_MAX_CREDENTIAL_REFS = 3


def normalize_credential_refs(values: Iterable[Any] | None) -> list[str]:
    if values is None:
        return []
    refs: list[str] = []
    for raw in values:
        value = str(raw or '').strip()
        if not value:
            continue
        try:
            value = str(uuid.UUID(value))
        except ValueError as exc:
            raise ValueError('credential_refs must contain UUID credential references only') from exc
        if value not in refs:
            refs.append(value)
    if len(refs) > _MAX_CREDENTIAL_REFS:
        raise ValueError(f'A capability execution may bind at most {_MAX_CREDENTIAL_REFS} credentials')
    return refs


def empty_credential_context() -> dict[str, Any]:
    return {
        'credential_policy_version': _POLICY_VERSION,
        'credential_refs': [],
        'credential_material_handling': 'no-credential-material',
    }


def credential_execution_context(metadata: list[dict[str, Any]], *, resolved: bool) -> dict[str, Any]:
    return {
        'credential_policy_version': _POLICY_VERSION,
        'credential_refs': metadata,
        'credential_material_handling': 'worker-resolved-redacted' if resolved else 'reference-authorized-only',
    }


def _actor(actor_id: Any):
    try:
        return get_user_model().objects.get(pk=actor_id)
    except get_user_model().DoesNotExist as exc:  # type: ignore[attr-defined]
        raise CredentialVaultDenied('Credential actor is not available.') from exc


def _credentials_for_project(project_id: Any, refs: list[str]) -> dict[str, CredentialSecret]:
    credentials = CredentialSecret.objects.filter(project_id=project_id, id__in=refs)
    return {str(credential.id): credential for credential in credentials}


def _record_denied(
    *, credential: CredentialSecret, actor: Any, purpose: str, reason: str, metadata: Mapping[str, Any] | None = None
) -> None:
    CredentialAccess.objects.create(
        credential=credential,
        project=credential.project,
        actor=actor,
        operation=CredentialAccess.Operation.AUTHORIZE_USE,
        result=CredentialAccess.Result.DENIED,
        purpose=purpose[:200],
        reason=reason[:500],
        metadata=dict(metadata or {}),
        ip_address='127.0.0.1',
        user_agent='',
    )


def _validate_kind(
    *, credential: CredentialSecret, actor: Any, purpose: str, allowed_kinds: tuple[str, ...]
) -> None:
    if allowed_kinds and credential.kind not in allowed_kinds:
        _record_denied(
            credential=credential,
            actor=actor,
            purpose=purpose,
            reason='credential kind is not allowed for this capability',
            metadata={'credential_ref': str(credential.id), 'kind': credential.kind, 'allowed_kinds': list(allowed_kinds)},
        )
        raise CredentialVaultDenied('Credential reference is not allowed for this capability.')


def _canonical_api_server(value: str) -> str:
    parsed = urlsplit(str(value or '').strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme != 'https' or not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Kubernetes API server scope must be an absolute HTTPS URL')
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError('Kubernetes API server scope contains an invalid port') from exc
    authority = host if port == 443 else f'{host}:{port}'
    return urlunsplit(('https', authority, parsed.path.rstrip('/'), '', ''))


def _canonical_web_origin(value: str) -> str:
    parsed = urlsplit(str(value or '').strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme not in {'http', 'https'} or not host or parsed.username or parsed.password:
        raise ValueError('Browser credential scope must be an absolute HTTP(S) origin')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Browser credential scope contains an invalid port') from exc
    default_port = 80 if scheme == 'http' else 443
    authority = host if port in {None, default_port} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


_PROTOCOL_SECURITY_CAPABILITIES = {
    'websocket.security-validation',
    'graphql.security-validation',
    'cross-protocol.security-validation',
    'identity-protocol.security-validation',
    'http-protocol.security-validation',
}


def _canonical_protocol_origin(value: str) -> str:
    parsed = urlsplit(str(value or '').strip())
    scheme = parsed.scheme.lower()
    if scheme == 'ws':
        scheme = 'http'
    elif scheme == 'wss':
        scheme = 'https'
    host = (parsed.hostname or '').lower().rstrip('.')
    if scheme not in {'http', 'https'} or not host or parsed.username or parsed.password:
        raise ValueError('Protocol credential scope must be an absolute HTTP(S)/WS(S) origin')
    if parsed.path not in {'', '/'} or parsed.query or parsed.fragment:
        raise ValueError('Protocol credential scope must contain origin only')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Protocol credential scope contains an invalid port') from exc
    default_port = 80 if scheme == 'http' else 443
    authority = host if port in {None, default_port} else f'{host}:{port}'
    return urlunsplit((scheme, authority, '', '', ''))


def _protocol_identity_binding(credential: CredentialSecret) -> str:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    raw = str(scope.get('protocol_identity_ref') or '').strip()
    if not raw or len(raw) > 255 or any(ch in raw for ch in '\r\n\x00'):
        raise CredentialVaultDenied('Protocol credential identity binding is missing or invalid.')
    return raw


def _validate_protocol_scope(
    *,
    credential: CredentialSecret,
    actor: Any,
    purpose: str,
    target: str,
    identity_ref: str,
) -> None:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    scoped_origin = str(scope.get('protocol_origin') or '').strip()
    try:
        expected = _canonical_protocol_origin(scoped_origin)
        actual = _canonical_protocol_origin(target)
    except ValueError:
        expected = ''
        actual = ''
    try:
        bound_identity = _protocol_identity_binding(credential)
    except CredentialVaultDenied:
        bound_identity = ''
    origin_matches = bool(expected and actual and expected == actual)
    identity_matches = bool(identity_ref and bound_identity == identity_ref)
    if origin_matches and identity_matches:
        return
    _record_denied(
        credential=credential,
        actor=actor,
        purpose=purpose,
        reason='protocol credential scope or identity binding does not match the governed request',
        metadata={
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'scope_type': 'protocol_origin+identity',
            'scope_matches_target': origin_matches,
            'identity_binding_matches': identity_matches,
        },
    )
    raise CredentialVaultDenied(
        'Protocol credential is not scoped to this target origin and identity.'
    )


def _browser_identity_binding(credential: CredentialSecret) -> str:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    raw = str(scope.get('browser_identity_ref') or '').strip()
    if raw:
        if len(raw) > 255 or any(ch in raw for ch in '\r\n\x00'):
            raise CredentialVaultDenied('Browser credential identity binding is invalid.')
        return raw
    return f'credential:{credential.id}'


def _validate_browser_scope(*, credential: CredentialSecret, actor: Any, purpose: str, target: str) -> None:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    scoped_origin = str(scope.get('browser_origin') or '').strip()
    try:
        expected = _canonical_web_origin(scoped_origin)
        actual = _canonical_web_origin(target)
    except ValueError:
        expected = ''
        actual = ''
    if expected and actual and expected == actual:
        return
    _record_denied(
        credential=credential,
        actor=actor,
        purpose=purpose,
        reason='browser session credential scope does not match the authorized target origin',
        metadata={
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'scope_type': 'browser_origin',
            'scope_matches_target': False,
        },
    )
    raise CredentialVaultDenied('Browser session credential is not scoped to this authorized target origin.')


def _validate_kube_scope(*, credential: CredentialSecret, actor: Any, purpose: str, target: str) -> None:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    scoped_target = str(scope.get('api_server') or '').strip()
    try:
        expected = _canonical_api_server(scoped_target)
        actual = _canonical_api_server(target)
    except ValueError:
        expected = ''
        actual = ''
    if expected and actual and expected == actual:
        return
    _record_denied(
        credential=credential,
        actor=actor,
        purpose=purpose,
        reason='kubeconfig credential scope does not match the authorized cluster target',
        metadata={
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'scope_type': 'api_server',
            'scope_matches_target': False,
        },
    )
    raise CredentialVaultDenied('Kubeconfig credential is not scoped to this authorized cluster target.')


def _validate_cloud_scope(*, credential: CredentialSecret, actor: Any, purpose: str, target: str) -> None:
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    try:
        cloud_target = parse_cloud_target(target)
    except ValueError:
        cloud_target = None
    provider = str(scope.get('provider') or '').strip().lower()
    expected_identifier = ''
    scope_key = ''
    if cloud_target is not None:
        scope_key = cloud_target.scope_key
        expected_identifier = str(scope.get(scope_key) or '').strip().lower()
    if (
        cloud_target is not None
        and provider == cloud_target.provider
        and expected_identifier == cloud_target.identifier
    ):
        return
    _record_denied(
        credential=credential,
        actor=actor,
        purpose=purpose,
        reason='cloud credential scope does not match the authorized provider target',
        metadata={
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'scope_type': 'cloud-provider-target',
            'scope_provider': provider[:20],
            'scope_identifier_key': scope_key,
            'scope_matches_target': False,
        },
    )
    raise CredentialVaultDenied('Cloud credential is not scoped to this authorized provider target.')


def _validate_scope(
    *,
    credential: CredentialSecret,
    actor: Any,
    purpose: str,
    target: str,
    capability_id: str,
    identity_ref: str = '',
) -> None:
    if capability_id == 'browser.spa-discovery':
        _validate_browser_scope(
            credential=credential,
            actor=actor,
            purpose=purpose,
            target=target,
        )
    elif capability_id in _PROTOCOL_SECURITY_CAPABILITIES:
        _validate_protocol_scope(
            credential=credential,
            actor=actor,
            purpose=purpose,
            target=target,
            identity_ref=identity_ref,
        )
    elif credential.kind == CredentialSecret.Kind.KUBECONFIG:
        _validate_kube_scope(credential=credential, actor=actor, purpose=purpose, target=target)
    elif credential.kind == CredentialSecret.Kind.CLOUD_ACCESS_KEY:
        _validate_cloud_scope(credential=credential, actor=actor, purpose=purpose, target=target)


def authorize_credential_refs_for_execution(
    *,
    project_id: Any,
    actor_id: Any,
    refs: Iterable[Any] | None,
    capability_id: str,
    allowed_kinds: tuple[str, ...] = (),
    purpose: str | None = None,
    target: str = '',
    identity_ref: str = '',
) -> dict[str, Any]:
    normalized_refs = normalize_credential_refs(refs)
    if not normalized_refs:
        return empty_credential_context()
    actor = _actor(actor_id)
    credentials = _credentials_for_project(project_id, normalized_refs)
    metadata: list[dict[str, Any]] = []
    purpose_value = purpose or f'capability:{capability_id}:authorize'
    for ref in normalized_refs:
        credential = credentials.get(ref)
        if credential is None:
            raise CredentialVaultDenied('Credential reference is not available for this project.')
        _validate_kind(credential=credential, actor=actor, purpose=purpose_value, allowed_kinds=allowed_kinds)
        _validate_scope(
            credential=credential,
            actor=actor,
            purpose=purpose_value,
            target=target,
            capability_id=capability_id,
            identity_ref=identity_ref,
        )
        authorized = authorize_credential_use(credential=credential, actor=actor, purpose=purpose_value)
        item = {'credential_ref': str(authorized.id), 'kind': authorized.kind, 'version': authorized.version}
        if capability_id == 'browser.spa-discovery':
            item['browser_identity_ref'] = _browser_identity_binding(authorized)
        elif capability_id in _PROTOCOL_SECURITY_CAPABILITIES:
            item['protocol_identity_ref'] = _protocol_identity_binding(authorized)
        metadata.append(item)
    return credential_execution_context(metadata, resolved=False)


def resolve_credential_refs_for_worker(
    *,
    project_id: Any,
    actor_id: Any,
    refs: Iterable[Any] | None,
    capability_id: str,
    allowed_kinds: tuple[str, ...] = (),
    purpose: str | None = None,
    target: str = '',
    identity_ref: str = '',
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    normalized_refs = normalize_credential_refs(refs)
    if not normalized_refs:
        return (), empty_credential_context()
    actor = _actor(actor_id)
    credentials = _credentials_for_project(project_id, normalized_refs)
    purpose_value = purpose or f'capability:{capability_id}:worker-resolve'
    materials: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    for ref in normalized_refs:
        credential = credentials.get(ref)
        if credential is None:
            raise CredentialVaultDenied('Credential reference is not available for this project.')
        _validate_kind(credential=credential, actor=actor, purpose=purpose_value, allowed_kinds=allowed_kinds)
        _validate_scope(
            credential=credential,
            actor=actor,
            purpose=purpose_value,
            target=target,
            capability_id=capability_id,
            identity_ref=identity_ref,
        )
        secret = resolve_credential_secret(credential=credential, actor=actor, purpose=purpose_value)
        credential.refresh_from_db(fields=['kind', 'version'])
        material = {
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'version': credential.version,
            'secret': secret,
        }
        if capability_id == 'browser.spa-discovery':
            material['browser_identity_ref'] = _browser_identity_binding(credential)
        elif capability_id in _PROTOCOL_SECURITY_CAPABILITIES:
            material['protocol_identity_ref'] = _protocol_identity_binding(credential)
        materials.append(material)
        item = {key: material[key] for key in ('credential_ref', 'kind', 'version')}
        if capability_id == 'browser.spa-discovery':
            item['browser_identity_ref'] = material['browser_identity_ref']
        elif capability_id in _PROTOCOL_SECURITY_CAPABILITIES:
            item['protocol_identity_ref'] = material['protocol_identity_ref']
        metadata.append(item)
    context = credential_execution_context(metadata, resolved=True)
    assert_no_credential_material_leaked(materials, context)
    return tuple(materials), context


def _browser_session_sensitive_values(secret: str) -> tuple[str, ...]:
    try:
        data = json.loads(secret)
    except (TypeError, json.JSONDecodeError):
        return ()
    if not isinstance(data, dict):
        return ()
    allowed = {'headers', 'cookies', 'local_storage', 'session_storage'}
    if not data or set(data) - allowed:
        return ()

    values: list[str] = []
    headers = data.get('headers')
    if isinstance(headers, dict):
        values.extend(str(value) for value in headers.values() if value not in {None, ''})
        authorization = next(
            (
                str(value)
                for name, value in headers.items()
                if str(name).lower() == 'authorization' and value not in {None, ''}
            ),
            '',
        )
        if authorization:
            parts = authorization.split(None, 1)
            if len(parts) == 2 and parts[1]:
                values.append(parts[1])

    cookies = data.get('cookies')
    if isinstance(cookies, list):
        for cookie in cookies:
            if isinstance(cookie, dict) and cookie.get('value') not in {None, ''}:
                values.append(str(cookie['value']))

    for key in ('local_storage', 'session_storage'):
        storage = data.get(key)
        if isinstance(storage, dict):
            values.extend(str(value) for value in storage.values() if value not in {None, ''})

    return tuple(dict.fromkeys(values))


def assert_no_credential_material_leaked(materials: Iterable[Mapping[str, Any]], *payloads: Any) -> None:
    for material in materials:
        secret = str(material.get('secret') or '')
        assert_no_secret_material(secret, *payloads)
        for nested_secret in _browser_session_sensitive_values(secret):
            assert_no_secret_material(nested_secret, *payloads)
