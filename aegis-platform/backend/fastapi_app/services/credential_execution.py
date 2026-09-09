from __future__ import annotations

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

_POLICY_VERSION = 'credential-execution.v2'
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


def _validate_scope(
    *, credential: CredentialSecret, actor: Any, purpose: str, target: str
) -> None:
    if credential.kind != CredentialSecret.Kind.KUBECONFIG:
        return
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    scoped_target = str(scope.get('api_server') or '').strip()
    try:
        expected = _canonical_api_server(scoped_target)
        actual = _canonical_api_server(target)
    except ValueError:
        expected = ''
        actual = ''
    if not expected or not actual or expected != actual:
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


def authorize_credential_refs_for_execution(
    *,
    project_id: Any,
    actor_id: Any,
    refs: Iterable[Any] | None,
    capability_id: str,
    allowed_kinds: tuple[str, ...] = (),
    purpose: str | None = None,
    target: str = '',
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
        _validate_scope(credential=credential, actor=actor, purpose=purpose_value, target=target)
        authorized = authorize_credential_use(credential=credential, actor=actor, purpose=purpose_value)
        metadata.append({'credential_ref': str(authorized.id), 'kind': authorized.kind, 'version': authorized.version})
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
        _validate_scope(credential=credential, actor=actor, purpose=purpose_value, target=target)
        secret = resolve_credential_secret(credential=credential, actor=actor, purpose=purpose_value)
        credential.refresh_from_db(fields=['kind', 'version'])
        material = {
            'credential_ref': str(credential.id),
            'kind': credential.kind,
            'version': credential.version,
            'secret': secret,
        }
        materials.append(material)
        metadata.append({key: material[key] for key in ('credential_ref', 'kind', 'version')})
    context = credential_execution_context(metadata, resolved=True)
    assert_no_credential_material_leaked(materials, context)
    return tuple(materials), context


def assert_no_credential_material_leaked(materials: Iterable[Mapping[str, Any]], *payloads: Any) -> None:
    for material in materials:
        assert_no_secret_material(str(material.get('secret') or ''), *payloads)
