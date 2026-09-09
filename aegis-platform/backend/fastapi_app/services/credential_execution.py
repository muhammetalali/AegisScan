from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping
from typing import Any

from django.contrib.auth import get_user_model

from django_project.system.credential_models import CredentialAccess, CredentialSecret
from django_project.system.credential_vault import (
    CredentialVaultDenied,
    assert_no_secret_material,
    authorize_credential_use,
    resolve_credential_secret,
)

_POLICY_VERSION = 'credential-execution.v1'
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


def authorize_credential_refs_for_execution(
    *,
    project_id: Any,
    actor_id: Any,
    refs: Iterable[Any] | None,
    capability_id: str,
    allowed_kinds: tuple[str, ...] = (),
    purpose: str | None = None,
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
