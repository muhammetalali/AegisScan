from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import uuid
from typing import Any, Mapping

from fastapi_app.contracts.governed_execution import GovernedExecutionEnvelope
from fastapi_app.services.capability_registry import Capability
from fastapi_app.services.wstg_observation_lineage import wstg_observation_lineage


CONTRACT_VERSION = '1.0'
_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')


@dataclass(frozen=True)
class GovernedExecutionDraft:
    policy_version: str
    actor_ref: str
    tenant_scope_ref: str
    project_ref: str
    asset_ref: str
    requested_capability_id: str
    capability_id: str
    methodology_refs: tuple[str, ...]
    allowed_options: dict[str, Any]
    credential_bindings: tuple[str, ...]
    runner_profile: str
    execution_mode: str
    risk_class: str
    depth: str
    idempotency_key: str
    correlation_id: str
    idempotency_fingerprint: str


def _fingerprint(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _normalized_optional_ref(name: str, value: str | None) -> str:
    normalized = str(value or '').strip()
    if not normalized:
        return ''
    if not _ID_RE.fullmatch(normalized):
        raise ValueError(f'{name} contains unsupported characters or exceeds 128 characters')
    return normalized


def _methodology_refs(capability_id: str) -> tuple[str, ...]:
    lineage = wstg_observation_lineage(capability_id)
    return tuple(sorted({
        str(item['wstg_id'])
        for item in lineage.get('tests', [])
        if isinstance(item, dict) and item.get('wstg_id')
    }))


def prepare_governed_execution_draft(
    *,
    policy_version: str,
    actor_id: str,
    project_id: str,
    asset_id: str,
    requested_capability_id: str,
    capability: Capability,
    allowed_options: Mapping[str, Any],
    credential_refs: list[str] | tuple[str, ...],
    depth: str,
    idempotency_key: str | None,
    correlation_id: str | None,
) -> GovernedExecutionDraft:
    if not capability.runner_profile:
        raise ValueError(f'Capability {capability.id} has no authoritative runner profile')

    normalized_idempotency = _normalized_optional_ref('idempotency_key', idempotency_key)
    normalized_correlation = _normalized_optional_ref('correlation_id', correlation_id)
    if not normalized_correlation:
        normalized_correlation = f'exec-{uuid.uuid4()}'

    methodology_refs = _methodology_refs(capability.id)
    credentials = tuple(sorted(str(item).strip() for item in credential_refs if str(item).strip()))
    options = dict(allowed_options)

    material = {
        'contract_version': CONTRACT_VERSION,
        'policy_version': policy_version,
        'actor_ref': f'user:{actor_id}',
        'tenant_scope_ref': f'project:{project_id}',
        'project_ref': f'project:{project_id}',
        'asset_ref': f'asset:{asset_id}',
        'requested_capability_id': requested_capability_id,
        'capability_id': capability.id,
        'methodology_refs': list(methodology_refs),
        'allowed_options': options,
        'credential_bindings': list(credentials),
        'runner_profile': capability.runner_profile,
        'execution_mode': capability.execution_mode,
        'risk_class': capability.risk,
        'depth': depth,
    }

    return GovernedExecutionDraft(
        policy_version=policy_version,
        actor_ref=material['actor_ref'],
        tenant_scope_ref=material['tenant_scope_ref'],
        project_ref=material['project_ref'],
        asset_ref=material['asset_ref'],
        requested_capability_id=requested_capability_id,
        capability_id=capability.id,
        methodology_refs=methodology_refs,
        allowed_options=options,
        credential_bindings=credentials,
        runner_profile=capability.runner_profile,
        execution_mode=capability.execution_mode,
        risk_class=capability.risk,
        depth=depth,
        idempotency_key=normalized_idempotency,
        correlation_id=normalized_correlation,
        idempotency_fingerprint=_fingerprint(material),
    )


def finalize_governed_execution_contract(
    draft: GovernedExecutionDraft,
    *,
    authorization_id: str,
) -> tuple[dict[str, Any], str]:
    authorization_ref = f'authorization:{authorization_id}'
    policy_material = {
        'contract_version': CONTRACT_VERSION,
        'policy_version': draft.policy_version,
        'actor_ref': draft.actor_ref,
        'tenant_scope_ref': draft.tenant_scope_ref,
        'project_ref': draft.project_ref,
        'asset_ref': draft.asset_ref,
        'authorization_ref': authorization_ref,
        'requested_capability_id': draft.requested_capability_id,
        'capability_id': draft.capability_id,
        'methodology_refs': list(draft.methodology_refs),
        'allowed_options': draft.allowed_options,
        'credential_bindings': list(draft.credential_bindings),
        'runner_profile': draft.runner_profile,
        'execution_mode': draft.execution_mode,
        'risk_class': draft.risk_class,
        'depth': draft.depth,
    }
    policy_fingerprint = _fingerprint(policy_material)
    envelope = GovernedExecutionEnvelope(
        **policy_material,
        idempotency_key=draft.idempotency_key or None,
        correlation_id=draft.correlation_id,
        idempotency_fingerprint=draft.idempotency_fingerprint,
        policy_fingerprint=policy_fingerprint,
    )
    payload = envelope.model_dump(mode='json')
    return payload, _fingerprint(payload)
