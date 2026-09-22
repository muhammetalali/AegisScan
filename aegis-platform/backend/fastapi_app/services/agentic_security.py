from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.utils import timezone

from django_project.projects.models import Project, ProjectMembership
from enterprise.agentic_security_models import AgenticActionDecision, AgenticSecurityProfile
from enterprise.models import Organization, OrganizationMembership, TenantProject
from enterprise.provider_approval_models import ProviderApprovalDecision

from .audit_writer import add_audit_entry
from .provider_approval import evaluate_provider_admissibility


AGENTIC_POLICY_VERSION = 'agentic-security.v1'
AGENTIC_CAPABILITY_ID = 'ai.agent.runtime'

_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,179}$')
_VERSION_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,119}$')
_TOOL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}$')
_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
_LABEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,99}$')

_BLOCKABLE_SIGNALS = {
    'prompt_injection',
    'jailbreak',
    'data_exfiltration',
    'tool_escalation',
    'policy_override',
    'cross_tenant_reference',
    'credential_request',
}


class AgenticSecurityError(ValueError):
    pass


class AgenticSecurityAuthorizationError(AgenticSecurityError):
    pass


class AgenticSecurityConflict(AgenticSecurityError):
    pass


@dataclass(frozen=True)
class AgenticProfileResult:
    profile: AgenticSecurityProfile
    replayed: bool


@dataclass(frozen=True)
class AgenticActionResult:
    decision: AgenticActionDecision
    replayed: bool

    @property
    def allowed(self) -> bool:
        return self.decision.decision == AgenticActionDecision.Decision.ALLOWED


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    normalized = ' '.join(str(value or '').split())
    if not normalized:
        raise AgenticSecurityError(f'{field} is required.')
    if len(normalized) > maximum or any(ch in normalized for ch in '\r\n\x00'):
        raise AgenticSecurityError(f'{field} is invalid.')
    if pattern is not None and not pattern.fullmatch(normalized):
        raise AgenticSecurityError(f'{field} contains unsupported characters.')
    return normalized


def _optional_text(value: Any, *, field: str, maximum: int) -> str:
    normalized = ' '.join(str(value or '').split())
    if len(normalized) > maximum or any(ch in normalized for ch in '\r\n\x00'):
        raise AgenticSecurityError(f'{field} is invalid.')
    return normalized


def _digest(value: Any, *, field: str) -> str:
    normalized = str(value or '').strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise AgenticSecurityError(f'{field} must be a lowercase SHA-256 digest.')
    return normalized


def _normalized_list(values: Any, *, field: str, maximum_items: int, maximum_length: int, pattern: re.Pattern[str] | None = None) -> list[str]:
    if not isinstance(values, list):
        raise AgenticSecurityError(f'{field} must be a list.')
    if len(values) > maximum_items:
        raise AgenticSecurityError(f'{field} exceeds the maximum item count.')
    result: list[str] = []
    for raw in values:
        value = ' '.join(str(raw or '').split())
        if not value or len(value) > maximum_length or any(ch in value for ch in '\r\n\x00'):
            raise AgenticSecurityError(f'{field} contains an invalid value.')
        if pattern is not None and not pattern.fullmatch(value):
            raise AgenticSecurityError(f'{field} contains unsupported characters.')
        if value not in result:
            result.append(value)
    return sorted(result)


def _allowed_tools(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict) or not value:
        raise AgenticSecurityError('allowed_tools must be a non-empty object.')
    if len(value) > 64:
        raise AgenticSecurityError('allowed_tools exceeds the maximum tool count.')
    normalized: dict[str, list[str]] = {}
    for raw_tool, raw_operations in value.items():
        tool = _text(raw_tool, field='tool_name', maximum=180, pattern=_TOOL_RE)
        operations = _normalized_list(
            raw_operations,
            field=f'allowed_tools[{tool}]',
            maximum_items=64,
            maximum_length=180,
            pattern=_TOOL_RE,
        )
        if not operations:
            raise AgenticSecurityError(f'allowed_tools[{tool}] requires at least one operation.')
        normalized[tool] = operations
    return dict(sorted(normalized.items()))


def _data_boundaries(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgenticSecurityError('data_boundaries must be an object.')
    unknown = sorted(set(value) - {'allowed_labels', 'denied_labels', 'max_prompt_chars'})
    if unknown:
        raise AgenticSecurityError(f'Unsupported data_boundaries fields: {unknown}.')
    allowed = _normalized_list(
        value.get('allowed_labels'),
        field='allowed_labels',
        maximum_items=128,
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    denied = _normalized_list(
        value.get('denied_labels', []),
        field='denied_labels',
        maximum_items=128,
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    if not allowed:
        raise AgenticSecurityError('data_boundaries.allowed_labels must not be empty.')
    if set(allowed).intersection(denied):
        raise AgenticSecurityError('A data label cannot be both allowed and denied.')
    try:
        max_prompt_chars = int(value.get('max_prompt_chars'))
    except (TypeError, ValueError) as exc:
        raise AgenticSecurityError('data_boundaries.max_prompt_chars must be an integer.') from exc
    if not 1 <= max_prompt_chars <= 200000:
        raise AgenticSecurityError('data_boundaries.max_prompt_chars is outside the supported range.')
    return {
        'allowed_labels': allowed,
        'denied_labels': denied,
        'max_prompt_chars': max_prompt_chars,
    }


def _prompt_policy(value: Any, *, allowed_tools: dict[str, list[str]]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgenticSecurityError('prompt_policy must be an object.')
    unknown = sorted(set(value) - {'blocked_risk_signals', 'human_approval_required_tools'})
    if unknown:
        raise AgenticSecurityError(f'Unsupported prompt_policy fields: {unknown}.')
    blocked = _normalized_list(
        value.get('blocked_risk_signals', []),
        field='blocked_risk_signals',
        maximum_items=len(_BLOCKABLE_SIGNALS),
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    unsupported = sorted(set(blocked) - _BLOCKABLE_SIGNALS)
    if unsupported:
        raise AgenticSecurityError(f'Unsupported agentic risk signals: {unsupported}.')
    human_tools = _normalized_list(
        value.get('human_approval_required_tools', []),
        field='human_approval_required_tools',
        maximum_items=64,
        maximum_length=180,
        pattern=_TOOL_RE,
    )
    unknown_tools = sorted(set(human_tools) - set(allowed_tools))
    if unknown_tools:
        raise AgenticSecurityError(
            f'human_approval_required_tools contains tools outside allowed_tools: {unknown_tools}.'
        )
    return {
        'blocked_risk_signals': blocked,
        'human_approval_required_tools': human_tools,
        'require_prompt_digest': True,
        'raw_prompt_storage': False,
        'raw_argument_storage': False,
    }


def _active_context(*, project_id: str, actor_id: str, policy_admin: bool):
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        raise AgenticSecurityAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise AgenticSecurityAuthorizationError('Enterprise tenant is inactive.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=identity['id'], organization=organization, project_id=project_id)
        .first()
    )
    if link is None:
        raise AgenticSecurityAuthorizationError('Tenant/project binding changed.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise AgenticSecurityAuthorizationError('Project was not found.')

    if policy_admin:
        project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
            project=project,
            user_id=actor_id,
            role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
        ).exists()
        org_roles = [
            OrganizationMembership.Role.OWNER,
            OrganizationMembership.Role.ADMIN,
            OrganizationMembership.Role.MANAGER,
        ]
    else:
        project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
            project=project,
            user_id=actor_id,
            role__in=[
                ProjectMembership.Role.OWNER,
                ProjectMembership.Role.ADMIN,
                ProjectMembership.Role.MEMBER,
            ],
        ).exists()
        org_roles = [
            OrganizationMembership.Role.OWNER,
            OrganizationMembership.Role.ADMIN,
            OrganizationMembership.Role.MANAGER,
            OrganizationMembership.Role.ANALYST,
        ]

    if not project_allowed:
        raise AgenticSecurityAuthorizationError('Actor lacks required project authority.')
    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
        role__in=org_roles,
    ).exists():
        raise AgenticSecurityAuthorizationError('Actor lacks an active enterprise agentic-security role.')
    return organization, project


def _provider_gate(decision: ProviderApprovalDecision) -> dict[str, Any]:
    return evaluate_provider_admissibility(
        project_id=str(decision.project_id),
        provider_name=decision.provider_name,
        provider_version=decision.provider_version,
        capability=decision.capability,
        expected_legacy_approval_id=(
            str(decision.legacy_approval_id) if decision.legacy_approval_id else None
        ),
        expected_decision_id=str(decision.id),
    )


@transaction.atomic
def register_agentic_profile(
    *,
    project_id: str,
    actor_id: str,
    provider_decision_id: str,
    agent_name: str,
    agent_version: str,
    model_name: str,
    model_version: str,
    allowed_tools: dict[str, Any],
    data_boundaries: dict[str, Any],
    prompt_policy: dict[str, Any],
    idempotency_key: str,
) -> AgenticProfileResult:
    organization, project = _active_context(
        project_id=str(project_id),
        actor_id=str(actor_id),
        policy_admin=True,
    )
    idem = _text(idempotency_key, field='idempotency_key', maximum=128)
    normalized_tools = _allowed_tools(allowed_tools)
    normalized_boundaries = _data_boundaries(data_boundaries)
    normalized_prompt_policy = _prompt_policy(prompt_policy, allowed_tools=normalized_tools)

    provider = (
        ProviderApprovalDecision.objects.select_for_update()
        .filter(pk=provider_decision_id, project=project, organization=organization)
        .first()
    )
    if provider is None:
        raise AgenticSecurityAuthorizationError('Provider governance decision is outside the tenant/project boundary.')
    if provider.capability != AGENTIC_CAPABILITY_ID:
        raise AgenticSecurityAuthorizationError('Provider governance decision does not authorize AI agent runtime.')
    gate = _provider_gate(provider)
    if gate.get('allowed') is not True:
        raise AgenticSecurityAuthorizationError(
            'Agentic provider is not currently admissible: ' + '; '.join(gate.get('failures') or [])
        )

    snapshot = {
        'schema': 'aegis.agentic-security-profile.v1',
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'provider_decision_id': str(provider.id),
        'provider_identity_sha256': provider.provider_identity_sha256,
        'provider_name': provider.provider_name,
        'provider_version': provider.provider_version,
        'capability': AGENTIC_CAPABILITY_ID,
        'agent_name': _text(agent_name, field='agent_name', maximum=180, pattern=_NAME_RE),
        'agent_version': _text(agent_version, field='agent_version', maximum=120, pattern=_VERSION_RE),
        'model_name': _text(model_name, field='model_name', maximum=180, pattern=_NAME_RE),
        'model_version': _text(model_version, field='model_version', maximum=120, pattern=_VERSION_RE),
        'allowed_tools': normalized_tools,
        'data_boundaries': normalized_boundaries,
        'prompt_policy': normalized_prompt_policy,
        'raw_prompt_storage': False,
        'raw_argument_storage': False,
    }
    profile_sha256 = _sha(snapshot)
    request_fingerprint = _sha({
        'project_id': str(project.id),
        'actor_id': str(actor_id),
        'idempotency_key': idem,
        'profile_sha256': profile_sha256,
    })

    existing = AgenticSecurityProfile.objects.filter(
        organization=organization,
        idempotency_key=idem,
    ).first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise AgenticSecurityConflict('Agentic profile idempotency key was reused with different content.')
        return AgenticProfileResult(profile=existing, replayed=True)

    profile = AgenticSecurityProfile.objects.create(
        organization=organization,
        project=project,
        provider_governance_decision=provider,
        created_by_id=actor_id,
        agent_name=snapshot['agent_name'],
        agent_version=snapshot['agent_version'],
        model_name=snapshot['model_name'],
        model_version=snapshot['model_version'],
        provider_name=provider.provider_name,
        provider_version=provider.provider_version,
        capability=AGENTIC_CAPABILITY_ID,
        allowed_tools=normalized_tools,
        data_boundaries=normalized_boundaries,
        prompt_policy=normalized_prompt_policy,
        idempotency_key=idem,
        profile_sha256=profile_sha256,
        request_fingerprint=request_fingerprint,
        policy_version=AGENTIC_POLICY_VERSION,
    )
    add_audit_entry(
        user=actor_id,
        action='agentic.profile.register',
        target=str(profile.id),
        project=str(project.id),
        resource_type='agentic_security_profile',
        resource_repr=profile.agent_name,
        metadata={
            'organization_id': str(organization.id),
            'provider_decision_id': str(provider.id),
            'provider_identity_sha256': provider.provider_identity_sha256,
            'profile_sha256': profile.profile_sha256,
            'policy_version': AGENTIC_POLICY_VERSION,
        },
    )
    return AgenticProfileResult(profile=profile, replayed=False)


@transaction.atomic
def authorize_agentic_action(
    *,
    project_id: str,
    profile_id: str,
    actor_id: str,
    tool_name: str,
    operation: str,
    prompt_sha256: str,
    prompt_length: int,
    arguments_sha256: str,
    argument_keys: list[str],
    data_labels: list[str],
    risk_signals: list[str],
    human_approval_ref: str = '',
    idempotency_key: str,
) -> AgenticActionResult:
    organization, project = _active_context(
        project_id=str(project_id),
        actor_id=str(actor_id),
        policy_admin=False,
    )
    profile = (
        AgenticSecurityProfile.objects.select_for_update()
        .select_related('provider_governance_decision')
        .filter(pk=profile_id, project=project, organization=organization)
        .first()
    )
    if profile is None:
        raise AgenticSecurityAuthorizationError('Agentic security profile was not found in the tenant/project boundary.')
    if profile.policy_version != AGENTIC_POLICY_VERSION:
        raise AgenticSecurityAuthorizationError('Agentic security profile policy version is no longer accepted.')

    tool = _text(tool_name, field='tool_name', maximum=180, pattern=_TOOL_RE)
    op = _text(operation, field='operation', maximum=180, pattern=_TOOL_RE)
    prompt_digest = _digest(prompt_sha256, field='prompt_sha256')
    argument_digest = _digest(arguments_sha256, field='arguments_sha256')
    try:
        normalized_prompt_length = int(prompt_length)
    except (TypeError, ValueError) as exc:
        raise AgenticSecurityError('prompt_length must be an integer.') from exc
    if normalized_prompt_length < 0:
        raise AgenticSecurityError('prompt_length cannot be negative.')

    keys = _normalized_list(
        argument_keys,
        field='argument_keys',
        maximum_items=128,
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    labels = _normalized_list(
        data_labels,
        field='data_labels',
        maximum_items=128,
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    signals = _normalized_list(
        risk_signals,
        field='risk_signals',
        maximum_items=32,
        maximum_length=100,
        pattern=_LABEL_RE,
    )
    unsupported_signals = sorted(set(signals) - _BLOCKABLE_SIGNALS)
    if unsupported_signals:
        raise AgenticSecurityError(f'Unsupported agentic risk signals: {unsupported_signals}.')
    approval_ref = _optional_text(human_approval_ref, field='human_approval_ref', maximum=255)
    idem = _text(idempotency_key, field='idempotency_key', maximum=128)

    provider_gate = _provider_gate(profile.provider_governance_decision)
    reasons: list[str] = []
    if provider_gate.get('allowed') is not True:
        reasons.append('PROVIDER_NOT_ADMISSIBLE')

    allowed_tools = profile.allowed_tools if isinstance(profile.allowed_tools, dict) else {}
    permitted_operations = allowed_tools.get(tool)
    if not isinstance(permitted_operations, list):
        reasons.append('TOOL_NOT_ALLOWED')
    elif op not in permitted_operations:
        reasons.append('OPERATION_NOT_ALLOWED')

    boundaries = profile.data_boundaries if isinstance(profile.data_boundaries, dict) else {}
    allowed_labels = set(boundaries.get('allowed_labels') or [])
    denied_labels = set(boundaries.get('denied_labels') or [])
    if any(label not in allowed_labels for label in labels):
        reasons.append('DATA_LABEL_NOT_ALLOWED')
    if denied_labels.intersection(labels):
        reasons.append('DATA_LABEL_DENIED')
    if normalized_prompt_length > int(boundaries.get('max_prompt_chars') or 0):
        reasons.append('PROMPT_LENGTH_EXCEEDED')

    prompt_policy = profile.prompt_policy if isinstance(profile.prompt_policy, dict) else {}
    blocked_signals = set(prompt_policy.get('blocked_risk_signals') or [])
    if blocked_signals.intersection(signals):
        reasons.append('RISK_SIGNAL_BLOCKED')
    if tool in set(prompt_policy.get('human_approval_required_tools') or []) and not approval_ref:
        reasons.append('HUMAN_APPROVAL_REQUIRED')

    reasons = sorted(set(reasons))
    decision_value = (
        AgenticActionDecision.Decision.ALLOWED
        if not reasons
        else AgenticActionDecision.Decision.DENIED
    )

    evidence_snapshot = {
        'schema': 'aegis.agentic-action-evidence.v1',
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'profile_id': str(profile.id),
        'profile_sha256': profile.profile_sha256,
        'provider_decision_id': str(profile.provider_governance_decision_id),
        'provider_identity_sha256': profile.provider_governance_decision.provider_identity_sha256,
        'provider_gate_allowed': provider_gate.get('allowed') is True,
        'provider_decision_version': provider_gate.get('decision_version'),
        'agent_name': profile.agent_name,
        'agent_version': profile.agent_version,
        'model_name': profile.model_name,
        'model_version': profile.model_version,
        'tool_name': tool,
        'operation': op,
        'prompt_sha256': prompt_digest,
        'prompt_length': normalized_prompt_length,
        'arguments_sha256': argument_digest,
        'argument_keys': keys,
        'data_labels': labels,
        'risk_signals': signals,
        'human_approval_bound': bool(approval_ref),
        'decision': decision_value,
        'reason_codes': reasons,
        'raw_prompt_captured': False,
        'raw_arguments_captured': False,
    }
    evidence_sha256 = _sha(evidence_snapshot)
    request_fingerprint = _sha({
        'profile_id': str(profile.id),
        'actor_id': str(actor_id),
        'idempotency_key': idem,
        'evidence_sha256': evidence_sha256,
    })
    decision_sha256 = _sha({
        'decision': decision_value,
        'reason_codes': reasons,
        'evidence_sha256': evidence_sha256,
        'request_fingerprint': request_fingerprint,
        'policy_version': AGENTIC_POLICY_VERSION,
    })

    existing = AgenticActionDecision.objects.filter(
        profile=profile,
        idempotency_key=idem,
    ).first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise AgenticSecurityConflict('Agentic action idempotency key was reused with different content.')
        return AgenticActionResult(decision=existing, replayed=True)

    row = AgenticActionDecision.objects.create(
        organization=organization,
        project=project,
        profile=profile,
        decided_by_id=actor_id,
        tool_name=tool,
        operation=op,
        prompt_sha256=prompt_digest,
        prompt_length=normalized_prompt_length,
        arguments_sha256=argument_digest,
        argument_keys=keys,
        data_labels=labels,
        risk_signals=signals,
        human_approval_ref=approval_ref,
        decision=decision_value,
        reason_codes=reasons,
        evidence_snapshot=evidence_snapshot,
        evidence_sha256=evidence_sha256,
        decision_sha256=decision_sha256,
        idempotency_key=idem,
        request_fingerprint=request_fingerprint,
        policy_version=AGENTIC_POLICY_VERSION,
    )
    add_audit_entry(
        user=actor_id,
        action=(
            'agentic.action.allow'
            if row.decision == AgenticActionDecision.Decision.ALLOWED
            else 'agentic.action.deny'
        ),
        target=str(row.id),
        project=str(project.id),
        resource_type='agentic_action_decision',
        resource_repr=f'{profile.agent_name}:{tool}:{op}',
        metadata={
            'organization_id': str(organization.id),
            'profile_id': str(profile.id),
            'provider_decision_id': str(profile.provider_governance_decision_id),
            'decision': row.decision,
            'reason_codes': list(row.reason_codes or []),
            'evidence_sha256': row.evidence_sha256,
            'decision_sha256': row.decision_sha256,
            'policy_version': AGENTIC_POLICY_VERSION,
        },
    )
    return AgenticActionResult(decision=row, replayed=False)
