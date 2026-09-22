from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.projects.models import Project
from enterprise.agentic_security_models import AgenticActionDecision, AgenticSecurityProfile
from enterprise.models import TenantProject
from fastapi_app.services.agentic_security import (
    AGENTIC_CAPABILITY_ID,
    AgenticSecurityAuthorizationError,
    AgenticSecurityConflict,
    authorize_agentic_action,
    register_agentic_profile,
)
from fastapi_app.services.provider_approval import record_provider_decision
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)

SHA_A = 'a' * 64
SHA_B = 'b' * 64
SHA_C = 'c' * 64


def _provider_manifest(marker: str = 'base') -> dict:
    return {
        'license': 'enterprise-test',
        'maintenance': {'status': 'active'},
        'sbom': True,
        'supply_chain_integrity': True,
        'sbom_sha256': SHA_A,
        'provenance_sha256': SHA_B,
        'artifact_sha256': SHA_C,
        'signature_identity': 'https://github.com/example/agent-provider/.github/workflows/release.yml@refs/tags/v1',
        'signature_verified': True,
        'container_privileges': [],
        'network_permissions': ['authorized-target-only'],
        'determinism': True,
        'evidence_quality': True,
        'ci_reproducibility': True,
        'unmitigated_critical_cves': [],
        'review_marker': marker,
    }


def _provider(disposition_fixture, marker: str = 'base', *, status: str = 'approved'):
    _client, user, project, *_rest = disposition_fixture
    return record_provider_decision(
        project_id=str(project.id),
        actor_id=str(user.id),
        provider_name='enterprise-agent-runtime',
        provider_version='2026.9',
        capability=AGENTIC_CAPABILITY_ID,
        status=status,
        manifest=_provider_manifest(marker),
        rationale=f'agentic provider {marker}',
    ).decision


def _profile(disposition_fixture, marker: str = 'base'):
    _client, user, project, *_rest = disposition_fixture
    provider = _provider(disposition_fixture, marker)
    return register_agentic_profile(
        project_id=str(project.id),
        actor_id=str(user.id),
        provider_decision_id=str(provider.id),
        agent_name='security-investigation-agent',
        agent_version='1.0.0',
        model_name='enterprise-security-model',
        model_version='2026.9',
        allowed_tools={
            'risk.read': ['read'],
            'security.search': ['query'],
        },
        data_boundaries={
            'allowed_labels': ['internal', 'public', 'security.finding'],
            'denied_labels': ['credential.raw', 'secret'],
            'max_prompt_chars': 4096,
        },
        prompt_policy={
            'blocked_risk_signals': [
                'credential_request',
                'data_exfiltration',
                'jailbreak',
                'policy_override',
                'prompt_injection',
                'tool_escalation',
            ],
            'human_approval_required_tools': ['security.search'],
        },
        idempotency_key=f'agentic-profile-{marker}',
    )


def _action(disposition_fixture, profile, marker: str = 'base', **overrides):
    _client, user, project, *_rest = disposition_fixture
    values = {
        'project_id': str(project.id),
        'profile_id': str(profile.id),
        'actor_id': str(user.id),
        'tool_name': 'security.search',
        'operation': 'query',
        'prompt_sha256': 'd' * 64,
        'prompt_length': 250,
        'arguments_sha256': 'e' * 64,
        'argument_keys': ['query', 'scope'],
        'data_labels': ['internal', 'security.finding'],
        'risk_signals': [],
        'human_approval_ref': 'approval:human-review-1',
        'idempotency_key': f'agentic-action-{marker}',
    }
    values.update(overrides)
    return authorize_agentic_action(**values)


def test_agentic_profile_is_provider_bound_immutable_and_replay_safe(disposition_fixture):
    first = _profile(disposition_fixture, 'profile-replay')
    _client, user, project, *_rest = disposition_fixture
    provider_id = first.profile.provider_governance_decision_id
    second = register_agentic_profile(
        project_id=str(project.id),
        actor_id=str(user.id),
        provider_decision_id=str(provider_id),
        agent_name='security-investigation-agent',
        agent_version='1.0.0',
        model_name='enterprise-security-model',
        model_version='2026.9',
        allowed_tools={'risk.read': ['read'], 'security.search': ['query']},
        data_boundaries={
            'allowed_labels': ['internal', 'public', 'security.finding'],
            'denied_labels': ['credential.raw', 'secret'],
            'max_prompt_chars': 4096,
        },
        prompt_policy={
            'blocked_risk_signals': [
                'credential_request', 'data_exfiltration', 'jailbreak',
                'policy_override', 'prompt_injection', 'tool_escalation',
            ],
            'human_approval_required_tools': ['security.search'],
        },
        idempotency_key='agentic-profile-profile-replay',
    )

    assert first.replayed is False
    assert second.replayed is True
    assert second.profile.id == first.profile.id
    assert first.profile.capability == AGENTIC_CAPABILITY_ID
    assert first.profile.prompt_policy['raw_prompt_storage'] is False
    assert first.profile.prompt_policy['raw_argument_storage'] is False
    assert len(first.profile.profile_sha256) == 64

    with pytest.raises(ValidationError):
        AgenticSecurityProfile.objects.filter(pk=first.profile.id).update(agent_name='mutated')
    with pytest.raises(ValidationError):
        first.profile.delete()


def test_allowed_action_creates_redacted_immutable_decision_evidence(disposition_fixture):
    profile = _profile(disposition_fixture, 'allowed').profile
    result = _action(disposition_fixture, profile, 'allowed')

    assert result.allowed is True
    row = result.decision
    assert row.decision == AgenticActionDecision.Decision.ALLOWED
    assert row.reason_codes == []
    assert len(row.evidence_sha256) == 64
    assert len(row.decision_sha256) == 64
    assert row.evidence_snapshot['raw_prompt_captured'] is False
    assert row.evidence_snapshot['raw_arguments_captured'] is False
    assert row.evidence_snapshot['prompt_sha256'] == 'd' * 64
    assert row.evidence_snapshot['arguments_sha256'] == 'e' * 64
    assert 'prompt' not in row.evidence_snapshot
    assert 'arguments' not in row.evidence_snapshot

    repeated = _action(disposition_fixture, profile, 'allowed')
    assert repeated.replayed is True
    assert repeated.decision.id == row.id

    with pytest.raises(ValidationError):
        AgenticActionDecision.objects.filter(pk=row.id).update(decision='denied')
    with pytest.raises(ValidationError):
        row.delete()


def test_agentic_policy_denies_tool_data_risk_and_missing_human_approval(disposition_fixture):
    profile = _profile(disposition_fixture, 'deny').profile
    denied = _action(
        disposition_fixture,
        profile,
        'deny',
        tool_name='admin.shell',
        operation='exec',
        data_labels=['secret'],
        risk_signals=['prompt_injection', 'tool_escalation'],
        human_approval_ref='',
    ).decision

    assert denied.decision == AgenticActionDecision.Decision.DENIED
    assert set(denied.reason_codes) == {
        'DATA_LABEL_DENIED',
        'DATA_LABEL_NOT_ALLOWED',
        'RISK_SIGNAL_BLOCKED',
        'TOOL_NOT_ALLOWED',
    }

    no_human = _action(
        disposition_fixture,
        profile,
        'no-human',
        tool_name='security.search',
        operation='query',
        data_labels=['internal'],
        risk_signals=[],
        human_approval_ref='',
    ).decision
    assert no_human.decision == AgenticActionDecision.Decision.DENIED
    assert no_human.reason_codes == ['HUMAN_APPROVAL_REQUIRED']


def test_provider_revocation_blocks_existing_agent_profile_fail_closed(disposition_fixture):
    profile = _profile(disposition_fixture, 'provider-revoke').profile
    _client, user, project, *_rest = disposition_fixture
    record_provider_decision(
        project_id=str(project.id),
        actor_id=str(user.id),
        provider_name='enterprise-agent-runtime',
        provider_version='2026.9',
        capability=AGENTIC_CAPABILITY_ID,
        status='revoked',
        manifest=_provider_manifest('provider-revoke'),
        rationale='revoke provider before action authorization',
    )

    denied = _action(
        disposition_fixture,
        profile,
        'provider-revoked',
        tool_name='risk.read',
        operation='read',
        data_labels=['internal'],
        human_approval_ref='',
    ).decision
    assert denied.decision == AgenticActionDecision.Decision.DENIED
    assert 'PROVIDER_NOT_ADMISSIBLE' in denied.reason_codes


def test_agentic_profile_and_action_are_tenant_project_isolated(disposition_fixture):
    profile = _profile(disposition_fixture, 'tenant').profile
    _client, user, project, *_rest = disposition_fixture
    organization = project.tenant_link.organization
    other = Project.objects.create(
        name='Agentic Isolation Project',
        slug=f'agentic-isolation-{str(project.id)[:8]}',
        owner=user,
    )
    TenantProject.objects.create(organization=organization, project=other)

    with pytest.raises(AgenticSecurityAuthorizationError, match='was not found'):
        authorize_agentic_action(
            project_id=str(other.id),
            profile_id=str(profile.id),
            actor_id=str(user.id),
            tool_name='risk.read',
            operation='read',
            prompt_sha256='f' * 64,
            prompt_length=20,
            arguments_sha256='1' * 64,
            argument_keys=['finding_id'],
            data_labels=['internal'],
            risk_signals=[],
            human_approval_ref='',
            idempotency_key='cross-project-agentic-action',
        )


def test_agentic_api_rejects_raw_prompt_and_raw_arguments(disposition_fixture):
    client, _user, project, *_rest = disposition_fixture
    provider = _provider(disposition_fixture, 'api')
    profile_response = client.post(
        f'/api/v1/agentic-security/projects/{project.id}/profiles',
        json={
            'provider_decision_id': str(provider.id),
            'agent_name': 'api-agent',
            'agent_version': '1.0.0',
            'model_name': 'enterprise-security-model',
            'model_version': '2026.9',
            'allowed_tools': {'risk.read': ['read']},
            'data_boundaries': {
                'allowed_labels': ['internal'],
                'denied_labels': ['secret'],
                'max_prompt_chars': 2048,
            },
            'prompt_policy': {
                'blocked_risk_signals': ['prompt_injection'],
                'human_approval_required_tools': [],
            },
            'idempotency_key': 'agentic-api-profile',
        },
    )
    assert profile_response.status_code == 201, profile_response.text
    profile_id = profile_response.json()['id']

    rejected = client.post(
        f'/api/v1/agentic-security/projects/{project.id}/profiles/{profile_id}/actions',
        json={
            'tool_name': 'risk.read',
            'operation': 'read',
            'prompt_sha256': '2' * 64,
            'prompt_length': 32,
            'arguments_sha256': '3' * 64,
            'argument_keys': ['finding_id'],
            'data_labels': ['internal'],
            'risk_signals': [],
            'human_approval_ref': '',
            'idempotency_key': 'agentic-api-action-rejected',
            'raw_prompt': 'do not persist me',
            'raw_arguments': {'finding_id': 'secret-value'},
        },
    )
    assert rejected.status_code == 422

    accepted = client.post(
        f'/api/v1/agentic-security/projects/{project.id}/profiles/{profile_id}/actions',
        json={
            'tool_name': 'risk.read',
            'operation': 'read',
            'prompt_sha256': '2' * 64,
            'prompt_length': 32,
            'arguments_sha256': '3' * 64,
            'argument_keys': ['finding_id'],
            'data_labels': ['internal'],
            'risk_signals': [],
            'human_approval_ref': '',
            'idempotency_key': 'agentic-api-action-accepted',
        },
    )
    assert accepted.status_code == 201, accepted.text
    body = accepted.json()
    assert body['allowed'] is True
    assert body['decision'] == 'allowed'
    assert body['evidence_sha256']
    assert body['decision_sha256']


def test_agentic_idempotency_conflict_is_fail_closed(disposition_fixture):
    profile = _profile(disposition_fixture, 'idem-conflict').profile
    _action(disposition_fixture, profile, 'same-idem')
    with pytest.raises(AgenticSecurityConflict, match='idempotency key'):
        _action(
            disposition_fixture,
            profile,
            'same-idem',
            prompt_sha256='9' * 64,
        )
