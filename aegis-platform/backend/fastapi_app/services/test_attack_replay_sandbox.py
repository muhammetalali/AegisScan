from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.evidence.models import Evidence
from django_project.users.models import User
from enterprise.attack_replay_models import AttackReplayRun, AttackReplayScenario
from enterprise.models import OrganizationMembership
from fastapi_app.services.attack_replay_sandbox import (
    ATTACK_REPLAY_ISOLATION_CONTRACT,
    AttackReplayAuthorizationError,
    AttackReplayConflict,
    AttackReplayError,
    create_attack_replay_scenario,
    run_attack_replay,
)
from fastapi_app.services.test_validated_attack_chain import _fixture
from fastapi_app.services.validated_attack_chain import validate_attack_path


pytestmark = pytest.mark.django_db(transaction=True)


def _validated(marker: str = 'replay'):
    data = _fixture(f'{marker}-attack-replay')
    validation, created = validate_attack_path(
        organization=data['organization'],
        project=data['project'],
        attack_path_id=str(data['path'].id),
        threat_model_snapshot_id=str(data['threat_model'].id),
        scenario_refs=['CHAIN-001'],
        evidence_ids=data['evidence_ids'],
        crown_jewel_asset_ids=[str(data['crown'].id)],
        max_depth=3,
        actor_id=str(data['user'].id),
    )
    assert created is True
    return data, validation


def _expected():
    return [
        {'control_id': 'control:segmentation', 'expected': 'detected'},
        {'control_id': 'control:edr', 'expected': 'prevented'},
    ]


def _scenario(data, validation, marker: str = 'base'):
    return create_attack_replay_scenario(
        project_id=str(data['project'].id),
        actor_id=str(data['user'].id),
        attack_path_validation_id=str(validation.id),
        expected_controls=_expected(),
        idempotency_key=f'attack-replay-scenario-{marker}',
    )


def _mark_evidence(evidence: Evidence, mapping: dict[str, str]) -> None:
    evidence.metadata = {
        **(evidence.metadata or {}),
        'replay_controls': dict(mapping),
        'replay_isolation': 'deterministic-simulation',
    }
    evidence.save(update_fields=['metadata', 'sha256'])


def _observed(data):
    _mark_evidence(data['evidence'], {'control:segmentation': 'detected'})
    _mark_evidence(data['middle_evidence'], {'control:edr': 'prevented'})
    return [
        {
            'control_id': 'control:segmentation',
            'observed': 'detected',
            'evidence_ids': [str(data['evidence'].id)],
        },
        {
            'control_id': 'control:edr',
            'observed': 'prevented',
            'evidence_ids': [str(data['middle_evidence'].id)],
        },
    ]


def test_replay_scenario_is_validation_pinned_immutable_and_replay_safe():
    data, validation = _validated('scenario')
    first = _scenario(data, validation, 'same')
    second = _scenario(data, validation, 'same')

    assert first.replayed is False
    assert second.replayed is True
    assert second.scenario.id == first.scenario.id
    row = first.scenario
    assert row.attack_path_validation_id == validation.id
    assert row.source_snapshot['validation_sha256'] == validation.validation_sha256
    assert row.source_snapshot['attack_path_id'] == str(data['path'].id)
    assert row.isolation_contract == ATTACK_REPLAY_ISOLATION_CONTRACT
    assert row.isolation_contract['network'] == 'deny'
    assert row.isolation_contract['credentials'] == 'none'
    assert row.isolation_contract['external_side_effects'] is False
    assert len(row.scenario_sha256) == 64

    with pytest.raises(ValidationError):
        AttackReplayScenario.objects.filter(pk=row.id).update(expected_controls=[])
    with pytest.raises(ValidationError):
        row.delete()

    with pytest.raises(AttackReplayConflict, match='idempotency key'):
        create_attack_replay_scenario(
            project_id=str(data['project'].id),
            actor_id=str(data['user'].id),
            attack_path_validation_id=str(validation.id),
            expected_controls=[{'control_id': 'control:segmentation', 'expected': 'prevented'}],
            idempotency_key='attack-replay-scenario-same',
        )


def test_replay_run_is_evidence_backed_deterministic_and_side_effect_free():
    data, validation = _validated('run')
    scenario = _scenario(data, validation, 'run').scenario
    observed = _observed(data)

    first = run_attack_replay(
        project_id=str(data['project'].id),
        scenario_id=str(scenario.id),
        actor_id=str(data['user'].id),
        observed_controls=observed,
        idempotency_key='attack-replay-run-same',
    )
    second = run_attack_replay(
        project_id=str(data['project'].id),
        scenario_id=str(scenario.id),
        actor_id=str(data['user'].id),
        observed_controls=observed,
        idempotency_key='attack-replay-run-same',
    )

    assert first.replayed is False
    assert second.replayed is True
    assert second.run.id == first.run.id
    row = first.run
    assert row.outcome == AttackReplayRun.Outcome.MATCHED
    assert row.result_snapshot['matched_controls'] == 2
    assert row.result_snapshot['divergent_controls'] == 0
    assert row.result_snapshot['match_ratio'] == 1.0
    assert row.result_snapshot['external_side_effects'] is False
    assert row.result_snapshot['production_execution_performed'] is False
    assert row.result_snapshot['network_access_performed'] is False
    assert row.result_snapshot['credentials_used'] is False
    assert len(row.input_sha256) == 64
    assert len(row.result_sha256) == 64
    assert len(row.comparison_sha256) == 64

    with pytest.raises(ValidationError):
        AttackReplayRun.objects.filter(pk=row.id).update(outcome='diverged')
    with pytest.raises(ValidationError):
        row.delete()


def test_replay_divergence_is_explicit_and_missing_observation_is_not_observed():
    data, validation = _validated('diverged')
    scenario = _scenario(data, validation, 'diverged').scenario
    _mark_evidence(data['evidence'], {'control:segmentation': 'allowed'})

    result = run_attack_replay(
        project_id=str(data['project'].id),
        scenario_id=str(scenario.id),
        actor_id=str(data['user'].id),
        observed_controls=[{
            'control_id': 'control:segmentation',
            'observed': 'allowed',
            'evidence_ids': [str(data['evidence'].id)],
        }],
        idempotency_key='attack-replay-run-diverged',
    ).run

    assert result.outcome == AttackReplayRun.Outcome.DIVERGED
    comparison = {item['control_id']: item for item in result.result_snapshot['comparison']}
    assert comparison['control:segmentation']['matches'] is False
    assert comparison['control:edr']['observed'] == 'not_observed'
    assert comparison['control:edr']['matches'] is False


def test_replay_rejects_evidence_without_explicit_control_proof():
    data, validation = _validated('unproven')
    scenario = _scenario(data, validation, 'unproven').scenario

    with pytest.raises(AttackReplayError, match='does not declare replay_controls'):
        run_attack_replay(
            project_id=str(data['project'].id),
            scenario_id=str(scenario.id),
            actor_id=str(data['user'].id),
            observed_controls=[{
                'control_id': 'control:segmentation',
                'observed': 'detected',
                'evidence_ids': [str(data['evidence'].id)],
            }],
            idempotency_key='attack-replay-run-unproven',
        )
    assert AttackReplayRun.objects.count() == 0


def test_replay_rejects_cross_tenant_evidence_and_read_only_role():
    data, validation = _validated('tenant-a')
    scenario = _scenario(data, validation, 'tenant-a').scenario
    other, _other_validation = _validated('tenant-b')
    _mark_evidence(other['evidence'], {'control:segmentation': 'detected'})

    with pytest.raises(AttackReplayAuthorizationError, match='project boundary'):
        run_attack_replay(
            project_id=str(data['project'].id),
            scenario_id=str(scenario.id),
            actor_id=str(data['user'].id),
            observed_controls=[{
                'control_id': 'control:segmentation',
                'observed': 'detected',
                'evidence_ids': [str(other['evidence'].id)],
            }],
            idempotency_key='attack-replay-cross-tenant',
        )

    membership = OrganizationMembership.objects.get(
        organization=data['organization'],
        user=data['user'],
    )
    membership.role = OrganizationMembership.Role.VIEWER
    membership.save(update_fields=['role', 'updated_at'])

    with pytest.raises(AttackReplayAuthorizationError, match='enterprise replay role'):
        create_attack_replay_scenario(
            project_id=str(data['project'].id),
            actor_id=str(data['user'].id),
            attack_path_validation_id=str(validation.id),
            expected_controls=_expected(),
            idempotency_key='attack-replay-viewer-denied',
        )


def test_replay_run_rejects_control_claim_that_evidence_does_not_prove():
    data, validation = _validated('mismatch')
    scenario = _scenario(data, validation, 'mismatch').scenario
    _mark_evidence(data['evidence'], {'control:segmentation': 'detected'})

    with pytest.raises(AttackReplayError, match='does not prove'):
        run_attack_replay(
            project_id=str(data['project'].id),
            scenario_id=str(scenario.id),
            actor_id=str(data['user'].id),
            observed_controls=[{
                'control_id': 'control:segmentation',
                'observed': 'prevented',
                'evidence_ids': [str(data['evidence'].id)],
            }],
            idempotency_key='attack-replay-evidence-mismatch',
        )


def test_attack_replay_api_rejects_raw_execution_payloads():
    data, validation = _validated('api')
    client = data.get('client')
    if client is None:
        from fastapi.testclient import TestClient
        from fastapi_app.main import app
        client = TestClient(app)
        client.cookies.clear()
        pytest.skip('Validated attack-chain fixture does not provide authenticated API client.')

    response = client.post(
        f"/api/v1/attack-replay/projects/{data['project'].id}/scenarios",
        json={
            'attack_path_validation_id': str(validation.id),
            'expected_controls': _expected(),
            'idempotency_key': 'attack-replay-api',
            'raw_command': 'curl https://example.invalid',
        },
    )
    assert response.status_code == 422
