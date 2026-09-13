from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise.models import OrganizationMembership
from fastapi_app.contracts.governed_operations import (
    ActionMode,
    ActorLayer,
    CapabilityManifest,
    DecisionPacket,
    EntityRef,
    GateResult,
    GateState,
    GateType,
    ProjectionSnapshot,
)
from fastapi_app.services.governed_operations import (
    ACTION_CONTRACTS,
    build_manifest,
    evaluate_action,
    get_action_contract,
    list_action_contracts,
    registry_summary,
)


def _pass(gate: GateType) -> GateResult:
    return GateResult(gate=gate, state=GateState.PASS, policy_version='test-policy.v1')


def _responsibilities(action_id: str) -> set[str]:
    return set(get_action_contract(action_id).required_responsibilities)


def test_action_ids_are_unique_and_contracts_are_auditable():
    contracts = list_action_contracts()
    assert contracts
    assert len(contracts) == len(ACTION_CONTRACTS)
    assert len({item.action_id for item in contracts}) == len(contracts)
    for item in contracts:
        assert item.policy_version
        assert item.audit_event
        assert item.entity_type
        assert item.allowed_states
        assert item.allowed_roles
        assert item.actor_layers
        assert item.required_responsibilities


def test_contract_roles_are_real_organization_membership_roles():
    canonical_roles = set(OrganizationMembership.Role.values)
    assert canonical_roles == {'owner', 'admin', 'manager', 'analyst', 'auditor', 'viewer'}
    for item in list_action_contracts():
        assert set(item.allowed_roles) <= canonical_roles, item.action_id


def test_wrong_role_is_hidden():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='verified',
        actor_role='analyst',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.HIDDEN
    assert item.reason_code == 'ACTOR_NOT_ELIGIBLE'


def test_wrong_operating_layer_is_hidden():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='verified',
        actor_role='owner',
        actor_layer=ActorLayer.OPERATE,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.HIDDEN
    assert item.reason_code == 'ACTOR_NOT_ELIGIBLE'


def test_missing_governed_responsibility_is_hidden():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='verified',
        actor_role='owner',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=set(),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.HIDDEN
    assert item.reason_code == 'RESPONSIBILITY_NOT_ASSIGNED'
    assert item.missing_requirements == ['closure_approver']


def test_wrong_state_is_blocked_with_actionable_reason():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='confirmed',
        actor_role='owner',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.BLOCKED
    assert item.reason_code == 'STATE_PRECONDITION_UNMET'
    assert item.missing_requirements


def test_sod_violation_is_blocked():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='verified',
        actor_role='owner',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready=True,
        sod_eligible=False,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.BLOCKED
    assert item.reason_code == 'SOD_VIOLATION'
    assert 'actor_must_not_be_remediation_verifier' in item.missing_requirements


def test_missing_evidence_is_blocked_before_gate_execution():
    contract = get_action_contract('finding.confirm')
    item = evaluate_action(
        contract,
        current_state='pending_confirmation',
        actor_role='analyst',
        actor_layer=ActorLayer.ASSURE,
        actor_responsibilities=_responsibilities('finding.confirm'),
        evidence_ready=False,
        sod_eligible=True,
        gate_results=[_pass(GateType.EVIDENCE)],
    )
    assert item.mode is ActionMode.BLOCKED
    assert item.reason_code == 'EVIDENCE_NOT_READY'
    assert 'finding_confirmation_evidence' in item.missing_requirements


def test_missing_required_gate_is_blocked():
    contract = get_action_contract('campaign.complete')
    item = evaluate_action(
        contract,
        current_state='active',
        actor_role='manager',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('campaign.complete'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.AUTHORIZATION), _pass(GateType.CLOSURE)],
    )
    assert item.mode is ActionMode.BLOCKED
    assert item.reason_code == 'GATE_NOT_SATISFIED'
    assert 'evidence' in item.missing_requirements


def test_explicit_failing_gate_is_blocked_and_explained():
    contract = get_action_contract('integration.live_accept')
    failed = GateResult(
        gate=GateType.LIVE_ACCEPTANCE,
        state=GateState.FAIL,
        reason_code='VENDOR_ACK_MISSING',
        reason='Vendor acknowledgement has not been captured.',
        missing_requirements=['vendor_ack'],
        policy_version='integration-acceptance.v1',
    )
    item = evaluate_action(
        contract,
        current_state='tested',
        actor_role='admin',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('integration.live_accept'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[failed, _pass(GateType.EVIDENCE)],
    )
    assert item.mode is ActionMode.BLOCKED
    assert item.reason_code == 'GATE_NOT_SATISFIED'
    assert 'live_acceptance:fail' in item.missing_requirements
    assert item.gate_results[0].reason_code == 'VENDOR_ACK_MISSING'


def test_all_required_gates_pass_enables_action():
    contract = get_action_contract('finding.close')
    item = evaluate_action(
        contract,
        current_state='verified',
        actor_role='owner',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready=True,
        sod_eligible=True,
        gate_results=[_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
    )
    assert item.mode is ActionMode.ENABLED
    assert item.reason_code == ''
    assert len(item.gate_results) == 2


def test_manifest_only_projects_actions_for_matching_entity_type():
    manifest = build_manifest(
        entity=EntityRef(entity_type='finding', entity_id='finding-1', project_id='project-1'),
        projection=ProjectionSnapshot(lifecycle='verified', governance='review_required', version=7),
        actor_role='owner',
        actor_layer=ActorLayer.GOVERN,
        actor_responsibilities=_responsibilities('finding.close'),
        evidence_ready_actions={'finding.close'},
        sod_eligible_actions={'finding.close'},
        gate_results_by_action={
            'finding.close': [_pass(GateType.CLOSURE), _pass(GateType.INDEPENDENT_VERIFICATION)],
        },
    )
    assert isinstance(manifest, CapabilityManifest)
    assert manifest.actor_responsibilities == ['closure_approver']
    action_ids = {item.action_id for item in manifest.capabilities}
    assert action_ids
    assert all(get_action_contract(action_id).entity_type == 'finding' for action_id in action_ids)
    close = next(item for item in manifest.capabilities if item.action_id == 'finding.close')
    assert close.mode is ActionMode.ENABLED


def test_registry_summary_exposes_canonical_taxonomy():
    summary = registry_summary()
    assert summary['contract_version'] == 'agom.v1'
    assert summary['policy_version'] == 'agom-governance.v1'
    assert summary['action_count'] == len(ACTION_CONTRACTS)
    assert set(summary['gate_types']) == {item.value for item in GateType}
    assert set(summary['actor_layers']) == {item.value for item in ActorLayer}


def test_contract_schemas_forbid_unknown_fields():
    with pytest.raises(ValidationError):
        EntityRef(entity_type='finding', entity_id='f-1', invented_authority=True)
    with pytest.raises(ValidationError):
        DecisionPacket(
            entity=EntityRef(entity_type='finding', entity_id='f-1'),
            current_projection=ProjectionSnapshot(lifecycle='verified'),
            requested_action='finding.close',
            sod_eligible=True,
            client_asserted_role='owner',
        )
