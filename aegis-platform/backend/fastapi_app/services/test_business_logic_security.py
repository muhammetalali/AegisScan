from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from enterprise.governed_action_models import BusinessLogicAssessment
from fastapi_app.services.business_logic_security import assess_governed_action_request
from fastapi_app.services.governed_operations import get_action_contract
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_governed_asset_authorization import (
    _approver,
    _execute,
    _ownerize,
    _proposer,
    _request,
)


pytestmark = pytest.mark.django_db(transaction=True)


def _revoke_request(disposition_fixture, marker: str):
    _client, owner, project, asset, _initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    proposer = _proposer(
        project=project,
        organization=organization,
        marker=f'{marker}-proposer',
    )
    approver = _approver(
        owner=owner,
        project=project,
        organization=organization,
        marker=f'{marker}-approver',
    )
    parameters = {'reason': f'Governed business logic assessment {marker}.'}
    request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker=marker,
    )
    return owner, project, asset, organization, proposer, approver, parameters, request


def test_current_request_passes_all_generic_workflow_invariants(disposition_fixture):
    _owner, _project, _asset, _organization, _proposer, approver, _parameters, request = _revoke_request(
        disposition_fixture,
        'pass',
    )

    first = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )
    second = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )

    assert first.assessment.decision == BusinessLogicAssessment.Decision.PASSED
    assert first.assessment.reason_codes == []
    assert all(item['status'] == 'pass' for item in first.assessment.invariant_results)
    assert first.replayed is False
    assert second.replayed is True
    assert second.assessment.id == first.assessment.id
    assert len(first.assessment.assessment_sha256) == 64

    with pytest.raises(ValidationError):
        BusinessLogicAssessment.objects.filter(pk=first.assessment.id).update(decision='blocked')
    with pytest.raises(ValidationError):
        first.assessment.delete()


def test_self_approval_is_exposed_as_business_logic_block(disposition_fixture):
    _client, owner, project, asset, _initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    approver = _approver(
        owner=owner,
        project=project,
        organization=organization,
        marker='self-approval',
    )
    parameters = {'reason': 'Self approval must be rejected by generic workflow assurance.'}
    request = _request(
        project=project,
        asset=asset,
        proposer=approver,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='self-approval',
    )

    result = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )

    assert result.assessment.decision == BusinessLogicAssessment.Decision.BLOCKED
    assert 'CURRENT_CAPABILITY_BLOCKED' in result.assessment.reason_codes
    capability = next(
        item for item in result.assessment.invariant_results
        if item['invariant_id'] == 'current_capability'
    )
    assert capability['evidence']['capability_reason_code'] == 'SOD_VIOLATION'


def test_executed_or_stale_request_cannot_pass_reassessment(disposition_fixture):
    _owner, project, asset, _organization, _proposer, approver, parameters, request = _revoke_request(
        disposition_fixture,
        'executed',
    )
    _execute(
        project=project,
        asset=asset,
        approver=approver,
        request=request,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='executed',
    )

    result = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )

    assert result.assessment.decision == BusinessLogicAssessment.Decision.BLOCKED
    assert 'REQUEST_ALREADY_EXECUTED' in result.assessment.reason_codes
    assert 'EXPECTED_VERSION_STALE' in result.assessment.reason_codes


def test_current_contract_drift_blocks_historical_request(disposition_fixture, monkeypatch):
    _owner, _project, _asset, _organization, _proposer, approver, _parameters, request = _revoke_request(
        disposition_fixture,
        'contract-drift',
    )
    original = get_action_contract

    def drifted(action_id: str):
        contract = original(action_id)
        if contract is None:
            return None
        return contract.model_copy(update={'policy_version': 'agom-governance.v999'})

    monkeypatch.setattr(
        'fastapi_app.services.business_logic_security.get_action_contract',
        drifted,
    )

    result = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )

    assert result.assessment.decision == BusinessLogicAssessment.Decision.BLOCKED
    assert 'CONTRACT_DRIFT' in result.assessment.reason_codes


def test_assessment_does_not_mutate_domain_state(disposition_fixture):
    _owner, _project, asset, _organization, _proposer, approver, _parameters, request = _revoke_request(
        disposition_fixture,
        'read-only',
    )
    before_configuration = dict(asset.configuration)
    before_version = request.expected_version

    result = assess_governed_action_request(
        request_id=str(request.id),
        assessed_by_id=str(approver.id),
    )

    asset.refresh_from_db()
    assert result.assessment.decision == BusinessLogicAssessment.Decision.PASSED
    assert asset.configuration == before_configuration
    assert request.expected_version == before_version
