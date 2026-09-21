from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from uuid import uuid4

import pytest
from django.db import close_old_connections

from django_project.assets.models import AssetAuthorization
from django_project.audit.models import AuditLog
from enterprise.governed_action_models import GovernedActionExecution
from fastapi_app.services import governed_action_executor as executor
from fastapi_app.services.asset_authorization_governance import (
    asset_authorization_version,
    govern_asset_authorization,
)
from fastapi_app.services.governed_action_executor import (
    GovernedActionBlocked,
    GovernedActionConflict,
    execute_governed_action,
)
from fastapi_app.services.race_toctou_security import verify_race_toctou_proof
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_governed_asset_authorization import (
    _approver,
    _ownerize,
    _proposer,
    _request,
)


pytestmark = pytest.mark.django_db(transaction=True)


def _race_setup(disposition_fixture, marker: str):
    _client, owner, project, asset, _initial, _scan, _finding, organization, owner_membership = disposition_fixture
    _ownerize(owner_membership)
    proposer = _proposer(project=project, organization=organization, marker=f'{marker}-proposer')
    approver = _approver(owner=owner, project=project, organization=organization, marker=f'{marker}-approver')
    parameters = {'reason': f'Race TOCTOU governed revocation {marker}.'}
    return owner, project, asset, organization, proposer, approver, parameters


def test_commit_time_race_toctou_proof_is_hash_verifiable(disposition_fixture):
    _owner, project, asset, _organization, proposer, approver, parameters = _race_setup(
        disposition_fixture,
        'proof',
    )
    request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='race-proof',
    )
    result = execute_governed_action(
        action_id='asset.authorization.revoke',
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='asset',
        entity_id=str(asset.id),
        expected_version=request.expected_version,
        idempotency_key='race-proof-execution',
        request_id=str(request.id),
        parameters=parameters,
    )

    proof = result.execution.result_payload['race_toctou']
    assert verify_race_toctou_proof(proof) is True
    assert proof['expected_version'] == request.expected_version
    assert proof['current_version'] == request.expected_version
    assert proof['governed_request_id'] == str(request.id)
    assert proof['governed_request_fingerprint'] == request.request_fingerprint
    assert len(proof['proof_sha256']) == 64
    assert result.execution.audit_log.metadata['race_toctou']['proof_sha256'] == proof['proof_sha256']


def test_two_distinct_requests_from_same_version_allow_exactly_one_commit(disposition_fixture):
    _owner, project, asset, _organization, proposer, approver, parameters = _race_setup(
        disposition_fixture,
        'dual-request',
    )
    first_request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='dual-a',
    )
    second_request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='dual-b',
    )
    assert first_request.expected_version == second_request.expected_version
    barrier = Barrier(2)

    def worker(request, key):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                result = execute_governed_action(
                    action_id='asset.authorization.revoke',
                    project_id=str(project.id),
                    actor_id=str(approver.id),
                    entity_type='asset',
                    entity_id=str(asset.id),
                    expected_version=request.expected_version,
                    idempotency_key=key,
                    request_id=str(request.id),
                    parameters=parameters,
                )
                return ('committed', str(result.execution.id), result.execution.result_payload['race_toctou'])
            except GovernedActionConflict as exc:
                return ('stale', str(exc), None)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda item: worker(*item),
            [
                (first_request, 'dual-execution-a'),
                (second_request, 'dual-execution-b'),
            ],
        ))

    assert sorted(item[0] for item in results) == ['committed', 'stale']
    committed = next(item for item in results if item[0] == 'committed')
    assert verify_race_toctou_proof(committed[2]) is True
    assert GovernedActionExecution.objects.filter(
        request_id__in=[first_request.id, second_request.id]
    ).count() == 1
    assert AuditLog.objects.filter(
        metadata__governed_action_id='asset.authorization.revoke',
        resource_id=str(asset.id),
    ).count() == 1
    assert AssetAuthorization.objects.filter(asset=asset).count() == 2


def test_domain_change_between_check_and_use_fails_closed_without_execution_envelope(
    disposition_fixture,
    monkeypatch,
):
    _owner, project, asset, _organization, proposer, approver, parameters = _race_setup(
        disposition_fixture,
        'check-use',
    )
    request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='check-use',
    )
    checked = Event()
    external_mutation_done = Event()
    original_dispatcher = executor._DISPATCH['asset.authorization.revoke']

    def gated_dispatcher(**kwargs):
        checked.set()
        assert external_mutation_done.wait(timeout=10)
        return original_dispatcher(**kwargs)

    monkeypatch.setitem(executor._DISPATCH, 'asset.authorization.revoke', gated_dispatcher)

    def governed_worker():
        close_old_connections()
        try:
            with pytest.raises(GovernedActionConflict, match='asset authorization version'):
                execute_governed_action(
                    action_id='asset.authorization.revoke',
                    project_id=str(project.id),
                    actor_id=str(approver.id),
                    entity_type='asset',
                    entity_id=str(asset.id),
                    expected_version=request.expected_version,
                    idempotency_key='check-use-execution',
                    request_id=str(request.id),
                    parameters=parameters,
                )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(governed_worker)
        assert checked.wait(timeout=10)
        before = asset_authorization_version(asset)
        govern_asset_authorization(
            asset_id=str(asset.id),
            project_id=str(project.id),
            actor_id=str(approver.id),
            expected_version=before,
            authorized=False,
            reason='Independent domain mutation used to prove use-time CAS.',
            governed_request_id=str(uuid4()),
            correlation_id=str(uuid4()),
        )
        external_mutation_done.set()
        future.result(timeout=15)

    assert GovernedActionExecution.objects.filter(request=request).count() == 0
    assert AuditLog.objects.filter(
        metadata__governed_action_id='asset.authorization.revoke',
        resource_id=str(asset.id),
    ).count() == 0
    assert AssetAuthorization.objects.filter(asset=asset).count() == 2


def test_temporal_policy_is_re_evaluated_fresh_at_commit_time(disposition_fixture, monkeypatch):
    _owner, project, asset, _organization, proposer, approver, parameters = _race_setup(
        disposition_fixture,
        'temporal-freshness',
    )
    request = _request(
        project=project,
        asset=asset,
        proposer=proposer,
        action_id='asset.authorization.revoke',
        parameters=parameters,
        marker='temporal-freshness',
    )
    before_count = AssetAuthorization.objects.filter(asset=asset).count()
    original = executor._preflight_temporal_policy
    observed_evaluated_at = []

    def temporal_probe(**kwargs):
        observed_evaluated_at.append(kwargs.get('evaluated_at'))
        if len(observed_evaluated_at) == 1:
            return original(**kwargs)
        if kwargs.get('evaluated_at') is None:
            raise GovernedActionBlocked(
                'TEMPORAL_POLICY_EXPIRED_AT_USE',
                'Synthetic expiry proves the commit-time policy check uses fresh time.',
                ['fresh_commit_time_temporal_policy'],
            )
        return original(**kwargs)

    monkeypatch.setattr(executor, '_preflight_temporal_policy', temporal_probe)

    with pytest.raises(GovernedActionBlocked) as blocked:
        execute_governed_action(
            action_id='asset.authorization.revoke',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='asset',
            entity_id=str(asset.id),
            expected_version=request.expected_version,
            idempotency_key='temporal-freshness-execution',
            request_id=str(request.id),
            parameters=parameters,
        )

    assert blocked.value.reason_code == 'TEMPORAL_POLICY_EXPIRED_AT_USE'
    assert observed_evaluated_at == [None, None]
    assert GovernedActionExecution.objects.filter(request=request).count() == 0
    assert AuditLog.objects.filter(
        metadata__governed_action_id='asset.authorization.revoke',
        resource_id=str(asset.id),
    ).count() == 0
    assert AssetAuthorization.objects.filter(asset=asset).count() == before_count
