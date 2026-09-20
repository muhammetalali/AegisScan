from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from django_project.audit.models import AuditLog
from django_project.users.models import User
from enterprise.governed_action_models import GovernedActionExecution
from enterprise.models import ExternalIntegration, IntegrationAcceptanceTest, IntegrationLiveAcceptance, OrganizationMembership
from fastapi_app.contracts.governed_operations import ActionMode
from fastapi_app.services.governed_action_executor import GovernedActionBlocked, GovernedActionConflict, execute_governed_action
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.integration_live_acceptance import IntegrationAcceptanceConflict, accept_integration_live, integration_acceptance_generation, record_integration_acceptance_test
from fastapi_app.services import entity_capability_adapters
from fastapi_app.services.entity_capability_adapters import build_entity_capability_manifest
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401
from fastapi_app.services.test_finding_governed_actions import _actor

pytestmark = pytest.mark.django_db(transaction=True)


def _ownerize(membership):
    membership.role=OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _integration(organization,owner,marker):
    return ExternalIntegration.objects.create(
        organization=organization,kind=ExternalIntegration.Kind.SPLUNK,
        name=f'A3 Integration {marker}',base_url='https://siem.example.invalid',
        enabled=True,created_by=owner,
    )


def _proposer(project,organization,marker):
    user=User.objects.create_user(email=f'a3-int-proposer-{marker}@example.invalid',password='Test-Password-123!')
    project.members.add(user)
    OrganizationMembership.objects.create(
        organization=organization,user=user,role=OrganizationMembership.Role.ANALYST,is_active=True,
    )
    return user


def _approver(owner,project,organization,marker):
    user,_membership=_actor(
        owner=owner,project=project,organization=organization,
        email=f'a3-int-approver-{marker}@example.invalid',
        role=OrganizationMembership.Role.ADMIN,responsibility='integration_acceptor',
    )
    return user


def _test(integration,project,actor,marker):
    return record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(actor.id),
        outcome='passed',source_ref=f'reality:{marker}',evidence_sha256='a'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    ).test


def _parameters(test):
    review=datetime.now(timezone.utc)+timedelta(days=30)
    return {
        'acceptance_test_id':str(test.id),
        'vendor_ack':'Vendor acknowledged the tested live transport.',
        'acceptance_evidence_sha256':'c'*64,
        'review_at':review.isoformat(),
        'expires_at':(review+timedelta(days=30)).isoformat(),
    }


def _request(project,integration,proposer,parameters,marker):
    return create_governed_action_request(
        project_id=str(project.id),requested_by_id=str(proposer.id),
        action_id='integration.live_accept',entity_type='integration',entity_id=str(integration.id),
        expected_version=integration_acceptance_generation(integration_id=str(integration.id),project_id=str(project.id)),
        idempotency_key=f'a3-int-request-{marker}',parameters=parameters,
    ).request


def _execute(project,integration,approver,request,parameters,marker):
    return execute_governed_action(
        action_id='integration.live_accept',project_id=str(project.id),actor_id=str(approver.id),
        entity_type='integration',entity_id=str(integration.id),expected_version=request.expected_version,
        idempotency_key=f'a3-int-execute-{marker}',request_id=str(request.id),parameters=parameters,
    )


def test_integration_test_ledger_is_idempotent_and_source_bound(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'ledger')
    first=record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:ledger',evidence_sha256='1'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    )
    replay=record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:ledger',evidence_sha256='1'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    )
    assert replay.replayed is True and replay.test.id==first.test.id
    with pytest.raises(IntegrationAcceptanceConflict):
        record_integration_acceptance_test(
            integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
            outcome='failed',source_ref='reality:ledger',evidence_sha256='2'*64,
            evidence_summary={'error_type':'RuntimeError'},test_type='live_transport_probe',
        )


def test_request_bound_live_acceptance_is_atomic_versioned_and_audited(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'execute')
    test=_test(integration,project,owner,'execute')
    proposer=_proposer(project,organization,'execute')
    approver=_approver(owner,project,organization,'execute')
    parameters=_parameters(test)
    plain=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(approver.id),entity_type='integration',entity_id=str(integration.id),
    )
    action=next(item for item in plain.capabilities if item.action_id=='integration.live_accept')
    assert plain.projection.lifecycle=='tested' and action.mode is ActionMode.BLOCKED
    request=_request(project,integration,proposer,parameters,'execute')
    result=_execute(project,integration,approver,request,parameters,'execute')
    acceptance=IntegrationLiveAcceptance.objects.get(pk=result.execution.result_payload['acceptance_id'])
    assert acceptance.acceptance_test_id==test.id
    assert result.execution.result_payload['version']==request.expected_version+1
    assert GovernedActionExecution.objects.filter(request=request).count()==1
    assert AuditLog.objects.filter(metadata__governed_action_id='integration.live_accept',resource_id=str(integration.id)).count()==1
    after=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(approver.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert after.projection.lifecycle=='live_accepted'


def test_self_approval_and_stale_test_fail_closed(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'guards')
    first=_test(integration,project,owner,'first')
    approver=_approver(owner,project,organization,'guards')
    self_params=_parameters(first)
    self_request=_request(project,integration,approver,self_params,'self')
    with pytest.raises(GovernedActionBlocked) as blocked:
        _execute(project,integration,approver,self_request,self_params,'self')
    assert blocked.value.reason_code=='SOD_VIOLATION'
    proposer=_proposer(project,organization,'stale')
    stale_params=_parameters(first)
    stale_request=_request(project,integration,proposer,stale_params,'stale')
    record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:newer',evidence_sha256='b'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    )
    with pytest.raises(GovernedActionConflict):
        _execute(project,integration,approver,stale_request,stale_params,'stale')
    assert not IntegrationLiveAcceptance.objects.filter(integration=integration).exists()


def test_expired_acceptance_requires_a_new_passed_test(disposition_fixture,monkeypatch):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'expiry')
    test=_test(integration,project,owner,'expiry')
    accepted=accept_integration_live(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        expected_version=integration_acceptance_generation(integration_id=str(integration.id),project_id=str(project.id)),
        acceptance_test_id=str(test.id),vendor_ack='Vendor acknowledged current transport acceptance.',
        acceptance_evidence_sha256='d'*64,
        review_at=datetime.now(timezone.utc)+timedelta(days=7),
        expires_at=datetime.now(timezone.utc)+timedelta(days=14),
    )
    monkeypatch.setattr(
        entity_capability_adapters.django_timezone,'now',
        lambda:accepted.acceptance.review_at+timedelta(seconds=1),
    )
    manifest=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(owner.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert manifest.projection.lifecycle=='acceptance_expired'
    with pytest.raises(IntegrationAcceptanceConflict,match='newer passed'):
        accept_integration_live(
            integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
            expected_version=integration_acceptance_generation(integration_id=str(integration.id),project_id=str(project.id)),
            acceptance_test_id=str(test.id),vendor_ack='Vendor acknowledged repeated transport acceptance.',
            acceptance_evidence_sha256='e'*64,
            review_at=datetime.now(timezone.utc)+timedelta(days=30),
            expires_at=datetime.now(timezone.utc)+timedelta(days=60),
        )


def test_agom_audit_failure_rolls_back_live_acceptance(disposition_fixture,monkeypatch):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'rollback')
    test=_test(integration,project,owner,'rollback')
    proposer=_proposer(project,organization,'rollback')
    approver=_approver(owner,project,organization,'rollback')
    parameters=_parameters(test)
    request=_request(project,integration,proposer,parameters,'rollback')
    monkeypatch.setattr(
        'fastapi_app.services.governed_action_executor.append_audit',
        lambda *args,**kwargs: (_ for _ in ()).throw(RuntimeError('synthetic audit failure')),
    )
    with pytest.raises(RuntimeError,match='synthetic audit failure'):
        _execute(project,integration,approver,request,parameters,'rollback')
    assert not IntegrationLiveAcceptance.objects.filter(integration=integration).exists()
    assert not GovernedActionExecution.objects.filter(request=request).exists()


def test_transport_probe_task_persists_sanitized_durable_test(disposition_fixture,monkeypatch):
    from enterprise.tasks import run_integration_acceptance_test

    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'task')
    monkeypatch.setattr(
        'enterprise.tasks.send_integration',
        lambda item,event:{'http_status':202,'status':'accepted','opaque_remote_value':'discard-me'},
    )
    task_result=run_integration_acceptance_test.apply(
        args=[str(integration.id),str(project.id),str(owner.id),{'type':'aegis.acceptance.probe'}],
        task_id='a3-integration-acceptance-task',
    ).get(propagate=True)
    test=IntegrationAcceptanceTest.objects.get(pk=task_result['acceptance_test_id'])
    assert task_result['status']=='passed'
    assert test.source_ref=='celery:a3-integration-acceptance-task'
    assert test.outcome==IntegrationAcceptanceTest.Outcome.PASSED
    assert set(test.evidence_summary)=={'transport_result_sha256','http_status','status'}
    assert 'opaque_remote_value' not in str(test.evidence_summary)
