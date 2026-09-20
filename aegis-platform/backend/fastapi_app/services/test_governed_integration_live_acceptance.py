from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from django_project.audit.models import AuditLog
from django_project.projects.models import Project
from django_project.users.models import User
from enterprise.governed_action_models import GovernedActionExecution
from enterprise.models import ExternalIntegration, IntegrationAcceptanceTest, IntegrationLiveAcceptance, Organization, OrganizationMembership, TenantProject
from fastapi_app.contracts.governed_operations import ActionMode
from fastapi_app.services.governed_action_executor import GovernedActionBlocked, GovernedActionConflict, execute_governed_action
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.integration_live_acceptance import IntegrationAcceptanceConflict, accept_integration_live, integration_acceptance_generation, integration_configuration_fingerprint, record_integration_acceptance_test
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
        'acceptance_evidence_sha256':test.evidence_sha256,
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
        acceptance_evidence_sha256=test.evidence_sha256,
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
            acceptance_evidence_sha256=test.evidence_sha256,
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


def test_transport_probe_pass_stays_bound_to_configuration_used_before_concurrent_drift(disposition_fixture,monkeypatch):
    from enterprise.tasks import run_integration_acceptance_test

    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'during-probe-drift')
    probed_fingerprint=integration_configuration_fingerprint(integration)

    def _drifting_send(item,event):
        ExternalIntegration.objects.filter(pk=item.pk).update(
            base_url='https://rotated-during-probe.example.invalid',
            updated_at=datetime.now(timezone.utc),
        )
        return {'http_status':202,'status':'accepted'}

    monkeypatch.setattr('enterprise.tasks.send_integration',_drifting_send)
    task_result=run_integration_acceptance_test.apply(
        args=[str(integration.id),str(project.id),str(owner.id),{'type':'aegis.acceptance.probe'}],
        task_id='a3-integration-during-probe-drift',
    ).get(propagate=True)

    recorded=IntegrationAcceptanceTest.objects.get(pk=task_result['acceptance_test_id'])
    integration.refresh_from_db()
    current_fingerprint=integration_configuration_fingerprint(integration)

    assert recorded.outcome==IntegrationAcceptanceTest.Outcome.PASSED
    assert recorded.configuration_fingerprint==probed_fingerprint
    assert recorded.configuration_fingerprint!=current_fingerprint
    manifest=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(owner.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert manifest.projection.lifecycle=='configuration_changed'


def test_acceptance_test_route_is_project_and_tenant_bound(disposition_fixture,monkeypatch):
    client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'route')
    captured=[]
    monkeypatch.setattr(
        'fastapi_app.routers.enterprise_extra.run_integration_acceptance_test.delay',
        lambda *args:(captured.append(args) or SimpleNamespace(id='queued-acceptance-test')),
    )
    response=client.post(
        f'/api/v1/enterprise/integrations/{integration.id}/acceptance-test',
        json={'project_id':str(project.id),'event':{'type':'aegis.acceptance.probe'}},
    )
    assert response.status_code==202,response.text
    assert response.json()['status']=='queued'
    assert captured==[(
        str(integration.id),str(project.id),str(owner.id),{'type':'aegis.acceptance.probe'},
    )]


def test_transport_probe_rejects_cross_tenant_scope_before_delivery(disposition_fixture,monkeypatch):
    from enterprise.tasks import run_integration_acceptance_test

    _client,owner,project,_asset,_authorization,_scan,_finding,_organization,_membership=disposition_fixture
    other_owner=User.objects.create_user(
        email='a3-int-other-owner@example.invalid',password='Test-Password-123!',
    )
    other_project=Project.objects.create(
        name='A3 Other Integration Project',slug='a3-other-integration-project',owner=other_owner,
    )
    other_org=Organization.objects.create(
        name='A3 Other Integration Org',slug='a3-other-integration-org',owner=other_owner,is_active=True,
    )
    OrganizationMembership.objects.create(
        organization=other_org,user=other_owner,role=OrganizationMembership.Role.OWNER,is_active=True,
    )
    TenantProject.objects.create(organization=other_org,project=other_project)
    integration=_integration(other_org,other_owner,'cross-tenant')
    delivered=[]
    monkeypatch.setattr(
        'enterprise.tasks.send_integration',
        lambda item,event:(delivered.append(str(item.id)) or {'http_status':202}),
    )
    result=run_integration_acceptance_test.apply(
        args=[str(integration.id),str(project.id),str(owner.id),{'type':'aegis.acceptance.probe'}],
        task_id='a3-cross-tenant-test',
    )
    with pytest.raises(PermissionError,match='scope is not authorized'):
        result.get(propagate=True)
    assert delivered==[]
    assert not IntegrationAcceptanceTest.objects.filter(integration=integration).exists()


def test_live_acceptance_rejects_unbound_evidence_hash(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'evidence-mismatch')
    test=_test(integration,project,owner,'evidence-mismatch')
    proposer=_proposer(project,organization,'evidence-mismatch')
    approver=_approver(owner,project,organization,'evidence-mismatch')
    parameters=_parameters(test)
    parameters['acceptance_evidence_sha256']='f'*64
    request=_request(project,integration,proposer,parameters,'evidence-mismatch')
    with pytest.raises(GovernedActionBlocked):
        _execute(project,integration,approver,request,parameters,'evidence-mismatch')
    assert not IntegrationLiveAcceptance.objects.filter(integration=integration).exists()


def test_configuration_drift_invalidates_test_and_pending_acceptance_request(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'config-drift')
    test=_test(integration,project,owner,'config-drift')
    proposer=_proposer(project,organization,'config-drift')
    approver=_approver(owner,project,organization,'config-drift')
    parameters=_parameters(test)
    request=_request(project,integration,proposer,parameters,'config-drift')

    integration.base_url='https://replacement-siem.example.invalid'
    integration.save(update_fields=['base_url','updated_at'])

    manifest=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(approver.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert manifest.projection.lifecycle=='configuration_changed'
    with pytest.raises(GovernedActionBlocked):
        _execute(project,integration,approver,request,parameters,'config-drift')
    assert not IntegrationLiveAcceptance.objects.filter(integration=integration).exists()

    replay=record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:config-drift',evidence_sha256='a'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    )
    assert replay.replayed is True
    assert replay.test.id==test.id

    new_test=record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:config-drift-new',evidence_sha256='9'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    ).test
    refreshed=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(approver.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert refreshed.projection.lifecycle=='tested'
    assert new_test.configuration_fingerprint!=test.configuration_fingerprint


def test_disable_reenable_does_not_resurrect_old_acceptance_test(disposition_fixture):
    _client,owner,project,_asset,_authorization,_scan,_finding,organization,membership=disposition_fixture
    _ownerize(membership)
    integration=_integration(organization,owner,'toggle')
    test=_test(integration,project,owner,'toggle')
    original_fingerprint=test.configuration_fingerprint

    integration.enabled=False
    integration.save(update_fields=['enabled','updated_at'])
    integration.enabled=True
    integration.save(update_fields=['enabled','updated_at'])

    manifest=build_entity_capability_manifest(
        project_id=str(project.id),user_id=str(owner.id),entity_type='integration',entity_id=str(integration.id),
    )
    assert manifest.projection.lifecycle=='configuration_changed'

    new_test=record_integration_acceptance_test(
        integration_id=str(integration.id),project_id=str(project.id),actor_id=str(owner.id),
        outcome='passed',source_ref='reality:toggle-new',evidence_sha256='8'*64,
        evidence_summary={'http_status':202},test_type='live_transport_probe',
    ).test
    assert new_test.configuration_fingerprint!=original_fingerprint
