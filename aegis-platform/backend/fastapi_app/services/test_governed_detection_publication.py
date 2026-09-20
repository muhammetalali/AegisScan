from __future__ import annotations

import threading
from datetime import timedelta
from http.server import ThreadingHTTPServer

import pytest
from django.utils import timezone

from django_project.audit.models import AuditLog
from django_project.users.models import User
from enterprise.detection_models import (
    DetectionPublication,
    DetectionPublicationDelivery,
    DetectionRule,
)
from enterprise.models import ExternalIntegration, OrganizationMembership
from fastapi_app.services.detection_engineering import (
    DetectionEngineeringError,
    deliver_publication_delivery,
    publish_revision,
    validate_revision,
)
from fastapi_app.services.governed_action_executor import (
    GovernedActionBlocked,
    execute_governed_action,
)
from fastapi_app.services.governed_action_requests import create_governed_action_request
from fastapi_app.services.integration_live_acceptance import (
    accept_integration_live,
    integration_acceptance_generation,
    record_integration_acceptance_test,
)
from fastapi_app.services.test_detection_engineering import (
    _CaptureHandler,
    _revision,
    _telemetry,
    detection_fixture,  # noqa: F401
)
from fastapi_app.services.test_finding_governed_actions import _actor


pytestmark = pytest.mark.django_db(transaction=True)


def _ownerize(membership):
    membership.role = OrganizationMembership.Role.OWNER
    membership.save(update_fields=['role'])


def _proposer(project, organization, marker):
    user = User.objects.create_user(
        email=f'a3-detection-proposer-{marker}@example.invalid',
        password='Strong-Test-Password-123!',
    )
    project.members.add(user)
    OrganizationMembership.objects.create(
        organization=organization,
        user=user,
        role=OrganizationMembership.Role.ANALYST,
        is_active=True,
    )
    return user


def _approver(owner, project, organization, marker):
    user, _membership = _actor(
        owner=owner,
        project=project,
        organization=organization,
        email=f'a3-detection-approver-{marker}@example.invalid',
        role=OrganizationMembership.Role.MANAGER,
        responsibility='detection_publisher',
    )
    return user


def _live_siem(*, owner, project, organization, marker, base_url):
    integration = ExternalIntegration.objects.create(
        organization=organization,
        kind=ExternalIntegration.Kind.ELASTIC,
        name=f'A3 Governed Elastic {marker}',
        base_url=base_url,
        config={'index': 'detections'},
        enabled=True,
        created_by=owner,
    )
    test = record_integration_acceptance_test(
        integration_id=str(integration.id),
        project_id=str(project.id),
        actor_id=str(owner.id),
        outcome='passed',
        source_ref=f'a3-detection:{marker}',
        evidence_sha256=('a' if marker != 'drift' else 'b') * 64,
        evidence_summary={'http_status': 201},
        test_type='live_transport_probe',
    ).test
    acceptance = accept_integration_live(
        integration_id=str(integration.id),
        project_id=str(project.id),
        actor_id=str(owner.id),
        expected_version=integration_acceptance_generation(
            integration_id=str(integration.id),
            project_id=str(project.id),
        ),
        acceptance_test_id=str(test.id),
        vendor_ack='SIEM transport accepted for governed detection publication.',
        acceptance_evidence_sha256=test.evidence_sha256,
        review_at=timezone.now() + timedelta(days=30),
        expires_at=timezone.now() + timedelta(days=60),
    ).acceptance
    return integration, acceptance


def _validated_revision(owner, project, finding, evidence):
    revision = _revision(owner, project, finding, evidence).revision
    validate_revision(
        revision_id=str(revision.id),
        project_id=str(project.id),
        user_id=str(owner.id),
        telemetry=_telemetry(),
        minimum_matches=1,
    )
    return revision


def _request(*, project, revision, integration, proposer, marker):
    expected_version = revision.version + DetectionPublicationDelivery.objects.filter(revision=revision).count()
    return create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(proposer.id),
        action_id='detection.publish',
        entity_type='detection_revision',
        entity_id=str(revision.id),
        expected_version=expected_version,
        idempotency_key=f'a3-detection-request-{marker}',
        parameters={'integration_id': integration.id},
    ).request


def _execute(*, project, revision, integration, approver, request, marker):
    return execute_governed_action(
        action_id='detection.publish',
        project_id=str(project.id),
        actor_id=str(approver.id),
        entity_type='detection_revision',
        entity_id=str(revision.id),
        expected_version=request.expected_version,
        idempotency_key=f'a3-detection-execute-{marker}',
        request_id=str(request.id),
        parameters={'integration_id': integration.id},
    )


def test_governed_detection_publication_is_durable_before_transport(detection_fixture, monkeypatch):
    _client, owner, project, finding, evidence, organization, membership = detection_fixture
    _ownerize(membership)
    revision = _validated_revision(owner, project, finding, evidence)
    integration, acceptance = _live_siem(
        owner=owner,
        project=project,
        organization=organization,
        marker='queued',
        base_url='http://127.0.0.1:9',
    )
    proposer = _proposer(project, organization, 'queued')
    approver = _approver(owner, project, organization, 'queued')
    queued = []
    monkeypatch.setattr(
        'enterprise.tasks.deliver_detection_publication.delay',
        lambda delivery_id: queued.append(str(delivery_id)),
    )

    request = _request(
        project=project,
        revision=revision,
        integration=integration,
        proposer=proposer,
        marker='queued',
    )
    result = _execute(
        project=project,
        revision=revision,
        integration=integration,
        approver=approver,
        request=request,
        marker='queued',
    )

    delivery = DetectionPublicationDelivery.objects.get(
        pk=result.execution.result_payload['delivery_id'],
    )
    assert delivery.status == DetectionPublicationDelivery.Status.QUEUED
    assert delivery.live_acceptance_id == acceptance.id
    assert delivery.governed_request_id == request.id
    assert queued == [str(delivery.id)]
    assert not DetectionPublication.objects.filter(revision=revision).exists()
    revision.rule.refresh_from_db()
    assert revision.rule.state == DetectionRule.State.VALIDATED
    assert result.execution.result_payload['version'] == request.expected_version + 1
    assert AuditLog.objects.filter(
        metadata__governed_action_id='detection.publish',
        resource_id=str(revision.id),
    ).count() == 1


def test_delivery_runs_real_http_after_governance_and_replays_without_resend(detection_fixture, monkeypatch):
    _client, owner, project, finding, evidence, organization, membership = detection_fixture
    _ownerize(membership)
    revision = _validated_revision(owner, project, finding, evidence)
    _CaptureHandler.requests = []
    server = ThreadingHTTPServer(('127.0.0.1', 0), _CaptureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        integration, _acceptance = _live_siem(
            owner=owner,
            project=project,
            organization=organization,
            marker='transport',
            base_url=f'http://127.0.0.1:{server.server_port}',
        )
        proposer = _proposer(project, organization, 'transport')
        approver = _approver(owner, project, organization, 'transport')
        monkeypatch.setattr(
            'enterprise.tasks.deliver_detection_publication.delay',
            lambda _delivery_id: None,
        )
        request = _request(
            project=project,
            revision=revision,
            integration=integration,
            proposer=proposer,
            marker='transport',
        )
        execution = _execute(
            project=project,
            revision=revision,
            integration=integration,
            approver=approver,
            request=request,
            marker='transport',
        )
        delivery_id = execution.execution.result_payload['delivery_id']
        first = deliver_publication_delivery(delivery_id=delivery_id)
        second = deliver_publication_delivery(delivery_id=delivery_id)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert first.delivery.status == DetectionPublicationDelivery.Status.DELIVERED
    assert first.publication is not None
    assert second.replayed is True
    assert second.publication.id == first.publication.id
    assert len(_CaptureHandler.requests) == 1
    request_body = _CaptureHandler.requests[0]['body']
    assert request_body['type'] == 'aegisscan.detection.package'
    assert request_body['delivery_id'] == delivery_id
    assert request_body['governed_request_id'] == str(request.id)
    revision.rule.refresh_from_db()
    assert revision.rule.state == DetectionRule.State.PUBLISHED


def test_configuration_drift_blocks_transport_without_remote_side_effect(detection_fixture, monkeypatch):
    _client, owner, project, finding, evidence, organization, membership = detection_fixture
    _ownerize(membership)
    revision = _validated_revision(owner, project, finding, evidence)
    integration, _acceptance = _live_siem(
        owner=owner,
        project=project,
        organization=organization,
        marker='drift',
        base_url='http://127.0.0.1:9',
    )
    proposer = _proposer(project, organization, 'drift')
    approver = _approver(owner, project, organization, 'drift')
    monkeypatch.setattr('enterprise.tasks.deliver_detection_publication.delay', lambda _delivery_id: None)
    request = _request(
        project=project,
        revision=revision,
        integration=integration,
        proposer=proposer,
        marker='drift',
    )
    execution = _execute(
        project=project,
        revision=revision,
        integration=integration,
        approver=approver,
        request=request,
        marker='drift',
    )
    integration.enabled = False
    integration.save(update_fields=['enabled', 'updated_at'])

    result = deliver_publication_delivery(
        delivery_id=execution.execution.result_payload['delivery_id'],
    )
    assert result.delivery.status == DetectionPublicationDelivery.Status.BLOCKED
    assert result.publication is None
    assert not DetectionPublication.objects.filter(revision=revision).exists()
    revision.rule.refresh_from_db()
    assert revision.rule.state == DetectionRule.State.VALIDATED


def test_self_approval_and_missing_live_acceptance_fail_closed(detection_fixture, monkeypatch):
    _client, owner, project, finding, evidence, organization, membership = detection_fixture
    _ownerize(membership)
    revision = _validated_revision(owner, project, finding, evidence)
    integration, _acceptance = _live_siem(
        owner=owner,
        project=project,
        organization=organization,
        marker='sod',
        base_url='http://127.0.0.1:9',
    )
    approver = _approver(owner, project, organization, 'sod')
    monkeypatch.setattr('enterprise.tasks.deliver_detection_publication.delay', lambda _delivery_id: None)
    self_request = _request(
        project=project,
        revision=revision,
        integration=integration,
        proposer=approver,
        marker='sod',
    )
    with pytest.raises(GovernedActionBlocked) as blocked:
        _execute(
            project=project,
            revision=revision,
            integration=integration,
            approver=approver,
            request=self_request,
            marker='sod',
        )
    assert blocked.value.reason_code == 'SOD_VIOLATION'

    unaccepted = ExternalIntegration.objects.create(
        organization=organization,
        kind=ExternalIntegration.Kind.ELASTIC,
        name='A3 Unaccepted SIEM',
        base_url='http://127.0.0.1:9',
        config={'index': 'detections'},
        enabled=True,
        created_by=owner,
    )
    proposer = _proposer(project, organization, 'unaccepted')
    request = create_governed_action_request(
        project_id=str(project.id),
        requested_by_id=str(proposer.id),
        action_id='detection.publish',
        entity_type='detection_revision',
        entity_id=str(revision.id),
        expected_version=revision.version,
        idempotency_key='a3-detection-request-unaccepted',
        parameters={'integration_id': unaccepted.id},
    ).request
    with pytest.raises(GovernedActionBlocked):
        execute_governed_action(
            action_id='detection.publish',
            project_id=str(project.id),
            actor_id=str(approver.id),
            entity_type='detection_revision',
            entity_id=str(revision.id),
            expected_version=request.expected_version,
            idempotency_key='a3-detection-execute-unaccepted',
            request_id=str(request.id),
            parameters={'integration_id': unaccepted.id},
        )


def test_legacy_direct_publication_is_fail_closed(detection_fixture):
    _client, owner, project, finding, evidence, organization, membership = detection_fixture
    _ownerize(membership)
    revision = _validated_revision(owner, project, finding, evidence)
    integration, _acceptance = _live_siem(
        owner=owner,
        project=project,
        organization=organization,
        marker='legacy',
        base_url='http://127.0.0.1:9',
    )
    with pytest.raises(DetectionEngineeringError, match='request-bound AGOM'):
        publish_revision(
            revision_id=str(revision.id),
            integration_id=str(integration.id),
            project_id=str(project.id),
            user_id=str(owner.id),
        )
    assert not DetectionPublicationDelivery.objects.filter(revision=revision).exists()
    assert not DetectionPublication.objects.filter(revision=revision).exists()
