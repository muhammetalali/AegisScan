from __future__ import annotations

import hashlib

import pytest
from django.core.exceptions import ValidationError

from django_project.assets.models import AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.users.models import User
from enterprise.governed_action_models import EvidenceQualificationEvaluation
from enterprise.iast_models import IASTObservation, IASTSession
from fastapi_app.services.iast_security import (
    IASTAuthorizationError,
    IASTConflict,
    IAST_CAPABILITY_ID,
    ingest_iast_observation,
    start_iast_session,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)


def _session(disposition_fixture, marker: str = 'base'):
    _client, user, project, asset, authorization, scan, _finding, _organization, _membership = disposition_fixture
    return start_iast_session(
        project_id=str(project.id),
        asset_id=str(asset.id),
        scan_id=str(scan.id),
        authorization_id=str(authorization.id),
        actor_id=str(user.id),
        provider_identity='aegis-iast-agent@sha256:test-attested-provider',
        instrumentation_mode='agent',
        idempotency_key=f'iast-session-{marker}',
    )


def _observation(session_id: str, actor_id: str, marker: str = 'base', **overrides):
    values = {
        'session_id': session_id,
        'actor_id': actor_id,
        'idempotency_key': f'iast-observation-{marker}',
        'observation_kind': 'taint-flow',
        'rule_id': 'iast.sql-injection.runtime-flow',
        'title': 'Runtime taint flow reaches SQL execution sink',
        'description': 'Untrusted request data reached a SQL execution sink without a proven sanitization boundary.',
        'severity': 'high',
        'confidence': 'confirmed',
        'source_kind': 'http.request.parameter',
        'sink_kind': 'database.sql.execute',
        'trace_id': f'trace-{marker}',
        'data_labels': ['input.untrusted', 'pii.email'],
        'location': 'https://aegis-disposition-target/orders',
        'cwe_id': 'CWE-89',
        'owasp_category': 'A03:2021-Injection',
        'remediation': 'Use parameterized queries and preserve the runtime sanitization boundary.',
        'method': 'POST',
        'parameter': 'email',
        'file_path': 'app/orders.py',
        'line': 144,
        'function_name': 'create_order',
    }
    values.update(overrides)
    return ingest_iast_observation(**values)


def test_iast_session_is_tenant_authorization_bound_immutable_and_replay_safe(disposition_fixture):
    first = _session(disposition_fixture, 'session-replay')
    second = _session(disposition_fixture, 'session-replay')

    assert first.replayed is False
    assert second.replayed is True
    assert second.session.id == first.session.id
    assert first.session.target_snapshot == 'aegis-disposition-target'
    assert first.session.authorization_decision_id is not None
    assert len(first.session.request_fingerprint) == 64
    assert len(first.session.contract_fingerprint) == 64
    assert first.session.contract_snapshot['redaction']['raw_request_bodies'] is False
    assert first.session.contract_snapshot['redaction']['secret_values'] is False

    with pytest.raises(ValidationError):
        IASTSession.objects.filter(pk=first.session.id).update(provider_identity='mutated')
    with pytest.raises(ValidationError):
        first.session.delete()


def test_iast_observation_creates_qualified_immutable_evidence_and_finding(disposition_fixture):
    _client, user, _project, _asset, _authorization, scan, _finding, organization, _membership = disposition_fixture
    session = _session(disposition_fixture, 'qualified').session
    result = _observation(str(session.id), str(user.id), 'qualified')

    assert result.replayed is False
    observation = result.observation
    finding = observation.finding
    evidence = observation.evidence
    qualification = observation.qualification

    assert finding.source_engine == 'iast'
    assert finding.category == 'iast-runtime-security'
    assert finding.cwe_id == 'CWE-89'
    assert finding.raw_data['raw_values_captured'] is False
    assert evidence.source == 'iast'
    assert evidence.evidence_type == 'runtime_observation'
    assert evidence.metadata['source_capability'] == IAST_CAPABILITY_ID
    assert evidence.metadata['organization_id'] == str(organization.id)
    assert evidence.metadata['execution_ref'] == str(session.id)
    assert evidence.metadata['authorization_decision_id'] == str(session.authorization_decision_id)
    assert evidence.metadata['raw_values_captured'] is False
    assert hashlib.sha256(evidence.raw_output.encode()).hexdigest() == evidence.sha256
    assert qualification.qualified is True
    assert qualification.decision == EvidenceQualificationEvaluation.Decision.QUALIFIED
    assert qualification.subject_id == str(finding.id)
    assert qualification.execution_ref == str(session.id)
    assert qualification.authorization_ref == str(session.authorization_decision_id)
    assert len(observation.observation_sha256) == 64
    assert scan.vulnerabilities.filter(pk=finding.id).exists()

    with pytest.raises(ValidationError):
        Evidence.objects.filter(pk=evidence.id).update(raw_output='tampered')
    with pytest.raises(ValidationError):
        IASTObservation.objects.filter(pk=observation.id).update(severity='low')
    with pytest.raises(ValidationError):
        observation.delete()


def test_iast_observation_replay_dedupes_and_conflicting_idempotency_fails(disposition_fixture):
    _client, user, *_rest = disposition_fixture
    session = _session(disposition_fixture, 'observation-replay').session

    first = _observation(str(session.id), str(user.id), 'same')
    second = _observation(str(session.id), str(user.id), 'same')
    same_content_new_idem = _observation(
        str(session.id),
        str(user.id),
        'different-idem',
        trace_id='trace-same',
    )

    assert first.replayed is False
    assert second.replayed is True
    assert second.observation.id == first.observation.id
    assert same_content_new_idem.replayed is True
    assert same_content_new_idem.observation.id == first.observation.id
    assert IASTObservation.objects.count() == 1

    with pytest.raises(IASTConflict, match='idempotency key'):
        _observation(
            str(session.id),
            str(user.id),
            'same',
            trace_id='trace-conflicting-payload',
        )


def test_authorization_drift_after_session_fails_closed_without_partial_artifacts(disposition_fixture):
    _client, user, _project, asset, authorization, _scan, _finding, _organization, _membership = disposition_fixture
    session = _session(disposition_fixture, 'auth-drift').session

    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot=authorization.target_snapshot,
        reason='Revoke IAST authorization before runtime evidence commit.',
        supersedes=authorization,
    )

    with pytest.raises(IASTAuthorizationError, match='superseded'):
        _observation(str(session.id), str(user.id), 'auth-drift')

    assert IASTObservation.objects.count() == 0
    assert Evidence.objects.filter(source='iast').count() == 0


def test_actor_must_have_both_project_access_and_active_enterprise_membership(disposition_fixture):
    _client, owner, project, asset, authorization, scan, _finding, _organization, _membership = disposition_fixture
    outsider = User.objects.create_user(
        email='iast-outsider@example.invalid',
        password='Strong-Test-Password-123!',
        first_name='IAST',
        last_name='Outsider',
    )
    project.members.add(outsider)

    with pytest.raises(IASTAuthorizationError, match='no active enterprise tenant membership'):
        start_iast_session(
            project_id=str(project.id),
            asset_id=str(asset.id),
            scan_id=str(scan.id),
            authorization_id=str(authorization.id),
            actor_id=str(outsider.id),
            provider_identity='aegis-iast-agent@sha256:outsider',
            instrumentation_mode='agent',
            idempotency_key='iast-cross-tenant-actor',
        )

    assert IASTSession.objects.count() == 0
    assert owner.id != outsider.id


def test_iast_api_rejects_unmodeled_raw_values_and_returns_lineage(disposition_fixture):
    client, _user, project, asset, authorization, scan, _finding, _organization, _membership = disposition_fixture
    session_response = client.post(
        '/api/v1/iast/sessions',
        json={
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'authorization_id': str(authorization.id),
            'provider_identity': 'aegis-iast-agent@sha256:api-provider',
            'instrumentation_mode': 'agent',
            'idempotency_key': 'iast-api-session',
        },
    )
    assert session_response.status_code == 200, session_response.text
    session_id = session_response.json()['id']

    payload = {
        'idempotency_key': 'iast-api-observation',
        'observation_kind': 'taint-flow',
        'rule_id': 'iast.command.runtime-flow',
        'title': 'Runtime taint flow reaches command execution sink',
        'description': 'Untrusted request data reached a command execution sink.',
        'severity': 'critical',
        'confidence': 'confirmed',
        'source_kind': 'http.request.parameter',
        'sink_kind': 'os.command.execute',
        'trace_id': 'trace-api',
        'data_labels': ['input.untrusted'],
        'location': 'https://aegis-disposition-target/admin',
        'cwe_id': 'CWE-78',
        'remediation': 'Use a fixed command allowlist and avoid shell interpretation.',
        'method': 'POST',
        'parameter': 'action',
        'file_path': 'app/admin.py',
        'line': 88,
        'function_name': 'run_action',
    }
    rejected = client.post(
        f'/api/v1/iast/sessions/{session_id}/observations',
        json={**payload, 'raw_value': 'never-store-this-secret'},
    )
    assert rejected.status_code == 422

    accepted = client.post(
        f'/api/v1/iast/sessions/{session_id}/observations',
        json=payload,
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body['finding_id']
    assert body['evidence_id']
    assert body['qualification_id']
    assert len(body['observation_sha256']) == 64
