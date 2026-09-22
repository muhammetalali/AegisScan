from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from django_project.assets.models import AssetAuthorization
from enterprise.crypto_lifecycle_models import CryptoLifecycleAssessment
from fastapi_app.services.crypto_asset_plane import record_crypto_inventory
from fastapi_app.services.crypto_lifecycle_pqc import (
    CryptoLifecycleAuthorizationError,
    CRYPTO_LIFECYCLE_POLICY_VERSION,
    evaluate_crypto_lifecycle,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)


def _snapshot(disposition_fixture, records, marker='base'):
    _client, user, project, asset, authorization, scan, *_rest = disposition_fixture
    return record_crypto_inventory(
        project_id=str(project.id),
        asset_id=str(asset.id),
        authorization_id=str(authorization.id),
        actor_id=str(user.id),
        scan_id=str(scan.id),
        source_type=f'crypto-lifecycle-test-{marker}',
        records=records,
    ).snapshot


def _evaluate(disposition_fixture, snapshot):
    _client, user, *_rest = disposition_fixture
    return evaluate_crypto_lifecycle(snapshot_id=str(snapshot.id), actor_id=str(user.id))


def test_lifecycle_assessment_is_deterministic_replay_safe_and_immutable(disposition_fixture):
    snapshot = _snapshot(disposition_fixture, [
        {
            'kind': 'certificate',
            'name': 'rsa-edge',
            'algorithm': 'RSA',
            'key_size': 3072,
            'protocol': 'TLS',
            'version': '1.3',
            'metadata': {'source': 'tls-handshake'},
        },
        {
            'kind': 'algorithm',
            'name': 'pqc-signature',
            'algorithm': 'ML-DSA',
            'metadata': {'source': 'runtime-manifest'},
        },
    ])
    first = _evaluate(disposition_fixture, snapshot)
    second = _evaluate(disposition_fixture, snapshot)

    assert first.replayed is False
    assert second.replayed is True
    assert second.assessment.id == first.assessment.id
    row = first.assessment
    assert row.assessment_version == 1
    assert row.policy_version == CRYPTO_LIFECYCLE_POLICY_VERSION
    assert row.lifecycle_state == 'action_required'
    assert row.pqc_readiness == 'transition_required'
    assert row.quantum_vulnerable_count == 1
    assert row.quantum_resistant_count == 1
    assert row.migration_plan['schema'] == 'aegis.crypto-migration-plan.v1'
    assert any(item['action'] == 'migrate_to_pqc_or_hybrid' for item in row.migration_plan['actions'])
    assert len(row.assessment_sha256) == 64

    with pytest.raises(ValidationError):
        CryptoLifecycleAssessment.objects.filter(pk=row.id).update(lifecycle_state='compliant')
    with pytest.raises(ValidationError):
        row.delete()


def test_weak_expired_and_rotation_windows_drive_fail_closed_state(disposition_fixture):
    now = timezone.now()
    snapshot = _snapshot(disposition_fixture, [
        {
            'kind': 'certificate',
            'name': 'expired-cert',
            'algorithm': 'RSA',
            'key_size': 1024,
            'not_before': (now - timedelta(days=400)).isoformat(),
            'not_after': (now - timedelta(days=1)).isoformat(),
            'metadata': {'source': 'certificate-store'},
        },
        {
            'kind': 'protocol',
            'name': 'legacy-tls',
            'protocol': 'TLS1.0',
            'metadata': {'source': 'config'},
        },
        {
            'kind': 'certificate',
            'name': 'rotate-soon',
            'algorithm': 'ML-DSA',
            'not_after': (now + timedelta(days=15)).isoformat(),
            'metadata': {'source': 'certificate-store'},
        },
    ], marker='critical')
    row = _evaluate(disposition_fixture, snapshot).assessment

    assert row.lifecycle_state == 'critical'
    assert row.expired_count == 1
    assert row.weak_deprecated_count >= 1
    assert row.expiring_30d_count == 1
    actions = {item['action'] for item in row.migration_plan['actions']}
    assert 'rotate_expired_material' in actions
    assert 'replace_deprecated_crypto' in actions
    assert 'rotate_before_expiry' in actions


def test_hybrid_inventory_reports_hybrid_transition(disposition_fixture):
    snapshot = _snapshot(disposition_fixture, [
        {
            'kind': 'algorithm',
            'name': 'hybrid-kex',
            'algorithm': 'hybrid',
            'metadata': {'hybrid_components': ['RSA', 'ML-KEM']},
        },
    ], marker='hybrid')
    row = _evaluate(disposition_fixture, snapshot).assessment
    assert row.pqc_readiness == 'hybrid'
    assert row.hybrid_count == 1
    assert row.quantum_vulnerable_count == 0


def test_stale_inventory_snapshot_cannot_be_assessed(disposition_fixture):
    first = _snapshot(disposition_fixture, [
        {'kind': 'algorithm', 'name': 'first', 'algorithm': 'RSA', 'metadata': {'source': 'runtime'}},
    ], marker='first')
    _snapshot(disposition_fixture, [
        {'kind': 'algorithm', 'name': 'second', 'algorithm': 'ML-DSA', 'metadata': {'source': 'runtime'}},
    ], marker='second')

    with pytest.raises(CryptoLifecycleAuthorizationError, match='latest cryptographic inventory'):
        _evaluate(disposition_fixture, first)
    assert CryptoLifecycleAssessment.objects.count() == 0


def test_authorization_revocation_blocks_lifecycle_assessment(disposition_fixture):
    _client, user, _project, asset, authorization, _scan, *_rest = disposition_fixture
    snapshot = _snapshot(disposition_fixture, [
        {'kind': 'algorithm', 'name': 'rsa', 'algorithm': 'RSA', 'metadata': {'source': 'runtime'}},
    ], marker='revoked')

    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot=authorization.target_snapshot,
        reason='Revoke crypto lifecycle authorization.',
        supersedes=authorization,
    )

    with pytest.raises(CryptoLifecycleAuthorizationError, match='not currently admissible'):
        _evaluate(disposition_fixture, snapshot)
    assert CryptoLifecycleAssessment.objects.count() == 0


def test_crypto_lifecycle_api_returns_policy_and_migration_lineage(disposition_fixture):
    client, _user, _project, *_rest = disposition_fixture
    snapshot = _snapshot(disposition_fixture, [
        {'kind': 'algorithm', 'name': 'pqc', 'algorithm': 'ML-DSA', 'metadata': {'source': 'runtime'}},
    ], marker='api')

    response = client.post(f'/api/v1/crypto-lifecycle/snapshots/{snapshot.id}/evaluate')
    assert response.status_code == 201, response.text
    body = response.json()
    assert body['inventory_snapshot_id'] == str(snapshot.id)
    assert body['policy_version'] == CRYPTO_LIFECYCLE_POLICY_VERSION
    assert body['pqc_readiness'] == 'ready'
    assert body['migration_plan']['target_profile']['signature'] == 'ML-DSA'
    assert len(body['assessment_sha256']) == 64
