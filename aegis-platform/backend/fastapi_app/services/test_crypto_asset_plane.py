from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from django_project.assets.models import AssetAuthorization
from enterprise.crypto_asset_models import CryptographicAssetRecord, CryptographicInventorySnapshot
from fastapi_app.services.crypto_asset_plane import (
    CryptoAssetAuthorizationError,
    CryptoAssetError,
    record_crypto_inventory,
)
from fastapi_app.services.test_finding_disposition import disposition_fixture  # noqa: F401


pytestmark = pytest.mark.django_db(transaction=True)


def _records(marker: str = 'base'):
    return [
        {
            'kind': 'certificate',
            'name': f'edge-cert-{marker}',
            'algorithm': 'RSA',
            'key_size': 2048,
            'protocol': 'TLS',
            'version': '1.3',
            'issuer': 'Aegis Test CA',
            'subject': 'CN=aegis-disposition-target',
            'metadata': {'source': 'tls-handshake', 'san_count': 1},
        },
        {
            'kind': 'algorithm',
            'name': 'application-signature',
            'algorithm': 'ML-DSA',
            'metadata': {'source': 'runtime-manifest'},
        },
    ]


def _record(disposition_fixture, marker: str = 'base', records=None):
    _client, user, project, asset, authorization, scan, *_rest = disposition_fixture
    return record_crypto_inventory(
        project_id=str(project.id),
        asset_id=str(asset.id),
        authorization_id=str(authorization.id),
        actor_id=str(user.id),
        scan_id=str(scan.id),
        source_type='enterprise-crypto-agent',
        records=records or _records(marker),
    )


def test_cbom_is_deterministic_replay_safe_and_immutable(disposition_fixture):
    first = _record(disposition_fixture, 'stable')
    second = _record(disposition_fixture, 'stable')

    assert first.replayed is False
    assert second.replayed is True
    assert second.snapshot.id == first.snapshot.id
    snapshot = first.snapshot
    assert snapshot.snapshot_version == 1
    assert snapshot.cbom['schema'] == 'aegis.cbom.v1'
    assert len(snapshot.cbom_sha256) == 64
    assert len(snapshot.inventory_sha256) == 64
    assert snapshot.risk_summary['record_count'] == 2
    assert snapshot.records.count() == 2

    with pytest.raises(ValidationError):
        CryptographicInventorySnapshot.objects.filter(pk=snapshot.id).update(source_type='tampered')
    with pytest.raises(ValidationError):
        snapshot.delete()
    record = snapshot.records.first()
    with pytest.raises(ValidationError):
        CryptographicAssetRecord.objects.filter(pk=record.id).update(name='tampered')


def test_cbom_drift_is_append_only_and_detects_added_removed(disposition_fixture):
    first = _record(disposition_fixture, 'first').snapshot
    changed = _records('second')
    changed.append({
        'kind': 'protocol',
        'name': 'legacy-tls',
        'protocol': 'TLS1.0',
        'metadata': {'source': 'config'},
    })
    second = _record(disposition_fixture, 'second', records=changed).snapshot

    assert second.snapshot_version == 2
    assert second.predecessor_id == first.id
    assert second.drift['baseline'] is False
    assert second.drift['changed'] is True
    assert second.drift['added']
    assert second.drift['removed']
    assert second.risk_summary['weak_or_deprecated_count'] >= 1


def test_crypto_classification_marks_quantum_vulnerable_and_resistant(disposition_fixture):
    snapshot = _record(disposition_fixture, 'classification').snapshot
    states = {
        row.algorithm.lower(): (row.security_state, row.quantum_state)
        for row in snapshot.records.all()
    }
    assert states['rsa'][1] == 'vulnerable'
    assert states['ml-dsa'][1] == 'resistant'


def test_crypto_inventory_rejects_secret_material(disposition_fixture):
    bad = [{
        'kind': 'key',
        'name': 'forbidden-private-key',
        'algorithm': 'RSA',
        'private_key': '-----BEGIN PRIVATE KEY-----',
    }]
    with pytest.raises(CryptoAssetError, match='forbidden'):
        _record(disposition_fixture, 'secret', records=bad)
    assert CryptographicInventorySnapshot.objects.count() == 0


def test_authorization_drift_fails_closed_without_snapshot(disposition_fixture):
    _client, user, _project, asset, authorization, _scan, *_rest = disposition_fixture
    AssetAuthorization.objects.create(
        asset=asset,
        actor=user,
        authorized=False,
        target_snapshot=authorization.target_snapshot,
        reason='Revoke crypto inventory authorization.',
        supersedes=authorization,
    )
    with pytest.raises(CryptoAssetAuthorizationError, match='not currently admissible'):
        _record(disposition_fixture, 'revoked')
    assert CryptographicInventorySnapshot.objects.count() == 0


def test_crypto_inventory_api_returns_cbom_lineage(disposition_fixture):
    client, _user, project, asset, authorization, scan, *_rest = disposition_fixture
    response = client.post(
        f'/api/v1/crypto-assets/projects/{project.id}/inventory',
        json={
            'asset_id': str(asset.id),
            'authorization_id': str(authorization.id),
            'scan_id': str(scan.id),
            'source_type': 'enterprise-crypto-agent',
            'records': _records('api'),
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body['snapshot_version'] == 1
    assert body['cbom']['schema'] == 'aegis.cbom.v1'
    assert body['authorization_decision_id'] == str(authorization.id)
    assert len(body['cbom_sha256']) == 64
