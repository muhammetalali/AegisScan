from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fastapi_app.services.cloud_live_provider_reality import (
    CloudLiveProviderProofError,
    validate_live_provider_result,
)


def _private_json(tmp_path: Path, name: str, data: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding='utf-8')
    os.chmod(path, 0o600)
    return path


def _aws_credential() -> dict:
    return {
        'provider': 'aws',
        'access_key_id': 'AKIALIVEPROOF123456',
        'secret_access_key': 'live-provider-secret-never-persist',
        'session_token': 'live-provider-session-token-never-persist',
        'region': 'us-east-1',
    }


def _result(**summary_overrides) -> dict:
    summary = {
        'kind': 'cloud-security-summary',
        'provider': 'aws',
        'target': 'aws://123456789012',
        'identity_verified': True,
        'read_only': True,
        'credential_source': 'vault-materialized-file',
        'ambient_credentials_used': False,
        'inventory': {'account_id': '123456789012'},
        'coverage_gaps': [],
        'finding_count': 1,
    }
    summary.update(summary_overrides)
    return {
        'schema': 'aegis.cloud-security.v1',
        'provider': 'aws',
        'target': 'aws://123456789012',
        'observations': [
            summary,
            {
                'kind': 'cloud-security-finding',
                'provider': 'aws',
                'rule_id': 'cloud.aws.fixture',
                'title': 'Fixture finding',
                'description': 'Live proof fixture without credentials.',
                'severity': 'high',
            },
        ],
    }


def test_live_provider_validator_emits_secret_free_minimal_proof(tmp_path: Path):
    credential = _private_json(tmp_path, 'credential.json', _aws_credential())
    result = _private_json(tmp_path, 'result.json', _result())
    proof = validate_live_provider_result(
        provider='aws',
        target='aws://123456789012',
        credential_path=str(credential),
        result_path=str(result),
        source_sha='a' * 40,
    )
    encoded = json.dumps(proof, sort_keys=True)
    assert proof['schema'] == 'aegis.cloud-live-provider-proof.v1'
    assert proof['provider'] == 'aws'
    assert proof['target'] == 'aws://123456789012'
    assert proof['identity_verified'] is True
    assert proof['read_only'] is True
    assert proof['ambient_credentials_used'] is False
    assert proof['finding_count'] == 1
    assert proof['coverage_gap_count'] == 0
    assert len(proof['result_sha256']) == 64
    for secret in _aws_credential().values():
        if isinstance(secret, str) and len(secret) > 8:
            assert secret not in encoded


@pytest.mark.parametrize(
    ('override', 'message'),
    (
        ({'identity_verified': False}, 'identity was not verified'),
        ({'read_only': False}, 'read-only execution'),
        ({'ambient_credentials_used': True}, 'ambient credentials'),
        ({'credential_source': 'environment'}, 'credential source'),
    ),
)
def test_live_provider_validator_fails_closed_on_runtime_trust_drift(tmp_path: Path, override: dict, message: str):
    credential = _private_json(tmp_path, 'credential.json', _aws_credential())
    result = _private_json(tmp_path, 'result.json', _result(**override))
    with pytest.raises(CloudLiveProviderProofError, match=message):
        validate_live_provider_result(
            provider='aws',
            target='aws://123456789012',
            credential_path=str(credential),
            result_path=str(result),
        )


def test_live_provider_validator_rejects_secret_leak(tmp_path: Path):
    credential_data = _aws_credential()
    credential = _private_json(tmp_path, 'credential.json', credential_data)
    data = _result()
    data['observations'][1]['description'] = credential_data['secret_access_key']
    result = _private_json(tmp_path, 'result.json', data)
    with pytest.raises(CloudLiveProviderProofError, match='credential material'):
        validate_live_provider_result(
            provider='aws',
            target='aws://123456789012',
            credential_path=str(credential),
            result_path=str(result),
        )


def test_live_provider_validator_rejects_non_private_credential_file(tmp_path: Path):
    credential = _private_json(tmp_path, 'credential.json', _aws_credential())
    os.chmod(credential, 0o644)
    result = _private_json(tmp_path, 'result.json', _result())
    with pytest.raises(CloudLiveProviderProofError, match='group/world'):
        validate_live_provider_result(
            provider='aws',
            target='aws://123456789012',
            credential_path=str(credential),
            result_path=str(result),
        )


def test_live_provider_validator_rejects_provider_target_mismatch(tmp_path: Path):
    credential = _private_json(tmp_path, 'credential.json', _aws_credential())
    result = _private_json(tmp_path, 'result.json', _result())
    with pytest.raises(CloudLiveProviderProofError, match='provider does not match target'):
        validate_live_provider_result(
            provider='azure',
            target='aws://123456789012',
            credential_path=str(credential),
            result_path=str(result),
        )
