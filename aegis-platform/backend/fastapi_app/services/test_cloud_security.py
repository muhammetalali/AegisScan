from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi_app.services import cloud_security
from fastapi_app.services.cloud_security import (
    CloudSecurityError,
    _aws_sg_findings,
    _azure_nsg_findings,
    _gcp_credentials,
    _load_credentials,
    _verify_gcp_target_identity,
    collect_cloud_posture,
    sanitize_cloud_runtime_environment,
)
from fastapi_app.services.cloud_target import parse_cloud_target


def _credential_file(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / 'credential.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(path, 0o600)
    return path


def _gcp_service_account(*, project_id: str = 'security-admin-123', token_uri: str = 'https://oauth2.googleapis.com/token', universe_domain: str = 'googleapis.com') -> dict:
    return {
        'type': 'service_account',
        'project_id': project_id,
        'private_key_id': 'key-id-123',
        'private_key': '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n',
        'client_email': f'scanner@{project_id}.iam.gserviceaccount.com',
        'client_id': '123456789012345678901',
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': token_uri,
        'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
        'client_x509_cert_url': 'https://www.googleapis.com/robot/v1/metadata/x509/scanner',
        'universe_domain': universe_domain,
    }


def test_aws_security_group_world_admin_rule_becomes_high_finding():
    groups = [{
        'GroupId': 'sg-0123456789',
        'IpPermissions': [{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
            'Ipv6Ranges': [],
        }],
    }]
    findings = _aws_sg_findings(groups, 'us-east-1')
    assert len(findings) == 1
    assert findings[0]['rule_id'] == 'cloud.aws.security-group.world-admin-or-all'
    assert findings[0]['provider'] == 'aws'
    assert findings[0]['severity'] == 'high'
    assert 'sg-0123456789' in findings[0]['location']


def test_aws_security_group_private_admin_rule_is_not_a_finding():
    groups = [{
        'GroupId': 'sg-private',
        'IpPermissions': [{
            'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}],
        }],
    }]
    assert _aws_sg_findings(groups, 'us-east-1') == []


def test_azure_nsg_world_rdp_rule_becomes_high_finding():
    rule = SimpleNamespace(
        name='allow-rdp', direction='Inbound', access='Allow',
        source_address_prefix='Internet', source_address_prefixes=None,
        destination_port_range='3389', destination_port_ranges=None,
    )
    nsg = SimpleNamespace(
        id='/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/open',
        name='open', security_rules=[rule],
    )
    findings = _azure_nsg_findings([nsg])
    assert len(findings) == 1
    assert findings[0]['rule_id'] == 'cloud.azure.nsg.world-admin-or-all'
    assert findings[0]['provider'] == 'azure'
    assert findings[0]['severity'] == 'high'


def test_credential_file_must_be_private_and_provider_bound(tmp_path: Path):
    path = _credential_file(tmp_path, {'provider': 'aws', 'access_key_id': 'x', 'secret_access_key': 'y'})
    target = parse_cloud_target('aws://123456789012')
    assert _load_credentials(str(path), target)['provider'] == 'aws'
    os.chmod(path, 0o644)
    with pytest.raises(CloudSecurityError, match='group/world'):
        _load_credentials(str(path), target)


def test_credential_provider_mismatch_fails_before_collector(tmp_path: Path):
    path = _credential_file(tmp_path, {'provider': 'gcp', 'project_id': 'aegis-prod-123', 'service_account': {}})
    with pytest.raises(CloudSecurityError, match='does not match'):
        collect_cloud_posture('aws://123456789012', str(path))


def test_gcp_service_account_can_belong_to_central_security_project():
    values = _gcp_credentials({
        'provider': 'gcp',
        'project_id': 'target-prod-123',
        'service_account': _gcp_service_account(project_id='security-admin-123'),
    })
    assert values['project_id'] == 'target-prod-123'
    assert values['credential_home_project_id'] == 'security-admin-123'


@pytest.mark.parametrize(
    ('token_uri', 'universe_domain', 'match'),
    [
        ('https://evil.example/token', 'googleapis.com', 'token endpoint'),
        ('https://oauth2.googleapis.com/token', 'evil.example', 'universe_domain'),
    ],
)
def test_gcp_rejects_nonofficial_routing_metadata(token_uri: str, universe_domain: str, match: str):
    payload = {
        'provider': 'gcp',
        'project_id': 'target-prod-123',
        'service_account': _gcp_service_account(token_uri=token_uri, universe_domain=universe_domain),
    }
    with pytest.raises(CloudSecurityError, match=match):
        _gcp_credentials(payload)


def test_gcp_rejects_unknown_service_account_fields():
    service_account = _gcp_service_account()
    service_account['custom_endpoint'] = 'https://evil.example/'
    with pytest.raises(CloudSecurityError, match='unsupported fields'):
        _gcp_credentials({
            'provider': 'gcp', 'project_id': 'target-prod-123', 'service_account': service_account,
        })


def test_gcp_identity_verification_uses_fixed_resource_manager_endpoint(monkeypatch):
    calls: list[tuple[str, int]] = []

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {'projectId': 'target-prod-123', 'name': 'projects/123456789', 'state': 'ACTIVE'}

    class Session:
        def __init__(self, credentials):
            self.credentials = credentials
            self.trust_env = True

        def get(self, url: str, timeout: int):
            calls.append((url, timeout))
            assert self.trust_env is False
            return Response()

    import google.auth.transport.requests
    monkeypatch.setattr(google.auth.transport.requests, 'AuthorizedSession', Session)
    result = _verify_gcp_target_identity(object(), parse_cloud_target('gcp://target-prod-123'))
    assert calls == [('https://cloudresourcemanager.googleapis.com/v3/projects/target-prod-123', 20)]
    assert result['project_id'] == 'target-prod-123'
    assert result['project_number'] == 'projects/123456789'


def test_gcp_identity_verification_rejects_project_mismatch(monkeypatch):
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {'projectId': 'other-project-123'}

    class Session:
        def __init__(self, credentials):
            self.trust_env = True

        def get(self, url: str, timeout: int):
            return Response()

    import google.auth.transport.requests
    monkeypatch.setattr(google.auth.transport.requests, 'AuthorizedSession', Session)
    with pytest.raises(CloudSecurityError, match='does not match'):
        _verify_gcp_target_identity(object(), parse_cloud_target('gcp://target-prod-123'))


def test_cloud_runtime_environment_removes_routing_and_endpoint_overrides(monkeypatch):
    poisoned = {
        'HTTPS_PROXY': 'http://proxy.example:8080',
        'http_proxy': 'http://proxy.example:8080',
        'NO_PROXY': '*',
        'AWS_ENDPOINT_URL': 'https://evil.example',
        'AWS_ENDPOINT_URL_STS': 'https://evil.example',
        'AWS_CA_BUNDLE': '/tmp/evil-ca.pem',
        'AZURE_AUTHORITY_HOST': 'https://evil.example',
        'CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDASSET': 'https://evil.example',
        'GOOGLE_API_USE_MTLS_ENDPOINT': 'always',
        'REQUESTS_CA_BUNDLE': '/tmp/evil-ca.pem',
    }
    for key, value in poisoned.items():
        monkeypatch.setenv(key, value)
    sanitize_cloud_runtime_environment()
    for key in poisoned:
        assert key not in os.environ
    assert os.environ['AWS_EC2_METADATA_DISABLED'] == 'true'


def test_collection_summary_is_read_only_identity_verified_and_secret_free(tmp_path: Path, monkeypatch):
    secret = 'sensitive-cloud-secret-value'
    payload = {'provider': 'aws', 'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': secret}
    path = _credential_file(tmp_path, payload)

    def fixture_collector(target, data):
        assert target.canonical == 'aws://123456789012'
        assert data['secret_access_key'] == secret
        return (
            {'account_id': '123456789012', 'security_groups': 1},
            [{
                'kind': 'cloud-security-finding',
                'provider': 'aws',
                'rule_id': 'cloud.aws.fixture',
                'title': 'Fixture posture finding',
                'description': 'A deterministic semantic posture observation.',
                'severity': 'high',
                'confidence': 'high',
                'category': 'cloud-security',
                'location': 'aws://fixture/resource',
                'resource_kind': 'aws.fixture',
                'resource_name': 'fixture',
                'remediation': 'Apply least privilege.',
            }],
            [{'provider': 'aws', 'operation': 'optional.read', 'code': 'AccessDenied'}],
        )

    monkeypatch.setitem(cloud_security._COLLECTORS, 'aws', fixture_collector)
    result = collect_cloud_posture('aws://123456789012', str(path))
    encoded = json.dumps(result, sort_keys=True)
    assert result['schema'] == 'aegis.cloud-security.v1'
    summary = result['observations'][0]
    assert summary['identity_verified'] is True
    assert summary['read_only'] is True
    assert summary['ambient_credentials_used'] is False
    assert summary['credential_source'] == 'vault-materialized-file'
    assert secret not in encoded
    assert payload['access_key_id'] not in encoded
