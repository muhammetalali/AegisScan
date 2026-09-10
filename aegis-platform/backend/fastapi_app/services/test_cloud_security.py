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
    _load_credentials,
    collect_cloud_posture,
)
from fastapi_app.services.cloud_target import parse_cloud_target


def _credential_file(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / 'credential.json'
    path.write_text(json.dumps(payload), encoding='utf-8')
    os.chmod(path, 0o600)
    return path


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
