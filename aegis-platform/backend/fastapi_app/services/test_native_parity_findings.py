from __future__ import annotations

from fastapi_app.services.native_finding_projection import native_observation_finding_specs


def test_nikto_observation_becomes_semantic_finding_spec():
    normalized = {
        'observations': [{
            'kind': 'web-vulnerability',
            'rule_id': 'nikto.999001',
            'title': 'Administrative endpoint is exposed',
            'description': 'Administrative endpoint is exposed',
            'severity': 'medium',
            'confidence': 'medium',
            'location': '/admin',
            'method': 'GET',
            'references': ['CVE-2099-0001'],
            'remediation': 'Restrict access.',
        }],
    }
    specs = native_observation_finding_specs(
        normalized,
        observation_kind='web-vulnerability',
        category='web-vulnerability-assessment',
    )
    assert len(specs) == 1
    spec = specs[0]
    assert spec.rule_id == 'nikto.999001'
    assert spec.category == 'web-vulnerability-assessment'
    assert spec.severity == 'medium'
    assert spec.identity_key == 'nikto.999001|/admin||GET'
    assert spec.raw_data['references'] == ['CVE-2099-0001']


def test_trivy_iac_observation_becomes_high_confidence_finding_spec():
    normalized = {
        'observations': [{
            'kind': 'iac-security-finding',
            'rule_id': 'AVD-AWS-0086',
            'title': 'Bucket has public ACL',
            'description': 'Public ACLs expose data.',
            'severity': 'high',
            'confidence': 'high',
            'location': 'main.tf:4',
            'resource': 'aws_s3_bucket.bad',
            'remediation': 'Use a private ACL.',
            'primary_url': 'https://avd.aquasec.com/misconfig/avd-aws-0086',
            'references': ['https://example.test/reference'],
            'class': 'config',
            'type': 'terraform',
        }],
    }
    specs = native_observation_finding_specs(
        normalized,
        observation_kind='iac-security-finding',
        category='iac-security',
    )
    assert len(specs) == 1
    spec = specs[0]
    assert spec.rule_id == 'AVD-AWS-0086'
    assert spec.severity == 'high'
    assert spec.confidence == 'high'
    assert spec.category == 'iac-security'
    assert spec.identity_key == 'AVD-AWS-0086|main.tf:4|aws_s3_bucket.bad|'
    assert spec.affected_urls == ('https://avd.aquasec.com/misconfig/avd-aws-0086',)
