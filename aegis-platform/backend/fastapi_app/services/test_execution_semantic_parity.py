from __future__ import annotations

from fastapi_app.services.execution_semantic_parity import compare_execution_semantics


def test_parity_ignores_only_outer_observation_order():
    legacy = {
        'schema': 'aegis.native-output.v1',
        'capability_id': 'recon.dnsenum',
        'observations': [
            {'kind': 'dns-hostname', 'value': 'b.parity.test', 'addresses': ['10.0.0.2', '10.0.0.1']},
            {'kind': 'dns-address', 'value': '10.0.0.10'},
        ],
    }
    candidate = {
        'schema': 'aegis.native-output.v1',
        'capability_id': 'recon.dnsenum',
        'observations': [
            {'kind': 'dns-address', 'value': '10.0.0.10'},
            {'addresses': ['10.0.0.2', '10.0.0.1'], 'value': 'b.parity.test', 'kind': 'dns-hostname'},
        ],
    }

    report = compare_execution_semantics(
        capability_id='recon.dnsenum',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )

    assert report.semantic_equivalent is True
    assert report.observation_equivalent is True
    assert report.finding_projection_applicable is False
    assert report.finding_projection_equivalent is True
    assert report.mismatches == ()


def test_parity_fails_closed_on_nested_sequence_order_drift():
    legacy = {
        'observations': [
            {'kind': 'ordered-chain', 'value': 'x', 'hops': ['first', 'second']},
        ],
    }
    candidate = {
        'observations': [
            {'kind': 'ordered-chain', 'value': 'x', 'hops': ['second', 'first']},
        ],
    }

    report = compare_execution_semantics(
        capability_id='recon.fierce',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )

    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert 'normalized-observation-drift' in report.mismatches


def test_parity_does_not_consider_runtime_provenance_or_raw_stdout():
    observations = [{'kind': 'dns-address', 'value': '10.10.10.10'}]
    legacy = {
        'observations': observations,
        'runtime_provenance': {'provider': 'legacy-native-worker'},
        'raw_stdout': 'legacy formatting',
        'execution_ref': 'legacy-1',
    }
    candidate = {
        'observations': observations,
        'runtime_provenance': {
            'provider': 'kali-recon-provider',
            'image_digest': 'sha256:' + 'a' * 64,
        },
        'raw_stdout': 'different formatting',
        'execution_ref': 'kali-2',
    }

    report = compare_execution_semantics(
        capability_id='recon.dnsenum',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )
    assert report.semantic_equivalent is True


def test_parity_fails_closed_on_observation_drift():
    report = compare_execution_semantics(
        capability_id='recon.dnsenum',
        legacy_normalized={'observations': [{'kind': 'dns-address', 'value': '10.0.0.1'}]},
        candidate_normalized={'observations': [{'kind': 'dns-address', 'value': '10.0.0.2'}]},
    )

    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert 'normalized-observation-drift' in report.mismatches


def test_parity_fails_closed_on_finding_projection_drift():
    legacy = {
        'observations': [
            {
                'kind': 'web-vulnerability',
                'rule_id': 'nikto.TEST',
                'title': 'Test issue',
                'description': 'Observed issue',
                'severity': 'medium',
                'confidence': 'high',
                'category': 'web-vulnerability-assessment',
                'location': 'https://parity.test/a',
                'remediation': 'Fix it',
            }
        ]
    }
    candidate = {
        'observations': [
            {
                'kind': 'web-vulnerability',
                'rule_id': 'nikto.TEST',
                'title': 'Test issue',
                'description': 'Observed issue',
                'severity': 'high',
                'confidence': 'high',
                'category': 'web-vulnerability-assessment',
                'location': 'https://parity.test/a',
                'remediation': 'Fix it',
            }
        ]
    }

    report = compare_execution_semantics(
        capability_id='web.nikto',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )

    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert report.finding_projection_applicable is True
    assert report.finding_projection_equivalent is False
    assert 'finding-projection-drift' in report.mismatches


def test_parity_report_is_stable_and_bounded_contract():
    report = compare_execution_semantics(
        capability_id='recon.fierce',
        legacy_normalized={'observations': []},
        candidate_normalized={'observations': []},
    ).as_dict()

    assert report['schema'] == 'aegis.execution-semantic-parity.v1'
    assert report['capability_id'] == 'recon.fierce'
    assert report['semantic_equivalent'] is True
    assert report['finding_projection_applicable'] is False
    assert len(report['legacy_observation_digest']) == 64
    assert len(report['candidate_observation_digest']) == 64
    assert len(report['legacy_finding_digest']) == 64
    assert len(report['candidate_finding_digest']) == 64
