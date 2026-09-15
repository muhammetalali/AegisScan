from __future__ import annotations

from fastapi_app.services.execution_semantic_parity import compare_execution_semantics
from fastapi_app.services.native_output_enrichment import normalize_enriched_native_output


_SAMPLE_A = """www.parity.test
api.parity.test
mail.parity.test
"""

_SAMPLE_B = """mail.parity.test
www.parity.test
api.parity.test
"""


def test_subfinder_normalizer_extracts_bounded_hostname_observations():
    normalized = normalize_enriched_native_output('recon.subfinder', _SAMPLE_A)
    assert normalized['schema'] == 'aegis.native-observations.v1'
    assert normalized['count'] == 3
    values = {
        (item.get('kind'), item.get('hostname'))
        for item in normalized['observations']
        if isinstance(item, dict)
    }
    assert values == {
        ('discovered-hostname', 'www.parity.test'),
        ('discovered-hostname', 'api.parity.test'),
        ('discovered-hostname', 'mail.parity.test'),
    }


def test_subfinder_semantic_parity_ignores_output_order_only():
    legacy = normalize_enriched_native_output('recon.subfinder', _SAMPLE_A)
    candidate = normalize_enriched_native_output('recon.subfinder', _SAMPLE_B)
    report = compare_execution_semantics(
        capability_id='recon.subfinder',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )
    assert report.semantic_equivalent is True
    assert report.observation_equivalent is True
    assert report.finding_projection_applicable is False
    assert report.finding_projection_equivalent is True
    assert report.mismatches == ()


def test_subfinder_semantic_parity_fails_closed_on_missing_observation():
    legacy = normalize_enriched_native_output('recon.subfinder', _SAMPLE_A)
    candidate = normalize_enriched_native_output(
        'recon.subfinder',
        _SAMPLE_B.replace('api.parity.test\n', ''),
    )
    report = compare_execution_semantics(
        capability_id='recon.subfinder',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )
    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert 'normalized-observation-drift' in report.mismatches
