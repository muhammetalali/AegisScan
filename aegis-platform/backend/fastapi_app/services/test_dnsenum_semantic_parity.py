from __future__ import annotations

from fastapi_app.services.execution_semantic_parity import compare_execution_semantics
from fastapi_app.services.native_output_enrichment import normalize_enriched_native_output


_DNSENUM_REALISTIC_SAMPLE = '''
Host's addresses:
__________________
parity.test. 60 IN A 172.28.0.10

Name Servers:
______________
ns1.parity.test. 60 IN A 172.28.0.53

Mail (MX) Servers:
___________________
mail.parity.test. 60 IN A 172.28.0.12

Brute forcing with /usr/share/dnsenum/dns.txt:
_____________________________________________
www.parity.test. 60 IN A 172.28.0.11
api.parity.test. 60 IN A 172.28.0.13
'''

_DNSENUM_SEMANTIC_SAMPLE_A = '''
parity.test. 60 IN A 172.28.0.10
ns1.parity.test. 60 IN A 172.28.0.53
mail.parity.test. 60 IN A 172.28.0.12
www.parity.test. 60 IN A 172.28.0.11
api.parity.test. 60 IN A 172.28.0.13
'''

_DNSENUM_SEMANTIC_SAMPLE_B = '''
api.parity.test. 60 IN A 172.28.0.13
www.parity.test. 60 IN A 172.28.0.11
mail.parity.test. 60 IN A 172.28.0.12
ns1.parity.test. 60 IN A 172.28.0.53
parity.test. 60 IN A 172.28.0.10
'''


def test_dnsenum_normalizer_extracts_deterministic_fixture_semantics():
    normalized = normalize_enriched_native_output('recon.dnsenum', _DNSENUM_REALISTIC_SAMPLE)
    values = {
        (item.get('kind'), item.get('value'))
        for item in normalized['observations']
        if isinstance(item, dict)
    }

    assert normalized['schema'] == 'aegis.native-observations.v1'
    assert ('dns-address', '172.28.0.10') in values
    assert ('dns-address', '172.28.0.53') in values
    assert ('dns-hostname', 'parity.test') in values
    assert ('dns-hostname', 'www.parity.test') in values
    assert ('dns-hostname', 'mail.parity.test') in values
    assert ('dns-hostname', 'api.parity.test') in values
    assert ('dns-hostname', 'ns1.parity.test') in values


def test_dnsenum_semantic_parity_ignores_output_order_only():
    legacy = normalize_enriched_native_output('recon.dnsenum', _DNSENUM_SEMANTIC_SAMPLE_A)
    candidate = normalize_enriched_native_output('recon.dnsenum', _DNSENUM_SEMANTIC_SAMPLE_B)

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


def test_dnsenum_semantic_parity_fails_closed_on_missing_observation():
    legacy = normalize_enriched_native_output('recon.dnsenum', _DNSENUM_SEMANTIC_SAMPLE_A)
    candidate = normalize_enriched_native_output(
        'recon.dnsenum',
        _DNSENUM_SEMANTIC_SAMPLE_B.replace('api.parity.test. 60 IN A 172.28.0.13\n', ''),
    )

    report = compare_execution_semantics(
        capability_id='recon.dnsenum',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )

    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert 'normalized-observation-drift' in report.mismatches
