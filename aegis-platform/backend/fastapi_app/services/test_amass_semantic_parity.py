from __future__ import annotations

from pathlib import Path

from fastapi_app.services import amass_managed_runtime as runtime
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


def test_amass_discovered_name_output_normalizes_to_hostname_observations():
    normalized = normalize_enriched_native_output('recon.amass', _SAMPLE_A)
    assert normalized['schema'] == 'aegis.native-observations.v1'
    assert normalized['count'] == 3
    assert {
        (item.get('kind'), item.get('hostname'))
        for item in normalized['observations']
        if isinstance(item, dict)
    } == {
        ('discovered-hostname', 'www.parity.test'),
        ('discovered-hostname', 'api.parity.test'),
        ('discovered-hostname', 'mail.parity.test'),
    }


def test_amass_semantic_parity_ignores_outer_output_order_only():
    legacy = normalize_enriched_native_output('recon.amass', _SAMPLE_A)
    candidate = normalize_enriched_native_output('recon.amass', _SAMPLE_B)
    report = compare_execution_semantics(
        capability_id='recon.amass',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )
    assert report.semantic_equivalent is True
    assert report.observation_equivalent is True
    assert report.finding_projection_applicable is False
    assert report.finding_projection_equivalent is True
    assert report.mismatches == ()


def test_amass_semantic_parity_fails_closed_on_missing_discovery():
    legacy = normalize_enriched_native_output('recon.amass', _SAMPLE_A)
    candidate = normalize_enriched_native_output(
        'recon.amass',
        _SAMPLE_B.replace('api.parity.test\n', ''),
    )
    report = compare_execution_semantics(
        capability_id='recon.amass',
        legacy_normalized=legacy,
        candidate_normalized=candidate,
    )
    assert report.semantic_equivalent is False
    assert report.observation_equivalent is False
    assert 'normalized-observation-drift' in report.mismatches


def test_amass_parity_requires_exact_authenticated_source_build(tmp_path):
    backend_root = Path(__file__).resolve().parents[2]
    builder = (backend_root / 'resources' / 'build-amass-v5-aegis.sh').read_text(encoding='utf-8')
    patch = (
        backend_root / 'resources' / 'patches' / 'amass-v5.1.1-aegis-engine-auth.patch'
    ).read_text(encoding='utf-8')
    source = Path(runtime.__file__).read_text(encoding='utf-8')

    assert 'AMASS_COMMIT="79299dce87b0085db0f2f4ef3e9c52cccb49f514"' in builder
    assert 'git -C "$SOURCE_ROOT" apply --unidiff-zero --check "$PATCH_PATH"' in builder
    assert 'go build -trimpath -buildvcs=false' in builder
    assert 'engineAuthHeader = "X-Aegis-Amass-Token"' in patch
    assert 'subtle.ConstantTimeCompare' in patch
    assert 'clone.Header.Set(engineAuthHeader, t.token)' in patch
    assert 'headers.Set(engineAuthHeader, c.token)' in patch
    assert 'http.StatusUnauthorized' in patch
    assert 'sessionConfig := config.NewConfig()' in patch
    assert 'v.mgr.NewSession(sessionConfig)' in patch
    assert 'import secrets' in source
    assert 'env["AEGIS_AMASS_ENGINE_TOKEN"] = secrets.token_hex(32)' in source
    assert 'AEGIS_AMASS_ENGINE_TOKEN' not in runtime._minimal_environment(tmp_path / 'env')
