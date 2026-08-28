from fastapi_app.services.fusion_engine import FusionEngine


def test_fusion_corroborates_sources():
    result = FusionEngine().fuse({
        "nvd": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]}},
        "osv": {"severity": [{"score": "8.0"}]},
        "epss": {"epss": "0.42"},
        "cisa_kev": {"cveID": "CVE-2026-0001"},
    })
    assert result.score >= 85
    assert result.confidence >= 0.8
    assert set(result.corroborated_sources) == {"cisa_kev", "epss", "nvd", "osv"}
    assert result.lineage


def test_fusion_retains_conflict():
    result = FusionEngine().fuse({
        "nvd": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}},
        "epss": {"epss": "0.001"},
    })
    assert result.conflicts
    assert "conflict" in result.rationale.lower()
