from fastapi_app.services.risk_engine import assess_risk


def test_kev_and_exploit_probability_raise_risk():
    assessment = assess_risk(cvss=9.8, epss=0.9, kev=True, matched_assets=2, published="2025-01-01T00:00:00Z", source_count=4)
    assert assessment.score >= 85
    assert assessment.severity == "critical"
    assert assessment.confidence > 0.8
    assert any(f["name"] == "known_exploited" and f["contribution"] == 20.0 for f in assessment.factors)


def test_missing_cvss_and_asset_match_reduce_confidence_not_integrity():
    assessment = assess_risk(cvss=None, epss=0.01, kev=False, matched_assets=0, published=None, source_count=1)
    assert assessment.score >= 0
    assert assessment.severity in {"low", "medium", "unknown"}
    assert assessment.confidence < 0.8


def test_risk_is_bounded():
    assessment = assess_risk(cvss=10, epss=1, kev=True, matched_assets=500, published=None, source_count=4)
    assert 0 <= assessment.score <= 100
