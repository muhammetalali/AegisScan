from fastapi_app.services.posture_engine import PostureEngine


def test_posture_uses_measured_dimensions_only():
    assessment = PostureEngine().assess(
        validations=[{
            "status": "completed",
            "results": {
                "findings": [{"severity": "high"}],
                "evidence": [{"id": "e1"}],
            },
        }],
        assets_total=2,
        assets_covered=1,
    )
    names = {metric["name"]: metric for metric in assessment.metrics}
    assert names["Control Effectiveness"]["measured"] is False
    assert names["Coverage"]["value"] == 50.0
    assert 0 <= assessment.score <= 100


def test_posture_trend_is_derived_from_history():
    assessment = PostureEngine().assess(validations=[], trend_scores=[50, 70])
    assert assessment.trend["direction"] == "improving"
    assert assessment.trend["change_rate"] == 20.0

