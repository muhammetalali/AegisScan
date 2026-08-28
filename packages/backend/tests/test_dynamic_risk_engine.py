from fastapi_app.services.dynamic_risk_engine import DynamicRiskModel


def test_dynamic_risk_raises_for_behavior_and_exposure() -> None:
    result = DynamicRiskModel().assess(
        base_score=72,
        behavioral_anomaly=0.8,
        newly_exposed_ports=2,
        critical_service_exposure=True,
    )

    assert result.score > 72
    assert result.severity == "critical"
    assert {item["factor"] for item in result.adjustments} == {
        "behavioral_anomaly",
        "newly_exposed_ports",
        "critical_service_exposure",
    }


def test_dynamic_risk_does_not_invent_adjustments() -> None:
    result = DynamicRiskModel().assess(base_score=72)

    assert result.score == 72
    assert result.severity == "high"
    assert result.adjustments == ()
