import pytest

from fastapi_app.services.intelligence_fabric import CircuitBreaker, IntelligenceFabric


def test_circuit_breaker_opens_after_threshold():
    breaker = CircuitBreaker(threshold=2, cooldown=60)
    assert breaker.allow()
    breaker.failure()
    assert breaker.allow()
    breaker.failure()
    assert not breaker.allow()


def test_severity_mapping():
    assert IntelligenceFabric._severity(9.8) == "critical"
    assert IntelligenceFabric._severity(8.0) == "high"
    assert IntelligenceFabric._severity(5.0) == "medium"
    assert IntelligenceFabric._severity(2.0) == "low"
    assert IntelligenceFabric._severity(None) == "unknown"


def test_cve_validation_rejects_non_cve():
    fabric = IntelligenceFabric(redis_url="redis://localhost:6379/0")
    with pytest.raises(ValueError):
        import asyncio
        asyncio.run(fabric.enrich("not-a-cve"))
