import pytest

from fastapi_app.services.autonomous_assurance import propose_remediation
from fastapi_app.services.behavioral_terrain import build_fingerprint
from fastapi_app.services.correlation_intelligence import correlate
from fastapi_app.services.external_intelligence import DisabledDarkIntelProvider


def test_behavioral_engine_detects_baseline_deviation():
    result = build_fingerprint("asset-1", {"cpu": 10.0, "cpu_std": 1.0}, {"cpu": 15.0})
    assert result.anomaly_score > 0
    assert result.signals
    assert result.confidence > 0


def test_correlation_reports_agreement_and_conflict():
    result = correlate("finding-1", [
        {"source": "nvd", "claim": "severity", "value": "high", "confidence": 0.9},
        {"source": "scanner", "claim": "severity", "value": "critical", "confidence": 0.8},
    ])
    assert result.confidence > 0
    assert result.conflicts


def test_remediation_is_proposal_only():
    result = propose_remediation("CVE-2026-1", [{"source": "nvd", "type": "cve_record"}], "asset-1")
    assert result.requires_approval is True
    assert "sandbox" in " ".join(result.validation_plan)
    assert result.rollback_plan


@pytest.mark.asyncio
async def test_dark_intel_boundary_is_disabled_by_default():
    assert await DisabledDarkIntelProvider().search("example") == []
