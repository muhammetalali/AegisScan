import pytest

from fastapi_app.services.autonomous_assurance import propose_remediation
from fastapi_app.services.behavioral_terrain import build_fingerprint
from fastapi_app.services.correlation_intelligence import correlate
from fastapi_app.services.external_intelligence import DisabledDarkIntelProvider
from fastapi_app.services.advanced_intelligence import ADIProvider, BTEProvider, CorrelationEngine, Evidence, ScannerAdapter, predictive_signal


def test_behavioral_engine_detects_baseline_deviation():
    result = build_fingerprint("asset-1", {"cpu": 10.0, "cpu_std": 1.0}, {"cpu": 15.0})
    assert result.anomaly_score > 0
    assert result.signals
    assert result.confidence > 0


@pytest.mark.asyncio
async def test_bte_is_telemetry_only():
    items = await BTEProvider().collect("asset-1", {"behavioral_signals": {"ports": 3}, "anomaly_score": 0.2})
    assert len(items) == 1
    assert items[0].source == "bte"


@pytest.mark.asyncio
async def test_adi_accepts_only_supplied_approved_feed():
    items = await ADIProvider().collect("cve-1", {"approved_cti": [{"subject": "cve-1", "id": "x", "confidence": 0.9, "credential": "redacted"}]})
    assert len(items) == 1
    assert "credential" not in items[0].attributes


def test_correlation_reports_agreement_and_conflict():
    result = correlate("finding-1", [
        {"source": "nvd", "claim": "severity", "value": "high", "confidence": 0.9},
        {"source": "scanner", "claim": "severity", "value": "critical", "confidence": 0.8},
    ])
    assert result.confidence > 0
    assert result.conflicts


def test_advanced_correlation_combines_sources():
    result = CorrelationEngine().correlate("CVE-1", [
        Evidence("1", "nvd", "vulnerability", "CVE-1", 0.9, "now"),
        Evidence("2", "cisa", "known_exploited", "CVE-1", 1.0, "now"),
    ])
    assert result["source_count"] == 2
    assert result["evidence_count"] == 2
    assert 0 < result["confidence"] <= 1


def test_scanner_adapter_normalizes_supported_tools():
    result = ScannerAdapter().normalize("trivy", [{"id": "CVE-1", "subject": "image:a", "confidence": 0.8}])
    assert result[0].source == "trivy"
    with pytest.raises(ValueError):
        ScannerAdapter().normalize("unknown", [])


def test_predictive_signal_is_bounded():
    result = predictive_signal([40, 50, 60])
    assert result == {"trend": 10.0, "forecast": 70.0}


def test_remediation_is_proposal_only():
    result = propose_remediation("CVE-2026-1", [{"source": "nvd", "type": "cve_record"}], "asset-1")
    assert result.requires_approval is True
    assert "sandbox" in " ".join(result.validation_plan)
    assert result.rollback_plan


@pytest.mark.asyncio
async def test_dark_intel_boundary_is_disabled_by_default():
    assert await DisabledDarkIntelProvider().search("example") == []
