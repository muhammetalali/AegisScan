from __future__ import annotations

import pytest

from fastapi_app.services.assurance_risk_pipeline import AssuranceRiskPipeline


class FakeIntelligence:
    async def enrich(self, cve_id, assets):
        return {"cve_id": cve_id, "cvss": 8.8, "epss": 0.42, "kev": False, "matched_assets": ["asset-1"]}


class FakeExternal:
    async def search(self, indicator):
        return {
            "indicator": indicator,
            "provider_status": {"greynoise": "ok", "shodan": "ok"},
            "items": [
                {"source": "greynoise", "confidence": 0.9, "provenance": {"classification": "malicious", "noise": True, "riot": False}},
                {"source": "shodan", "confidence": 0.9, "provenance": {"ports": [22, 443, 8080]}},
            ],
        }


class FakeRemediation:
    async def validate_workspace(self, candidate, *, tools, timeout):
        return {"passed": True, "blocked": False, "summary": {"requested": 1, "available": 1, "failed": 0, "missing": 0}, "tools": []}


@pytest.mark.asyncio
async def test_pipeline_correlates_cti_and_remediation():
    pipeline = AssuranceRiskPipeline(intelligence=FakeIntelligence(), external=FakeExternal(), remediation=FakeRemediation())
    result = await pipeline.assess(
        indicator="203.0.113.10",
        cve_id="CVE-2026-0001",
        behavioral_anomaly=0.20,
        critical_service_exposure=True,
        remediation_candidate={"approval_id": "approval-1", "authorized": True, "workspace": "."},
        remediation_tools=["semgrep"],
    )
    assert result["fusion"]["score"] >= 0
    assert result["fusion"]["confidence"] > 0
    assert "external_intelligence" in result["fusion"]["corroborated_sources"]
    assert "remediation_validation" in result["fusion"]["corroborated_sources"]
    assert result["remediation_validation"]["passed"] is True
    assert result["dynamic_risk"]["score"] != result["fusion"]["score"]
    assert result["decision"]["derived_newly_exposed_ports"] == 3


@pytest.mark.asyncio
async def test_pipeline_propagates_validation_regression():
    class RegressedRemediation(FakeRemediation):
        async def validate_workspace(self, candidate, *, tools, timeout):
            return {"passed": False, "regressed": True, "blocked": False, "tools": []}

    pipeline = AssuranceRiskPipeline(intelligence=FakeIntelligence(), external=FakeExternal(), remediation=RegressedRemediation())
    result = await pipeline.assess(
        indicator="203.0.113.10",
        cve_id="CVE-2026-0001",
        remediation_candidate={"approval_id": "approval-2", "authorized": True, "workspace": "."},
        remediation_tools=["semgrep"],
    )
    assert result["remediation_validation"]["regressed"] is True
    assert any(item["source"] == "remediation_validation" and item["factor"] == "risk_regression" for item in result["fusion"]["lineage"])
    assert result["dynamic_risk"]["score"] >= result["fusion"]["score"]
