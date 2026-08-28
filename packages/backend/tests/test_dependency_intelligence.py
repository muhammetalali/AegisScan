import pytest

from fastapi_app.services import security_intelligence


@pytest.mark.asyncio
async def test_requirements_manifest_correlates_osv_and_preserves_lineage(monkeypatch):
    async def fake_query(dependencies, ecosystem):
        assert ecosystem == "PyPI"
        assert dependencies == [{"name": "jinja2", "version": "2.4.1"}]
        return [{"vulns": [{"id": "GHSA-test-1234", "modified": "2026-01-01T00:00:00Z"}]}]

    monkeypatch.setattr(security_intelligence, "_query_osv", fake_query)

    result = await security_intelligence.analyze_dependency_manifest("jinja2==2.4.1\n", "requirements.txt")

    assert result.status == "completed"
    assert result.metrics["registry"] == "OSV"
    assert result.metrics["cve_correlation"] is True
    assert result.metrics["vulnerability_matches"] == 1
    assert result.findings[0]["vulnerability_id"] == "GHSA-test-1234"
    assert any(item["type"] == "dependency_vulnerability_correlation" for item in result.evidence)


@pytest.mark.asyncio
async def test_package_lock_extracts_resolved_versions(monkeypatch):
    captured = {}

    async def fake_query(dependencies, ecosystem):
        captured["dependencies"] = dependencies
        captured["ecosystem"] = ecosystem
        return [{} for _ in dependencies]

    monkeypatch.setattr(security_intelligence, "_query_osv", fake_query)
    manifest = '{"packages":{"node_modules/axios":{"version":"1.20.0"},"node_modules/express":{"version":"5.1.0"}}}'

    result = await security_intelligence.analyze_dependency_manifest(manifest, "package-lock.json")

    assert result.status == "completed"
    assert captured["ecosystem"] == "npm"
    assert captured["dependencies"] == [
        {"name": "axios", "version": "1.20.0"},
        {"name": "express", "version": "5.1.0"},
    ]
    assert result.metrics["vulnerability_matches"] == 0


@pytest.mark.asyncio
async def test_registry_failure_does_not_fabricate_findings(monkeypatch):
    async def fake_query(dependencies, ecosystem):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(security_intelligence, "_query_osv", fake_query)
    result = await security_intelligence.analyze_dependency_manifest("requests==2.31.0\n", "requirements.txt")

    assert result.status == "completed"
    assert result.findings == []
    assert result.metrics["registry_status"] == "error"
    assert result.metrics["cve_correlation"] is False
    assert result.evidence[0]["data"]["registry_status"] == "error"
