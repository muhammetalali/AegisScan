from __future__ import annotations

import pytest

from fastapi_app.services.itsm_capability import provider_capability


@pytest.mark.asyncio
async def test_unconfigured_provider_is_not_configured(monkeypatch):
    for key in (
        "JIRA_BASE_URL",
        "JIRA_API_TOKEN",
        "JIRA_USER_EMAIL",
        "JIRA_PROJECT_KEY",
        "SERVICENOW_BASE_URL",
        "SERVICENOW_API_TOKEN",
        "SERVICENOW_USERNAME",
        "SERVICENOW_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)

    result = await provider_capability("jira")

    assert result["status"] == "not_configured"
    assert result["capabilities"] == {}


@pytest.mark.asyncio
async def test_invalid_provider_configuration_is_rejected_without_network_probe(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://acme-security.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_USER_EMAIL", "user@example.invalid")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    result = await provider_capability("jira")

    assert result["status"] == "invalid_configuration"
    assert "health" not in result
    assert result["capabilities"] == {}


@pytest.mark.asyncio
async def test_ready_jira_is_configuration_ready_not_network_health(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://tenant.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_USER_EMAIL", "user@example.invalid")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    result = await provider_capability("jira")

    assert result["status"] == "ready"
    assert result["readiness_basis"] == "configuration"
    assert result["external"] is True
    assert "health" not in result
    assert result["capabilities"]["create_ticket"] is True
    assert result["capabilities"]["reconcile_by_idempotency"] is True
    assert result["capabilities"]["lifecycle_sync"] is True


@pytest.mark.asyncio
async def test_servicenow_uses_safe_default_idempotency_field(monkeypatch):
    monkeypatch.setenv("SERVICENOW_BASE_URL", "https://tenant.service-now.com")
    monkeypatch.setenv("SERVICENOW_API_TOKEN", "token")
    monkeypatch.delenv("SERVICENOW_IDEMPOTENCY_FIELD", raising=False)

    result = await provider_capability("servicenow")

    assert result["status"] == "ready"
    assert result["readiness_basis"] == "configuration"
    assert result["capabilities"]["reconcile_by_idempotency"] is True
    assert result["warnings"] == []


@pytest.mark.asyncio
async def test_sandbox_capability_has_no_network_health_dependency(monkeypatch):
    monkeypatch.setenv("AEGIS_ITSM_MODE", "sandbox")

    result = await provider_capability("jira")

    assert result["status"] == "ready"
    assert result["mode"] == "sandbox"
    assert result["external"] is False
    assert result["readiness_basis"] == "sandbox"
    assert "health" not in result
