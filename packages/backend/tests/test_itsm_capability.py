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
async def test_invalid_provider_configuration_never_reaches_health(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://acme-security.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_USER_EMAIL", "user@example.invalid")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    result = await provider_capability("jira")

    assert result["status"] == "invalid_configuration"
    assert "health" not in result
    assert result["capabilities"] == {}


@pytest.mark.asyncio
async def test_ready_jira_exposes_implemented_operations(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://tenant.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_USER_EMAIL", "user@example.invalid")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    async def healthy(provider: str, timeout: float = 8.0):
        return {"provider": provider, "status": "healthy", "http_status": 200}

    monkeypatch.setattr("fastapi_app.services.itsm_capability.check_provider", healthy)
    result = await provider_capability("jira")

    assert result["status"] == "ready"
    assert result["capabilities"]["create_ticket"] is True
    assert result["capabilities"]["reconcile_by_idempotency"] is True
    assert result["capabilities"]["lifecycle_sync"] is True


@pytest.mark.asyncio
async def test_servicenow_without_idempotency_field_is_degraded(monkeypatch):
    monkeypatch.setenv("SERVICENOW_BASE_URL", "https://tenant.service-now.com")
    monkeypatch.setenv("SERVICENOW_API_TOKEN", "token")
    monkeypatch.delenv("SERVICENOW_IDEMPOTENCY_FIELD", raising=False)

    async def healthy(provider: str, timeout: float = 8.0):
        return {"provider": provider, "status": "healthy", "http_status": 200}

    monkeypatch.setattr("fastapi_app.services.itsm_capability.check_provider", healthy)
    result = await provider_capability("servicenow")

    assert result["status"] == "degraded"
    assert result["capabilities"]["create_ticket"] is True
    assert result["capabilities"]["reconcile_by_idempotency"] is False
    assert result["warnings"]


@pytest.mark.asyncio
async def test_unhealthy_provider_has_no_write_capabilities(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://tenant.atlassian.net")
    monkeypatch.setenv("JIRA_API_TOKEN", "token")
    monkeypatch.setenv("JIRA_USER_EMAIL", "user@example.invalid")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    async def unhealthy(provider: str, timeout: float = 8.0):
        return {"provider": provider, "status": "auth_failed", "http_status": 401}

    monkeypatch.setattr("fastapi_app.services.itsm_capability.check_provider", unhealthy)
    result = await provider_capability("jira")

    assert result["status"] == "unhealthy"
    assert result["capabilities"] == {}
