from __future__ import annotations

import httpx
import pytest

from fastapi_app.services import itsm_provider_health as health
from fastapi_app.services.itsm_configuration import validate_itsm_configuration


@pytest.mark.parametrize(
    "provider_env, expected_provider",
    [
        ({"JIRA_BASE_URL": "https://acme-security.atlassian.net", "JIRA_USER_EMAIL": "a@example.invalid", "JIRA_API_TOKEN": "token", "JIRA_PROJECT_KEY": "SEC"}, "jira"),
        ({"SERVICENOW_BASE_URL": "https://acme-security.service-now.com", "SERVICENOW_API_TOKEN": "token"}, "servicenow"),
    ],
)
def test_example_provider_hosts_are_rejected(provider_env, expected_provider, monkeypatch):
    for key, value in provider_env.items():
        monkeypatch.setenv(key, value)
    state = validate_itsm_configuration()[expected_provider]
    assert state.enabled
    assert not state.valid
    assert any("placeholder" in error.lower() or "example" in error.lower() for error in state.errors)


@pytest.mark.asyncio
async def test_jira_health_never_exposes_credentials(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.org")
    monkeypatch.setenv("JIRA_USER_EMAIL", "security@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "secret-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url):
            request = httpx.Request("GET", url)
            response = httpx.Response(200, request=request, json={"accountId": "abc"})
            return response

    monkeypatch.setattr(health.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    result = await health.check_provider("jira")

    assert result["status"] == "healthy"
    assert "secret-token" not in str(result)


@pytest.mark.asyncio
async def test_provider_health_maps_auth_failure(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.org")
    monkeypatch.setenv("JIRA_USER_EMAIL", "security@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "secret-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, url):
            request = httpx.Request("GET", url)
            return httpx.Response(401, request=request)

    monkeypatch.setattr(health.httpx, "AsyncClient", lambda **kwargs: FakeClient())
    result = await health.check_provider("jira")
    assert result["status"] == "auth_failed"
    assert result["http_status"] == 401
