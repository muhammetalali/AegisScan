from __future__ import annotations

from fastapi_app.services.itsm_configuration import startup_validation, validate_itsm_configuration


def test_placeholder_urls_are_invalid(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://YOUR-INSTANCE.atlassian.net")
    monkeypatch.setenv("JIRA_USER_EMAIL", "security@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "test-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")
    monkeypatch.setenv("SERVICENOW_BASE_URL", "https://YOUR-INSTANCE.service-now.com")
    monkeypatch.setenv("SERVICENOW_API_TOKEN", "test-token")

    states = validate_itsm_configuration()

    assert not states["jira"].valid
    assert any("placeholder" in error.lower() for error in states["jira"].errors)
    assert not states["servicenow"].valid
    assert any("placeholder" in error.lower() for error in states["servicenow"].errors)


def test_example_acme_hosts_are_invalid_but_non_blocking_at_startup(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://acme-security.atlassian.net")
    monkeypatch.setenv("JIRA_USER_EMAIL", "security@example.invalid")
    monkeypatch.setenv("JIRA_API_TOKEN", "test-token")
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")
    monkeypatch.setenv("SERVICENOW_BASE_URL", "https://acme-security.service-now.com")
    monkeypatch.setenv("SERVICENOW_API_TOKEN", "test-token")

    states = validate_itsm_configuration()
    ready, _ = startup_validation()

    assert not states["jira"].valid
    assert not states["servicenow"].valid
    assert ready


def test_unconfigured_optional_provider_is_not_an_error(monkeypatch):
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

    states = validate_itsm_configuration()

    assert not states["jira"].enabled
    assert states["jira"].valid
    assert not states["servicenow"].enabled
    assert states["servicenow"].valid


def test_partial_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("JIRA_BASE_URL", "https://security.example.net")
    monkeypatch.delenv("JIRA_API_TOKEN", raising=False)
    monkeypatch.delenv("JIRA_USER_EMAIL", raising=False)
    monkeypatch.setenv("JIRA_PROJECT_KEY", "SEC")

    states = validate_itsm_configuration()

    assert states["jira"].enabled
    assert not states["jira"].valid
    assert any("missing JIRA_API_TOKEN" in error for error in states["jira"].errors)

    ready, _ = startup_validation()
    assert not ready
