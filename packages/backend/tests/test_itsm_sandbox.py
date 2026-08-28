import pytest

from fastapi_app.services import itsm_sandbox
from fastapi_app.services.itsm_capability import provider_capability
from fastapi_app.services.itsm_provider_health import check_provider


def test_sandbox_mode_is_explicit(monkeypatch):
    monkeypatch.setenv("AEGIS_ITSM_MODE", "sandbox")
    assert itsm_sandbox.enabled() is True
    monkeypatch.setenv("AEGIS_ITSM_MODE", "real")
    assert itsm_sandbox.enabled() is False


def test_sandbox_ids_are_deterministic_and_provider_scoped():
    jira = itsm_sandbox.create(
        provider="jira", decision={"decisionId": "d1"}, action={"actionId": "a1"}, evidence=[], idempotency_key="idem-123456789"
    )
    again = itsm_sandbox.create(
        provider="jira", decision={"decisionId": "d1"}, action={"actionId": "a1"}, evidence=[], idempotency_key="idem-123456789"
    )
    snow = itsm_sandbox.create(
        provider="servicenow", decision={"decisionId": "d1"}, action={"actionId": "a1"}, evidence=[], idempotency_key="idem-123456789"
    )
    assert jira["external_id"] == again["external_id"]
    assert jira["external_id"].startswith("SANDBOX-JIRA-")
    assert snow["external_id"].startswith("SANDBOX-SNOW-")
    assert jira["external_id"] != snow["external_id"]


@pytest.mark.asyncio
async def test_sandbox_health_is_non_external(monkeypatch):
    monkeypatch.setenv("AEGIS_ITSM_MODE", "sandbox")
    jira = await check_provider("jira")
    snow = await check_provider("servicenow")
    assert jira["status"] == "healthy" and jira["external"] is False
    assert snow["status"] == "healthy" and snow["external"] is False


@pytest.mark.asyncio
async def test_sandbox_capability_is_ready(monkeypatch):
    monkeypatch.setenv("AEGIS_ITSM_MODE", "sandbox")
    for provider in ("jira", "servicenow"):
        result = await provider_capability(provider)
        assert result["status"] == "ready"
        assert result["mode"] == "sandbox"
        assert result["external"] is False
        assert result["capabilities"]["reconcile_by_idempotency"] is True
