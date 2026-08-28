import pytest

from fastapi_app.services.ticket_orchestration import JiraProvider, ServiceNowProvider, TicketOrchestrator


@pytest.mark.asyncio
async def test_jira_not_configured_fails_open_without_network():
    result = await JiraProvider().create(title="Test", description="Desc", priority="high", evidence=[], finding={})
    assert result.status == "not_configured"
    assert result.external_id is None


@pytest.mark.asyncio
async def test_servicenow_not_configured_fails_open_without_network(monkeypatch):
    monkeypatch.delenv("SERVICENOW_BASE_URL", raising=False)
    monkeypatch.delenv("SERVICENOW_API_TOKEN", raising=False)
    result = await ServiceNowProvider().create(title="Test", description="Desc", priority="high", evidence=[], finding={})
    assert result.status == "not_configured"


def test_ticket_description_carries_security_decision_context():
    text = TicketOrchestrator._description({"severity": "critical", "final_score": 92, "confidence": 0.88, "recommended_action": "Patch"}, [])
    assert "critical" in text
    assert "92" in text
    assert "Patch" in text
