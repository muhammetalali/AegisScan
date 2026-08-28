from fastapi_app.services.capability_control_plane import engine_contract
from fastapi_app.services.itsm_capability import provider_capability


def test_dependency_capability_has_live_evidence_contract():
    contract = engine_contract("dependency_risk")
    assert contract["status"] == "implemented"
    assert contract["evidence"] is True
    assert contract["input_contract"]["target_types"] == ["code"]
    assert contract["safety"]["no_fabricated_cve_data"] is True


def test_unknown_engine_is_explicitly_not_ready():
    contract = engine_contract("does_not_exist")
    assert contract["status"] == "unknown"
    assert contract["safety"]["scope_required"] is True

async def test_provider_capability_exposes_full_lifecycle(monkeypatch):
    for key in (
        "JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY",
        "SERVICENOW_BASE_URL", "SERVICENOW_API_TOKEN", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD",
    ):
        monkeypatch.delenv(key, raising=False)
    result = await provider_capability("jira")
    assert result["operations"]["create"]["supported"] is True
    assert result["operations"]["reconcile"]["supported"] is True
    assert result["operations"]["transition"]["supported"] is True
    assert result["operations"]["verify"]["supported"] is True
    assert result["status"] == "not_configured"
