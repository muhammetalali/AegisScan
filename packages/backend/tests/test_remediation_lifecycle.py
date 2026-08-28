from __future__ import annotations

import pytest

from fastapi_app.services.remediation_lifecycle import validate_and_verify


class FakeValidation:
    async def validate_workspace(self, candidate, *, tools=None, timeout=180):
        return {"passed": candidate.get("tool_pass", True), "blocked": False, "summary": {"requested": 1, "available": 1, "failed": 0, "missing": 0}}


@pytest.mark.asyncio
async def test_failed_validation_cannot_be_verified(monkeypatch):
    import fastapi_app.services.remediation_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "get_lifecycle", lambda action_id: {"action_id": action_id, "provider": "jira", "external_id": "SEC-1", "external_url": "https://jira/browse/SEC-1", "validation": {}})
    monkeypatch.setattr(lifecycle, "get_action", lambda action_id: {"actionId": action_id, "state": "awaiting_revalidation", "riskBefore": 80})
    monkeypatch.setattr(lifecycle, "RemediationValidationSuite", lambda: FakeValidation())
    monkeypatch.setattr(lifecycle, "transition", lambda action_id, state, actor, note=None: {"actionId": action_id, "state": state})
    monkeypatch.setattr(lifecycle, "_sync_external_ticket", lambda *args, **kwargs: {"provider": "jira", "status": "synced", "target_state": "in_progress"})
    recorded = {}
    monkeypatch.setattr(lifecycle, "_record", lambda *args, **kwargs: recorded.update({"state": args[4], "validation": args[5]}))

    result = await validate_and_verify("act-1", "tester", candidate={"approval_id": "a", "authorized": True, "workspace": ".", "tool_pass": False, "risk_before": 80, "risk_after": 90})
    assert result["action"]["state"] == "in_progress"
    assert result["validation"]["passed"] is False
    assert recorded["state"] == "in_progress"


@pytest.mark.asyncio
async def test_passed_validation_reaches_verified(monkeypatch):
    import fastapi_app.services.remediation_lifecycle as lifecycle

    monkeypatch.setattr(lifecycle, "get_lifecycle", lambda action_id: {"action_id": action_id, "provider": "servicenow", "external_id": "sys-1", "external_url": "https://snow", "validation": {}})
    monkeypatch.setattr(lifecycle, "get_action", lambda action_id: {"actionId": action_id, "state": "awaiting_revalidation", "riskBefore": 80})
    monkeypatch.setattr(lifecycle, "RemediationValidationSuite", lambda: FakeValidation())
    monkeypatch.setattr(lifecycle, "transition", lambda action_id, state, actor, note=None: {"actionId": action_id, "state": state})
    monkeypatch.setattr(lifecycle, "_sync_external_ticket", lambda *args, **kwargs: {"provider": "servicenow", "status": "synced", "target_state": "verified"})
    monkeypatch.setattr(lifecycle, "_record", lambda *args, **kwargs: None)

    result = await validate_and_verify("act-2", "tester", candidate={"approval_id": "a", "authorized": True, "workspace": ".", "risk_before": 80, "risk_after": 65})
    assert result["action"]["state"] == "verified"
    assert result["validation"]["passed"] is True
    assert result["validation"]["risk_diff"]["regressed"] is False
