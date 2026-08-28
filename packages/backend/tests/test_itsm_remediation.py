import pytest

from fastapi_app.services import itsm_remediation_v2 as itsm


def test_severity_and_sla_are_derived_from_final_risk():
    assert itsm._severity_and_sla({"final_score": 92}) == ("critical", 24)
    assert itsm._severity_and_sla({"final_score": 78}) == ("high", 72)
    assert itsm._severity_and_sla({"final_score": 55}) == ("medium", 168)
    assert itsm._severity_and_sla({"final_score": 10}) == ("low", 720)


def test_ticket_description_contains_traceability():
    description = itsm._description(
        {"decisionId": "dec-1", "final_score": 91, "confidence": 0.87, "label": "CVE finding"},
        {"actionId": "act-1", "title": "Remediation"},
        [{"id": "ev-1"}],
        24,
        "critical",
    )
    assert "act-1" in description
    assert "dec-1" in description
    assert "Dynamic risk: 91.00" in description
    assert "Fusion confidence: 0.870" in description


class _FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, *args, **kwargs):
        return None

    def fetchone(self):
        return None


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def commit(self):
        return None


class _FakePool:
    def __init__(self):
        self.conn = _FakeConn()

    def getconn(self):
        return self.conn

    def putconn(self, conn):
        return None


@pytest.mark.asyncio
async def test_verify_case_only_reaches_verified_with_success(monkeypatch):
    calls = []
    monkeypatch.setattr(itsm, "get_case", lambda action_id: {"action": {"actionId": action_id, "state": "awaiting_revalidation", "riskBefore": 80}, "integrations": []})
    monkeypatch.setattr(itsm, "transition", lambda action_id, state, actor, note=None, **kwargs: (calls.append((action_id, state, kwargs)), {"actionId": action_id, "state": state})[1])
    monkeypatch.setattr(itsm, "_db", lambda: _FakePool())

    class FakeSuite:
        async def validate_workspace(self, candidate, tools=None, timeout=180):
            return {"passed": True, "summary": {"requested": 1, "available": 1}}

        @staticmethod
        def compare_scores(before, after):
            return {"before": before, "after": after, "delta": after - before, "regressed": False, "improvement": max(0, before - after)}

    monkeypatch.setattr(itsm, "RemediationValidationSuite", FakeSuite)
    monkeypatch.setattr(itsm, "_sync_external_states", lambda *args, **kwargs: _async_noop())
    monkeypatch.setattr(itsm, "_audit", lambda *args, **kwargs: None)

    result = await itsm.verify_case("act-1", "tester", {"approval_id": "a-1", "authorized": True, "workspace": ".", "risk_before": 80, "risk_after": 30}, tools=["semgrep"])
    assert result["action"]["state"] == "verified"
    assert any(item[1] == "verified" and item[2].get("verification_context") is True for item in calls)


@pytest.mark.asyncio
async def test_verify_case_reopens_when_validation_fails(monkeypatch):
    calls = []
    monkeypatch.setattr(itsm, "get_case", lambda action_id: {"action": {"actionId": action_id, "state": "awaiting_revalidation", "riskBefore": 80}, "integrations": []})
    monkeypatch.setattr(itsm, "transition", lambda action_id, state, actor, note=None, **kwargs: (calls.append((action_id, state, kwargs)), {"actionId": action_id, "state": state})[1])
    monkeypatch.setattr(itsm, "_db", lambda: _FakePool())

    class FakeSuite:
        async def validate_workspace(self, candidate, tools=None, timeout=180):
            return {"passed": False, "summary": {"requested": 1, "available": 1}}

        @staticmethod
        def compare_scores(before, after):
            return {"before": before, "after": after, "delta": after - before, "regressed": True, "improvement": 0}

    monkeypatch.setattr(itsm, "RemediationValidationSuite", FakeSuite)
    monkeypatch.setattr(itsm, "_sync_external_states", lambda *args, **kwargs: _async_noop())
    monkeypatch.setattr(itsm, "_audit", lambda *args, **kwargs: None)

    result = await itsm.verify_case("act-1", "tester", {"approval_id": "a-1", "authorized": True, "workspace": ".", "risk_before": 80, "risk_after": 85}, tools=["semgrep"])
    assert result["action"]["state"] == "in_progress"
    assert not any(item[1] == "verified" for item in calls)


@pytest.mark.asyncio
async def test_jira_configuration_requires_all_credentials(monkeypatch):
    for key in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert itsm._configured("jira") is False


async def _async_noop():
    return None
