import pytest

from fastapi_app.services import itsm_remediation as itsm


def test_ticket_payload_derives_severity_priority_and_sla_from_final_risk():
    title, description, priority = itsm._ticket_payload(
        {"decisionId": "dec-1", "final_score": 92, "confidence": 0.87, "label": "CVE finding"},
        {"actionId": "act-1", "title": "Remediation"},
        [{"id": "ev-1"}],
    )
    assert title == "CVE finding"
    assert priority == "1"
    assert "act-1" in description
    assert "dec-1" in description
    assert "Dynamic risk: 92.00" in description
    assert "Fusion confidence: 0.870" in description
    assert "SLA target: 24h" in description


def test_ticket_payload_priority_bands():
    cases = ((78, "2", 72), (55, "3", 168), (10, "4", 720))
    for score, priority, sla in cases:
        _, description, actual_priority = itsm._ticket_payload(
            {"final_score": score, "confidence": 0.5, "label": "finding"},
            {"actionId": "act-1", "title": "Remediation"},
            [],
        )
        assert actual_priority == priority
        assert f"Dynamic risk: {score:.2f}" in description
        assert f"SLA target: {sla}h" in description


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
    def getconn(self):
        return _FakeConn()

    def putconn(self, conn):
        return None


def _install_verify_mocks(monkeypatch, *, passed: bool, regressed: bool):
    case = {
        "action": {
            "actionId": "act-1",
            "state": "awaiting_revalidation",
            "riskBefore": 80,
        },
        "integrations": [],
    }
    calls = []

    def fake_get_case(action_id):
        return case

    def fake_transition(action_id, state, actor, note=None, **kwargs):
        calls.append((action_id, state, kwargs))
        case["action"] = {**case["action"], "state": state}
        return {"actionId": action_id, "state": state}

    monkeypatch.setattr(itsm, "get_case", fake_get_case)
    monkeypatch.setattr(itsm, "transition", fake_transition)
    monkeypatch.setattr(itsm, "_db", lambda: _FakePool())
    monkeypatch.setattr(itsm, "_sync_external_states", lambda *args, **kwargs: _async_noop())
    monkeypatch.setattr(itsm, "_audit", lambda *args, **kwargs: None)

    class FakeSuite:
        async def validate_workspace(self, candidate, tools=None, timeout=180):
            return {"passed": passed, "summary": {"requested": 1, "available": 1}}

        @staticmethod
        def compare_scores(before, after):
            return {
                "before": before,
                "after": after,
                "delta": after - before,
                "regressed": regressed,
                "improvement": max(0, before - after),
            }

    monkeypatch.setattr(itsm, "RemediationValidationSuite", FakeSuite)
    return case, calls


@pytest.mark.asyncio
async def test_verify_case_only_reaches_verified_with_success(monkeypatch):
    case, calls = _install_verify_mocks(monkeypatch, passed=True, regressed=False)

    result = await itsm.verify_case(
        "act-1",
        "tester",
        {"approval_id": "a-1", "authorized": True, "workspace": ".", "risk_before": 80, "risk_after": 30},
        tools=["semgrep"],
    )

    assert result["action"]["state"] == "verified"
    assert any(item[1] == "verified" for item in calls)
    assert case["action"]["state"] == "verified"


@pytest.mark.asyncio
async def test_verify_case_reopens_when_validation_fails(monkeypatch):
    case, calls = _install_verify_mocks(monkeypatch, passed=False, regressed=True)

    result = await itsm.verify_case(
        "act-1",
        "tester",
        {"approval_id": "a-1", "authorized": True, "workspace": ".", "risk_before": 80, "risk_after": 85},
        tools=["semgrep"],
    )

    assert result["action"]["state"] == "in_progress"
    assert any(item[1] == "in_progress" for item in calls)
    assert not any(item[1] == "verified" for item in calls)
    assert case["action"]["state"] == "in_progress"


def test_jira_configuration_requires_all_credentials(monkeypatch):
    for key in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert itsm._configured("jira") is False


async def _async_noop():
    return None
