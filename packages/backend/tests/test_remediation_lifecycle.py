from __future__ import annotations

import pytest

from fastapi_app.services import remediation_lifecycle as lifecycle


@pytest.mark.asyncio
async def test_validate_and_verify_delegates_with_safe_defaults(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_verify_case(action_id, actor, validation, *, tools=None):
        captured.update(
            action_id=action_id,
            actor=actor,
            validation=validation,
            tools=tools,
        )
        return {"action": {"actionId": action_id, "state": "in_progress"}, "validation": validation}

    monkeypatch.setattr(lifecycle, "verify_case", fake_verify_case)

    result = await lifecycle.validate_and_verify(
        "act-1",
        "tester",
        candidate={"tool_pass": False},
        tools=["semgrep"],
    )

    assert captured["action_id"] == "act-1"
    assert captured["actor"] == "tester"
    assert captured["tools"] == ["semgrep"]
    assert captured["validation"] == {
        "tool_pass": False,
        "authorized": True,
        "workspace": ".",
    }
    assert result["action"]["state"] == "in_progress"


@pytest.mark.asyncio
async def test_validate_and_verify_preserves_explicit_authorization_and_workspace(monkeypatch):
    captured: dict[str, object] = {}

    async def fake_verify_case(action_id, actor, validation, *, tools=None):
        captured["validation"] = validation
        return {"action": {"actionId": action_id, "state": "verified"}, "validation": validation}

    monkeypatch.setattr(lifecycle, "verify_case", fake_verify_case)

    result = await lifecycle.validate_and_verify(
        "act-2",
        "tester",
        candidate={
            "authorized": False,
            "workspace": "/workspace/aegis",
            "risk_before": 80,
            "risk_after": 65,
        },
        timeout=90,
    )

    assert captured["validation"] == {
        "authorized": False,
        "workspace": "/workspace/aegis",
        "risk_before": 80,
        "risk_after": 65,
    }
    assert result["action"]["state"] == "verified"
