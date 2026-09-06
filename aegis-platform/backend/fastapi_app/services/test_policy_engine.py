from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.db import close_old_connections, connection
from fastapi import HTTPException

from fastapi_app.routers import policy as policy_router
from fastapi_app.services.policy_engine import list_policies, save_policy


@pytest.mark.django_db(transaction=True)
def test_concurrent_policy_versions_are_serialized() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("PostgreSQL advisory-lock behavior")
    policy_id = f"concurrent-{uuid.uuid4().hex}"
    barrier = Barrier(2)
    payload = {
        "id": policy_id,
        "name": "Concurrent policy",
        "enabled": True,
        "priority": 50,
        "when": {"risk_gte": 50},
        "actions": {"sla_hours": 24},
    }

    def persist(actor: str) -> int:
        close_old_connections()
        barrier.wait(timeout=10)
        try:
            return int(save_policy(payload, actor)["version"])
        finally:
            close_old_connections()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            versions = sorted(executor.map(persist, ("actor-a", "actor-b")))
        assert versions == [1, 2]
        stored = [item for item in list_policies() if item["id"] == policy_id]
        assert sorted(item["version"] for item in stored) == [1, 2]
        with pytest.raises(FileExistsError):
            save_policy(payload, "actor-c", require_existing=False)
        with pytest.raises(KeyError):
            save_policy({**payload, "id": f"missing-{uuid.uuid4().hex}"}, "actor-c", require_existing=True)
    finally:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM assurance_policies WHERE policy_id=%s", (policy_id,))


@pytest.mark.asyncio
async def test_policy_mutation_requires_staff(monkeypatch) -> None:
    called = False

    def unexpected_save(*args, **kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(policy_router, "save_policy", unexpected_save)
    monkeypatch.setattr(policy_router, "_is_policy_administrator", lambda user_id: False)
    body = policy_router.PolicyPayload(id="blocked", name="Blocked")

    with pytest.raises(HTTPException) as exc_info:
        await policy_router.create_policy(body, {"user_id": "user-1", "is_staff": False})

    assert exc_info.value.status_code == 403
    assert called is False


@pytest.mark.asyncio
async def test_policy_evaluation_scopes_action_to_authenticated_actor(monkeypatch) -> None:
    observed: list[tuple[str, str]] = []

    def scoped_get(action_id: str, actor: str):
        observed.append((action_id, actor))
        return None

    monkeypatch.setattr(policy_router, "get_action", scoped_get)

    with pytest.raises(HTTPException) as exc_info:
        await policy_router.evaluate_action_policy("action-1", {"user_id": "user-1"})

    assert exc_info.value.status_code == 404
    assert observed == [("action-1", "user-1")]
