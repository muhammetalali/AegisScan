from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from fastapi_app.services import decision_action_orchestration as store
from fastapi_app.services import policy_engine
from fastapi_app.services.workflow_sla import evaluate_sla_actions
from enterprise.models import DecisionAction, DecisionActionEvent
from django.utils import timezone


@pytest.mark.parametrize("module,initializer", [
    (store, store.initialize_action_store),
    (policy_engine, policy_engine.initialize_policy_store),
])
def test_runtime_initializers_never_execute_schema_ddl(monkeypatch, module, initializer):
    monkeypatch.setattr(module, "_schema_ready", False)

    initializer()

    assert module._schema_ready is True


@pytest.mark.django_db(transaction=True)
def test_decision_actions_are_tenant_isolated() -> None:
    suffix = uuid.uuid4().hex[:10]
    user_a = f"tenant-a-{suffix}"
    user_b = f"tenant-b-{suffix}"
    decision_a = {
        "decisionId": f"decision-a-{suffix}",
        "nodeId": f"node-a-{suffix}",
        "label": "Tenant A finding",
        "risk": 80,
        "confidence": 95,
        "priority": 90,
        "recommendedAction": "Remediate A",
        "revalidationPlan": ["validate-a"],
    }
    decision_b = {
        "decisionId": f"decision-b-{suffix}",
        "nodeId": f"node-b-{suffix}",
        "label": "Tenant B finding",
        "risk": 70,
        "confidence": 90,
        "priority": 80,
        "recommendedAction": "Remediate B",
        "revalidationPlan": ["validate-b"],
    }

    action_a = store.create_action(decision_a, "owner-a", 24, user_a)
    action_b = store.create_action(decision_b, "owner-b", 24, user_b)
    try:
        visible_to_a = store.list_actions(user_a)
        visible_to_b = store.list_actions(user_b)

        assert [item["actionId"] for item in visible_to_a] == [action_a["actionId"]]
        assert [item["actionId"] for item in visible_to_b] == [action_b["actionId"]]

        assert store.get_action(action_a["actionId"], user_a)["actionId"] == action_a["actionId"]
        assert store.get_action(action_b["actionId"], user_a) is None

        with pytest.raises(KeyError):
            store.transition(action_b["actionId"], "approved", user_a)

        transitioned = store.transition(action_b["actionId"], "approved", user_b)
        assert transitioned["state"] == "approved"
        assert transitioned["version"] == 2
        assert [event["type"] for event in transitioned["events"]] == ["action.created", "action.approved"]
    finally:
        DecisionAction.objects.filter(action_id__in=[action_a["actionId"],action_b["actionId"]]).delete()


@pytest.mark.django_db(transaction=True)
def test_action_and_creation_event_are_atomic(monkeypatch) -> None:
    requested_by = f"atomic-{uuid.uuid4().hex}"

    def fail_event(*args, **kwargs):
        raise RuntimeError("event persistence failed")

    monkeypatch.setattr(DecisionActionEvent.objects, "create", fail_event)
    with pytest.raises(RuntimeError, match="event persistence failed"):
        store.create_action({"decisionId": "atomic", "nodeId": "node"}, "owner", 4, requested_by)

    assert not DecisionAction.objects.filter(requested_by=requested_by).exists()


@pytest.mark.django_db(transaction=True)
def test_sla_breach_is_durable_versioned_and_idempotent() -> None:
    requested_by = f"sla-{uuid.uuid4().hex}"
    action = store.create_action({"decisionId": "sla", "nodeId": "node"}, "owner", 1, requested_by)
    evaluation_time = timezone.now() + timedelta(hours=2)

    first = evaluate_sla_actions(evaluation_time)
    second = evaluate_sla_actions(evaluation_time)
    persisted = store.get_action(action["actionId"], requested_by)

    assert [item["actionId"] for item in first] == [action["actionId"]]
    assert second == []
    assert persisted is not None
    assert persisted["slaStatus"] == "breached"
    assert persisted["escalationLevel"] == 2
    assert persisted["version"] == 2
    assert [event["type"] for event in persisted["events"]] == ["action.created", "action.sla_breached"]
