from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
from django.db import close_old_connections
from pydantic import ValidationError

from enterprise.models import DecisionAction, DecisionActionEvent
from fastapi_app.routers.decision_actions import ActionCreate, ActionTransition
from fastapi_app.services import decision_action_orchestration as store
from fastapi_app.services.test_decision_action_orchestration import _lineage


@pytest.mark.django_db(transaction=True)
def test_transition_exact_retry_is_durable_and_side_effect_safe(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="cas-replay@example.invalid")
    organization, project, validation, decision = _lineage(user, "cas-replay")
    action = store.create_action(
        decision, "owner", 24, str(user.id),
        organization=organization, project=project, validation=validation,
    )

    first = store.transition(
        action["actionId"], "approved", str(user.id), "approved by policy",
        expected_version=1, idempotency_key="transition-replay-001",
    )
    second = store.transition(
        action["actionId"], "approved", str(user.id), "approved by policy",
        expected_version=1, idempotency_key="transition-replay-001",
    )

    persisted = DecisionAction.objects.get(pk=action["actionId"])
    assert first["version"] == 2
    assert first["mutation"]["replayed"] is False
    assert second["mutation"]["replayed"] is True
    assert second["mutation"]["resultVersion"] == 2
    assert persisted.version == 2
    assert DecisionActionEvent.objects.filter(action=persisted, event_type="action.approved").count() == 1
    event = DecisionActionEvent.objects.get(action=persisted, event_type="action.approved")
    assert "transition-replay-001" not in str(event.note)
    assert first["mutation"]["idempotencySha256"] in str(event.note)


@pytest.mark.django_db(transaction=True)
def test_stale_expected_version_fails_without_state_or_event_mutation(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="stale-version@example.invalid")
    organization, project, validation, decision = _lineage(user, "stale-version")
    action = store.create_action(
        decision, "owner", 24, str(user.id),
        organization=organization, project=project, validation=validation,
    )
    store.transition(
        action["actionId"], "approved", str(user.id),
        expected_version=1, idempotency_key="stale-first-001",
    )

    with pytest.raises(store.StaleActionVersion, match="expected 1, current 2"):
        store.transition(
            action["actionId"], "assigned", str(user.id),
            expected_version=1, idempotency_key="stale-second-001",
        )

    persisted = DecisionAction.objects.get(pk=action["actionId"])
    assert persisted.state == "approved"
    assert persisted.version == 2
    assert not DecisionActionEvent.objects.filter(action=persisted, event_type="action.assigned").exists()


@pytest.mark.django_db(transaction=True)
def test_idempotency_key_cannot_be_reused_for_different_transition(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="key-reuse@example.invalid")
    organization, project, validation, decision = _lineage(user, "key-reuse")
    action = store.create_action(
        decision, "owner", 24, str(user.id),
        organization=organization, project=project, validation=validation,
    )
    store.transition(
        action["actionId"], "approved", str(user.id),
        expected_version=1, idempotency_key="single-command-key-001",
    )

    with pytest.raises(store.IdempotencyConflict, match="different request"):
        store.transition(
            action["actionId"], "assigned", str(user.id),
            expected_version=2, idempotency_key="single-command-key-001",
        )

    persisted = DecisionAction.objects.get(pk=action["actionId"])
    assert persisted.state == "approved"
    assert persisted.version == 2
    assert not DecisionActionEvent.objects.filter(action=persisted, event_type="action.assigned").exists()


@pytest.mark.django_db(transaction=True)
def test_two_concurrent_transitions_from_same_version_allow_exactly_one_winner(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="cas-race@example.invalid")
    organization, project, validation, decision = _lineage(user, "cas-race")
    action = store.create_action(
        decision, "owner", 24, str(user.id),
        organization=organization, project=project, validation=validation,
    )

    def invoke(target_state: str, key: str):
        close_old_connections()
        try:
            result = store.transition(
                action["actionId"], target_state, str(user.id),
                expected_version=1, idempotency_key=key,
            )
            return ("applied", result["state"], result["version"])
        except store.StaleActionVersion as exc:
            return ("stale", str(exc), None)
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(invoke, "approved", "cas-race-approved-001"),
            executor.submit(invoke, "deferred", "cas-race-deferred-001"),
        ]
        results = [future.result() for future in futures]

    assert sorted(item[0] for item in results) == ["applied", "stale"]
    persisted = DecisionAction.objects.get(pk=action["actionId"])
    assert persisted.version == 2
    transition_events = DecisionActionEvent.objects.filter(action=persisted).exclude(event_type="action.created")
    assert transition_events.count() == 1
    assert persisted.state in {"approved", "deferred"}


@pytest.mark.django_db(transaction=True)
def test_concurrent_exact_replay_creates_one_transition_event(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="exact-race@example.invalid")
    organization, project, validation, decision = _lineage(user, "exact-race")
    action = store.create_action(
        decision, "owner", 24, str(user.id),
        organization=organization, project=project, validation=validation,
    )

    def invoke():
        close_old_connections()
        try:
            result = store.transition(
                action["actionId"], "approved", str(user.id), "same command",
                expected_version=1, idempotency_key="exact-race-command-001",
            )
            return bool(result["mutation"]["replayed"])
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        replay_flags = list(executor.map(lambda _: invoke(), range(2)))

    assert sorted(replay_flags) == [False, True]
    persisted = DecisionAction.objects.get(pk=action["actionId"])
    assert persisted.version == 2
    assert DecisionActionEvent.objects.filter(action=persisted, event_type="action.approved").count() == 1


@pytest.mark.django_db(transaction=True)
def test_create_action_exact_retry_is_project_serialized_and_idempotent(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="create-race@example.invalid")
    organization, project, validation, decision = _lineage(user, "create-race")

    def invoke():
        close_old_connections()
        try:
            return store.create_action(
                decision, "owner", 24, str(user.id),
                organization=organization, project=project, validation=validation,
                idempotency_key="create-action-race-001",
            )
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: invoke(), range(2)))

    assert results[0]["actionId"] == results[1]["actionId"]
    assert sorted(result["mutation"]["replayed"] for result in results) == [False, True]
    assert DecisionAction.objects.filter(project=project, requested_by=str(user.id)).count() == 1
    action = DecisionAction.objects.get(project=project, requested_by=str(user.id))
    assert DecisionActionEvent.objects.filter(action=action, event_type="action.created").count() == 1
    event = DecisionActionEvent.objects.get(action=action, event_type="action.created")
    assert "create-action-race-001" not in str(event.note)


@pytest.mark.django_db(transaction=True)
def test_create_idempotency_key_reuse_with_changed_semantics_is_rejected(django_user_model) -> None:
    user = django_user_model.objects.create_user(email="create-key-reuse@example.invalid")
    organization, project, validation, decision = _lineage(user, "create-key-reuse")
    store.create_action(
        decision, "owner-a", 24, str(user.id),
        organization=organization, project=project, validation=validation,
        idempotency_key="create-key-reuse-001",
    )

    with pytest.raises(store.IdempotencyConflict, match="different request"):
        store.create_action(
            decision, "owner-b", 24, str(user.id),
            organization=organization, project=project, validation=validation,
            idempotency_key="create-key-reuse-001",
        )
    assert DecisionAction.objects.filter(project=project, requested_by=str(user.id)).count() == 1


def test_api_contract_requires_concurrency_preconditions_and_forbids_extras() -> None:
    with pytest.raises(ValidationError):
        ActionTransition.model_validate({"state": "approved"})
    with pytest.raises(ValidationError):
        ActionCreate.model_validate({"decision_id": "d", "owner": "o", "unexpected": True})

    transition = ActionTransition.model_validate({
        "state": "approved",
        "expected_version": 1,
        "idempotency_key": "api-contract-key-001",
    })
    creation = ActionCreate.model_validate({
        "decision_id": "d",
        "owner": "o",
        "idempotency_key": "api-create-key-001",
    })
    assert transition.expected_version == 1
    assert creation.sla_hours == 24
