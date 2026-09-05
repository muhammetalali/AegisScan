from __future__ import annotations

import uuid

import pytest

from fastapi_app.services import decision_action_orchestration as store
from fastapi_app.services import policy_engine


class _BootstrapCursor:
    def __init__(self, fail_after_lock=False):
        self.statements = []
        self.fail_after_lock = fail_after_lock

    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def execute(self, sql, _params=None):
        self.statements.append(sql)
        if self.fail_after_lock and len(self.statements) == 2:
            raise RuntimeError("deterministic DDL failure")
    def fetchone(self): return (1,)


class _BootstrapConnection:
    def __init__(self, cursor):
        self.bootstrap_cursor = cursor
        self.committed = False
        self.rolled_back = False

    def cursor(self): return self.bootstrap_cursor
    def commit(self): self.committed = True
    def rollback(self): self.rolled_back = True


class _BootstrapPool:
    def __init__(self, connection): self.connection = connection
    def getconn(self): return self.connection
    def putconn(self, connection): assert connection is self.connection


@pytest.mark.parametrize("module,initializer", [
    (store, store.initialize_action_store),
    (policy_engine, policy_engine.initialize_policy_store),
])
def test_bootstrap_schema_takes_cross_process_advisory_lock(monkeypatch, module, initializer):
    cursor = _BootstrapCursor()
    connection = _BootstrapConnection(cursor)
    monkeypatch.setattr(module, "_schema_ready", False)
    monkeypatch.setattr(module, "_pool_instance", lambda: _BootstrapPool(connection))

    initializer()

    assert "pg_advisory_xact_lock" in cursor.statements[0]
    assert connection.committed is True


def test_bootstrap_schema_rolls_back_failed_connection(monkeypatch):
    cursor = _BootstrapCursor(fail_after_lock=True)
    connection = _BootstrapConnection(cursor)
    monkeypatch.setattr(store, "_schema_ready", False)
    monkeypatch.setattr(store, "_pool_instance", lambda: _BootstrapPool(connection))

    with pytest.raises(RuntimeError, match="deterministic DDL failure"):
        store.initialize_action_store()

    assert connection.rolled_back is True


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
    finally:
        pool = store._pool_instance()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM security_decision_actions WHERE action_id IN (%s, %s)",
                    (action_a["actionId"], action_b["actionId"]),
                )
                conn.commit()
        finally:
            pool.putconn(conn)
