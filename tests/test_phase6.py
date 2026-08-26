"""اختبارات المرحلة 6 — التحقق المنضبط."""

import pytest
from aegis.core.event_bus import EventBus
from aegis.engines.validation.authorization import (
    AuthorizationGate, AuthorizationPolicy, AuthorizationRequest, ActionLevel,
)
from aegis.engines.validation.planner import (
    ExecutionPlanner, PlannedAction, PlanStatus,
)
from aegis.engines.validation.controller import ExecutionController
from aegis.engines.validation.recorder import ActionRecorder
from aegis.engines.validation.replay import ReplayEngine


# ─── Authorization Gate ───────────────────────────────────

def test_auth_allows_read():
    gate = AuthorizationGate()
    req = AuthorizationRequest(
        action_id="a1", action_type="scan",
        level=ActionLevel.READ, target="/code",
    )
    result = gate.check(req)
    assert result.authorized


def test_auth_allows_analyze():
    gate = AuthorizationGate()
    req = AuthorizationRequest(
        action_id="a2", action_type="analyze",
        level=ActionLevel.ANALYZE, target="/code",
    )
    result = gate.check(req)
    assert result.authorized


def test_auth_denies_destructive_by_default():
    gate = AuthorizationGate()
    req = AuthorizationRequest(
        action_id="a3", action_type="exploit",
        level=ActionLevel.DESTRUCTIVE, target="/prod",
    )
    result = gate.check(req)
    assert not result.authorized
    assert "غير مسموح" in result.reason


def test_auth_denies_unknown_target():
    policy = AuthorizationPolicy(allowed_targets={"safe-target"})
    gate = AuthorizationGate(policy)
    req = AuthorizationRequest(
        action_id="a4", action_type="scan",
        level=ActionLevel.READ, target="unknown-target",
    )
    result = gate.check(req)
    assert not result.authorized
    assert "غير مصرّح" in result.reason


def test_auth_needs_approval_for_write():
    policy = AuthorizationPolicy(
        allowed_levels={ActionLevel.READ, ActionLevel.ANALYZE, ActionLevel.WRITE}
    )
    gate = AuthorizationGate(policy)
    req = AuthorizationRequest(
        action_id="a5", action_type="modify",
        level=ActionLevel.WRITE, target="/code",
    )
    result = gate.check(req)
    assert not result.authorized
    assert result.requires_approval


def test_auth_approve_then_passes():
    policy = AuthorizationPolicy(
        allowed_levels={ActionLevel.READ, ActionLevel.ANALYZE, ActionLevel.WRITE}
    )
    gate = AuthorizationGate(policy)
    req = AuthorizationRequest(
        action_id="a6", action_type="modify",
        level=ActionLevel.WRITE, target="/code",
    )
    gate.check(req)  # requires approval
    gate.approve("a6")
    result = gate.check(req)  # now should pass
    assert result.authorized


def test_auth_status():
    gate = AuthorizationGate()
    req = AuthorizationRequest(
        action_id="a7", action_type="scan",
        level=ActionLevel.READ, target="/code",
    )
    gate.check(req)
    status = gate.status()
    assert status["active_actions"] == 1


# ─── Execution Planner ────────────────────────────────────

def test_planner_topological_sort():
    gate = AuthorizationGate()
    planner = ExecutionPlanner(gate)

    actions = [
        PlannedAction("a1", "scan", ActionLevel.READ, "/code", depends_on=[]),
        PlannedAction("a2", "analyze", ActionLevel.ANALYZE, "/code", depends_on=["a1"]),
        PlannedAction("a3", "report", ActionLevel.READ, "stdout", depends_on=["a2"]),
    ]
    plan = planner.create_plan("plan1", actions)

    # a1 يجب أن يكون قبل a2 قبل a3
    ids = [a.action_id for a in plan.actions]
    assert ids.index("a1") < ids.index("a2") < ids.index("a3")


def test_planner_authorize_plan():
    gate = AuthorizationGate()
    planner = ExecutionPlanner(gate)

    actions = [
        PlannedAction("a1", "scan", ActionLevel.READ, "/code"),
    ]
    plan = planner.create_plan("plan2", actions)
    result = planner.authorize_plan(plan)
    assert result["all_authorized"]
    assert plan.status == PlanStatus.APPROVED


def test_planner_blocks_destructive():
    gate = AuthorizationGate()
    planner = ExecutionPlanner(gate)

    actions = [
        PlannedAction("a1", "exploit", ActionLevel.DESTRUCTIVE, "/prod"),
    ]
    plan = planner.create_plan("plan3", actions)
    result = planner.authorize_plan(plan)
    assert not result["all_authorized"]


def test_planner_get_ready_actions():
    gate = AuthorizationGate()
    planner = ExecutionPlanner(gate)

    actions = [
        PlannedAction("a1", "scan", ActionLevel.READ, "/code", depends_on=[]),
        PlannedAction("a2", "analyze", ActionLevel.ANALYZE, "/code", depends_on=["a1"]),
    ]
    plan = planner.create_plan("plan4", actions)

    # أولاً: a1 فقط جاهز
    ready = planner.get_ready_actions(plan)
    assert len(ready) == 1
    assert ready[0].action_id == "a1"

    # بعد إكمال a1: a2 جاهز
    planner.mark_completed(plan, "a1")
    ready = planner.get_ready_actions(plan)
    assert len(ready) == 1
    assert ready[0].action_id == "a2"


# ─── Execution Controller ─────────────────────────────────

@pytest.mark.asyncio
async def test_controller_executes_action():
    bus = EventBus()
    await bus.start()

    ctrl = ExecutionController(bus)

    async def handler(target, params):
        return {"status": "ok", "target": target}

    ctrl.register_handler("scan", handler)

    action = PlannedAction("a1", "scan", ActionLevel.READ, "/code")
    result = await ctrl._execute_action(action)
    assert result.success
    assert result.result["status"] == "ok"
    await bus.stop()


@pytest.mark.asyncio
async def test_controller_handles_timeout():
    import asyncio
    bus = EventBus()
    await bus.start()

    ctrl = ExecutionController(bus)

    async def slow_handler(target, params):
        await asyncio.sleep(10)
        return "never"

    ctrl.register_handler("slow", slow_handler)

    action = PlannedAction("a1", "slow", ActionLevel.READ, "/x", timeout_seconds=1)
    result = await ctrl._execute_action(action)
    assert not result.success
    assert "انتهت المهلة" in result.error
    await bus.stop()


@pytest.mark.asyncio
async def test_controller_missing_handler():
    bus = EventBus()
    await bus.start()

    ctrl = ExecutionController(bus)
    action = PlannedAction("a1", "unknown", ActionLevel.READ, "/x")
    result = await ctrl._execute_action(action)
    assert not result.success
    assert "معالج" in result.error
    await bus.stop()


# ─── Action Recorder ──────────────────────────────────────

@pytest.mark.asyncio
async def test_recorder_log_and_retrieve():
    bus = EventBus()
    await bus.start()

    rec = ActionRecorder(bus)
    await rec.record_action(
        action_id="r1", plan_id="p1", action_type="scan",
        level="read", target="/code", parameters={"key": "val"},
        result={"found": 5}, success=True, duration_seconds=1.2,
    )

    log = rec.get_log(plan_id="p1")
    assert len(log) == 1
    assert log[0]["action_id"] == "r1"
    assert log[0]["success"] == 1

    summary = rec.get_summary()
    assert summary["total_actions"] == 1
    assert summary["successful"] == 1

    rec.close()
    await bus.stop()


# ─── Replay Engine ────────────────────────────────────────

@pytest.mark.asyncio
async def test_replay_matches_result():
    bus = EventBus()
    await bus.start()

    rec = ActionRecorder(bus)
    replay = ReplayEngine(bus, rec)

    call_count = 0

    async def scan_handler(target, params):
        nonlocal call_count
        call_count += 1
        return {"vulns": 3}

    replay.register_handler("scan", scan_handler)

    # سجّل إجراء أصلي
    await rec.record_action(
        action_id="orig1", plan_id=None, action_type="scan",
        level="read", target="/code", parameters={},
        result={"vulns": 3}, success=True,
    )

    # أعد التشغيل
    result = await replay.replay_action("orig1", verify=True)
    assert result.replayed
    assert result.matches is True
    assert call_count == 1  # handler called once during replay

    rec.close()
    await bus.stop()


@pytest.mark.asyncio
async def test_replay_detects_difference():
    bus = EventBus()
    await bus.start()

    rec = ActionRecorder(bus)
    replay = ReplayEngine(bus, rec)

    async def unstable_handler(target, params):
        return {"vulns": 99}  # نتيجة مختلفة!

    replay.register_handler("scan", unstable_handler)

    await rec.record_action(
        action_id="orig2", plan_id=None, action_type="scan",
        level="read", target="/code", parameters={},
        result={"vulns": 3}, success=True,
    )

    result = await replay.replay_action("orig2", verify=True)
    assert result.replayed
    assert result.matches is False
    assert result.difference is not None

    rec.close()
    await bus.stop()
