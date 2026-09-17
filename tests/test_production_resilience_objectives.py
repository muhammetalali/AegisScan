import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_resilience_objectives.py"
SPEC = importlib.util.spec_from_file_location("production_resilience_objectives", PATH)
assert SPEC and SPEC.loader
objectives = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(objectives)


def test_objectives_accept_measured_recovery_inside_budgets():
    result = objectives.evaluate(
        backup_completed_at="2026-09-17T12:00:00Z",
        failure_epoch=1789646410,
        recovery_verified_epoch=1789646500,
        rpo_objective_seconds=60,
        rto_objective_seconds=300,
    )
    assert result["status"] == "success"
    assert result["rpo"] == {"objective_seconds": 60, "observed_seconds": 10, "met": True}
    assert result["rto"] == {"objective_seconds": 300, "observed_seconds": 90, "met": True}


def test_objectives_reject_rpo_breach():
    with pytest.raises(objectives.ObjectiveError, match="RPO"):
        objectives.evaluate(
            backup_completed_at="2026-09-17T12:00:00Z",
            failure_epoch=1789646470,
            recovery_verified_epoch=1789646500,
            rpo_objective_seconds=60,
            rto_objective_seconds=300,
        )


def test_objectives_reject_rto_breach():
    with pytest.raises(objectives.ObjectiveError, match="RTO"):
        objectives.evaluate(
            backup_completed_at="2026-09-17T12:00:00Z",
            failure_epoch=1789646410,
            recovery_verified_epoch=1789646800,
            rpo_objective_seconds=60,
            rto_objective_seconds=300,
        )


def test_objectives_reject_impossible_timeline():
    with pytest.raises(objectives.ObjectiveError, match="precedes"):
        objectives.evaluate(
            backup_completed_at="2026-09-17T12:00:00Z",
            failure_epoch=1789646399,
            recovery_verified_epoch=1789646500,
            rpo_objective_seconds=60,
            rto_objective_seconds=300,
        )
