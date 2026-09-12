from pathlib import Path

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/frontend-lock-sync.yml"


def test_frontend_lock_gate_runs_for_canonical_main_and_pull_requests():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    triggers = document["on"]

    assert "main" in triggers["push"]["branches"]
    assert triggers["pull_request"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers
