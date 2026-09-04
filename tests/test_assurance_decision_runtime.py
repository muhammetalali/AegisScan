from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ROUTER_ROOT = REPO_ROOT / "aegis-platform" / "backend" / "fastapi_app" / "routers"


def test_assurance_decision_routes_use_persisted_validation_loader() -> None:
    decision_actions = (ROUTER_ROOT / "decision_actions.py").read_text(encoding="utf-8")
    security_decision = (ROUTER_ROOT / "security_decision.py").read_text(encoding="utf-8")
    assurance_graph = (ROUTER_ROOT / "assurance_graph.py").read_text(encoding="utf-8")

    assert "from .validations import _store" not in decision_actions
    assert "from .validations import _store" not in security_decision
    assert "from .validations import _store" not in assurance_graph
    assert "from .assurance_graph import _load_validations" in decision_actions
    assert "from .assurance_graph import _load_validations" in security_decision
    assert "ValidationRun.objects.filter" in assurance_graph


def test_fastapi_audit_writer_is_used_without_silent_failure() -> None:
    decision_actions = (ROUTER_ROOT / "decision_actions.py").read_text(encoding="utf-8")

    assert "from ..services.audit_writer import add_audit_entry" in decision_actions
    assert "except Exception:\n        pass" not in decision_actions
    assert "await sync_to_async(add_audit_entry)" in decision_actions
