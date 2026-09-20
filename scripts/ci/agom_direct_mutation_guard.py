#!/usr/bin/env python3
from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "aegis-platform" / "backend"

WRITE_METHODS = {
    "create", "update", "update_or_create", "get_or_create",
    "bulk_create", "bulk_update", "delete",
}

LEDGER_OWNERS = {
    "AssetAuthorization": "aegis-platform/backend/fastapi_app/services/asset_authorization_governance.py",
    "FindingConfirmation": "aegis-platform/backend/fastapi_app/services/finding_confirmation.py",
    "FindingDisposition": "aegis-platform/backend/fastapi_app/services/finding_disposition.py",
    "InvestigationClosure": "aegis-platform/backend/fastapi_app/services/soc_closure_governance.py",
    "DetectionPublication": "aegis-platform/backend/fastapi_app/services/detection_engineering.py",
    "IntegrationLiveAcceptance": "aegis-platform/backend/fastapi_app/services/integration_live_acceptance.py",
    "CampaignObjectiveAssessment": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "CampaignAuditEvent": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "AssuranceObligationEvent": "aegis-platform/backend/fastapi_app/services/assurance_obligation_governance.py",
    "GovernedActionRequest": "aegis-platform/backend/fastapi_app/services/governed_action_requests.py",
    "GovernedActionExecution": "aegis-platform/backend/fastapi_app/services/governed_action_executor.py",
    "EvidenceQualificationEvaluation": "aegis-platform/backend/fastapi_app/services/evidence_qualification.py",
    "GovernedWorkClaim": "aegis-platform/backend/fastapi_app/services/governed_work_queue.py",
    "GovernedWorkClaimEvent": "aegis-platform/backend/fastapi_app/services/governed_work_queue.py",
}

TERMINAL_STATE_OWNERS = {
    "Vulnerability.Status.CONFIRMED": "aegis-platform/backend/fastapi_app/services/finding_confirmation.py",
    "Vulnerability.Status.FALSE_POSITIVE": "aegis-platform/backend/fastapi_app/services/finding_confirmation.py",
    "Vulnerability.Status.FIXED": "aegis-platform/backend/fastapi_app/services/finding_closure.py",
    "Vulnerability.Status.ACCEPTED_RISK": "aegis-platform/backend/fastapi_app/services/finding_disposition.py",
    "Vulnerability.Status.WONT_FIX": "aegis-platform/backend/fastapi_app/services/finding_disposition.py",
    "Vulnerability.Status.DUPLICATE": "aegis-platform/backend/fastapi_app/services/finding_disposition.py",
    "InvestigationCase.Status.CLOSED": "aegis-platform/backend/fastapi_app/services/soc_closure_governance.py",
    "DetectionRule.State.PUBLISHED": "aegis-platform/backend/fastapi_app/services/detection_engineering.py",
    "AdversaryCampaign.Status.COMPLETED": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "CampaignObjective.Status.REACHED": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "CampaignObjective.Status.BLOCKED": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "CampaignObjective.Status.INCONCLUSIVE": "aegis-platform/backend/fastapi_app/services/campaign_objective_assurance.py",
    "AssuranceObligation.Status.SATISFIED": "aegis-platform/backend/fastapi_app/services/assurance_obligation_governance.py",
}

ASSET_PROJECTION_OWNER = "aegis-platform/backend/fastapi_app/services/asset_authorization_governance.py"
ASSET_DELETE_OWNER = ASSET_PROJECTION_OWNER


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    code: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.code}: {self.detail}"


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _contains_manager(node: ast.AST | None, model: str) -> bool:
    if node is None:
        return False
    return any(
        isinstance(part, ast.Attribute)
        and part.attr == "objects"
        and isinstance(part.value, ast.Name)
        and part.value.id == model
        for part in ast.walk(node)
    )


def _contains_string_key(node: ast.AST | None, key: str) -> bool:
    if node is None:
        return False
    for part in ast.walk(node):
        if isinstance(part, ast.Dict):
            for item in part.keys:
                if isinstance(item, ast.Constant) and item.value == key:
                    return True
    return False


def _target_names(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from _target_names(item)


def _is_authorized_subscript(node: ast.AST) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    key = node.slice
    return isinstance(key, ast.Constant) and key.value == "authorized"


def _is_asset_configuration_attr(node: ast.AST) -> bool:
    if not isinstance(node, ast.Attribute) or node.attr != "configuration":
        return False
    return isinstance(node.value, ast.Name) and node.value.id in {
        "asset", "locked_asset", "current_asset",
    }


class MutationVisitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.violations: list[Violation] = []
        self.tainted: dict[str, str] = {}
        self.state_tainted: dict[str, str] = {}

    def add(self, node: ast.AST, code: str, detail: str) -> None:
        self.violations.append(
            Violation(self.path, getattr(node, "lineno", 1), code, detail)
        )

    def _state_value(self, value: ast.AST) -> str:
        direct = _dotted(value)
        if direct in TERMINAL_STATE_OWNERS:
            return direct
        if isinstance(value, ast.Name):
            return self.state_tainted.get(value.id, "")
        return ""

    def _check_status_target(self, node: ast.AST, target: ast.AST, value: ast.AST) -> None:
        state = self._state_value(value)
        owner = TERMINAL_STATE_OWNERS.get(state)
        if not owner or self.path == owner:
            return
        if isinstance(target, ast.Attribute) and target.attr in {"status", "state"}:
            self.add(node, "AGOM-DIRECT-STATUS", f"{state} may only be written by {owner}")
        elif isinstance(target, ast.Subscript):
            key = target.slice
            if isinstance(key, ast.Constant) and key.value in {"status", "state"}:
                self.add(node, "AGOM-DIRECT-STATUS", f"{state} may only be written by {owner}")

    def _check_target(self, node: ast.AST, target: ast.AST) -> None:
        if self.path == ASSET_PROJECTION_OWNER:
            return
        if _is_authorized_subscript(target):
            self.add(
                node,
                "AGOM-ASSET-AUTH-PROJECTION",
                "authorized projection is server-owned by asset authorization governance",
            )
        elif _is_asset_configuration_attr(target):
            self.add(
                node,
                "AGOM-ASSET-CONFIG-REPLACE",
                "asset.configuration replacement must flow through authorization-preserving governance",
            )

    def visit_Assign(self, node: ast.Assign) -> None:
        direct_state = _dotted(node.value)
        manager_models = [model for model in LEDGER_OWNERS if _contains_manager(node.value, model)]
        for target in node.targets:
            for name in _target_names(target):
                if manager_models:
                    self.tainted[name] = manager_models[0]
                else:
                    self.tainted.pop(name, None)
                if direct_state in TERMINAL_STATE_OWNERS:
                    self.state_tainted[name] = direct_state
                else:
                    self.state_tainted.pop(name, None)
            self._check_status_target(node, target, node.value)
            self._check_target(node, target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            direct_state = _dotted(node.value)
            manager_models = [model for model in LEDGER_OWNERS if _contains_manager(node.value, model)]
            for name in _target_names(node.target):
                if manager_models:
                    self.tainted[name] = manager_models[0]
                else:
                    self.tainted.pop(name, None)
                if direct_state in TERMINAL_STATE_OWNERS:
                    self.state_tainted[name] = direct_state
                else:
                    self.state_tainted.pop(name, None)
            self._check_status_target(node, node.target, node.value)
        self._check_target(node, node.target)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if method in WRITE_METHODS:
            for model, owner in LEDGER_OWNERS.items():
                if _contains_manager(node.func.value if isinstance(node.func, ast.Attribute) else None, model):
                    if self.path != owner:
                        self.add(
                            node,
                            "AGOM-LEDGER-WRITE",
                            f"{model}.{method} write may only occur in {owner}",
                        )
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                model = self.tainted.get(node.func.value.id)
                if model and self.path != LEDGER_OWNERS[model]:
                    self.add(
                        node,
                        "AGOM-LEDGER-WRITE",
                        f"tainted {model} instance/query write may only occur in {LEDGER_OWNERS[model]}",
                    )

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"save", "delete"}:
            if isinstance(node.func.value, ast.Name):
                model = self.tainted.get(node.func.value.id)
                if model and self.path != LEDGER_OWNERS[model]:
                    self.add(
                        node,
                        "AGOM-LEDGER-WRITE",
                        f"{model} instance {node.func.attr} may only occur in {LEDGER_OWNERS[model]}",
                    )

        if isinstance(node.func, ast.Attribute) and node.func.attr == "delete" and self.path != ASSET_DELETE_OWNER:
            receiver = node.func.value
            direct_asset_name = isinstance(receiver, ast.Name) and receiver.id in {
                "asset", "locked_asset", "current_asset",
            }
            asset_manager_delete = _contains_manager(receiver, "Asset")
            if direct_asset_name or asset_manager_delete:
                self.add(
                    node,
                    "AGOM-ASSET-HARD-DELETE",
                    f"Asset hard-delete may only occur in {ASSET_DELETE_OWNER}",
                )

        for value in [*node.args, *(kw.value for kw in node.keywords)]:
            if _dotted(value) == "RemediationState.CLOSED":
                self.add(
                    node,
                    "AGOM-REMEDIATION-CLOSE",
                    "RemediationState.CLOSED must not be invoked directly; terminal finding closure is finding.close",
                )

        for kw in node.keywords:
            state = self._state_value(kw.value)
            owner = TERMINAL_STATE_OWNERS.get(state)
            if kw.arg in {"status", "state"} and owner and self.path != owner:
                self.add(
                    node,
                    "AGOM-DIRECT-STATUS",
                    f"{state} may only be written by {owner}",
                )
            if (
                kw.arg == "configuration"
                and self.path != ASSET_PROJECTION_OWNER
                and _contains_string_key(kw.value, "authorized")
            ):
                self.add(
                    node,
                    "AGOM-ASSET-AUTH-PROJECTION",
                    "inline asset authorization projection cannot be client/domain-written",
                )

        if isinstance(node.func, ast.Name) and node.func.id == "setattr" and len(node.args) >= 3:
            state = self._state_value(node.args[2])
            owner = TERMINAL_STATE_OWNERS.get(state)
            if owner and self.path != owner:
                self.add(node, "AGOM-DIRECT-STATUS", f"{state} may only be written by {owner}")

        self.generic_visit(node)


def is_production_python(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if not rel.startswith("aegis-platform/backend/") or not rel.endswith(".py"):
        return False
    if "/migrations/" in rel or "/tests/" in rel:
        return False
    name = path.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return False
    return True


def scan_source(source: str, path: str) -> list[Violation]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Violation(path, exc.lineno or 1, "AGOM-PARSE", str(exc))]
    visitor = MutationVisitor(path)
    visitor.visit(tree)
    return visitor.violations


def scan_repo(root: Path = REPO_ROOT) -> list[Violation]:
    violations: list[Violation] = []
    backend = root / "aegis-platform" / "backend"
    for path in sorted(backend.rglob("*.py")):
        if not is_production_python(path):
            continue
        rel = path.relative_to(root).as_posix()
        violations.extend(scan_source(path.read_text(encoding="utf-8"), rel))
    return violations


def main() -> int:
    violations = scan_repo()
    if violations:
        print("AGOM direct mutation bypass guard FAILED")
        for item in violations:
            print(item.render())
        return 1
    print("AGOM direct mutation bypass guard PASS")
    print(f"Protected ledgers: {', '.join(sorted(LEDGER_OWNERS))}")
    print(f"Protected terminal states: {len(TERMINAL_STATE_OWNERS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
