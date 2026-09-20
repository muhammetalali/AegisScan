#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MUTATING_MANAGER_METHODS = {
    "create", "get_or_create", "update_or_create", "bulk_create",
    "bulk_update", "update", "delete",
}

@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    code: str
    detail: str

    def render(self) -> str:
        location = f"{self.path}:{self.line}" if self.line else self.path
        return f"{location} [{self.code}] {self.detail}"

def load_policy(path: Path) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if int(policy.get("schema_version", 0)) != 1:
        raise ValueError("Unsupported AGOM direct-mutation policy schema_version.")
    for field in (
        "production_roots", "protected_models", "protected_callables",
        "protected_state_assignments", "required_source_guards",
    ):
        if field not in policy:
            raise ValueError(f"AGOM direct-mutation policy is missing {field}.")
    return policy

def _normalized(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()

def _production_python_files(root: Path, policy: dict[str, Any]) -> Iterable[Path]:
    excluded_parts = set(policy.get("excluded_path_parts") or [])
    excluded_prefixes = tuple(policy.get("excluded_filename_prefixes") or [])
    seen: set[Path] = set()
    for raw in policy["production_roots"]:
        base = root / str(raw)
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            if path in seen:
                continue
            seen.add(path)
            rel = path.relative_to(root)
            if any(part in excluded_parts for part in rel.parts):
                continue
            if path.name.startswith(excluded_prefixes):
                continue
            yield path

def _dotted_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value, aliases)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""

def _import_aliases(tree: ast.AST, protected: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for item in node.names:
                if item.name in protected:
                    aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.Import):
            for item in node.names:
                leaf = item.name.rsplit(".", 1)[-1]
                if leaf in protected:
                    aliases[item.asname or leaf] = leaf
    return aliases

def _names_in(node: ast.AST, aliases: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(aliases.get(child.id, child.id))
    return names

def _call_name(node: ast.Call, aliases: dict[str, str]) -> str:
    if isinstance(node.func, ast.Name):
        return aliases.get(node.func.id, node.func.id)
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""

def _audit_ast(rel: str, source: str, policy: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        return [Violation(rel, int(exc.lineno or 0), "PYTHON_SYNTAX", str(exc))]

    protected_models: dict[str, list[str]] = policy["protected_models"]
    protected_callables: dict[str, list[str]] = policy["protected_callables"]
    protected_states: dict[str, list[str]] = policy["protected_state_assignments"]
    symbols = set(protected_models) | set(protected_callables)
    aliases = _import_aliases(tree, symbols)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _call_name(node, aliases)
            if call_name in protected_callables:
                allowed = set(protected_callables[call_name])
                if rel not in allowed:
                    violations.append(Violation(
                        rel, int(getattr(node, "lineno", 0) or 0),
                        "SENSITIVE_CALL_BYPASS",
                        f"{call_name} may only be called from {sorted(allowed)}.",
                    ))

            if isinstance(node.func, ast.Attribute) and node.func.attr in MUTATING_MANAGER_METHODS:
                referenced = _names_in(node.func.value, aliases)
                for model in sorted(referenced & set(protected_models)):
                    allowed = set(protected_models[model])
                    if rel not in allowed:
                        violations.append(Violation(
                            rel, int(getattr(node, "lineno", 0) or 0),
                            "PROTECTED_MODEL_WRITE",
                            f"{model}.{node.func.attr} is restricted to {sorted(allowed)}.",
                        ))

        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = getattr(node, "value", None)
            if value is None:
                continue
            state = _dotted_name(value, aliases)
            if state in protected_states:
                allowed = set(protected_states[state])
                if rel not in allowed:
                    violations.append(Violation(
                        rel, int(getattr(node, "lineno", 0) or 0),
                        "PROTECTED_STATE_WRITE",
                        f"Assignment of {state} is restricted to {sorted(allowed)}.",
                    ))

            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                target = getattr(node, "target", None)
                if target is not None:
                    targets = [target]
            for target in targets:
                if not isinstance(target, ast.Subscript):
                    continue
                slice_node = target.slice
                key = slice_node.value if isinstance(slice_node, ast.Constant) else None
                if key != "authorized":
                    continue
                owner = _dotted_name(target.value, aliases)
                if owner.endswith(".configuration"):
                    violations.append(Violation(
                        rel, int(getattr(node, "lineno", 0) or 0),
                        "LEGACY_AUTHORIZATION_WRITE",
                        "Asset authorization must not be encoded by mutating configuration['authorized']; use the immutable AssetAuthorization governance ledger.",
                    ))
    return violations

def _audit_required_guards(root: Path, policy: dict[str, Any]) -> list[Violation]:
    violations: list[Violation] = []
    for guard in policy["required_source_guards"]:
        rel = str(guard["path"])
        path = root / rel
        token = str(guard["token"])
        minimum = int(guard.get("min_count", 1))
        if not path.is_file():
            violations.append(Violation(rel, 0, "GUARD_FILE_MISSING", "Required governance guard file is missing."))
            continue
        source = path.read_text(encoding="utf-8")
        observed = source.count(token)
        if observed < minimum:
            violations.append(Violation(
                rel, 0, "REQUIRED_GUARD_MISSING",
                f"Required token {token!r} expected at least {minimum} time(s), observed {observed}.",
            ))
    return violations

def audit_repository(root: Path, policy: dict[str, Any]) -> list[Violation]:
    root = root.resolve()
    violations = _audit_required_guards(root, policy)
    for path in _production_python_files(root, policy):
        rel = _normalized(path, root)
        violations.extend(_audit_ast(rel, path.read_text(encoding="utf-8"), policy))
    unique = {(v.path, v.line, v.code, v.detail): v for v in violations}
    return [unique[key] for key in sorted(unique)]

def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    policy_path = Path(argv[2] if len(argv) > 2 else ".github/governance/agom-direct-mutation-policy.json")
    if not policy_path.is_absolute():
        policy_path = (root / policy_path).resolve()
    policy = load_policy(policy_path)
    violations = audit_repository(root, policy)
    if violations:
        print("AGOM direct mutation bypass audit: FAILED")
        for violation in violations:
            print(violation.render())
        return 1
    print("AGOM direct mutation bypass audit: PASS")
    print("Protected governance writers are reachable only through the declared authoritative paths.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
