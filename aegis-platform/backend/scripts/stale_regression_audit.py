from __future__ import annotations

import ast
import json
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parents[1]
ROUTERS_ROOT = BACKEND_ROOT / "fastapi_app" / "routers"
DIGITAL_TWIN = ROUTERS_ROOT / "digital_twin.py"

LEGACY_ROUTER_IMPORTS = (
    "from .validations import _store",
    "from .audit import add_audit_entry",
)

LEGACY_DIGITAL_TWIN_MARKERS = (
    "TODO: Run simulation",
    "security_impact=2.5",
    "performance_impact=0.5",
    "risk_reduction=15.0",
    "Recommended - reduces risk",
)

REQUIRED_DIGITAL_TWIN_MARKERS = (
    "predict_digital_twin_scenario_task.delay(",
    "status='queued'",
    "source='postgresql'",
)


def _relative_target_exists(path: Path, node: ast.ImportFrom) -> bool:
    if not node.module:
        return True
    package_dir = path.parent
    for _ in range(max(0, node.level - 1)):
        package_dir = package_dir.parent
    target = package_dir.joinpath(*node.module.split("."))
    return target.with_suffix(".py").is_file() or target.is_dir()


def main() -> int:
    failures: list[str] = []
    checked_router_files = 0
    checked_relative_imports = 0

    for path in sorted(ROUTERS_ROOT.glob("*.py")):
        checked_router_files += 1
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            failures.append(f"{path.relative_to(BACKEND_ROOT)}:{exc.lineno}: syntax error: {exc.msg}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level <= 0:
                continue
            checked_relative_imports += 1
            if not _relative_target_exists(path, node):
                module = "." * node.level + (node.module or "")
                failures.append(
                    f"{path.relative_to(BACKEND_ROOT)}:{getattr(node, 'lineno', '?')}: "
                    f"unresolved relative import target {module}"
                )

        for forbidden in LEGACY_ROUTER_IMPORTS:
            if forbidden in text:
                failures.append(
                    f"{path.relative_to(BACKEND_ROOT)}: forbidden stale router import: {forbidden}"
                )

    if not DIGITAL_TWIN.is_file():
        failures.append("fastapi_app/routers/digital_twin.py: missing canonical Digital Twin router")
    else:
        text = DIGITAL_TWIN.read_text(encoding="utf-8")
        for marker in LEGACY_DIGITAL_TWIN_MARKERS:
            if marker in text:
                failures.append(f"fastapi_app/routers/digital_twin.py: legacy placeholder marker present: {marker}")
        for marker in REQUIRED_DIGITAL_TWIN_MARKERS:
            if marker not in text:
                failures.append(
                    f"fastapi_app/routers/digital_twin.py: deterministic queued simulation contract marker missing: {marker}"
                )

    result = {
        "status": "failed" if failures else "passed",
        "checked_router_files": checked_router_files,
        "checked_relative_imports": checked_relative_imports,
        "failures": failures,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
