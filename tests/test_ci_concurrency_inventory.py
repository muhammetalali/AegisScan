from pathlib import Path

import yaml


WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"


def test_reality_workflows_declare_concurrency_policy():
    missing = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        with path.open(encoding="utf-8") as handle:
            workflow = yaml.safe_load(handle)
        name = str(workflow.get("name", ""))
        if "Reality" not in name:
            continue
        if not workflow.get("concurrency"):
            missing.append(path.name)
    assert not missing, f"Reality workflows missing concurrency policy: {missing}"
