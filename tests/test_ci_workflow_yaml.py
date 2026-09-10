from pathlib import Path

import yaml


def test_all_github_workflows_are_valid_yaml():
    root = Path(__file__).parents[1] / ".github" / "workflows"
    workflows = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    assert workflows
    for path in workflows:
        with path.open(encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        assert isinstance(document, dict), path.name
        assert document.get("name"), path.name
        assert "jobs" in document, path.name
