from pathlib import Path

import yaml


WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"
CANCELLABLE = {
    "domain-contract-reality.yml",
    "frontend-lock-sync.yml",
}
NON_CANCELLABLE = {
    "supply-chain-release.yml",
}


def _load(name: str) -> dict:
    with (WORKFLOWS / name).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_supersedable_validation_workflows_cancel_old_heads():
    for name in CANCELLABLE:
        concurrency = _load(name).get("concurrency", {})
        assert concurrency.get("group"), name
        assert concurrency.get("cancel-in-progress") is True, name
        group = str(concurrency["group"])
        assert "pull_request.number" in group or "github.ref" in group, name


def test_release_workflow_is_never_cancelled_mid_publish():
    concurrency = _load("supply-chain-release.yml").get("concurrency", {})
    assert concurrency.get("group")
    assert concurrency.get("cancel-in-progress") is False
