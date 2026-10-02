from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.release1_version import RELEASE_TAG

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    "release1-closure.yml",
    "external-provider-acceptance-closure.yml",
    "final-project-hygiene.yml",
    "fresh-main-final-verification.yml",
    "project-completion.yml",
)


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_publication_consumers_load_same_immutable_patch_tag(workflow, tmp_path):
    data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    jobs = [j for j in data["jobs"].values() if any(
        s.get("name") == "Load current Release 1 publication tag" for s in j["steps"]
    )]
    assert len(jobs) == 1
    steps = jobs[0]["steps"]
    index = next(i for i, s in enumerate(steps) if s.get("name") == "Load current Release 1 publication tag")
    env_file = tmp_path / "github-env"
    env_file.write_text("")
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", steps[index]["run"]],
        cwd=ROOT, env={**os.environ, "GITHUB_ENV": str(env_file)},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert env_file.read_text() == f"AEGIS_RELEASE_TAG={RELEASE_TAG}\n"
    assert RELEASE_TAG == "v1.0.4"
    for step in steps[index + 1:]:
        script = step.get("run", "")
        if "gh release " in script:
            assert "v1.0.0" not in script
            assert "AEGIS_RELEASE_TAG" in script


def test_performance_acceptance_regressions_run_before_full_stack_build():
    data = yaml.safe_load((ROOT / ".github/workflows/performance-load-soak-reality.yml").read_text())
    steps = data["jobs"]["capacity-recovery"]["steps"]
    preflight = next(i for i, s in enumerate(steps) if s.get("name") == "Prove capacity evidence contract")
    build = next(i for i, s in enumerate(steps) if s.get("name") == "Build full platform once")
    assert preflight < build
    assert "tests/test_release_performance_acceptance.py" in steps[preflight]["run"]
    for event in ("pull_request", "push"):
        paths = data["on"][event]["paths"]
        assert "scripts/ci/release_performance_acceptance.py" in paths
        assert "tests/test_release_performance_acceptance.py" in paths
