from pathlib import Path

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/production-launch-readiness.yml"


def test_launch_readiness_dependency_install_is_bounded():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = document["jobs"]["production-launch-readiness"]
    assert 20 <= job["timeout-minutes"] <= 45

    install = next(step for step in job["steps"] if step.get("name") == "Install launch-gate dependencies")
    assert 10 <= install["timeout-minutes"] <= 15

    script = install["run"]
    assert "timeout --foreground 180s apt-get" in script
    assert "Acquire::http::Timeout=20" in script
    assert "Acquire::https::Timeout=20" in script
    assert "timeout --foreground 420s apt-get" in script
    assert "install -y --no-install-recommends postgresql-client openssl" in script
