from pathlib import Path

import yaml


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/security-reality-check.yml"


def test_backend_and_nmap_install_are_bounded():
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    backend = document["jobs"]["backend"]
    assert 1 <= backend["timeout-minutes"] < 60

    install = next(step for step in backend["steps"] if step.get("name") == "Install Nmap")
    assert 1 <= install["timeout-minutes"] <= 10
    script = install["run"]
    assert "timeout --foreground 180s apt-get" in script
    assert "Acquire::http::Timeout=20" in script
    assert "Acquire::https::Timeout=20" in script
