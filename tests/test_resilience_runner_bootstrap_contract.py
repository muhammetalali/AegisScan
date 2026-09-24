from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "aegis-platform/scripts/resilience_runner_bootstrap.sh"


def test_resilience_runner_is_pinned_private_and_dedicated():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "resilience runner bootstrap must run as root" in text
    assert "aegisscan-resilience" in text
    assert "aegisscan-production" not in text
    assert "actions-runner-linux-x64-" in text
    assert "sha256sum -c -" in text
    assert "--disableupdate" in text
    assert "schema=aegisscan.resilience-runner.v1" in text


def test_resilience_runner_provisions_required_host_dependencies_without_workflow_sudo():
    text = SCRIPT.read_text(encoding="utf-8")
    for package in ("git", "gh", "openssh-client", "postgresql-client"):
        assert package in text
    assert "docker info" in text
    assert 'usermod -aG docker "$RUNNER_USER"' in text
    assert '/opt/aegis-resilience-runner' in text
    assert '/var/lib/aegisscan/resilience-runner-work' in text
