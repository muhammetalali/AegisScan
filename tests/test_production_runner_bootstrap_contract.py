from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "aegis-platform/scripts/production_runner_bootstrap.sh"


def test_runner_bootstrap_is_fail_closed_and_pinned():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "production runner bootstrap must run as root" in text
    assert "AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" in text
    assert "sha256sum -c -" in text
    assert "https://github.com/actions/runner/releases/download/" in text
    assert "--proto '=https'" in text
    assert "--tlsv1.2" in text
    assert "aegisscan-production" in text


def test_runner_bootstrap_installs_dedicated_service_without_hosted_fallback():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'RUNNER_USER="D{AEGIS_GITHUB_RUNNER_USER:-aegisrunner}"'.replace("D{", "$" + "{") in text
    assert 'RUNNER_DIR="D{AEGIS_GITHUB_RUNNER_DIR:-/opt/actions-runner}"'.replace("D{", "$" + "{") in text
    assert 'RUNNER_WORK="D{AEGIS_GITHUB_RUNNER_WORK:-/var/lib/aegisscan/actions-runner-work}"'.replace("D{", "$" + "{") in text
    assert 'runuser -u "$RUNNER_USER"' in text
    assert './svc.sh install "$RUNNER_USER"' in text
    assert './svc.sh start' in text
    assert 'systemctl is-enabled --quiet "$service_name"' in text
    assert 'systemctl is-active --quiet "$service_name"' in text
    assert "ubuntu-latest" not in text


def test_runner_bootstrap_refuses_destructive_live_replacement():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "existing production runner service is active" in text
    assert "refusing destructive replacement" in text
