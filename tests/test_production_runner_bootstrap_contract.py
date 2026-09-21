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
    assert "--disableupdate" in text


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
    assert "existing approved production runner service is active" in text
    assert "refusing destructive replacement" in text


def test_runner_bootstrap_provisions_execution_dependencies_from_verified_archive():
    text = SCRIPT.read_text(encoding="utf-8")
    for package in ("git", "gh", "openssh-client"):
        assert package in text
    assert 'bin/installdependencies.sh' in text
    assert 'verified runner archive is missing bin/installdependencies.sh' in text
    for command_name in ("git", "gh", "ssh", "ssh-keygen", "curl", "tar"):
        assert f'command -v "$command_name"' in text or f'command_name in' in text


def test_runner_bootstrap_requires_attested_existing_runner_marker():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'RUNNER_MARKER="/etc/aegisscan/production-runner.env"' in text
    assert "schema=aegisscan.production-runner.v1" in text
    assert "runner_url=$AEGIS_GITHUB_RUNNER_URL" in text
    assert "runner_name=$RUNNER_NAME" in text
    assert "runner_labels=$RUNNER_LABELS" in text
    assert "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" in text
    assert "root:root:640" in text
    assert "existing active runner is not bound to the approved AegisScan production runner marker" in text
    assert "marker_matches" in text
