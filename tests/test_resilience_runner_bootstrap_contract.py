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


def test_resilience_runner_recovery_requires_full_attested_marker():
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'stat -c \'%U:%G:%a\' "$RUNNER_MARKER"' in text
    assert "root:root:640" in text
    assert "runner_url=$AEGIS_GITHUB_RUNNER_URL" in text
    assert "runner_name=$RUNNER_NAME" in text
    assert "runner_labels=$RUNNER_LABELS" in text
    assert "runner_archive_sha256=$AEGIS_GITHUB_RUNNER_ARCHIVE_SHA256" in text
    assert "existing resilience runner is not bound to the approved AegisScan resilience marker" in text
    assert "approved resilience runner service is inactive; attempting bounded service recovery" in text
    assert "AEGISSCAN_RESILIENCE_RUNNER_RECOVERY=PASS" in text
    assert "marker_matches" in text


def test_resilience_runner_rejects_verified_archive_without_dependency_installer():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "verified runner archive is missing bin/installdependencies.sh" in text


def test_resilience_runner_download_recovers_from_stalls_without_restarting_archive():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "download_runner_archive()" in text
    assert "--continue-at -" in text
    assert "--connect-timeout 30" in text
    assert "--speed-limit 1024 --speed-time 60" in text
    assert "max_attempts=8" in text
    assert "resuming partial archive" in text
    assert "--progress-bar" in text
