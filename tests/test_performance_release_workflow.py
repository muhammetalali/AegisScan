from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github/workflows/performance-load-soak-reality.yml"
REQUEST_PATH = ".github/live-acceptance-requests/performance.json"


def _workflow() -> dict:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_performance_release_request_is_bounded_to_exact_main_and_live_authorization_contract():
    data = _workflow()
    triggers = data["on"]
    assert REQUEST_PATH in triggers["push"]["paths"]
    assert REQUEST_PATH not in triggers["pull_request"]["paths"]

    job = data["jobs"]["capacity-recovery"]
    assert job["timeout-minutes"] >= 120
    steps = job["steps"]
    names = [step.get("name") for step in steps]
    profile = steps[names.index("Resolve bounded performance profile")]
    script = profile["run"]

    assert "live_acceptance_request.py" in script
    assert "--scope release-performance" in script
    assert "--required-confirm VALIDATE" in script
    assert "--event-before" in script
    assert REQUEST_PATH in script
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in script
    assert 'test "$(git rev-parse origin/main)" = "$AEGIS_EXACT_HEAD"' in script
    assert 'git diff --name-only "$before" "$AEGIS_EXACT_HEAD"' in script
    assert '[ -f .github/live-acceptance-requests/performance.json ]' in script
    assert "AEGIS_PERFORMANCE_PROFILE=$profile" in script


def test_release_profile_expands_capacity_and_soak_without_relaxing_thresholds():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'tenants=3' in text
    assert 'if [ "${AEGIS_PERFORMANCE_PROFILE:-ci}" = "release" ]; then tenants=6; fi' in text
    assert 'stages=(--stage 20:30 --stage 50:30 --stage 100:30 --stage 25:120)' in text
    assert 'stages=(--stage 30:120 --stage 75:180 --stage 125:180 --stage 50:900)' in text
    assert 'if [ "${AEGIS_PERFORMANCE_PROFILE:-ci}" = "release" ]; then' in text
    assert '--max-p95-ms 750' in text
    assert '--max-error-rate 0.01' in text
    assert '--min-requests "$min_requests"' in text
    assert '--min-rps "$min_rps"' in text


def test_release_request_file_is_not_committed_until_authorization():
    assert not (ROOT / REQUEST_PATH).exists()
