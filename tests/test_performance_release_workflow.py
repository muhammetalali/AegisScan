from __future__ import annotations

import json
from datetime import datetime
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


def test_optional_release_request_is_governed_when_present():
    request_path = ROOT / REQUEST_PATH
    if not request_path.exists():
        return

    payload = json.loads(request_path.read_text(encoding="utf-8"))
    assert payload["schema"] == "aegisscan.live-acceptance-request.v1"
    assert payload["scope"] == "release-performance"
    assert payload["confirm"] == "VALIDATE"
    assert payload["requested_branch"] == "main"

    requested_base_sha = payload["requested_base_sha"]
    assert len(requested_base_sha) == 40
    assert all(ch in "0123456789abcdef" for ch in requested_base_sha)

    requested_at = datetime.fromisoformat(payload["requested_at"].replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
    assert expires_at > requested_at
