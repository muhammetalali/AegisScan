from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.ci.release1_applicability import (
    Release1ApplicabilityError,
    decide,
)

CANDIDATE = "2" * 40
PUBLISHED = "1" * 40


def test_first_release_closure_is_applicable_when_nothing_is_published():
    decision = decide(event_name="workflow_run", candidate_sha=CANDIDATE)
    assert decision.state == "close"
    assert decision.should_close is True
    assert decision.published_sha is None


def test_idempotent_same_sha_closure_remains_applicable():
    decision = decide(
        event_name="workflow_run",
        candidate_sha=PUBLISHED,
        published_release_sha=PUBLISHED,
        published_tag_sha=PUBLISHED,
    )
    assert decision.state == "close"
    assert decision.should_close is True
    assert decision.published_sha == PUBLISHED


def test_automatic_post_release_sha_becomes_successful_noop():
    decision = decide(
        event_name="workflow_run",
        candidate_sha=CANDIDATE,
        published_release_sha=PUBLISHED,
        published_tag_sha=PUBLISHED,
    )
    assert decision.state == "already_closed"
    assert decision.should_close is False
    assert decision.published_sha == PUBLISHED


def test_manual_dispatch_cannot_retarget_immutable_release_tag():
    with pytest.raises(Release1ApplicabilityError, match="cannot retarget"):
        decide(
            event_name="workflow_dispatch",
            candidate_sha=CANDIDATE,
            published_release_sha=PUBLISHED,
            published_tag_sha=PUBLISHED,
        )


@pytest.mark.parametrize(
    ("release_sha", "tag_sha", "message"),
    [
        (PUBLISHED, "", "presence mismatch"),
        ("", PUBLISHED, "presence mismatch"),
        (PUBLISHED, "3" * 40, "inconsistent"),
    ],
)
def test_corrupt_or_partial_publication_fails_closed(release_sha, tag_sha, message):
    with pytest.raises(Release1ApplicabilityError, match=message):
        decide(
            event_name="workflow_run",
            candidate_sha=CANDIDATE,
            published_release_sha=release_sha,
            published_tag_sha=tag_sha,
        )


ROOT = Path(__file__).resolve().parents[1]


def _gate_script() -> str:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release1-closure.yml").read_text())
    steps = workflow["jobs"]["release1-applicability"]["steps"]
    return next(step["run"] for step in steps if step.get("id") == "gate")


def _fake_gh(tmp_path: Path) -> Path:
    binary = tmp_path / "bin"
    binary.mkdir()
    gh = binary / "gh"
    gh.write_text(
        """#!/bin/sh
set -eu
mode="${GH_MODE:-published}"
endpoint="${2:-}"
if [ "$mode" = network ]; then
  echo 'transport failure' >&2
  exit 1
fi
if [ "$mode" = missing ]; then
  echo 'gh: Not Found (HTTP 404)' >&2
  exit 1
fi
case "$endpoint" in
  */releases/tags/*|*/git/ref/tags/*)
    printf '%s\n' "${PUBLISHED_SHA:?}"
    ;;
  *)
    echo 'unexpected endpoint' >&2
    exit 2
    ;;
esac
"""
    )
    gh.chmod(0o755)
    return binary


@pytest.mark.parametrize(
    ("mode", "expected_state", "expected_should_close"),
    [
        ("missing", "close", "true"),
        ("published", "already_closed", "false"),
    ],
)
def test_workflow_gate_distinguishes_missing_release_from_immutable_post_release(
    tmp_path, mode, expected_state, expected_should_close
):
    output = tmp_path / "github-output"
    output.write_text("")
    binary = _fake_gh(tmp_path)
    proc = subprocess.run(
        ["bash", "-c", _gate_script()],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{binary}:{os.environ['PATH']}",
            "GH_MODE": mode,
            "PUBLISHED_SHA": PUBLISHED,
            "AEGIS_RELEASE_TAG": "v1.0.6",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_EVENT_NAME": "workflow_run",
            "AEGIS_RELEASE_SHA": CANDIDATE,
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    values = dict(line.split("=", 1) for line in output.read_text().splitlines())
    assert values["state"] == expected_state
    assert values["should_close"] == expected_should_close


def test_workflow_gate_fails_closed_on_github_transport_error(tmp_path):
    output = tmp_path / "github-output"
    output.write_text("")
    binary = _fake_gh(tmp_path)
    proc = subprocess.run(
        ["bash", "-c", _gate_script()],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{binary}:{os.environ['PATH']}",
            "GH_MODE": "network",
            "PUBLISHED_SHA": PUBLISHED,
            "AEGIS_RELEASE_TAG": "v1.0.6",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_EVENT_NAME": "workflow_run",
            "AEGIS_RELEASE_SHA": CANDIDATE,
            "GITHUB_OUTPUT": str(output),
        },
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "transport failure" in proc.stderr
