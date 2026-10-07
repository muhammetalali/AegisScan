from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci.resilient_artifact_download import (
    ArtifactDownloadError,
    download_artifact,
)


ROOT = Path(__file__).parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/release1-closure.yml",
    ROOT / ".github/workflows/fresh-main-final-verification.yml",
    ROOT / ".github/workflows/project-completion.yml",
    ROOT / ".github/workflows/external-provider-acceptance-closure.yml",
    ROOT / ".github/workflows/production-final-governance.yml",
)


def test_transient_503_retries_then_commits_complete_download(tmp_path: Path):
    calls = []
    sleeps = []

    def runner(command, **_kwargs):
        calls.append(command)
        destination = Path(command[command.index("--dir") + 1])
        if len(calls) == 1:
            return SimpleNamespace(
                returncode=1,
                stdout="",
                stderr="HTTP 503: 503 Egress is over the account limit.",
            )
        (destination / "evidence.json").write_text('{"ok":true}\n', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    destination = tmp_path / "final"
    attempt = download_artifact(
        run_id=42,
        repository="muhammetalali/AegisScan",
        artifact_name="proof",
        destination=destination,
        runner=runner,
        sleeper=sleeps.append,
    )

    assert attempt == 2
    assert len(calls) == 2
    assert sleeps == [10]
    assert (destination / "evidence.json").is_file()


def test_non_transient_missing_artifact_fails_without_retry(tmp_path: Path):
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1, stdout="", stderr="artifact not found")

    with pytest.raises(ArtifactDownloadError, match="non-transient") as exc_info:
        download_artifact(
            run_id=42,
            repository="muhammetalali/AegisScan",
            artifact_name="missing",
            destination=tmp_path / "final",
            runner=runner,
            sleeper=lambda _seconds: pytest.fail("must not back off"),
        )
    assert "artifact not found" in str(exc_info.value)
    assert len(calls) == 1


def test_all_transient_attempts_fail_closed_after_bounded_backoff(tmp_path: Path):
    calls = []
    sleeps = []

    def runner(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1, stdout="", stderr="ECONNRESET")

    with pytest.raises(ArtifactDownloadError, match="all bounded transient"):
        download_artifact(
            run_id=42,
            repository="muhammetalali/AegisScan",
            destination=tmp_path / "final",
            runner=runner,
            sleeper=sleeps.append,
        )
    assert len(calls) == 3
    assert sleeps == [10, 30]


def test_preexisting_destination_content_is_rejected(tmp_path: Path):
    destination = tmp_path / "final"
    destination.mkdir()
    (destination / "stale.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ArtifactDownloadError, match="destination is not empty"):
        download_artifact(
            run_id=42,
            repository="muhammetalali/AegisScan",
            destination=destination,
        )


def test_final_evidence_workflows_use_resilient_downloader_only():
    for workflow in WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        assert "python scripts/ci/resilient_artifact_download.py" in text, workflow
        assert "gh run download" not in text, workflow


def test_diagnostic_redacts_presigned_urls(tmp_path: Path, capsys):
    secret_url = "https://example.invalid/artifact.zip?sig=super-secret&se=tomorrow"

    def runner(command, **_kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=f"HTTP 503: Egress is over the account limit. ({secret_url})",
        )

    with pytest.raises(ArtifactDownloadError, match="all bounded transient"):
        download_artifact(
            run_id=42,
            repository="muhammetalali/AegisScan",
            destination=tmp_path / "final",
            runner=runner,
            sleeper=lambda _seconds: None,
        )

    output = capsys.readouterr().out
    assert "HTTP 503" in output
    assert "<url-redacted>" in output
    assert "super-secret" not in output
    assert "sig=" not in output
