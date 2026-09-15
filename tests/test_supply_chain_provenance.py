import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "aegis-platform/scripts/create_slsa_provenance.py"
SPEC = importlib.util.spec_from_file_location("create_slsa_provenance", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_provenance_is_bound_to_repository_commit_and_run(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/aegis")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    output = tmp_path / "provenance.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["create_slsa_provenance.py", "--image", "ghcr.io/owner/aegis-django", "--digest", "sha256:" + "b" * 64, "--dockerfile", "Dockerfile", "--output", str(output)],
    )
    assert MODULE.main() == 0
    predicate = json.loads(output.read_text())
    assert predicate["builder"]["id"].endswith("/actions/runs/123")
    assert predicate["invocation"]["configSource"]["digest"] == {"sha1": "a" * 40}
    assert predicate["materials"][0]["digest"] == {"sha1": "a" * 40}


def test_provenance_rejects_mutable_or_malformed_digest(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/aegis")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(sys, "argv", ["p", "--image", "image", "--digest", "latest", "--dockerfile", "D", "--output", str(tmp_path / "p")])
    with pytest.raises(SystemExit):
        MODULE.main()


WORKFLOW = Path(__file__).parents[1] / ".github/workflows/supply-chain-release.yml"


def test_supply_chain_cosign_bootstrap_is_retryable_and_digest_pinned():
    workflow = WORKFLOW.read_text()
    assert "sigstore/cosign-installer@" not in workflow
    assert "COSIGN_VERSION: v2.6.1" in workflow
    assert "COSIGN_LINUX_AMD64_SHA256: 064954c5d8c7e3b28188eee5b1727b31c411550bc5fefd41aa672d3c761d103a" in workflow
    assert "--retry 5 --retry-all-errors --retry-delay 2 --retry-max-time 180" in workflow
    assert "sha256sum --check --strict" in workflow
