import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]
PATH = ROOT / "aegis-platform/scripts/production_storage_reclaim.py"
SPEC = importlib.util.spec_from_file_location("production_storage_reclaim", PATH)
assert SPEC and SPEC.loader
reclaim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reclaim)


def test_noop_when_capacity_is_already_above_target(monkeypatch, tmp_path):
    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: 70 * reclaim.GIB)
    monkeypatch.setattr(
        reclaim,
        "_docker_ready",
        lambda: (_ for _ in ()).throw(AssertionError("docker must not be touched")),
    )

    result = reclaim.reclaim(
        path=tmp_path,
        minimum_free_bytes=60 * reclaim.GIB,
        target_free_bytes=68 * reclaim.GIB,
    )

    assert result["status"] == "success"
    assert result["mode"] == "noop-capacity-already-sufficient"
    assert result["volume_prune_performed"] is False
    assert result["stages"] == []


def test_docker_unavailable_is_tolerated_only_when_minimum_capacity_is_preserved(monkeypatch, tmp_path):
    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: 64 * reclaim.GIB)
    monkeypatch.setattr(
        reclaim,
        "_docker_ready",
        lambda: (_ for _ in ()).throw(reclaim.StorageReclaimError("docker access denied")),
    )

    result = reclaim.reclaim(
        path=tmp_path,
        minimum_free_bytes=60 * reclaim.GIB,
        target_free_bytes=68 * reclaim.GIB,
    )

    assert result["status"] == "success"
    assert result["mode"] == "minimum-preserved-docker-unavailable"
    assert result["after_free_bytes"] == 64 * reclaim.GIB
    assert result["reclaimed_bytes"] == 0
    assert result["docker_reclaim_available"] is False
    assert result["docker_reclaim_error"] == "docker access denied"
    assert result["volume_prune_performed"] is False
    assert result["stages"] == []


def test_docker_unavailable_can_explicitly_defer_to_privileged_deploy(monkeypatch, tmp_path):
    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: 44 * reclaim.GIB)
    monkeypatch.setattr(
        reclaim,
        "_docker_ready",
        lambda: (_ for _ in ()).throw(reclaim.StorageReclaimError("docker access denied")),
    )

    result = reclaim.reclaim(
        path=tmp_path,
        minimum_free_bytes=60 * reclaim.GIB,
        target_free_bytes=68 * reclaim.GIB,
        defer_on_docker_unavailable=True,
    )

    assert result["status"] == "success"
    assert result["mode"] == "deferred-to-privileged-production-deploy"
    assert result["after_free_bytes"] == 44 * reclaim.GIB
    assert result["docker_reclaim_available"] is False
    assert result["deferred_to_privileged_deploy"] is True
    assert result["volume_prune_performed"] is False


def test_docker_unavailable_fails_closed_below_minimum(monkeypatch, tmp_path):
    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: 59 * reclaim.GIB)
    monkeypatch.setattr(
        reclaim,
        "_docker_ready",
        lambda: (_ for _ in ()).throw(reclaim.StorageReclaimError("docker access denied")),
    )

    with pytest.raises(
        reclaim.StorageReclaimError,
        match="below the production minimum and Docker reclaim is unavailable",
    ):
        reclaim.reclaim(
            path=tmp_path,
            minimum_free_bytes=60 * reclaim.GIB,
            target_free_bytes=68 * reclaim.GIB,
        )


def test_reclaim_uses_only_non_volume_docker_prunes(monkeypatch, tmp_path):
    free = {"value": 50 * reclaim.GIB}
    commands = []

    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: free["value"])
    monkeypatch.setattr(reclaim, "_docker_ready", lambda: None)
    monkeypatch.setattr(reclaim, "_docker_df", lambda: "docker-df")

    def fake_stage(name, argv, *, path):
        commands.append((name, list(argv)))
        free["value"] += 7 * reclaim.GIB
        return {
            "name": name,
            "argv": list(argv),
            "before_free_bytes": free["value"] - 7 * reclaim.GIB,
            "after_free_bytes": free["value"],
            "reclaimed_bytes": 7 * reclaim.GIB,
            "stdout_tail": "",
        }

    monkeypatch.setattr(reclaim, "_execute_stage", fake_stage)

    result = reclaim.reclaim(
        path=tmp_path,
        minimum_free_bytes=60 * reclaim.GIB,
        target_free_bytes=68 * reclaim.GIB,
    )

    assert result["status"] == "success"
    assert result["after_free_bytes"] >= 68 * reclaim.GIB
    assert result["volume_prune_performed"] is False
    assert commands == [
        (
            "aged-build-cache",
            ["docker", "builder", "prune", "--all", "--force", "--filter", "until=24h"],
        ),
        (
            "aged-stopped-containers",
            ["docker", "container", "prune", "--force", "--filter", "until=24h"],
        ),
        (
            "aged-dangling-images",
            ["docker", "image", "prune", "--force", "--filter", "until=24h"],
        ),
    ]
    assert all("volume" not in token for _, argv in commands for token in argv)


def test_reclaim_escalates_to_all_non_durable_cache_before_failing(monkeypatch, tmp_path):
    free = {"value": 50 * reclaim.GIB}
    commands = []

    monkeypatch.setattr(reclaim, "_free_bytes", lambda path: free["value"])
    monkeypatch.setattr(reclaim, "_docker_ready", lambda: None)
    monkeypatch.setattr(reclaim, "_docker_df", lambda: "docker-df")

    def fake_stage(name, argv, *, path):
        commands.append((name, list(argv)))
        return {
            "name": name,
            "argv": list(argv),
            "before_free_bytes": free["value"],
            "after_free_bytes": free["value"],
            "reclaimed_bytes": 0,
            "stdout_tail": "",
        }

    monkeypatch.setattr(reclaim, "_execute_stage", fake_stage)

    with pytest.raises(reclaim.StorageReclaimError, match="still below the production minimum"):
        reclaim.reclaim(
            path=tmp_path,
            minimum_free_bytes=60 * reclaim.GIB,
            target_free_bytes=68 * reclaim.GIB,
        )

    assert [name for name, _ in commands] == [
        "aged-build-cache",
        "aged-stopped-containers",
        "aged-dangling-images",
        "all-build-cache",
        "all-stopped-containers",
        "all-dangling-images",
    ]
    assert all("volume" not in token for _, argv in commands for token in argv)
    # Tagged images may be the only verified rollback release even if unused.
    assert all("--all" not in argv for _, argv in commands if argv[:3] == ["docker", "image", "prune"])


def test_docker_command_failures_are_fail_closed(monkeypatch):
    monkeypatch.setattr(reclaim.shutil, "which", lambda name: "/usr/bin/docker")

    def fake_run(argv, **kwargs):
        raise reclaim.StorageReclaimError("docker access denied")

    monkeypatch.setattr(reclaim, "_run", fake_run)
    with pytest.raises(reclaim.StorageReclaimError, match="docker access denied"):
        reclaim._docker_ready()


def test_cli_rejects_target_below_minimum(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        reclaim.sys,
        "argv",
        [
            "production_storage_reclaim.py",
            "--path",
            str(tmp_path),
            "--minimum-free-gib",
            "60",
            "--target-free-gib",
            "59",
        ],
    )
    assert reclaim.main() == 1
    payload = capsys.readouterr().err
    assert '"status": "failed"' in payload
    assert '"volume_prune_performed": false' in payload
