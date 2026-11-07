"""Safety and real-origin semantics for the read-only G5 schedule collector."""
from datetime import datetime, timezone, timedelta
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json
import pytest

ROOT = Path(__file__).parents[1]
SPEC = spec_from_file_location("g5_schedule_runtime_receipt", ROOT / "scripts/ci/g5_schedule_runtime_receipt.py")
assert SPEC and SPEC.loader
module = module_from_spec(SPEC)
SPEC.loader.exec_module(module)
SHA = "a" * 40
CID = "b" * 64
START = datetime(2026, 11, 6, 13, 8, 41, tzinfo=timezone.utc)
NOW = datetime(2026, 11, 7, 14, tzinfo=timezone.utc)
INSPECT = (CID + "|" + START.isoformat() + '|0|true|["schedule"]|'
           '["python3","/app/scripts/remote_backup_service.py"]\n')


def line(at, backup_id, manifest, object_version, *, status="success"):
    value = {"status": status, "schema": "aegisscan.remote-backup.v1",
             "backup_id": backup_id, "completed_at": at.isoformat(),
             "manifest_version_id": manifest, "object_version_id": object_version,
             "source_sha256": "f" * 64}
    return (at + timedelta(milliseconds=300)).isoformat() + " " + json.dumps(value) + "\n"


def receipt(logs, **kw):
    return module.make_receipt(expected_release_sha=SHA, actual_release_sha=kw.get("sha", SHA),
                               checkout_clean=kw.get("clean", True), inspection_text=kw.get("inspect", INSPECT),
                               logs=logs, interval_seconds=kw.get("interval", 86400), collected_at=NOW)


def test_first_real_scheduler_event_remains_partial():
    first = line(START + timedelta(seconds=24), "id-1", "manifest-1", "object-1")
    result = receipt(first)
    assert result["status"] == "PARTIAL_NEEDS_TWO_CYCLES"
    assert result["g5_accepted"] is False
    assert len(result["automatic_backup_events"]) == 1
    assert result["automatic_backup_events"][0]["origin"] == "schedule"


def test_two_distinct_uninterrupted_docker_log_events_are_only_candidates():
    first_at = START + timedelta(seconds=24)
    logs = line(first_at, "id-1", "manifest-1", "object-1") + line(
        first_at + timedelta(seconds=86415), "id-2", "manifest-2", "object-2")
    result = receipt(logs)
    assert result["two_cycle_candidate"] is True
    assert result["status"] == "CANDIDATE_TWO_CYCLES"
    assert result["g5_accepted"] is False
    assert len(result["unverified_gates"]) == 3
    assert result["automatic_backup_events"][0]["scheduler_instance_id"] == CID


@pytest.mark.parametrize("inspect", [
    INSPECT.replace('|0|true|', '|1|true|'),
    INSPECT.replace('|0|true|', '|0|false|'),
    INSPECT.replace('["schedule"]', '["once"]'),
    INSPECT.replace('remote_backup_service.py', 'malicious.py'),
])
def test_restart_stop_or_wrong_command_fails_closed(inspect):
    with pytest.raises(module.EvidenceError):
        receipt(line(START + timedelta(seconds=30), "id", "manifest", "obj"), inspect=inspect)


def test_refuse_wrong_release_or_dirty_checkout_or_wrong_interval():
    logs = line(START + timedelta(seconds=30), "id", "manifest", "obj")
    for change in ({"sha": "c" * 40}, {"clean": False}, {"interval": 3600}):
        with pytest.raises(module.EvidenceError):
            receipt(logs, **change)


def test_reject_replayed_backup_even_with_two_log_lines():
    at = START + timedelta(seconds=25)
    logs = line(at, "same-id", "v1", "v1") + line(at + timedelta(seconds=86400), "same-id", "v2", "v2")
    with pytest.raises(module.EvidenceError, match="duplicate backup"):
        receipt(logs)


def test_reject_different_manifest_and_object_versions_or_short_cycle():
    at = START + timedelta(seconds=25)
    for later, manifest, object_version in ((86400, "v1", "o2"), (86400, "v2", "o1"), (1000, "v2", "o2")):
        logs = line(at, "id-1", "v1", "o1") + line(at + timedelta(seconds=later), "id-2", manifest, object_version)
        assert receipt(logs)["two_cycle_candidate"] is False


def test_ignore_synthetic_log_line_after_collection_and_bad_hash():
    first = line(START + timedelta(seconds=24), "id-1", "v1", "o1")
    fake_time = NOW + timedelta(days=1)
    future = line(fake_time, "id-2", "v2", "o2")
    assert len(receipt(first + future)["automatic_backup_events"]) == 1
    invalid = first.replace('"source_sha256": "' + 'f' * 64, '"source_sha256": "not-a-hash')
    assert not receipt(invalid)["automatic_backup_events"]


def test_stdout_source_has_no_raw_secrets_in_receipt():
    logs = ("2026-11-06T13:09:05Z " + json.dumps({"status": "failed", "error": "private-key-do-not-emit"}) + "\n"
            + line(START + timedelta(seconds=24), "id-1", "m1", "o1"))
    result = receipt(logs)
    assert result["backup_failure_line_count"] == 1
    assert "private-key-do-not-emit" not in json.dumps(result)
