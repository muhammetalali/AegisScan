"""G5/G6 evidence acceptance: fail-closed, not a substitute for real UAT."""
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "g5_g6_evidence_acceptance", ROOT / "scripts/ci/g5_g6_evidence_acceptance.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
SHA = "a" * 40

def _event(time, instance="schedule-1", backup="backup-1", origin="schedule"):
    return {
        "completed_at": time.isoformat(), "scheduler_instance_id": instance,
        "origin": origin, "status": "success", "backup_id": backup,
        "manifest_version_id": "manifest-v1" if backup == "backup-1" else "manifest-v0", "object_version_id": "object-v1" if backup == "backup-1" else "object-v0",
        "source_sha256": "b" * 64,
    }

def _g5():
    t = NOW - timedelta(hours=1)
    return {
        "release_sha": SHA,
        "interval_seconds": 86400,
        "automatic_backup_events": [
            _event(t - timedelta(days=1), backup="backup-0"), _event(t)],
        "restore_verification": {
            "status": "PASS", "postgres_restore_verified": True,
            "backup_id": "backup-1", "manifest_version_id": "manifest-v1",
            "object_version_id": "object-v1", "source_sha256": "b" * 64,
            "network_scope": "isolated-backup-db",
            "plaintext_scope": "ephemeral-backup-container-tmpfs",
            "production_database_modified": False, "elapsed_seconds": 120,
        },
        "platform_recovery": {
            "status": "PASS", "release_sha": SHA, "isolated_environment": True,
            "original_production_unchanged": True, "elapsed_seconds": 600,
            "services_verified": ["postgres", "redis", "django", "fastapi", "scanner", "frontend"]},
        "approved_recovery_contract": {
            "owner_approved": True, "rpo_seconds": 7200, "rto_seconds": 1800},
        "inventory": {
            "volume_total": 55, "volume_attached": 23,
            "unused_volumes_deleted_without_consumer_proof": False,
            "rollback_images_retained": True, "git_fsck_connectivity": "PASS",
            "production_checkout_clean": True,
        }
    }

def _g6():
    requirements = [{"code": "REQ-%03d" % i, "exact_text": "owner supplied clause %d" % i}
                    for i in range(1, 108)]
    import json
    decisions = json.loads(
        (ROOT / "docs/acceptance/g6-owner-decisions-100.source.json").read_text(encoding="utf-8")
    )["original_decisions_100"]
    matrix = [{
        "code": x["code"], "release_sha": SHA,
        "test_ref": "tests/a.py", "ci_run_ref": "run/1",
        "production_runtime_ref": "runtime/1", "uat_actor_ref": "UAT/1",
        "rollback_evidence_ref": "rollback/1", "independently_verified": True,
    } for x in requirements]
    return {
        "original_requirements_107": requirements,
        "original_decisions_100": decisions,
        "requirement_evidence_matrix": matrix,
        "decision_evidence_matrix": [
            {**matrix[0], "code": x["code"]} for x in decisions
        ],
        "provenance": {"owner_authenticated_source": True,
                       "original_107_source_sha256": "c" * 64},
        "owner_signoff": {"independently_verified": True,
                          "signed_artifact_ref": "signoff/verified",
                          "release_sha": SHA},
        "g0_to_g5_all_accepted": True,
    }

def test_g5_only_accepts_proven_scheduled_two_interval_continuity():
    result = gate.assess_g5(_g5(), now=NOW)
    assert result["status"] == "ACCEPTED"
    assert result["same_scheduler_24h_cycle_proved"] is True
    assert result["latest_scheduled_backup_age_seconds"] == 3600

def test_g5_rejects_single_startup_backup_and_missing_targets():
    evidence = _g5()
    evidence["automatic_backup_events"] = [_event(NOW - timedelta(hours=1), origin="startup")]
    evidence["approved_recovery_contract"] = None
    result = gate.assess_g5(evidence, now=NOW)
    assert result["status"] == "PARTIAL"
    assert "24H_UNINTERRUPTED_AUTOMATIC_BACKUP_CYCLE_NOT_PROVED" in result["gaps"]
    assert "OWNER_APPROVED_NUMERICAL_RPO_RTO_MISSING" in result["gaps"]

def test_g5_rejects_restore_of_different_backup_and_unsafe_cleanup():
    evidence = _g5()
    evidence["restore_verification"]["backup_id"] = "old-receipt"
    evidence["inventory"]["unused_volumes_deleted_without_consumer_proof"] = True
    result = gate.assess_g5(evidence, now=NOW)
    assert "EXACT_CURRENT_BACKUP_ISOLATED_RESTORE_NOT_PROVED" in result["gaps"]
    assert "NONDESTRUCTIVE_VOLUME_ROLLBACK_AND_GIT_INTEGRITY_INVENTORY_INCOMPLETE" in result["gaps"]

def test_g5_rejects_actual_rpo_rto_over_contract():
    evidence = _g5()
    evidence["approved_recovery_contract"]["rpo_seconds"] = 1800
    evidence["approved_recovery_contract"]["rto_seconds"] = 60
    result = gate.assess_g5(evidence, now=NOW)
    assert "ACTUAL_RPO_EXCEEDS_APPROVED_RPO" in result["gaps"]
    assert "MEASURED_RESTORE_EXCEEDS_APPROVED_RTO" in result["gaps"]

def test_g6_does_not_invent_original_107_from_100_decisions():
    evidence = _g6()
    evidence.pop("original_requirements_107")
    result = gate.assess_g6(evidence, release_sha=SHA)
    assert result["status"] == "BLOCKED_SOURCE"
    assert result["no_invented_requirement_text"] is True
    assert "LITERAL_ORIGINAL_107_NOT_AVAILABLE" in result["gaps"]

def test_g6_rejects_unverified_signoff_and_mismatched_release():
    evidence = _g6()
    evidence["owner_signoff"]["independently_verified"] = False
    evidence["requirement_evidence_matrix"][0]["release_sha"] = "d" * 40
    result = gate.assess_g6(evidence, release_sha=SHA)
    assert result["status"] == "PARTIAL"
    assert "OWNER_SIGNED_FINAL_ACCEPTANCE_MISSING" in result["gaps"]
    assert any("MAPPING_INCOMPLETE" in code for code in result["gaps"])

def test_g6_requires_distinct_100_and_actual_107_even_with_all_green_ci():
    evidence = _g6()
    evidence["original_decisions_100"][99]["code"] = evidence["original_decisions_100"][0]["code"]
    result = gate.assess_g6(evidence, release_sha=SHA)
    assert "DISTINCT_100_ORIGINAL_DECISIONS_NOT_VERIFIED" in result["gaps"]

def test_g6_only_accepts_complete_tested_and_signed_fixture():
    evidence = _g6()
    result = gate.assess_g6(evidence, release_sha=SHA)
    assert result["status"] == "ACCEPTED"
    assert result["literal_107_count"] == 107
    assert result["distinct_decision_100_count"] == 100

def test_release_gate_not_complete_if_either_g5_or_g6_pending():
    result = gate.assessment(g5=_g5(), g6=None, release_sha=SHA, now=NOW)
    assert result["g5"]["status"] == "ACCEPTED"
    assert result["g6"]["status"] == "BLOCKED_SOURCE"
    assert result["project_complete"] is False

def test_g5_rejects_replayed_same_backup_as_fake_second_cycle():
    evidence = _g5()
    evidence["automatic_backup_events"][0]["backup_id"] = "backup-1"
    evidence["automatic_backup_events"][0]["manifest_version_id"] = "manifest-v1"
    result = gate.assess_g5(evidence, now=NOW)
    assert "24H_UNINTERRUPTED_AUTOMATIC_BACKUP_CYCLE_NOT_PROVED" in result["gaps"]

def test_g5_refuses_to_equate_postgres_restore_with_full_platform_restore():
    evidence = _g5()
    evidence.pop("platform_recovery")
    result = gate.assess_g5(evidence, now=NOW)
    assert "FULL_PLATFORM_ISOLATED_RECOVERY_NOT_PROVED" in result["gaps"]

def test_g6_requires_individual_evidence_for_all_hundred_owner_decisions():
    evidence = _g6()
    evidence["decision_evidence_matrix"].pop()
    result = gate.assess_g6(evidence, release_sha=SHA)
    assert "100_OWNER_DECISIONS_EXACT_SHA_EVIDENCE_MAPPING_INCOMPLETE" in result["gaps"]
