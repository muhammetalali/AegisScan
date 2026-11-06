#!/usr/bin/env python3
"""Evidence-gated G5/G6 assessment. Read-only: never mutate backup, user or network state.

G5 requires independently proven scheduled 24h continuity, encrypted/versioned
restore of the SAME backup, approved numerical RPO/RTO targets and non-destructive
cleanup inventory. G6 requires the literal 107-clause original (NOT inferred
from the distinct 100 decision register), per-clause live traceability and an
independently verified owner acceptance. Missing evidence yields PARTIAL/BLOCKED.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
DECISION_CODE = re.compile(r"[A-I][0-9]{2}\Z")
TIMING_TOLERANCE_SECONDS = 900

def _utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a UTC ISO-8601 string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None or dt.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp must carry explicit UTC offset")
    return dt.astimezone(timezone.utc)

def _valid_sha(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and bool((SHA64 if length == 64 else SHA40).fullmatch(value))

def _required_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())

def _number(value: object) -> bool:
    return type(value) in (int, float) and 0 < value < 10**9

def _load(path: Path | None) -> Any:
    if path is None or not path.is_file():
        return None
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("assessment input exceeds 8 MiB")
    return json.loads(path.read_text(encoding="utf-8"))

def assess_g5(evidence: dict[str, Any] | None, *, now: datetime) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(evidence, dict):
        return {"status": "BLOCKED_EVIDENCE", "gaps": ["G5_OPERATIONAL_SNAPSHOT_REQUIRED"]}
    expected_release = evidence.get("release_sha")
    if not _valid_sha(expected_release, 40):
        gaps.append("EXACT_RELEASE_SHA_REQUIRED")
    interval = evidence.get("interval_seconds")
    if type(interval) is not int or interval != 86400:
        gaps.append("APPROVED_86400S_SCHEDULE_NOT_PROVED")
    events = evidence.get("automatic_backup_events", [])
    valid_events: list[tuple[datetime, dict[str, Any]]] = []
    if isinstance(events, list):
        for entry in events:
            if not isinstance(entry, dict):
                continue
            try:
                when = _utc(entry.get("completed_at"))
            except (ValueError, TypeError):
                continue
            if (entry.get("origin") == "schedule"
                and entry.get("status") == "success"
                and _required_str(entry.get("backup_id"))
                and _required_str(entry.get("manifest_version_id"))
                and _required_str(entry.get("object_version_id"))
                and _valid_sha(entry.get("source_sha256"))
                and _required_str(entry.get("scheduler_instance_id"))
                and when <= now):
                valid_events.append((when, entry))
    valid_events.sort(key=lambda v: v[0])
    consecutive = any(
        before[1]["scheduler_instance_id"] == after[1]["scheduler_instance_id"]
        and before[1]["backup_id"] != after[1]["backup_id"]
        and before[1]["manifest_version_id"] != after[1]["manifest_version_id"]
        and abs((after[0] - before[0]).total_seconds() - 86400) <= TIMING_TOLERANCE_SECONDS
        for before, after in zip(valid_events, valid_events[1:])
    )
    if not consecutive:
        gaps.append("24H_UNINTERRUPTED_AUTOMATIC_BACKUP_CYCLE_NOT_PROVED")
    last = valid_events[-1] if valid_events else None
    if last is None:
        gaps.append("LATEST_SCHEDULED_BACKUP_VERSIONED_PROOF_MISSING")
    restore = evidence.get("restore_verification")
    restore_valid = (
        last is not None
        and isinstance(restore, dict)
        and restore.get("status") in ("PASS", "success", "restored-and-verified-on-production-host")
        and restore.get("postgres_restore_verified") is True
        and restore.get("backup_id") == last[1]["backup_id"]
        and restore.get("manifest_version_id") == last[1]["manifest_version_id"]
        and restore.get("object_version_id") == last[1]["object_version_id"]
        and restore.get("source_sha256") == last[1]["source_sha256"]
        and restore.get("network_scope") == "isolated-backup-db"
        and restore.get("plaintext_scope") == "ephemeral-backup-container-tmpfs"
        and restore.get("production_database_modified") is False
        and _number(restore.get("elapsed_seconds"))
    )
    if not restore_valid:
        gaps.append("EXACT_CURRENT_BACKUP_ISOLATED_RESTORE_NOT_PROVED")
    contract = evidence.get("approved_recovery_contract")
    approved = isinstance(contract, dict) and contract.get("owner_approved") is True
    rpo = contract.get("rpo_seconds") if approved else None
    rto = contract.get("rto_seconds") if approved else None
    if not (_number(rpo) and _number(rto)):
        gaps.append("OWNER_APPROVED_NUMERICAL_RPO_RTO_MISSING")
    backup_age = (now - last[0]).total_seconds() if last else None
    if _number(rpo) and backup_age is not None and backup_age > rpo:
        gaps.append("ACTUAL_RPO_EXCEEDS_APPROVED_RPO")
    if _number(rto) and isinstance(restore, dict) and _number(restore.get("elapsed_seconds")) and restore["elapsed_seconds"] > rto:
        gaps.append("MEASURED_RESTORE_EXCEEDS_APPROVED_RTO")
    inventory = evidence.get("inventory")
    inventory_ok = (
        isinstance(inventory, dict)
        and type(inventory.get("volume_total")) is int and inventory["volume_total"] >= 0
        and type(inventory.get("volume_attached")) is int
        and 0 <= inventory["volume_attached"] <= inventory["volume_total"]
        and inventory.get("unused_volumes_deleted_without_consumer_proof") is False
        and inventory.get("rollback_images_retained") is True
        and inventory.get("git_fsck_connectivity") == "PASS"
        and inventory.get("production_checkout_clean") is True
    )
    if not inventory_ok:
        gaps.append("NONDESTRUCTIVE_VOLUME_ROLLBACK_AND_GIT_INTEGRITY_INVENTORY_INCOMPLETE")
    return {
        "status": "ACCEPTED" if not gaps else "PARTIAL",
        "gaps": gaps,
        "verified_scheduled_backup_count": len(valid_events),
        "same_scheduler_24h_cycle_proved": consecutive,
        "latest_scheduled_backup_age_seconds": round(backup_age, 1) if backup_age is not None else None,
        "exact_current_backup_isolated_restore_proved": restore_valid,
        "approved_rpo_seconds": rpo if _number(rpo) else None,
        "approved_rto_seconds": rto if _number(rto) else None,
        "production_data_modified": False,
        "unused_volumes_deleted": 0,
    }

def assess_g6(evidence: dict[str, Any] | None, *, release_sha: str) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(evidence, dict):
        return {"status": "BLOCKED_SOURCE", "gaps": ["LITERAL_ORIGINAL_107_NOT_AVAILABLE"]}
    original = evidence.get("original_requirements_107")
    decisions = evidence.get("original_decisions_100")
    matrix = evidence.get("requirement_evidence_matrix")
    origin = evidence.get("provenance")
    if not (isinstance(origin, dict) and origin.get("owner_authenticated_source") is True
            and _valid_sha(origin.get("original_107_source_sha256"))):
        gaps.append("ORIGINAL_107_SOURCE_PROVENANCE_NOT_VERIFIED")
    good_107 = (
        isinstance(original, list) and len(original) == 107
        and all(isinstance(x, dict) and _required_str(x.get("code"))
                and _required_str(x.get("exact_text")) for x in original)
        and len({x["code"] for x in original if isinstance(x, dict) and _required_str(x.get("code"))}) == 107
    )
    if not good_107:
        gaps.append("LITERAL_ORIGINAL_107_NOT_AVAILABLE")
    good_100 = (
        isinstance(decisions, list) and len(decisions) == 100
        and all(isinstance(x, dict) and _required_str(x.get("exact_text"))
                and isinstance(x.get("code"), str)
                and DECISION_CODE.fullmatch(x["code"]) for x in decisions)
        and len({x["code"] for x in decisions if isinstance(x, dict) and _required_str(x.get("code"))}) == 100
    )
    if not good_100:
        gaps.append("DISTINCT_100_ORIGINAL_DECISIONS_NOT_VERIFIED")
    matrix_ok = False
    if good_107 and isinstance(matrix, list) and len(matrix) == 107:
        required_codes = {x["code"] for x in original}
        observed_codes = [x.get("code") for x in matrix if isinstance(x, dict)]
        matrix_ok = (len(observed_codes) == 107 and set(observed_codes) == required_codes
                     and len(set(observed_codes)) == 107
                     and all(
                         x.get("release_sha") == release_sha
                         and all(_required_str(x.get(field)) for field in
                             ("test_ref", "ci_run_ref", "production_runtime_ref",
                              "uat_actor_ref", "rollback_evidence_ref"))
                         and x.get("independently_verified") is True
                         for x in matrix if isinstance(x, dict)))
    if not matrix_ok:
        gaps.append("107_REQUIREMENTS_EXACT_SHA_TEST_CI_RUNTIME_UAT_ROLLBACK_MAPPING_INCOMPLETE")
    approval = evidence.get("owner_signoff")
    if not (isinstance(approval, dict) and approval.get("independently_verified") is True
            and _required_str(approval.get("signed_artifact_ref"))
            and approval.get("release_sha") == release_sha):
        gaps.append("OWNER_SIGNED_FINAL_ACCEPTANCE_MISSING")
    if evidence.get("g0_to_g5_all_accepted") is not True:
        gaps.append("PREREQUISITE_GATES_NOT_ALL_ACCEPTED")
    return {
        "status": "ACCEPTED" if not gaps else "BLOCKED_SOURCE" if "LITERAL_ORIGINAL_107_NOT_AVAILABLE" in gaps else "PARTIAL",
        "gaps": gaps,
        "literal_107_count": len(original) if isinstance(original, list) else 0,
        "distinct_decision_100_count": len(decisions) if isinstance(decisions, list) else 0,
        "no_invented_requirement_text": True,
        "project_complete": not gaps,
    }

def assessment(*, g5: Any, g6: Any, release_sha: str, now: datetime) -> dict[str, Any]:
    if not _valid_sha(release_sha, 40):
        raise ValueError("exact lowercase 40-char SHA required")
    if now.tzinfo is None:
        raise ValueError("aware UTC evaluation time required")
    g5_result = assess_g5(g5, now=now.astimezone(timezone.utc))
    g6_result = assess_g6(g6, release_sha=release_sha)
    return {
        "schema": "aegisscan.g5-g6-evidence-acceptance.v1",
        "evaluated_utc": now.astimezone(timezone.utc).isoformat(),
        "release_sha": release_sha,
        "g5": g5_result,
        "g6": g6_result,
        "project_complete": g5_result["status"] == "ACCEPTED" and g6_result["project_complete"],
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--g5-evidence", type=Path)
    parser.add_argument("--g6-evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = assessment(
            g5=_load(args.g5_evidence), g6=_load(args.g6_evidence),
            release_sha=args.release_sha, now=datetime.now(timezone.utc))
        output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as f:
                f.write(output)
        else:
            sys.stdout.write(output)
        return 0 if result["project_complete"] else 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "failed", "error_class": type(exc).__name__}), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
