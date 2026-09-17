#!/usr/bin/env python3
"""Evaluate observed production recovery point and recovery time against explicit objectives."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "aegisscan.production-resilience-objectives.v1"
MAX_OBJECTIVE_SECONDS = 30 * 24 * 60 * 60


class ObjectiveError(RuntimeError):
    pass


def _epoch(value: str) -> int:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObjectiveError("backup completed_at must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ObjectiveError("backup completed_at must include a timezone")
    return int(parsed.astimezone(timezone.utc).timestamp())


def _objective(name: str, value: int) -> int:
    if value < 1 or value > MAX_OBJECTIVE_SECONDS:
        raise ObjectiveError(f"{name} must be between 1 and {MAX_OBJECTIVE_SECONDS} seconds")
    return value


def evaluate(
    *,
    backup_completed_at: str,
    failure_epoch: int,
    recovery_verified_epoch: int,
    rpo_objective_seconds: int,
    rto_objective_seconds: int,
) -> dict[str, object]:
    backup_epoch = _epoch(backup_completed_at)
    rpo_objective = _objective("RPO objective", rpo_objective_seconds)
    rto_objective = _objective("RTO objective", rto_objective_seconds)
    if failure_epoch <= 0 or recovery_verified_epoch <= 0:
        raise ObjectiveError("failure/recovery epochs must be positive Unix timestamps")
    if failure_epoch < backup_epoch:
        raise ObjectiveError("simulated failure precedes the committed recovery point")
    if recovery_verified_epoch < failure_epoch:
        raise ObjectiveError("recovery verification precedes the simulated failure")

    observed_rpo = failure_epoch - backup_epoch
    observed_rto = recovery_verified_epoch - failure_epoch
    rpo_met = observed_rpo <= rpo_objective
    rto_met = observed_rto <= rto_objective
    if not rpo_met or not rto_met:
        failures = []
        if not rpo_met:
            failures.append(f"RPO {observed_rpo}s exceeds {rpo_objective}s")
        if not rto_met:
            failures.append(f"RTO {observed_rto}s exceeds {rto_objective}s")
        raise ObjectiveError("; ".join(failures))

    return {
        "schema": SCHEMA,
        "status": "success",
        "simulation": "failure-immediately-after-fresh-committed-backup",
        "backup_completed_at": backup_completed_at,
        "backup_completed_epoch": backup_epoch,
        "failure_epoch": failure_epoch,
        "recovery_verified_epoch": recovery_verified_epoch,
        "rpo": {
            "objective_seconds": rpo_objective,
            "observed_seconds": observed_rpo,
            "met": True,
        },
        "rto": {
            "objective_seconds": rto_objective,
            "observed_seconds": observed_rto,
            "met": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-completed-at", required=True)
    parser.add_argument("--failure-epoch", required=True, type=int)
    parser.add_argument("--recovery-verified-epoch", required=True, type=int)
    parser.add_argument("--rpo-objective-seconds", required=True, type=int)
    parser.add_argument("--rto-objective-seconds", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = evaluate(
            backup_completed_at=args.backup_completed_at,
            failure_epoch=args.failure_epoch,
            recovery_verified_epoch=args.recovery_verified_epoch,
            rpo_objective_seconds=args.rpo_objective_seconds,
            rto_objective_seconds=args.rto_objective_seconds,
        )
    except ObjectiveError as exc:
        print(json.dumps({"schema": SCHEMA, "status": "failed", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
