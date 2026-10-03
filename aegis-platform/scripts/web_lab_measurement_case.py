#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi_app.services.web_lab_measurement import case_from_proof, validate_plan


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive one sealed P6 measurement case from an actual live proof artifact."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--case-ref", required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--fixture-image-id", required=True)
    parser.add_argument("--scanner-image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    plan = validate_plan(json.loads(args.plan.read_text()))
    plan_case = next(
        (row for row in plan["cases"] if row["case_ref"] == args.case_ref), None
    )
    if plan_case is None:
        raise SystemExit(f"Unknown sealed case_ref: {args.case_ref}")

    proof_bytes = args.proof.read_bytes()
    proof = json.loads(proof_bytes)
    metrics = json.loads(args.metrics.read_text())

    case = case_from_proof(
        plan_case=plan_case,
        proof=proof,
        proof_sha256=hashlib.sha256(proof_bytes).hexdigest(),
        source_commit=args.source_commit,
        fixture_image_id=args.fixture_image_id,
        scanner_image_id=args.scanner_image_id,
        metrics=metrics,
        definition_id=plan["definition_id"],
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    print(
        json.dumps(
            {
                "case_ref": case["case_ref"],
                "observed_verdict": case["observed_verdict"],
                "proof_sha256": case["proof_sha256"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
