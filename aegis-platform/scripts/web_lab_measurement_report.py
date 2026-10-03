#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1] / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi_app.services.web_lab_measurement import build_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a sealed Web Labs P6 measurement report from measured case artifacts."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--case", type=Path, action="append", required=True, dest="cases")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text())
    cases = [json.loads(path.read_text()) for path in args.cases]
    report = build_report(cases, plan=plan, source_commit=args.source_commit)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )
    print(
        json.dumps(
            {
                "status": report["status"],
                "case_count": report["case_count"],
                "measurement_sha256": report["measurement_sha256"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
