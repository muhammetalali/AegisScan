#!/usr/bin/env python3
"""Create the signed provenance predicate for one immutable release image."""

from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--dockerfile", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not DIGEST.fullmatch(args.digest):
        parser.error("--digest must be sha256:<64 lowercase hex characters>")

    repository = os.environ["GITHUB_REPOSITORY"]
    commit = os.environ["GITHUB_SHA"]
    run_id = os.environ["GITHUB_RUN_ID"]
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    predicate = {
        "builder": {"id": f"{server}/{repository}/actions/runs/{run_id}"},
        "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
        "invocation": {
            "configSource": {
                "uri": f"git+{server}/{repository}@refs/heads/main",
                "digest": {"sha1": commit},
                "entryPoint": ".github/workflows/supply-chain-release.yml",
            },
            "parameters": {"image": args.image, "dockerfile": args.dockerfile},
            "environment": {"github_run_id": run_id},
        },
        "metadata": {"buildStartedOn": now, "buildFinishedOn": now, "reproducible": False},
        "materials": [{"uri": f"git+{server}/{repository}", "digest": {"sha1": commit}}],
    }
    args.output.write_text(json.dumps(predicate, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
