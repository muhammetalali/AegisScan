#!/usr/bin/env python3
"""Decide whether Release 1 closure should run for a candidate SHA."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_EVENTS = {"workflow_run", "workflow_dispatch"}


class Release1ApplicabilityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Decision:
    state: str
    should_close: bool
    published_sha: str | None = None


def _sha(value: str, label: str) -> str:
    value = value.strip().lower()
    if not SHA_RE.fullmatch(value):
        raise Release1ApplicabilityError(f"{label} must be exactly 40 lowercase hexadecimal characters")
    return value


def decide(
    *,
    event_name: str,
    candidate_sha: str,
    published_release_sha: str = "",
    published_tag_sha: str = "",
) -> Decision:
    if event_name not in ALLOWED_EVENTS:
        raise Release1ApplicabilityError(f"unsupported event: {event_name}")

    candidate = _sha(candidate_sha, "candidate SHA")
    release_raw = published_release_sha.strip().lower()
    tag_raw = published_tag_sha.strip().lower()

    if bool(release_raw) != bool(tag_raw):
        raise Release1ApplicabilityError("Release 1 publication is incomplete: release/tag presence mismatch")

    if not release_raw:
        return Decision(state="close", should_close=True)

    release_sha = _sha(release_raw, "published release SHA")
    tag_sha = _sha(tag_raw, "published tag SHA")
    if release_sha != tag_sha:
        raise Release1ApplicabilityError("Release 1 publication is inconsistent: release target and tag SHA differ")

    if candidate == release_sha:
        return Decision(state="close", should_close=True, published_sha=release_sha)

    if event_name == "workflow_run":
        return Decision(state="already_closed", should_close=False, published_sha=release_sha)

    raise Release1ApplicabilityError(
        "manual Release 1 closure cannot retarget the immutable published Release 1 tag"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--published-release-sha", default="")
    parser.add_argument("--published-tag-sha", default="")
    args = parser.parse_args()

    try:
        decision = decide(
            event_name=args.event_name,
            candidate_sha=args.candidate_sha,
            published_release_sha=args.published_release_sha,
            published_tag_sha=args.published_tag_sha,
        )
    except Release1ApplicabilityError as exc:
        parser.error(str(exc))

    print(f"state={decision.state}")
    print(f"should_close={'true' if decision.should_close else 'false'}")
    print(f"published_sha={decision.published_sha or ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
