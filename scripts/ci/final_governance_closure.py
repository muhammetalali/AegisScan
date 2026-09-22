#!/usr/bin/env python3
"""Build and verify the exact-SHA Final Governance Closure manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

DIMENSION_SCHEMA = "aegisscan.final-governance-dimension.v1"
MANIFEST_SCHEMA = "aegisscan.final-governance-closure.v1"
DIMENSIONS = (
    "responsibility_sod",
    "risk_acceptance",
    "obligations_expiry",
    "audit_integrity",
    "evidence_governance",
)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIMENSION_FIELDS = {
    "schema",
    "status",
    "dimension",
    "release_sha",
    "suites",
    "artifacts",
}


class GovernanceClosureError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise GovernanceClosureError(f"{label} does not exist: {path}")
    if path.stat().st_size <= 0 or path.stat().st_size > 4 * 1024 * 1024:
        raise GovernanceClosureError(f"{label} has invalid size")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceClosureError(f"{label} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise GovernanceClosureError(f"{label} must contain a JSON object")
    return payload


def _unique(root: Path, name: str, label: str) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise GovernanceClosureError(f"{label} contains an unsafe artifact filename")
    matches = [path for path in root.rglob(name) if path.is_file()]
    if len(matches) != 1:
        raise GovernanceClosureError(
            f"{label} must contain exactly one {name}; found {len(matches)}"
        )
    return matches[0]


def _verify_dimension(*, root: Path, dimension: str, release_sha: str) -> dict[str, Any]:
    path = _unique(root, f"{dimension}.json", f"{dimension} governance evidence")
    payload = _load_json(path, f"{dimension} governance evidence")
    if set(payload) != DIMENSION_FIELDS:
        raise GovernanceClosureError(
            f"{dimension} fields mismatch: "
            f"missing={sorted(DIMENSION_FIELDS - set(payload))} "
            f"unknown={sorted(set(payload) - DIMENSION_FIELDS)}"
        )
    if payload.get("schema") != DIMENSION_SCHEMA:
        raise GovernanceClosureError(f"{dimension} governance schema mismatch")
    if payload.get("status") != "success":
        raise GovernanceClosureError(f"{dimension} governance evidence is not successful")
    if payload.get("dimension") != dimension:
        raise GovernanceClosureError(f"{dimension} governance dimension mismatch")
    if payload.get("release_sha") != release_sha:
        raise GovernanceClosureError(f"{dimension} release SHA mismatch")

    suites = payload.get("suites")
    if (
        not isinstance(suites, list)
        or not suites
        or any(not isinstance(item, str) or not item.strip() for item in suites)
        or len(suites) != len(set(suites))
    ):
        raise GovernanceClosureError(f"{dimension} suites are invalid")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise GovernanceClosureError(f"{dimension} artifact map is missing")
    normalized_artifacts: dict[str, str] = {}
    for raw_name, raw_digest in artifacts.items():
        name = str(raw_name or "")
        digest = str(raw_digest or "").strip().lower()
        if not SHA256_RE.fullmatch(digest):
            raise GovernanceClosureError(f"{dimension} digest is invalid for {name}")
        artifact = _unique(root, name, f"{dimension} governance evidence")
        actual = _sha256_file(artifact)
        if actual != digest:
            raise GovernanceClosureError(
                f"{dimension} artifact digest mismatch for {name}: {actual} != {digest}"
            )
        normalized_artifacts[name] = digest

    return {
        "status": "success",
        "dimension": dimension,
        "suites": sorted(item.strip() for item in suites),
        "artifacts": dict(sorted(normalized_artifacts.items())),
        "evidence_sha256": _sha256_file(path),
    }


def build_manifest(*, release_sha: str, evidence_root: Path, output: Path) -> dict[str, Any]:
    release_sha = str(release_sha or "").strip().lower()
    if not SHA_RE.fullmatch(release_sha):
        raise GovernanceClosureError(
            "release SHA must be exactly 40 lowercase hexadecimal characters"
        )
    evidence_root = evidence_root.resolve()
    if not evidence_root.is_dir():
        raise GovernanceClosureError("governance evidence root does not exist")

    dimensions = {
        dimension: _verify_dimension(
            root=evidence_root,
            dimension=dimension,
            release_sha=release_sha,
        )
        for dimension in DIMENSIONS
    }
    payload: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "status": "success",
        "decision": "APPROVED",
        "release_sha": release_sha,
        "controls": {
            "authoritative_responsibility_and_sod": True,
            "governed_risk_acceptance_lineage": True,
            "assurance_obligation_expiry_enforced": True,
            "append_only_audit_integrity": True,
            "evidence_qualification_and_immutability": True,
            "exact_sha_evidence_binding": True,
        },
        "dimensions": dimensions,
    }
    payload["governance_sha256"] = _sha256_bytes(_canonical(payload))
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build_manifest(
            release_sha=args.release_sha,
            evidence_root=args.evidence_root,
            output=args.output,
        )
    except GovernanceClosureError as exc:
        print(
            json.dumps(
                {
                    "schema": MANIFEST_SCHEMA,
                    "status": "failed",
                    "decision": "REJECTED",
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
