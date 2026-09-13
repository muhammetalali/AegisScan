#!/usr/bin/env python3
"""Fail-closed Aegis Kali runner foundation.

PR-2 intentionally provides lifecycle and contract validation only. Tool dispatch is
introduced by profile PRs after capability adapters are registered by the control plane.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

ALLOWED_RISK_LEVELS = {
    "passive",
    "active-low",
    "active-medium",
    "active-high",
    "state-changing",
    "exploit-validation",
}
REQUIRED_FIELDS = {
    "execution_id": str,
    "capability_id": str,
    "asset_id": str,
    "authorization_id": str,
    "authorization_decision": str,
    "risk_level": str,
    "profile": str,
    "options": dict,
}
FORBIDDEN_EXECUTION_FIELDS = {"command", "cmd", "shell", "argv", "binary", "executable"}
MAX_MANIFEST_BYTES = 64 * 1024
RUNTIME_MANIFEST_PATH = Path("/opt/aegis-runner/runtime-manifest.json")


def _fail(message: str, code: int = 64) -> int:
    print(json.dumps({"status": "rejected", "reason": message}, sort_keys=True), file=sys.stderr)
    return code


def _load_manifest(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("job manifest is missing")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("job manifest exceeds size limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("job manifest is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("job manifest must be an object")
    return payload


def _validate_manifest(payload: dict[str, Any]) -> None:
    for field, expected_type in REQUIRED_FIELDS.items():
        value = payload.get(field)
        if not isinstance(value, expected_type) or (expected_type is str and not value.strip()):
            raise ValueError(f"invalid or missing field: {field}")

    if payload["authorization_decision"] != "authorized":
        raise ValueError("authorization decision is not authorized")
    if payload["risk_level"] not in ALLOWED_RISK_LEVELS:
        raise ValueError("unsupported risk level")
    if payload["profile"] != os.environ.get("AEGIS_RUNNER_PROFILE", "base"):
        raise ValueError("runner profile binding mismatch")
    if FORBIDDEN_EXECUTION_FIELDS.intersection(payload):
        raise ValueError("raw command execution fields are forbidden")


def _load_runtime_manifest(path: Path = RUNTIME_MANIFEST_PATH) -> tuple[dict[str, Any], bytes]:
    if not path.is_file():
        raise ValueError("runtime manifest is missing")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("runtime manifest must be an object")

    expected = {
        "runtime": "aegis-kali",
        "runner_version": os.environ.get("AEGIS_RUNNER_VERSION", "unknown"),
        "profile": os.environ.get("AEGIS_RUNNER_PROFILE", "base"),
        "base_image_digest": os.environ.get("AEGIS_BASE_IMAGE_DIGEST", "unknown"),
        "build_commit": os.environ.get("AEGIS_BUILD_COMMIT", "unknown"),
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"runtime manifest binding mismatch: {key}")
    return payload, raw


def _runtime_provenance(payload: dict[str, Any], raw: bytes, runtime_raw: bytes) -> dict[str, Any]:
    return {
        "execution_id": payload["execution_id"],
        "capability_id": payload["capability_id"],
        "asset_id": payload["asset_id"],
        "authorization_id": payload["authorization_id"],
        "runtime": "aegis-kali",
        "runner_version": os.environ.get("AEGIS_RUNNER_VERSION", "unknown"),
        "runner_profile": os.environ.get("AEGIS_RUNNER_PROFILE", "base"),
        "base_image_digest": os.environ.get("AEGIS_BASE_IMAGE_DIGEST", "unknown"),
        "build_commit": os.environ.get("AEGIS_BUILD_COMMIT", "unknown"),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_manifest_digest": "sha256:" + hashlib.sha256(runtime_raw).hexdigest(),
        "status": "accepted-no-dispatch",
    }


def main() -> int:
    manifest_path = Path(os.environ.get("AEGIS_JOB_MANIFEST", "/workspace/job.json"))
    try:
        raw = manifest_path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError("job manifest exceeds size limit")
        payload = _load_manifest(manifest_path)
        _validate_manifest(payload)
        _, runtime_raw = _load_runtime_manifest()
    except (OSError, ValueError) as exc:
        return _fail(str(exc))

    # Foundation PR deliberately performs no tool execution. This prevents an
    # unregistered capability from becoming an authorization bypass.
    print(json.dumps(_runtime_provenance(payload, raw, runtime_raw), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
