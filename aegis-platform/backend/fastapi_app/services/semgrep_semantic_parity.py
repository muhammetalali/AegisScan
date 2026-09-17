from __future__ import annotations

import hashlib
import json
from typing import Any

_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "info",
}


def _observation(item: dict[str, Any]) -> dict[str, Any]:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    message = str(extra.get("message") or item.get("check_id") or "Semgrep finding")
    raw_severity = str(extra.get("severity") or "WARNING").lower()
    return {
        "check_id": str(item.get("check_id") or ""),
        "message": message,
        "severity": _SEVERITY_MAP.get(raw_severity, "medium"),
        "path": str(item.get("path") or ""),
        "line": int(start.get("line") or 0),
    }


def normalize_semgrep_semantics(raw_output: str) -> dict[str, Any]:
    if not raw_output.strip():
        payload: Any = {}
    else:
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError:
            payload = {}
    results = payload.get("results", []) if isinstance(payload, dict) else []
    observations = [
        _observation(item)
        for item in results
        if isinstance(item, dict)
    ]
    observations.sort(
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )
    canonical = json.dumps(
        observations,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "finding_count": len(observations),
        "observations": observations,
        "semantic_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def compare_semgrep_semantics(legacy_output: str, candidate_output: str) -> dict[str, Any]:
    legacy = normalize_semgrep_semantics(legacy_output)
    candidate = normalize_semgrep_semantics(candidate_output)
    mismatches: list[str] = []
    if legacy["observations"] != candidate["observations"]:
        mismatches.append("finding_semantics")
    if legacy["semantic_sha256"] != candidate["semantic_sha256"]:
        mismatches.append("semantic_digest")
    return {
        "equivalent": not mismatches,
        "mismatches": mismatches,
        "legacy": legacy,
        "candidate": candidate,
    }
