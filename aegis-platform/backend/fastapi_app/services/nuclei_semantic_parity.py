from __future__ import annotations

import hashlib
import json
from typing import Any

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _first_string(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item.strip():
                return item.strip()
    return ""


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\x00", r"\u0000")
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key).replace("\x00", r"\u0000"): _sanitize(item)
            for key, item in value.items()
        }
    return value


def _canonical_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(item).strip() for item in value if str(item).strip()})


def _observation(record: dict[str, Any]) -> dict[str, Any]:
    info = record.get("info") if isinstance(record.get("info"), dict) else {}
    classification = (
        info.get("classification")
        if isinstance(info.get("classification"), dict)
        else {}
    )
    cve_ids = classification.get("cve-id")
    cwe_ids = classification.get("cwe-id")
    severity = _first_string(info.get("severity")).lower()
    if severity not in _ALLOWED_SEVERITIES:
        severity = "info"
    matched_at = _first_string(record.get("matched-at")) or _first_string(record.get("host"))
    return {
        "title": _first_string(info.get("name"))
        or _first_string(record.get("template-id"))
        or "Nuclei finding",
        "description": _first_string(info.get("description"))
        or "Finding reported by Nuclei.",
        "remediation": _first_string(info.get("remediation")),
        "severity": severity,
        "references": _canonical_list(info.get("reference")),
        "cve_ids": _canonical_list(cve_ids),
        "cwe_id": _first_string(cwe_ids) if isinstance(cwe_ids, list) else "",
        "url": matched_at,
        "method": _first_string(record.get("type")).upper(),
        "template_id": _first_string(record.get("template-id")),
        "matcher_name": _first_string(record.get("matcher-name")),
    }


def normalize_nuclei_semantics(raw_output: str) -> dict[str, Any]:
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    raw_record_count = 0
    for raw_line in raw_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = _sanitize(json.loads(line))
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        raw_record_count += 1
        observation = _observation(record)
        identity = (observation["title"], observation["url"])
        by_identity.setdefault(identity, observation)

    observations = sorted(
        by_identity.values(),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )
    canonical = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "raw_record_count": raw_record_count,
        "finding_count": len(observations),
        "observations": observations,
        "semantic_sha256": hashlib.sha256(canonical).hexdigest(),
    }


def compare_nuclei_semantics(legacy_output: str, candidate_output: str) -> dict[str, Any]:
    legacy = normalize_nuclei_semantics(legacy_output)
    candidate = normalize_nuclei_semantics(candidate_output)
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
