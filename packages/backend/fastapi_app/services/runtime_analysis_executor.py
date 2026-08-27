from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .validation_executor import ExecutionResult

ENGINE = "runtime_analysis"
MAX_LOG_CHARS = 300_000


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


async def analyze_runtime(extra: dict[str, Any]) -> ExecutionResult:
    log_text = extra.get("runtime_logs")
    if not isinstance(log_text, str) or not log_text.strip():
        return ExecutionResult(
            status="unsupported",
            findings=[],
            evidence=[],
            metrics={"engine": ENGINE, "execution": "awaiting_runtime_logs"},
            error="Provide extra.runtime_logs for runtime analysis.",
        )

    log_text = log_text[:MAX_LOG_CHARS]
    source = str(extra.get("runtime_log_source") or "<inline-runtime-log>")
    evidence_id = f"ev-runtime-{abs(hash((source, log_text[:3000]))) & 0xffffffff:08x}"
    evidence = [{
        "id": evidence_id,
        "type": "runtime_log_snapshot",
        "engine": ENGINE,
        "created_at": _utc(),
        "data": {
            "source": source,
            "lines": log_text.count("\n") + 1,
            "bytes": len(log_text.encode("utf-8", errors="ignore")),
        },
    }]

    patterns = [
        ("unhandled-exception", re.compile(r"\b(?:Traceback \(most recent call last\)|Unhandled(?:Exception| Error)|panic:)\b", re.I), "Unhandled runtime exception observed", "high"),
        ("http-5xx", re.compile(r"\b5\d\d\b"), "HTTP 5xx response observed", "high"),
        ("auth-failure", re.compile(r"\b(?:authentication|authorization|login).{0,40}(?:failed|denied|invalid)\b", re.I), "Authentication or authorization failure observed", "medium"),
        ("database-error", re.compile(r"\b(?:database|db|sql).{0,50}\b(?:error|exception|timeout|failed)\b", re.I), "Database/runtime persistence error observed", "high"),
    ]

    lines = log_text.splitlines()
    findings: list[dict[str, Any]] = []
    for rule, pattern, title, severity in patterns:
        for line_no, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append({
                    "id": f"finding-runtime-{abs(hash((source, rule, line_no))) & 0xffffffff:08x}",
                    "title": title,
                    "severity": severity,
                    "status": "open",
                    "confidence": 91,
                    "category": "runtime_analysis",
                    "asset": source,
                    "rule": rule,
                    "line": line_no,
                    "evidence_ids": [evidence_id],
                    "description": f"Runtime signal {rule} observed at line {line_no}.",
                    "observed_at": _utc(),
                })

    return ExecutionResult(
        status="completed",
        findings=findings,
        evidence=evidence,
        metrics={
            "engine": ENGINE,
            "lines_analyzed": len(lines),
            "findings_count": len(findings),
            "evidence_count": 1,
        },
    )
