from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .validation_executor import ExecutionResult

ENGINE = "code_quality"
MAX_CONTENT_CHARS = 400_000


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding(file_name: str, rule: str, title: str, severity: str, line: int, evidence_id: str, detail: str) -> dict[str, Any]:
    return {
        "id": f"finding-code-{abs(hash((file_name, rule, line))) & 0xffffffff:08x}",
        "title": title,
        "severity": severity,
        "status": "open",
        "confidence": 94,
        "category": "code_quality",
        "asset": file_name,
        "rule": rule,
        "line": line,
        "evidence_ids": [evidence_id],
        "description": detail,
        "observed_at": _utc(),
    }


def _iter_sources(extra: dict[str, Any]) -> list[tuple[str, str]]:
    sources: list[tuple[str, str]] = []
    content = extra.get("code_content")
    if isinstance(content, str) and content.strip():
        sources.append((str(extra.get("code_filename") or "<inline>"), content[:MAX_CONTENT_CHARS]))

    files = extra.get("code_files")
    if isinstance(files, dict):
        for name, value in list(files.items())[:100]:
            if isinstance(value, str) and value.strip():
                sources.append((str(name), value[:MAX_CONTENT_CHARS]))
    return sources


async def analyze_code(extra: dict[str, Any]) -> ExecutionResult:
    sources = _iter_sources(extra)
    if not sources:
        return ExecutionResult(
            status="unsupported",
            findings=[],
            evidence=[],
            metrics={"engine": ENGINE, "execution": "awaiting_code_snapshot"},
            error="Provide extra.code_content or extra.code_files for code-quality analysis.",
        )

    findings: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    rules = [
        ("dynamic-eval", re.compile(r"\beval\s*\("), "Dynamic eval usage", "high"),
        ("dynamic-exec", re.compile(r"\bexec\s*\("), "Dynamic exec usage", "high"),
        ("shell-command", re.compile(r"subprocess\.(?:run|Popen|call)\([^\n]*shell\s*=\s*True", re.I), "Shell command execution with shell=True", "high"),
        ("hardcoded-secret", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"'][^\"']{6,}[\"']"), "Potential hardcoded credential", "critical"),
        ("insecure-tls", re.compile(r"verify\s*=\s*False", re.I), "TLS certificate verification disabled", "high"),
    ]

    for file_name, content in sources:
        evidence_id = f"ev-code-{abs(hash((file_name, content[:2000]))) & 0xffffffff:08x}"
        evidence.append({
            "id": evidence_id,
            "type": "code_snapshot",
            "engine": ENGINE,
            "created_at": _utc(),
            "data": {
                "file": file_name,
                "bytes": len(content.encode("utf-8", errors="ignore")),
                "lines": content.count("\n") + 1,
            },
        })
        lines = content.splitlines()
        for rule_id, pattern, title, severity in rules:
            for line_no, line in enumerate(lines, start=1):
                if pattern.search(line):
                    findings.append(_finding(
                        file_name,
                        rule_id,
                        title,
                        severity,
                        line_no,
                        evidence_id,
                        f"Rule {rule_id} matched in {file_name} at line {line_no}.",
                    ))

    return ExecutionResult(
        status="completed",
        findings=findings,
        evidence=evidence,
        metrics={
            "engine": ENGINE,
            "files_analyzed": len(sources),
            "findings_count": len(findings),
            "evidence_count": len(evidence),
        },
    )
