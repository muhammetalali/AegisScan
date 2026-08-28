from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    kind: str
    subject: str
    confidence: float
    observed_at: str
    attributes: dict[str, Any] = field(default_factory=dict)


class IntelligenceProvider(Protocol):
    name: str

    async def collect(self, subject: str, context: dict[str, Any] | None = None) -> list[Evidence]: ...


class SafeProvider:
    """Base provider contract. Network collection belongs in explicit adapters."""

    name = "safe"

    async def collect(self, subject: str, context: dict[str, Any] | None = None) -> list[Evidence]:
        return []


def evidence_id(source: str, subject: str, kind: str, value: Any) -> str:
    raw = f"{source}|{subject}|{kind}|{value}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


class BTEProvider(SafeProvider):
    """Behavioral Terrain Engine: derives a bounded behavioral fingerprint from supplied telemetry.

    It never probes a target by itself. Telemetry must come from an authorized collector.
    """

    name = "bte"

    async def collect(self, subject: str, context: dict[str, Any] | None = None) -> list[Evidence]:
        context = context or {}
        signals = context.get("behavioral_signals", {})
        if not signals:
            return []
        normalized = {str(k): str(v) for k, v in sorted(signals.items())}
        fingerprint = hashlib.sha256(repr(normalized).encode()).hexdigest()
        anomaly = float(context.get("anomaly_score", 0.0))
        anomaly = max(0.0, min(1.0, anomaly))
        return [Evidence(
            evidence_id=evidence_id(self.name, subject, "behavioral_fingerprint", fingerprint),
            source=self.name, kind="behavioral_fingerprint", subject=subject,
            confidence=round(1.0 - anomaly * 0.5, 3), observed_at=datetime.now(timezone.utc).isoformat(),
            attributes={"fingerprint": fingerprint, "anomaly_score": anomaly, "signals": normalized},
        )]


class ADIProvider(SafeProvider):
    """Dark-intelligence boundary.

    Only consumes organization-approved, lawfully obtained CTI feeds. No anonymous
    collection, credential harvesting, or direct dark-web crawling is performed here.
    """

    name = "adi"

    async def collect(self, subject: str, context: dict[str, Any] | None = None) -> list[Evidence]:
        context = context or {}
        feeds = context.get("approved_cti", [])
        if not isinstance(feeds, list):
            return []
        result: list[Evidence] = []
        for item in feeds:
            if not isinstance(item, dict) or item.get("subject") != subject:
                continue
            result.append(Evidence(
                evidence_id=evidence_id(self.name, subject, "cti", item.get("id", item)),
                source=self.name, kind="cti", subject=subject,
                confidence=max(0.0, min(1.0, float(item.get("confidence", 0.5)))),
                observed_at=str(item.get("observed_at") or datetime.now(timezone.utc).isoformat()),
                attributes={k: v for k, v in item.items() if k not in {"secret", "credential", "token"}},
            ))
        return result


class CorrelationEngine:
    """Correlates heterogeneous evidence without allowing one weak source to dominate."""

    def correlate(self, subject: str, evidence: list[Evidence]) -> dict[str, Any]:
        relevant = [e for e in evidence if e.subject == subject]
        by_kind: dict[str, list[Evidence]] = {}
        for item in relevant:
            by_kind.setdefault(item.kind, []).append(item)
        source_count = len({e.source for e in relevant})
        if not relevant:
            confidence = 0.0
        else:
            weighted = sum(e.confidence for e in relevant) / len(relevant)
            corroboration = min(1.0, source_count / 4.0)
            confidence = round(0.7 * weighted + 0.3 * corroboration, 3)
        story = sorted({e.attributes.get("attack_technique") for e in relevant if e.attributes.get("attack_technique")})
        return {
            "subject": subject,
            "confidence": confidence,
            "source_count": source_count,
            "evidence_count": len(relevant),
            "evidence_by_kind": {k: len(v) for k, v in by_kind.items()},
            "attack_story": story,
            "lineage": [e.__dict__ for e in relevant],
        }


class ScannerAdapter:
    """Safe result adapter for Nuclei/Trivy/Semgrep/Gitleaks/OpenVAS exports.

    Execution is deliberately external and policy-controlled; this layer only normalizes output.
    """

    SUPPORTED = {"nuclei", "trivy", "semgrep", "gitleaks", "openvas"}

    def normalize(self, tool: str, findings: list[dict[str, Any]]) -> list[Evidence]:
        tool = tool.lower().strip()
        if tool not in self.SUPPORTED:
            raise ValueError(f"unsupported scanner adapter: {tool}")
        output = []
        for finding in findings:
            subject = str(finding.get("subject") or finding.get("target") or "unknown")
            output.append(Evidence(
                evidence_id=evidence_id(tool, subject, "scanner_finding", finding.get("id", finding)),
                source=tool, kind="scanner_finding", subject=subject,
                confidence=max(0.0, min(1.0, float(finding.get("confidence", 0.8)))),
                observed_at=str(finding.get("observed_at") or datetime.now(timezone.utc).isoformat()),
                attributes={k: v for k, v in finding.items() if k not in {"secret", "token", "password"}},
            ))
        return output


def predictive_signal(history: list[float]) -> dict[str, float]:
    """Transparent trend signal; it supplements, never replaces, deterministic risk scoring."""
    values = [max(0.0, min(100.0, float(x))) for x in history]
    if len(values) < 2:
        return {"trend": 0.0, "forecast": values[-1] if values else 0.0}
    slope = (values[-1] - values[0]) / max(1, len(values) - 1)
    forecast = max(0.0, min(100.0, values[-1] + slope))
    return {"trend": round(slope, 3), "forecast": round(forecast, 2)}
