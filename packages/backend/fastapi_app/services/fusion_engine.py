from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FusionResult:
    score: float
    confidence: float
    rationale: str
    corroborated_sources: tuple[str, ...]
    conflicts: tuple[dict[str, Any], ...]
    lineage: tuple[dict[str, Any], ...]


class FusionEngine:
    """Deterministic, explainable fusion of vulnerability, dependency, external, and remediation evidence."""

    def fuse(self, observations: dict[str, dict[str, Any]]) -> FusionResult:
        available = {name: value for name, value in observations.items() if value and "_error" not in value}
        sources = tuple(sorted(available))
        scores: list[float] = []
        lineage: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []

        nvd = available.get("nvd", {})
        cvss = self._number(self._nested(nvd, "metrics", "cvssMetricV40", 0, "cvssData", "baseScore"))
        if cvss is None:
            cvss = self._number(self._nested(nvd, "metrics", "cvssMetricV31", 0, "cvssData", "baseScore"))
        if cvss is not None:
            scores.append(cvss / 10.0)
            lineage.append({"source": "nvd", "factor": "cvss", "value": cvss})

        osv = available.get("osv", {})
        osv_score = self._number(self._nested(osv, "severity", 0, "score"))
        if osv_score is not None:
            scores.append(max(0.0, min(1.0, osv_score / 10.0)))
            lineage.append({"source": "osv", "factor": "severity_score", "value": osv_score})

        dependency = available.get("dependency_risk", {})
        dependency_matches = self._number(dependency.get("vulnerability_matches")) or 0.0
        dependency_count = self._number(dependency.get("dependency_count")) or 0.0
        if dependency.get("cve_correlation") and dependency_count > 0:
            density = min(1.0, dependency_matches / dependency_count)
            dependency_signal = min(1.0, 0.45 + (0.5 * density) if dependency_matches else 0.05)
            scores.append(dependency_signal)
            lineage.append({
                "source": "dependency_risk",
                "factor": "osv_vulnerability_density",
                "value": round(density, 4),
                "vulnerability_matches": int(dependency_matches),
                "dependency_count": int(dependency_count),
                "registry": dependency.get("registry", "OSV"),
            })
            if dependency_matches:
                lineage.append({
                    "source": "dependency_risk",
                    "factor": "known_package_vulnerabilities",
                    "value": int(dependency_matches),
                })

        epss = self._number(available.get("epss", {}).get("epss"))
        if epss is not None:
            scores.append(max(0.0, min(1.0, epss)))
            lineage.append({"source": "epss", "factor": "exploit_probability", "value": epss})

        kev = bool(available.get("cisa_kev"))
        if kev:
            scores.append(1.0)
            lineage.append({"source": "cisa_kev", "factor": "known_exploited", "value": True})

        external = available.get("external_intelligence", {})
        external_items = external.get("items", []) if isinstance(external, dict) else []
        external_risk = self._external_risk(external_items)
        if external_risk is not None:
            scores.append(external_risk)
            lineage.append({"source": "external_intelligence", "factor": "cti_risk", "value": external_risk, "items": len(external_items)})

        remediation = available.get("remediation_validation", {})
        remediation_state = self._remediation_state(remediation)
        if remediation_state == "passed":
            scores.append(0.20)
            lineage.append({"source": "remediation_validation", "factor": "validated_clean", "value": True})
        elif remediation_state == "failed":
            scores.append(0.90)
            lineage.append({"source": "remediation_validation", "factor": "validation_failed", "value": True})
        elif remediation_state == "regressed":
            scores.append(1.00)
            lineage.append({"source": "remediation_validation", "factor": "risk_regression", "value": True})

        if cvss is not None and epss is not None:
            if cvss >= 7 and epss < 0.01 or cvss < 4 and epss >= 0.5:
                conflicts.append({"type": "severity_vs_exploit_probability", "cvss": cvss, "epss": epss})

        if external_risk is not None and epss is not None:
            if external_risk >= 0.75 and epss < 0.10 or external_risk < 0.25 and epss >= 0.80:
                conflicts.append({"type": "external_cti_vs_epss", "external_risk": external_risk, "epss": epss})

        evidence_signals = sum(bool(value) for value in (nvd, osv, dependency, available.get("epss"), available.get("cisa_kev"), external_items, remediation))
        confidence = {0: 0.0, 1: 0.55, 2: 0.68, 3: 0.78}.get(evidence_signals, 0.86)
        confidence -= min(0.18, 0.04 * len(conflicts))
        if dependency_matches:
            confidence += 0.04
        if remediation_state == "passed":
            confidence += 0.04
        confidence = round(max(0.0, min(1.0, confidence)), 3)

        score = round((sum(scores) / len(scores)) * 100.0, 2) if scores else 0.0
        if kev:
            score = max(score, 85.0)
        if dependency_matches:
            score = max(score, min(90.0, 55.0 + dependency_matches * 7.5))
        if remediation_state == "passed":
            score -= 12.0
        elif remediation_state == "regressed":
            score += 12.0
        score = round(max(0.0, min(100.0, score)), 2)

        if not sources:
            rationale = "No provider produced usable evidence; confidence is 0%."
        else:
            rationale = f"Evidence from {', '.join(s.upper() for s in sources)} fused into {confidence * 100:.0f}% confidence."
            if dependency_matches:
                rationale += f" OSV correlated {int(dependency_matches)} vulnerable package version(s) from the supplied dependency manifests."
            elif dependency.get("cve_correlation"):
                rationale += " Dependency manifests were correlated against OSV with no known matches returned."
            if external_items:
                rationale += f" External CTI contributed {len(external_items)} provenance-tagged item(s)."
            if remediation_state == "passed":
                rationale += " Remediation validation passed, lowering residual risk."
            elif remediation_state == "failed":
                rationale += " Remediation validation failed, so residual risk remains elevated."
            elif remediation_state == "regressed":
                rationale += " Validation detected a regression; risk was increased."
            if conflicts:
                rationale += " Conflicting signals were retained for investigation."
            if kev:
                rationale += " CISA KEV confirms known exploitation."

        return FusionResult(score=score, confidence=confidence, rationale=rationale, corroborated_sources=sources, conflicts=tuple(conflicts), lineage=tuple(lineage))

    @staticmethod
    def _external_risk(items: list[dict[str, Any]]) -> float | None:
        if not items:
            return None
        values: list[float] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            source = str(item.get("source", "")).lower()
            provenance = item.get("provenance") if isinstance(item.get("provenance"), dict) else {}
            confidence = max(0.0, min(1.0, float(item.get("confidence", 0.5))))
            signal = confidence
            if source == "greynoise":
                classification = str(provenance.get("classification", "")).lower()
                noise = bool(provenance.get("noise"))
                riot = bool(provenance.get("riot"))
                if classification == "malicious":
                    signal = max(signal, 0.90)
                elif noise and not riot:
                    signal = max(signal, 0.65)
                elif riot:
                    signal = min(signal, 0.35)
            elif source == "github_advisory":
                severity = str(provenance.get("severity", "")).lower()
                signal = {"critical": 0.95, "high": 0.80, "moderate": 0.55, "low": 0.25}.get(severity, signal)
            elif source == "shodan":
                ports = provenance.get("ports", [])
                if isinstance(ports, list):
                    signal = max(signal, min(0.95, 0.20 + 0.03 * len(ports)))
            values.append(signal)
        return round(sum(values) / len(values), 3) if values else None

    @staticmethod
    def _remediation_state(value: Any) -> str | None:
        if not isinstance(value, dict):
            return None
        if value.get("regressed") is True:
            return "regressed"
        if value.get("passed") is True:
            return "passed"
        if value.get("passed") is False and value.get("blocked") is not True:
            return "failed"
        status = str(value.get("status", "")).lower()
        return status if status in {"failed", "regressed"} else None

    @staticmethod
    def _number(value: Any) -> float | None:
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _nested(value: Any, *path: Any) -> Any:
        current = value
        try:
            for part in path:
                current = current[part]
            return current
        except (KeyError, IndexError, TypeError):
            return None
