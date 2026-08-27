"""محاكاة خصم دفاعية ومعزولة دون تنفيذ استغلال أو أساليب تخفٍ.

تختبر هذه الطبقة تغطية الضوابط عبر نماذج مجردة فقط. لا تحتوي على payloads
أو أوامر أو اتصالات شبكية، ولا تولد كود استغلال أو تعليمات لتجاوز الكشف.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DefensiveTechnique:
    """حالة هجومية مجردة مرتبطة بضوابط دفاعية مطلوبة."""

    technique_id: str
    name: str
    category: str
    required_controls: tuple[str, ...]
    severity: str = "medium"


@dataclass(frozen=True)
class SimulationObservation:
    """نتيجة اختبار تغطية لحالة مجردة."""

    technique_id: str
    coverage_score: float
    detected: bool
    missing_controls: tuple[str, ...] = ()


@dataclass
class DefensiveSimulationResult:
    """ملخص قابل للتدقيق لمحاكاة دفاعية غير تنفيذية."""

    observations: list[SimulationObservation] = field(default_factory=list)
    coverage_percent: float = 0.0
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


DEFAULT_TECHNIQUES: tuple[DefensiveTechnique, ...] = (
    DefensiveTechnique(
        "web-input-abuse",
        "Web input abuse",
        "application",
        ("waf", "secure-input-validation"),
        "high",
    ),
    DefensiveTechnique(
        "credential-abuse",
        "Credential abuse",
        "identity",
        ("mfa", "identity-monitoring", "rate-limiting"),
        "high",
    ),
    DefensiveTechnique(
        "privilege-boundary",
        "Privilege boundary violation",
        "authorization",
        ("least-privilege", "edr", "identity-monitoring"),
        "critical",
    ),
    DefensiveTechnique(
        "lateral-movement",
        "Lateral movement",
        "network",
        ("network-segmentation", "ids_ips", "edr"),
        "high",
    ),
    DefensiveTechnique(
        "data-egress",
        "Sensitive data egress",
        "data",
        ("dlp", "egress-firewall", "siem"),
        "critical",
    ),
    DefensiveTechnique(
        "build-integrity",
        "Build and dependency integrity",
        "supply-chain",
        ("signed-builds", "dependency-locking", "artifact-scanning"),
        "critical",
    ),
)


class DefensiveAdversarySimulator:
    """محلل تغطية دفاعية؛ لا ينفذ أي نشاط على أهداف حقيقية."""

    def __init__(
        self,
        techniques: Iterable[DefensiveTechnique] = DEFAULT_TECHNIQUES,
    ) -> None:
        self._techniques = {item.technique_id: item for item in techniques}

    def simulate(
        self,
        technique_ids: Iterable[str],
        controls: Mapping[str, bool] | Iterable[str],
    ) -> DefensiveSimulationResult:
        """حساب التغطية النظرية من قائمة الضوابط المفعلة."""
        active_controls = (
            {name for name, enabled in controls.items() if enabled}
            if isinstance(controls, Mapping)
            else set(controls)
        )
        observations: list[SimulationObservation] = []
        for technique_id in technique_ids:
            technique = self._techniques.get(technique_id)
            if technique is None:
                raise ValueError(f"Unknown defensive technique: {technique_id}")
            missing = tuple(
                control
                for control in technique.required_controls
                if control not in active_controls
            )
            score = (
                len(technique.required_controls) - len(missing)
            ) / max(len(technique.required_controls), 1)
            observations.append(
                SimulationObservation(
                    technique_id=technique_id,
                    coverage_score=round(score, 3),
                    detected=not missing,
                    missing_controls=missing,
                )
            )

        coverage = (
            sum(item.coverage_score for item in observations)
            / max(len(observations), 1)
            * 100
        )
        gaps = [item.technique_id for item in observations if not item.detected]
        recommendations = [
            f"Enable control '{control}' for technique '{item.technique_id}'"
            for item in observations
            for control in item.missing_controls
        ]
        return DefensiveSimulationResult(
            observations=observations,
            coverage_percent=round(coverage, 1),
            gaps=gaps,
            recommendations=recommendations,
        )
