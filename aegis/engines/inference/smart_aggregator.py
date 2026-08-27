"""تجميع مرجح يقلل تضخيم الثقة من المصادر المترابطة."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel, Field

from aegis.models.evidence import Evidence
from aegis.models.provenance import DecisionStep


class AggregationResult(BaseModel):
    confidence: float = Field(ge=0.0, le=1.0)
    independent_sources: list[str] = Field(default_factory=list)
    correlated_groups: dict[str, list[str]] = Field(default_factory=dict)
    decision_trail: list[DecisionStep] = Field(default_factory=list)


class SmartAggregator:
    """يحسب متوسطًا مشبعًا لكل مجموعة مصدر مستقلة."""

    def __init__(self, source_groups: dict[str, str] | None = None) -> None:
        self.source_groups = source_groups or {}

    def aggregate(self, evidences: Iterable[Evidence]) -> AggregationResult:
        items = list(evidences)
        groups: dict[str, list[Evidence]] = defaultdict(list)
        for evidence in items:
            group = self.source_groups.get(evidence.source_tool, evidence.source_tool)
            groups[group].append(evidence)

        group_scores = {
            group: max(item.confidence_weight for item in values)
            for group, values in groups.items()
        }
        score = 1.0
        trail: list[DecisionStep] = []
        for group, value in group_scores.items():
            score *= 1 - value
            trail.append(DecisionStep(
                stage='aggregation',
                operation='independent_source_vote',
                reason=f'تم احتساب أعلى دليل واحد للمجموعة {group} لتجنب التكرار',
                source_ids=[item.id for item in groups[group]],
                input_values={'group': group, 'evidence_count': len(groups[group])},
                contribution=value,
            ))
        score = round(1 - score, 3) if group_scores else 0.0
        correlated = {
            group: [item.source_tool for item in values]
            for group, values in groups.items()
            if len(values) > 1
        }
        return AggregationResult(
            confidence=score,
            independent_sources=sorted(group_scores),
            correlated_groups=correlated,
            decision_trail=trail,
        )
