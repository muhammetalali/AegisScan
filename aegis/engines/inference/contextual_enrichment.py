"""ترتيب النتائج حسب خطورة الأصل والسياق التشغيلي."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from aegis.models.finding import Finding


class EnrichedFinding(BaseModel):
    finding_id: str
    asset_id: str | None = None
    asset_criticality: float = Field(ge=0.0, le=1.0)
    priority_score: float = Field(ge=0.0, le=100.0)
    priority: str
    rationale: str


class ContextualEnricher:
    """يحوّل درجة الثغرة إلى أولوية قابلة للتنفيذ دون تغيير الدليل الأصلي."""

    def enrich(self, finding: Finding, asset: dict[str, Any] | None = None) -> EnrichedFinding:
        asset = asset or {}
        criticality = float(asset.get('criticality', 0.5))
        criticality = max(0.0, min(1.0, criticality))
        score = round(finding.confidence_score * criticality * 100, 2)
        priority = 'urgent' if score >= 75 else 'high' if score >= 50 else 'normal'
        return EnrichedFinding(
            finding_id=finding.id,
            asset_id=asset.get('id') or asset.get('asset_id'),
            asset_criticality=criticality,
            priority_score=score,
            priority=priority,
            rationale=f'الثقة {finding.confidence_score:.0%} × أهمية الأصل {criticality:.0%}',
        )
