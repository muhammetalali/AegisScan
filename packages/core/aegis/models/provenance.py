"""نماذج إثبات المصدر وسجل قرار الثقة."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DecisionStep(BaseModel):
    """خطوة قابلة للتدقيق في حساب نتيجة Finding."""

    stage: str = Field(..., min_length=1)
    operation: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    source_ids: list[str] = Field(default_factory=list)
    input_values: dict[str, Any] = Field(default_factory=dict)
    contribution: float = 0.0
    penalty: float = 0.0
    output_score: float | None = Field(default=None, ge=0.0, le=1.0)


class DecisionTrail(BaseModel):
    """سجل مرتب يشرح كيف وصلت المنظومة إلى القرار النهائي."""

    steps: list[DecisionStep] = Field(default_factory=list)
    final_score: float = Field(..., ge=0.0, le=1.0)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode='json')
