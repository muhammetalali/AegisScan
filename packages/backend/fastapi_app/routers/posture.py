from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel

from ..services.posture_engine import PostureEngine

router = APIRouter()
engine = PostureEngine()

class PostureResponse(BaseModel):
    id: str
    project_id: str
    overall_score: float
    rating: str
    metrics: List[dict]
    recommendations: List[str]
    created_at: str

class MetricResponse(BaseModel):
    name: str
    value: float | None
    max_value: float
    category: str
    trend: str
    percentage: float | None

class TrendResponse(BaseModel):
    metric_name: str
    snapshots: List[dict]
    direction: str
    change_rate: float

def _store():
    from .validations import _store as validation_store
    return validation_store

def _project_validations(project_id: str) -> list[dict]:
    return [item for item in _store().values() if project_id in str(item.get("target_value") or item.get("scope") or "") or project_id == str(item.get("project_id") or "")]

def _evaluate(project_id: str):
    validations = _project_validations(project_id)
    assets = {str(v.get("target_value")) for v in validations if v.get("target_value")}
    history = []
    for validation in sorted(validations, key=lambda x: str(x.get("created_at", ""))):
        results = validation.get("results") if isinstance(validation.get("results"), dict) else {}
        findings = results.get("findings", []) if isinstance(results, dict) else []
        debt = sum({"critical": 25, "high": 15, "medium": 8, "low": 3}.get(str(f.get("severity", "")).lower(), 0) for f in findings if isinstance(f, dict))
        history.append(max(0.0, 100.0 - debt))
    return engine.assess(validations=validations, assets_total=len(assets), assets_covered=len(assets), trend_scores=history[-30:]), history

@router.get("/projects/{project_id}/posture", response_model=PostureResponse)
async def get_posture(project_id: str):
    assessment, _ = _evaluate(project_id)
    return PostureResponse(id=f"posture-{project_id}", project_id=project_id, overall_score=assessment.score, rating=assessment.rating, metrics=list(assessment.metrics), recommendations=list(assessment.recommendations), created_at=assessment.evaluated_at)

@router.get("/projects/{project_id}/metrics", response_model=List[MetricResponse])
async def get_metrics(project_id: str):
    assessment, _ = _evaluate(project_id)
    return [MetricResponse(name=str(m["name"]), value=m.get("value"), max_value=float(m.get("max_value", 100)), category=str(m.get("category", "unknown")), trend=str(m.get("trend", "stable")), percentage=m.get("percentage")) for m in assessment.metrics]

@router.get("/projects/{project_id}/trend", response_model=TrendResponse)
async def get_trend(project_id: str, metric_name: Optional[str] = None, periods: int = Query(10, ge=2, le=90)):
    assessment, history = _evaluate(project_id)
    samples = history[-periods:]
    snapshots = [{"timestamp": datetime.utcnow().isoformat(), "value": value} for value in samples]
    return TrendResponse(metric_name=metric_name or "overall", snapshots=snapshots, direction=assessment.trend["direction"], change_rate=assessment.trend["change_rate"])

@router.post("/projects/{project_id}/evaluate")
async def evaluate_posture(project_id: str):
    assessment, _ = _evaluate(project_id)
    return {"message": "Posture evaluation completed", "evaluation_id": f"eval-{project_id}-{assessment.evaluated_at.replace(':', '').replace('.', '')}", "score": assessment.score, "rating": assessment.rating, "evaluated_at": assessment.evaluated_at}

@router.get("/projects/{project_id}/compare")
async def compare_periods(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str):
    assessment, history = _evaluate(project_id)
    if len(history) < 2:
        return {"period_a_avg": assessment.score, "period_b_avg": assessment.score, "change": 0.0, "improvement": None, "samples": len(history)}
    midpoint = max(1, len(history) // 2)
    a, b = history[:midpoint], history[midpoint:]
    period_a, period_b = sum(a) / len(a), sum(b) / len(b)
    return {"period_a_avg": round(period_a, 2), "period_b_avg": round(period_b, 2), "change": round(period_b - period_a, 2), "improvement": period_b >= period_a, "period_a": {"start": period_a_start, "end": period_a_end}, "period_b": {"start": period_b_start, "end": period_b_end}}

@router.get("/projects/{project_id}/history")
async def get_history(project_id: str, limit: int = Query(30, ge=1, le=90)):
    _, history = _evaluate(project_id)
    return [{"timestamp": datetime.utcnow().isoformat(), "overall_score": round(value, 2)} for value in history[-limit:]]
