from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

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
    value: float
    max_value: float
    category: str
    trend: str
    percentage: float

class TrendResponse(BaseModel):
    metric_name: str
    snapshots: List[dict]
    direction: str
    change_rate: float

@router.get("/projects/{project_id}/posture", response_model=PostureResponse)
async def get_posture(project_id: str):
    return PostureResponse(
        id="posture-id",
        project_id=project_id,
        overall_score=75.5,
        rating="good",
        metrics=[
            {"name": "Vulnerability Health", "value": 70, "max_value": 100, "category": "vulnerabilities", "trend": "improving"},
            {"name": "Control Effectiveness", "value": 80, "max_value": 100, "category": "controls", "trend": "stable"},
            {"name": "Evidence Quality", "value": 85, "max_value": 100, "category": "evidence", "trend": "improving"},
            {"name": "Coverage", "value": 75, "max_value": 100, "category": "coverage", "trend": "declining"},
        ],
        recommendations=["Improve vulnerability remediation", "Add more security controls"],
        created_at=datetime.utcnow().isoformat(),
    )

@router.get("/projects/{project_id}/metrics", response_model=List[MetricResponse])
async def get_metrics(project_id: str):
    return [
        {"name": "Vulnerability Health", "value": 70, "max_value": 100, "category": "vulnerabilities", "trend": "improving", "percentage": 70},
        {"name": "Control Effectiveness", "value": 80, "max_value": 100, "category": "controls", "trend": "stable", "percentage": 80},
        {"name": "Evidence Quality", "value": 85, "max_value": 100, "category": "evidence", "trend": "improving", "percentage": 85},
        {"name": "Coverage", "value": 75, "max_value": 100, "category": "coverage", "trend": "declining", "percentage": 75},
    ]

@router.get("/projects/{project_id}/trend", response_model=TrendResponse)
async def get_trend(project_id: str, metric_name: Optional[str] = None, periods: int = 10):
    return TrendResponse(
        metric_name=metric_name or "overall",
        snapshots=[
            {"timestamp": (datetime.utcnow()).isoformat(), "value": 75.5},
            {"timestamp": (datetime.utcnow()).isoformat(), "value": 74.0},
        ],
        direction="improving",
        change_rate=1.5,
    )

@router.post("/projects/{project_id}/evaluate")
async def evaluate_posture(project_id: str):
    return {"message": "Posture evaluation started", "evaluation_id": "new-eval-id"}

@router.get("/projects/{project_id}/compare")
async def compare_periods(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str):
    return {
        "period_a_avg": 72.0,
        "period_b_avg": 75.5,
        "change": 3.5,
        "improvement": True,
    }

@router.get("/projects/{project_id}/history")
async def get_history(project_id: str, limit: int = 30):
    return [
        {"timestamp": datetime.utcnow().isoformat(), "overall_score": 75.5, "rating": "good"},
        {"timestamp": datetime.utcnow().isoformat(), "overall_score": 74.0, "rating": "good"},
    ]