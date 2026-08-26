from fastapi import APIRouter, Depends, Query
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime, timedelta
import random

router = APIRouter()


class DashboardSummary(BaseModel):
    total_projects: int
    total_assets: int
    total_validations: int
    critical: int
    high: int
    medium: int
    low: int
    security_score: int
    compliance_score: int


class RiskDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    informational: int


class RecentValidation(BaseModel):
    id: str
    project_name: str
    status: str
    risk_level: str
    progress: int
    created_at: str
    security_score: int


class TrendPoint(BaseModel):
    date: str
    score: int
    validations: int


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def dashboard_summary():
    """Get dashboard summary statistics"""
    return DashboardSummary(
        total_projects=random.randint(5, 25),
        total_assets=random.randint(15, 80),
        total_validations=random.randint(20, 150),
        critical=random.randint(1, 10),
        high=random.randint(5, 25),
        medium=random.randint(15, 45),
        low=random.randint(20, 60),
        security_score=random.randint(60, 95),
        compliance_score=random.randint(75, 98),
    )


@router.get("/dashboard/risk-distribution", response_model=RiskDistribution)
async def dashboard_risk_distribution():
    """Get risk distribution across all validations"""
    return RiskDistribution(
        critical=random.randint(1, 10),
        high=random.randint(5, 25),
        medium=random.randint(15, 45),
        low=random.randint(20, 60),
        informational=random.randint(30, 80),
    )


@router.get("/dashboard/recent-validations", response_model=List[RecentValidation])
async def dashboard_recent_validations(
    limit: int = Query(10, le=50),
):
    """Get recent validations for dashboard sidebar"""
    statuses = ["completed", "running", "failed", "pending"]
    risk_levels = ["critical", "high", "medium", "low"]
    projects = ["Website A", "API B", "Project C", "Mobile App", "E-Commerce"]

    results = []
    for i in range(min(limit, 8)):
        results.append(
            RecentValidation(
                id=f"val-{i+1:03d}",
                project_name=projects[i % len(projects)],
                status=statuses[i % len(statuses)],
                risk_level=risk_levels[i % len(risk_levels)],
                progress=random.randint(50, 100),
                created_at=(datetime.now() - timedelta(days=i+1)).strftime("%Y-%m-%d"),
                security_score=random.randint(50, 100),
            )
        )
    return results


@router.get("/dashboard/trends", response_model=List[TrendPoint])
async def dashboard_trends(
    days: int = Query(30, ge=7, le=90),
):
    """Get security score trends over time"""
    results = []
    base_date = datetime.now() - timedelta(days=days)
    base_score = random.randint(50, 80)

    for i in range(days):
        date = (base_date + timedelta(days=i)).strftime("%Y-%m-%d")
        # Score tends to fluctuate around a mean
        score = max(20, min(100, base_score + random.randint(-10, 10)))
        validations = random.randint(1, 5)
        results.append(TrendPoint(date=date, score=score, validations=validations))

    return results