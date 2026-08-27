from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Query
from pydantic import BaseModel

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


def _store():
    """Use the existing validation state as the single dashboard source."""
    from .validations import _store as validation_store
    return validation_store


def _findings(validation: dict) -> list[dict]:
    results = validation.get("results") or {}
    findings = results.get("findings") if isinstance(results, dict) else None
    return findings if isinstance(findings, list) else []


def _risk_counts(validations: list[dict]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for validation in validations:
        for finding in _findings(validation):
            severity = str(finding.get("severity", "informational")).lower()
            if severity in {"critical", "high", "medium", "low", "informational"}:
                counts[severity] += 1
    return counts


def _score(validation: dict) -> int:
    results = validation.get("results") or {}
    if isinstance(results, dict) and isinstance(results.get("security_score"), (int, float)):
        return max(0, min(100, int(results["security_score"])))
    findings = _findings(validation)
    weighted = sum({"critical": 25, "high": 15, "medium": 8, "low": 3, "informational": 0}.get(str(f.get("severity", "informational")).lower(), 0) for f in findings)
    return max(0, min(100, 100 - weighted))


def _risk_level(validation: dict) -> str:
    counts = _risk_counts([validation])
    if counts["critical"]:
        return "critical"
    if counts["high"]:
        return "high"
    if counts["medium"]:
        return "medium"
    if counts["low"]:
        return "low"
    return "informational"


def _project_name(validation: dict) -> str:
    target = str(validation.get("target_value") or validation.get("scope") or "Unknown target")
    return target.replace("https://", "").replace("http://", "").split("/")[0] or "Unknown target"


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def dashboard_summary():
    """Dashboard summary derived from the active validation store."""
    validations = list(_store().values())
    counts = _risk_counts(validations)
    completed = [v for v in validations if v.get("status") == "completed"]
    scores = [_score(v) for v in completed or validations]
    security_score = round(sum(scores) / len(scores)) if scores else 0
    assets = set()
    for validation in validations:
        for asset in (validation.get("results") or {}).get("assets", []) if isinstance(validation.get("results"), dict) else []:
            assets.add(str(asset.get("id") or asset.get("name")))
        if not assets and validation.get("target_value"):
            assets.add(str(validation.get("target_value")))
    compliance_score = max(0, min(100, security_score))
    return DashboardSummary(
        total_projects=len({_project_name(v) for v in validations}),
        total_assets=len(assets),
        total_validations=len(validations),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        security_score=security_score,
        compliance_score=compliance_score,
    )


@router.get("/dashboard/risk-distribution", response_model=RiskDistribution)
async def dashboard_risk_distribution():
    counts = _risk_counts(list(_store().values()))
    return RiskDistribution(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        informational=counts["informational"],
    )


@router.get("/dashboard/recent-validations", response_model=List[RecentValidation])
async def dashboard_recent_validations(limit: int = Query(10, le=50)):
    validations = sorted(_store().values(), key=lambda item: str(item.get("created_at", "")), reverse=True)[:limit]
    return [
        RecentValidation(
            id=str(v["id"]),
            project_name=_project_name(v),
            status=str(v.get("status", "unknown")),
            risk_level=_risk_level(v),
            progress=int(v.get("progress", 0)),
            created_at=str(v.get("created_at", "")),
            security_score=_score(v),
        )
        for v in validations
    ]


@router.get("/dashboard/trends", response_model=List[TrendPoint])
async def dashboard_trends(days: int = Query(30, ge=7, le=90)):
    """Return measured validation checkpoints; no synthetic historical points are created."""
    cutoff = datetime.now() - timedelta(days=days)
    points: list[TrendPoint] = []
    validations = sorted(_store().values(), key=lambda item: str(item.get("created_at", "")))
    for validation in validations:
        raw_date = str(validation.get("completed_at") or validation.get("created_at") or "")
        try:
            dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
            if dt.replace(tzinfo=None) < cutoff:
                continue
            date = dt.date().isoformat()
        except ValueError:
            continue
        points.append(TrendPoint(date=date, score=_score(validation), validations=1))

    grouped: dict[str, list[int]] = {}
    for point in points:
        grouped.setdefault(point.date, []).append(point.score)
    return [
        TrendPoint(date=date, score=round(sum(scores) / len(scores)), validations=len(scores))
        for date, scores in sorted(grouped.items())
    ]