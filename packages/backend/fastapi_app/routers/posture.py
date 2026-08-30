from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from asgiref.sync import sync_to_async
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .dashboard import current_user_id

router = APIRouter()
OPEN_STATUSES = ("open", "confirmed", "in_progress")


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


def _parse_datetime(value: str) -> datetime:
    parsed = parse_datetime(value)
    if parsed is None:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {value}")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed)
    return parsed


@sync_to_async
def _snapshot(user_id: str, project_id: str, days: int = 30, limit: int = 90) -> dict:
    from assets.models import Asset
    from projects.models import Project
    from scans.models import Scan
    from vulnerabilities.models import Vulnerability

    project = Project.objects.filter(
        Q(pk=project_id) & (Q(owner_id=user_id) | Q(memberships__user_id=user_id))
    ).distinct().first()
    if not project:
        raise LookupError

    scans = Scan.objects.filter(project=project)
    completed = scans.filter(status=Scan.Status.COMPLETED).order_by("created_at")
    latest = completed.order_by("-created_at").first()
    findings = Vulnerability.objects.filter(project=project, status__in=OPEN_STATUSES)
    counts = findings.aggregate(
        critical=Count("id", filter=Q(severity=Vulnerability.Severity.CRITICAL)),
        high=Count("id", filter=Q(severity=Vulnerability.Severity.HIGH)),
        medium=Count("id", filter=Q(severity=Vulnerability.Severity.MEDIUM)),
        low=Count("id", filter=Q(severity=Vulnerability.Severity.LOW)),
    )
    total_findings = sum(int(v or 0) for v in counts.values())
    confirmed = findings.filter(confidence=Vulnerability.Confidence.CONFIRMED).count()
    assets_total = Asset.objects.filter(project=project).count()
    start = timezone.now() - timezone.timedelta(days=min(max(int(days), 7), 90) - 1)
    rows = list(
        completed.filter(created_at__gte=start)
        .values("created_at", "security_score")
        .order_by("created_at")[:limit]
    )
    history = [
        {"timestamp": row["created_at"].isoformat(), "overall_score": round(float(row["security_score"] or 0), 2)}
        for row in rows
    ]
    score = round(float(latest.security_score or 0), 2) if latest else 0.0
    recommendations: list[str] = []
    if counts["critical"]:
        recommendations.append(f"Remediate {counts['critical']} open critical findings.")
    if counts["high"]:
        recommendations.append(f"Remediate {counts['high']} open high findings.")
    if confirmed:
        recommendations.append(f"Review {confirmed} confirmed findings and track their remediation evidence.")
    if not recommendations:
        recommendations.append("No open critical or high findings are currently recorded for this project.")
    return {
        "score": score,
        "rating": _rating(score, bool(history)),
        "latest_at": latest.created_at.isoformat() if latest else timezone.now().isoformat(),
        "assets_total": assets_total,
        "open_findings": total_findings,
        "counts": {key: int(value or 0) for key, value in counts.items()},
        "confirmed_findings": confirmed,
        "history": history,
        "recommendations": recommendations,
    }


def _rating(score: float, has_scans: bool) -> str:
    if not has_scans:
        return "not_assessed"
    if score >= 90:
        return "excellent"
    if score >= 80:
        return "good"
    if score >= 70:
        return "fair"
    if score >= 60:
        return "poor"
    return "critical"


def _metrics(snapshot: dict) -> list[dict]:
    return [
        {"name": "Security Score", "value": snapshot["score"], "max_value": 100, "category": "security", "trend": "measured", "percentage": snapshot["score"]},
        {"name": "Assets", "value": float(snapshot["assets_total"]), "max_value": float(snapshot["assets_total"] or 0), "category": "coverage", "trend": "measured", "percentage": 100.0 if snapshot["assets_total"] else 0.0},
        {"name": "Open Findings", "value": float(snapshot["open_findings"]), "max_value": float(max(snapshot["open_findings"], 1)), "category": "risk", "trend": "measured", "percentage": 100.0},
    ]


async def _get_snapshot(user_id: str, project_id: str, days: int = 30, limit: int = 90) -> dict:
    try:
        return await _snapshot(user_id, project_id, days, limit)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/projects/{project_id}/posture", response_model=PostureResponse)
async def get_posture(project_id: str, user_id: str = Depends(current_user_id)):
    snapshot = await _get_snapshot(user_id, project_id)
    return PostureResponse(id=f"posture-{project_id}", project_id=project_id, overall_score=snapshot["score"], rating=snapshot["rating"], metrics=_metrics(snapshot), recommendations=snapshot["recommendations"], created_at=snapshot["latest_at"])


@router.get("/projects/{project_id}/metrics", response_model=List[MetricResponse])
async def get_metrics(project_id: str, user_id: str = Depends(current_user_id)):
    return [MetricResponse(**item) for item in _metrics(await _get_snapshot(user_id, project_id))]


@router.get("/projects/{project_id}/trend", response_model=TrendResponse)
async def get_trend(project_id: str, metric_name: Optional[str] = None, periods: int = Query(10, ge=2, le=90), user_id: str = Depends(current_user_id)):
    snapshot = await _get_snapshot(user_id, project_id, limit=90)
    samples = snapshot["history"][-periods:]
    if len(samples) < 2:
        direction, change_rate = "stable", 0.0
    else:
        first, last = float(samples[0]["overall_score"]), float(samples[-1]["overall_score"])
        delta = last - first
        direction = "up" if delta > 0 else "down" if delta < 0 else "stable"
        change_rate = round(delta / max(abs(first), 1) * 100, 2)
    return TrendResponse(metric_name=metric_name or "overall", snapshots=samples, direction=direction, change_rate=change_rate)


@router.post("/projects/{project_id}/evaluate")
async def evaluate_posture(project_id: str, user_id: str = Depends(current_user_id)):
    snapshot = await _get_snapshot(user_id, project_id)
    return {"message": "Posture evaluation completed from persisted scan and finding data", "project_id": project_id, "score": snapshot["score"], "rating": snapshot["rating"], "evaluated_at": timezone.now().isoformat()}


@router.get("/projects/{project_id}/compare")
async def compare_periods(project_id: str, period_a_start: str, period_a_end: str, period_b_start: str, period_b_end: str, user_id: str = Depends(current_user_id)):
    a_start, a_end = _parse_datetime(period_a_start), _parse_datetime(period_a_end)
    b_start, b_end = _parse_datetime(period_b_start), _parse_datetime(period_b_end)

    @sync_to_async
    def _compare() -> dict:
        from projects.models import Project
        from scans.models import Scan
        project = Project.objects.filter(Q(pk=project_id) & (Q(owner_id=user_id) | Q(memberships__user_id=user_id))).distinct().first()
        if not project:
            raise LookupError

        def avg(start: datetime, end: datetime):
            values = list(Scan.objects.filter(project=project, status=Scan.Status.COMPLETED, created_at__gte=start, created_at__lte=end).values_list("security_score", flat=True))
            return round(sum(float(v or 0) for v in values) / len(values), 2) if values else None

        score_a, score_b = avg(a_start, a_end), avg(b_start, b_end)
        return {"period_a_avg": score_a, "period_b_avg": score_b, "change": round(score_b - score_a, 2) if score_a is not None and score_b is not None else None, "improvement": score_b > score_a if score_a is not None and score_b is not None else None, "period_a": {"start": a_start.isoformat(), "end": a_end.isoformat()}, "period_b": {"start": b_start.isoformat(), "end": b_end.isoformat()}}

    try:
        return await _compare()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Project not found") from exc


@router.get("/projects/{project_id}/history")
async def get_history(project_id: str, limit: int = Query(30, ge=1, le=90), user_id: str = Depends(current_user_id)):
    snapshot = await _get_snapshot(user_id, project_id, limit=90)
    return snapshot["history"][-limit:]
