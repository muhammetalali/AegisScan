from __future__ import annotations

from fastapi import APIRouter, Depends

from .dashboard import _dashboard_snapshot, current_user_id

router = APIRouter()


@router.get("/dashboard/live")
async def dashboard_live(user_id: str = Depends(current_user_id)):
    snapshot = await _dashboard_snapshot(user_id, days=30, limit=10)
    summary = snapshot["summary"]
    scores = [item["score"] for item in snapshot["trends"] if item.get("score") is not None]
    latest_score = summary.get("security_score") or 0
    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        direction = "up" if delta > 0 else "down" if delta < 0 else "stable"
        change_rate = round(delta / max(abs(scores[0]), 1) * 100, 2)
    else:
        direction, change_rate = "stable", 0.0
    return {
        "posture": {
            "score": latest_score,
            "rating": "not_assessed" if not snapshot["trends"] else ("excellent" if latest_score >= 90 else "good" if latest_score >= 80 else "fair" if latest_score >= 70 else "poor" if latest_score >= 60 else "critical"),
            "metrics": [
                {"name": "Security Score", "value": latest_score, "max_value": 100, "category": "security", "trend": "measured", "percentage": latest_score},
                {"name": "Assets", "value": summary["total_assets"], "max_value": summary["total_assets"], "category": "coverage", "trend": "measured", "percentage": 100 if summary["total_assets"] else 0},
                {"name": "Open Findings", "value": sum(summary[key] for key in ("critical", "high", "medium", "low")), "max_value": max(sum(summary[key] for key in ("critical", "high", "medium", "low")), 1), "category": "risk", "trend": "measured", "percentage": 100},
            ],
            "recommendations": ([f"Remediate {summary['critical']} open critical findings."] if summary["critical"] else []) + ([f"Remediate {summary['high']} open high findings."] if summary["high"] else []) or ["No open critical or high findings are currently recorded."],
            "trend": {"direction": direction, "change_rate": change_rate},
            "evaluated_at": snapshot["trends"][-1]["date"] if snapshot["trends"] else None,
        },
        "summary": {
            "projects": summary["total_projects"],
            "assets": summary["total_assets"],
            "validations": summary["total_validations"],
        },
        "risk_distribution": snapshot["risk_distribution"],
        "recent_validations": snapshot["recent_validations"],
        "posture_history": snapshot["trends"],
    }
