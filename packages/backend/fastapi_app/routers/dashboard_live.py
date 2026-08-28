from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter

from ..services.posture_engine import PostureEngine
from ..services.posture_state import posture_state

router = APIRouter()
_engine = PostureEngine()


def _store() -> dict[str, dict[str, Any]]:
    from .validations import _store as validation_store
    return validation_store


def _findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        results = item.get("results") if isinstance(item.get("results"), dict) else {}
        rows = results.get("findings") if isinstance(results, dict) else []
        if isinstance(rows, list):
            output.extend(row for row in rows if isinstance(row, dict))
    return output


def _assessment(scope: str = "global") -> dict[str, Any]:
    validations = list(_store().values())
    asset_ids: set[str] = set()
    for validation in validations:
        results = validation.get("results") if isinstance(validation.get("results"), dict) else {}
        rows = results.get("assets", []) if isinstance(results, dict) else []
        for asset in rows if isinstance(rows, list) else []:
            if isinstance(asset, dict) and (asset.get("id") or asset.get("name")):
                asset_ids.add(str(asset.get("id") or asset.get("name")))
        if validation.get("target_value"):
            asset_ids.add(str(validation["target_value"]))
    history = []
    for validation in sorted(validations, key=lambda x: str(x.get("created_at", ""))):
        findings = validation.get("results", {}).get("findings", []) if isinstance(validation.get("results"), dict) else []
        weighted = sum({"critical": 25, "high": 15, "medium": 8, "low": 3}.get(str(row.get("severity", "")).lower(), 0) for row in findings if isinstance(row, dict))
        history.append(max(0.0, 100.0 - weighted))
    assessment = _engine.assess(validations=validations, assets_total=len(asset_ids), assets_covered=len(asset_ids), trend_scores=history[-30:])
    payload = {"score": assessment.score, "rating": assessment.rating, "metrics": list(assessment.metrics), "recommendations": list(assessment.recommendations), "trend": assessment.trend, "evaluated_at": assessment.evaluated_at}
    posture_state.record(scope, payload)
    return payload


@router.get("/dashboard/live")
async def dashboard_live():
    validations = list(_store().values())
    findings = _findings(validations)
    counts = Counter(str(row.get("severity", "informational")).lower() for row in findings)
    posture = _assessment()
    return {
        "posture": posture,
        "summary": {"projects": len({str(v.get("target_value") or v.get("scope") or "unknown") for v in validations}), "assets": len({str(v.get("target_value")) for v in validations if v.get("target_value")}), "validations": len(validations)},
        "risk_distribution": {"critical": counts["critical"], "high": counts["high"], "medium": counts["medium"], "low": counts["low"], "informational": counts["informational"]},
        "recent_validations": sorted(validations, key=lambda x: str(x.get("created_at", "")), reverse=True)[:10],
        "posture_history": posture_state.history("global", 30),
    }
