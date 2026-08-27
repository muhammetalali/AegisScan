from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..services.engine_adapters import execute_engine
from .validations import ALL_ENGINES, ENGINE_PHASE, GROUPS, _engine_state, _make_live_event, _store, _tasks

router = APIRouter()


class ValidationCreate(BaseModel):
    target_type: str = Field(description="url | ip | code | api")
    target_value: str
    profile: str = "full"
    engines: list[str] = Field(default_factory=list)
    scope: str | None = None
    authorized: bool
    include_subdomains: bool = False
    duration_minutes: int = 60
    rate_limit: int = 5
    extra: dict = Field(default_factory=dict)


class ValidationOut(BaseModel):
    id: str
    target_type: str
    target_value: str
    profile: str
    engines: list[str]
    scope: str | None
    status: str
    progress: int
    current_phase: str
    created_at: str
    audit_note: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _run_real_validation(vid: str) -> None:
    try:
        from ..main import websocket_manager
    except Exception:
        websocket_manager = None

    async def broadcast(message: dict) -> None:
        if websocket_manager:
            try:
                await websocket_manager.broadcast(f"validation_{vid}", message)
                await websocket_manager.broadcast(f"scan_{vid}", message)
            except Exception:
                pass

    item = _store.get(vid)
    if not item:
        return

    item["status"] = "running"
    item["current_phase"] = "initializing"
    item["progress"] = 1
    item["live_events"].append(_make_live_event("validation.started", f"Validation {vid} started", {"target": item["target_value"]}))
    await broadcast({"type": "validation.started", "validation_id": vid, "progress": 1, "current_phase": "initializing"})

    selected = [engine for engine in ALL_ENGINES if engine in item["engines"]]
    if not selected:
        selected = ["recon"]
        item["engines"] = selected

    total = len(selected)
    for index, engine in enumerate(selected):
        if item.get("status") == "cancelled":
            return

        phase = ENGINE_PHASE.get(engine, "analysis")
        item["current_phase"] = phase
        item["engines_state"][engine]["status"] = "running"
        item["live_events"].append(_make_live_event("engine.started", f"Engine {engine} started", {"engine": engine}))
        await broadcast({"type": "engine.started", "engine": engine, "phase": phase})

        result = await execute_engine(engine, item["target_type"], item["target_value"])
        item["results"]["findings"].extend(result.findings)
        item["results"]["evidence"].extend(result.evidence)
        item["results"]["metrics"].append(result.metrics)
        item["engines_state"][engine]["findings"] = len(result.findings)
        item["engines_state"][engine]["error"] = result.error
        item["engines_state"][engine]["status"] = result.status
        item["engines_state"][engine]["progress"] = 100 if result.status in {"completed", "unsupported", "unavailable", "failed"} else 0

        if result.status == "failed":
            item["engines_state"][engine]["status"] = "failed"
            item["error"] = result.error
            item["status"] = "failed"
            item["live_events"].append(_make_live_event("engine.failed", result.error or "Execution failed", {"engine": engine}))
            await broadcast({"type": "engine.failed", "engine": engine, "error": result.error})
            return
        if result.status in {"unsupported", "unavailable"}:
            item["live_events"].append(_make_live_event(f"engine.{result.status}", result.error or "Engine unavailable", {"engine": engine}))
            await broadcast({"type": f"engine.{result.status}", "engine": engine, "message": result.error})
        else:
            item["live_events"].append(_make_live_event("evidence.collected", f"{engine} produced live evidence", {"engine": engine, "findings": len(result.findings), "evidence": len(result.evidence)}))
            await broadcast({"type": "evidence.collected", "engine": engine, "findings": len(result.findings), "evidence": len(result.evidence)})

        item["progress"] = int(((index + 1) / total) * 100)
        item["live_events"].append(_make_live_event("engine.completed", f"Engine {engine} completed", {"engine": engine}))
        await broadcast({"type": "engine.completed", "engine": engine, "overall": item["progress"]})

    item["current_phase"] = "completed"
    item["status"] = "completed"
    item["progress"] = 100
    item["completed_at"] = _now()
    item["live_events"].append(_make_live_event("validation.completed", "Validation completed from real execution adapters", {"findings": len(item["results"]["findings"]), "evidence": len(item["results"]["evidence"])}))
    await broadcast({"type": "validation.completed", "validation_id": vid, "progress": 100, "findings": len(item["results"]["findings"])})


@router.post("/validations", response_model=ValidationOut, status_code=201)
async def create_real_validation(body: ValidationCreate):
    if body.target_type not in {"url", "ip", "code", "api"}:
        raise HTTPException(status_code=400, detail="Unsupported target_type")
    if not body.authorized:
        raise HTTPException(status_code=400, detail="authorized must be true - scope authorization required")
    if not body.target_value.strip():
        raise HTTPException(status_code=400, detail="target_value is required")

    vid = f"val-{uuid.uuid4().hex[:8]}"
    engines = [e for e in body.engines if e in ALL_ENGINES]
    if not engines:
        engines = ["recon"]

    item = {
        "id": vid,
        "target_type": body.target_type,
        "target_value": body.target_value.strip(),
        "profile": body.profile,
        "engines": engines,
        "scope": body.scope or body.target_value.strip(),
        "status": "queued",
        "progress": 0,
        "current_phase": "queued",
        "created_at": _now(),
        "completed_at": None,
        "audit_note": f"REAL_EXECUTION scope={body.scope or body.target_value.strip()} authorized={body.authorized}",
        "extra": body.extra,
        "include_subdomains": body.include_subdomains,
        "rate_limit": body.rate_limit,
        "duration_minutes": body.duration_minutes,
        "engines_state": {e: _engine_state("queued" if e in engines else "skipped") for e in ALL_ENGINES},
        "live_events": [_make_live_event("validation.queued", f"Validation {vid} queued for real execution", {"scope": body.scope or body.target_value.strip()})],
        "groups": GROUPS,
        "results": {"findings": [], "evidence": [], "metrics": []},
        "error": None,
    }
    _store[vid] = item
    _tasks[vid] = asyncio.create_task(_run_real_validation(vid))

    return ValidationOut(**{key: item[key] for key in ValidationOut.model_fields})


@router.get("/validations/{vid}/results")
async def validation_results(vid: str):
    item = _store.get(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return {
        "id": vid,
        "status": item["status"],
        "findings": item.get("results", {}).get("findings", []),
        "evidence": item.get("results", {}).get("evidence", []),
        "metrics": item.get("results", {}).get("metrics", []),
        "error": item.get("error"),
    }
