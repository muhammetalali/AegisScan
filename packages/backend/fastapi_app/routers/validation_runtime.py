from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..core.security import verify_token
from ..services.engine_adapters import execute_engine
from ..services.remediation_validation import RemediationValidationSuite
from ..services.validation_state import (
    ALL_ENGINES,
    ENGINE_PHASE,
    GROUPS,
    PHASES,
    _store,
    engine_state,
    get_task,
    get_validation,
    make_live_event,
    now_iso,
    persist_validation,
    put_task,
    put_validation,
)

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def ensure_owner(item: dict, user: dict) -> None:
    if item.get("owner_id") != str(user.get("id")) and not user.get("is_superuser"):
        raise HTTPException(status_code=404, detail="Validation not found")


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


class RemediationValidationRequest(BaseModel):
    approval_id: str = Field(min_length=1, max_length=200)
    authorized: bool
    workspace: str
    tools: list[str] = Field(default_factory=lambda: ["semgrep"])
    validation_target: str | None = None
    before_score: float | None = Field(default=None, ge=0, le=100)
    after_score: float | None = Field(default=None, ge=0, le=100)
    timeout: int = Field(default=180, ge=10, le=900)


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


def _group_state(item: dict) -> list[dict]:
    states = item.get("engines_state", {})
    result: list[dict] = []
    for group in GROUPS:
        engines = []
        for engine in group["engines"]:
            state = states.get(engine, engine_state("skipped"))
            engines.append({
                "id": engine,
                "label": engine,
                "status": state.get("status", "skipped"),
                "progress": int(state.get("progress", 0)),
                "findings": int(state.get("findings", 0)),
            })
        selected = [engine for engine in group["engines"] if engine in item.get("engines", [])]
        selected_states = [states.get(engine, {}) for engine in selected]
        if not selected:
            group_status = "skipped"
        elif all(s.get("status") in {"completed", "unsupported"} for s in selected_states):
            group_status = "completed"
        elif any(s.get("status") == "running" for s in selected_states):
            group_status = "running"
        elif any(s.get("status") == "failed" for s in selected_states):
            group_status = "failed"
        else:
            group_status = "queued"
        result.append({**group, "status": group_status, "engines": engines})
    return result


def _progress_payload(item: dict) -> dict:
    states = item.get("engines_state", {})
    return {
        "id": item["id"],
        "target_type": item["target_type"],
        "target_value": item["target_value"],
        "scope": item["scope"],
        "profile": item["profile"],
        "engines_requested": item.get("engines", []),
        "status": item["status"],
        "progress": int(item.get("progress", 0)),
        "current_phase": item.get("current_phase", "queued"),
        "created_at": item["created_at"],
        "completed_at": item.get("completed_at"),
        "groups": _group_state(item),
        "engines": [
            {
                "id": engine,
                "phase": ENGINE_PHASE.get(engine, "analysis"),
                "status": states.get(engine, {}).get("status", "skipped"),
                "progress": int(states.get(engine, {}).get("progress", 0)),
                "findings": int(states.get(engine, {}).get("findings", 0)),
            }
            for engine in ALL_ENGINES
        ],
        "phases": PHASES,
        "live_events": item.get("live_events", [])[-200:],
        "error": item.get("error"),
    }


async def _broadcast(vid: str, message: dict) -> None:
    try:
        from ..main import websocket_manager
        await websocket_manager.broadcast(f"validation_{vid}", message)
        await websocket_manager.broadcast(f"scan_{vid}", message)
    except Exception:
        pass


async def _run_real_validation(vid: str) -> None:
    item = _store.get(vid) or get_validation(vid)
    if not item:
        return
    try:
        item["status"], item["current_phase"], item["progress"] = "running", "initializing", 1
        item["live_events"].append(make_live_event("validation.started", f"Validation {vid} started", {"target": item["target_value"]}))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.started", "validation_id": vid, "progress": 1, "current_phase": "initializing"})
        selected = [engine for engine in ALL_ENGINES if engine in item["engines"]]
        total = len(selected)
        if not total:
            raise RuntimeError("No valid execution engines selected")
        for index, engine in enumerate(selected):
            while item.get("status") == "paused":
                await asyncio.sleep(0.25)
                refreshed = get_validation(vid)
                if refreshed:
                    item = refreshed
            if item.get("status") == "cancelled":
                return
            phase = ENGINE_PHASE.get(engine, "analysis")
            item["current_phase"] = phase
            item["engines_state"][engine]["status"] = "running"
            item["engines_state"][engine]["progress"] = 1
            persist_validation(vid)
            await _broadcast(vid, {"type": "engine.started", "engine": engine, "phase": phase})
            result = await execute_engine(engine, item["target_type"], item["target_value"], item.get("extra") or {})
            refreshed = get_validation(vid)
            if refreshed:
                item = refreshed
            if item.get("status") == "cancelled":
                persist_validation(vid)
                return
            item["results"]["findings"].extend(result.findings)
            item["results"]["evidence"].extend(result.evidence)
            item["results"]["metrics"].append(result.metrics)
            item["engines_state"][engine].update({"findings": len(result.findings), "error": result.error, "status": result.status, "progress": 100})
            if result.status == "failed":
                item["error"] = result.error or "Execution failed"
                item["status"] = "failed"
                persist_validation(vid)
                await _broadcast(vid, {"type": "engine.failed", "engine": engine, "error": item["error"]})
                return
            item["live_events"].append(make_live_event("evidence.collected", result.error or f"{engine} produced live evidence", {"engine": engine, "findings": len(result.findings), "evidence": len(result.evidence)}))
            item["progress"] = int(((index + 1) / total) * 100)
            item["live_events"].append(make_live_event("engine.completed", f"Engine {engine} completed", {"engine": engine, "progress": item["progress"]}))
            persist_validation(vid)
            await _broadcast(vid, {"type": "engine.completed", "engine": engine, "overall": item["progress"]})
        item["current_phase"], item["status"], item["progress"], item["completed_at"] = "completed", "completed", 100, now_iso()
        item["live_events"].append(make_live_event("validation.completed", "Validation completed from real execution adapters", {"findings": len(item["results"]["findings"]), "evidence": len(item["results"]["evidence"])}))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.completed", "validation_id": vid, "progress": 100, "findings": len(item["results"]["findings"])})
    except asyncio.CancelledError:
        item["status"], item["current_phase"], item["completed_at"] = "cancelled", "cancelled", now_iso()
        item["live_events"].append(make_live_event("validation.cancelled", "Validation cancelled"))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.cancelled", "validation_id": vid})
        raise
    except Exception as exc:
        item["status"], item["error"] = "failed", str(exc)
        item["live_events"].append(make_live_event("validation.failed", str(exc)))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.failed", "validation_id": vid, "reason": str(exc)})


@router.post("/validations", response_model=ValidationOut, status_code=201)
async def create_real_validation(body: ValidationCreate, user: dict = Depends(current_user)):
    if body.target_type not in {"url", "ip", "code", "api"}:
        raise HTTPException(status_code=400, detail="Unsupported target_type")
    if not body.authorized:
        raise HTTPException(status_code=400, detail="authorized must be true - scope authorization required")
    if not body.target_value.strip():
        raise HTTPException(status_code=400, detail="target_value is required")
    engines = [engine for engine in body.engines if engine in ALL_ENGINES]
    if not engines:
        raise HTTPException(status_code=400, detail="At least one valid execution engine is required")
    vid = f"val-{uuid.uuid4().hex[:8]}"
    scope = body.scope or body.target_value.strip()
    item = {"id": vid, "owner_id": str(user["id"]), "target_type": body.target_type, "target_value": body.target_value.strip(), "profile": body.profile, "engines": engines, "scope": scope, "status": "queued", "progress": 0, "current_phase": "queued", "created_at": now_iso(), "completed_at": None, "audit_note": f"REAL_EXECUTION scope={scope} authorized={body.authorized}", "extra": body.extra, "include_subdomains": body.include_subdomains, "rate_limit": body.rate_limit, "duration_minutes": body.duration_minutes, "engines_state": {engine: engine_state("queued" if engine in engines else "skipped") for engine in ALL_ENGINES}, "live_events": [make_live_event("validation.queued", f"Validation {vid} queued for real execution", {"scope": scope})], "groups": GROUPS, "results": {"findings": [], "evidence": [], "metrics": []}, "error": None}
    put_validation(vid, item)
    task = asyncio.create_task(_run_real_validation(vid))
    put_task(vid, task)
    task.add_done_callback(lambda _: persist_validation(vid))
    return ValidationOut(**{key: item[key] for key in ValidationOut.model_fields})


@router.post("/remediation/validate")
async def remediation_validate(body: RemediationValidationRequest, user: dict = Depends(current_user)):
    if not body.authorized:
        raise HTTPException(status_code=403, detail="authorized scope is required")
    suite = RemediationValidationSuite()
    try:
        result = await suite.validate_workspace(body.model_dump(), tools=body.tools, timeout=body.timeout)
    except (PermissionError, ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if body.before_score is not None and body.after_score is not None:
        result["risk_diff"] = suite.compare_scores(body.before_score, body.after_score)
    result["approval_id"] = body.approval_id
    result["validated_by"] = str(user.get("id"))
    result["validation_mode"] = "real-tool-execution"
    return result


@router.get("/validations/{vid}/progress")
async def validation_progress(vid: str, user: dict = Depends(current_user)):
    item = get_validation(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    return _progress_payload(item)


@router.post("/validations/{vid}/pause")
async def pause_validation(vid: str, user: dict = Depends(current_user)):
    item = get_validation(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    if item["status"] in {"queued", "running"}:
        item["status"] = "paused"
        item["live_events"].append(make_live_event("validation.paused", "Validation paused"))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.paused", "validation_id": vid})
    return _progress_payload(item)


@router.post("/validations/{vid}/resume")
async def resume_validation(vid: str, user: dict = Depends(current_user)):
    item = get_validation(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    if item["status"] == "paused":
        item["status"] = "running"
        item["live_events"].append(make_live_event("validation.resumed", "Validation resumed"))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.resumed", "validation_id": vid})
    return _progress_payload(item)


@router.post("/validations/{vid}/cancel")
async def cancel_validation(vid: str, user: dict = Depends(current_user)):
    item = get_validation(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    if item["status"] not in {"completed", "failed", "cancelled"}:
        item["status"], item["current_phase"], item["completed_at"] = "cancelled", "cancelled", now_iso()
        task = get_task(vid)
        if task and not task.done():
            task.cancel()
        item["live_events"].append(make_live_event("validation.cancelled", "Validation cancelled"))
        persist_validation(vid)
        await _broadcast(vid, {"type": "validation.cancelled", "validation_id": vid})
    return _progress_payload(item)


@router.get("/validations/{vid}/results")
async def validation_results(vid: str, user: dict = Depends(current_user)):
    item = get_validation(vid)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    ensure_owner(item, user)
    return {"id": vid, "status": item["status"], "target_type": item["target_type"], "target_value": item["target_value"], "scope": item["scope"], "profile": item["profile"], "findings": item.get("results", {}).get("findings", []), "evidence": item.get("results", {}).get("evidence", []), "metrics": item.get("results", {}).get("metrics", []), "error": item.get("error")}
