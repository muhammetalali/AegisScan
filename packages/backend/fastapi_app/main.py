import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django  # noqa: E402

django.setup()

from contextlib import asynccontextmanager  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
import asyncio  # noqa: E402
import logging  # noqa: E402

from asgiref.sync import sync_to_async  # noqa: E402
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import Response  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # noqa: E402

from .routers import attack_surface, assurance, assurance_graph, capability_control, dashboard, dashboard_live, decision_actions, digital_twin, engine_capabilities, governance, intelligence, knowledge, orchestration, posture, policy, remediation_itsm, remediation_lifecycle, security_decision, security_sessions, system, validation_runtime  # noqa: E402
from .services.celery_monitoring import get_task_metrics  # noqa: E402
from .services.observability import metrics_payload, configure_tracing  # noqa: E402
from .services.decision_action_orchestration import initialize_action_store  # noqa: E402
from .services.remediation_lifecycle import initialize_lifecycle_store  # noqa: E402
from .services.itsm_remediation import initialize_itsm_store  # noqa: E402
from .services.itsm_configuration import startup_validation  # noqa: E402
from .services.policy_engine import initialize_policy_store  # noqa: E402
from .services.scan_orchestrator import ScanOrchestrator  # noqa: E402
from .services.validation_state import get_validation  # noqa: E402
from .services.websocket_manager import WebSocketManager  # noqa: E402
from .services.workflow_live_bridge import WorkflowLiveBridge  # noqa: E402
from .core.config import settings  # noqa: E402
from .core.security import verify_token  # noqa: E402

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
websocket_manager = WebSocketManager()
scan_orchestrator = ScanOrchestrator(websocket_manager)
workflow_bridge = WorkflowLiveBridge(lambda event: websocket_manager.broadcast("workflow", event))
_itsm_ready = True
_itsm_config_errors: dict[str, tuple[str, ...]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _itsm_ready, _itsm_config_errors
    logger.info("Starting AegisScan FastAPI server...")
    configure_tracing()
    _itsm_ready, states = startup_validation()
    _itsm_config_errors = {provider: state.errors for provider, state in states.items() if state.enabled and not state.valid}
    if not _itsm_ready:
        for provider, errors in _itsm_config_errors.items():
            logger.critical("ITSM provider configuration rejected: %s: %s", provider, "; ".join(errors))
        raise RuntimeError("Invalid ITSM configuration detected during startup. " + " | ".join(f"{provider}: {', '.join(errors)}" for provider, errors in _itsm_config_errors.items()))
    initialize_action_store()
    initialize_lifecycle_store()
    initialize_itsm_store()
    initialize_policy_store()
    await workflow_bridge.start()
    await scan_orchestrator.start()
    yield
    await workflow_bridge.stop()
    await scan_orchestrator.stop()
    logger.info("Shutting down AegisScan FastAPI server...")


app = FastAPI(title="AegisScan Platform API", description="Security Validation Platform - High Performance API Layer", version="1.0.0", lifespan=lifespan, docs_url="/docs", redoc_url="/redoc")
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
security = HTTPBearer(auto_error=False)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or inactive token")
    return user


def require_permission(user: dict, permission: str) -> dict:
    if user.get("is_superuser") or permission in user.get("permissions", []):
        return user
    raise HTTPException(status_code=403, detail="Insufficient permissions")


async def websocket_user(websocket: WebSocket) -> dict | None:
    header = websocket.headers.get("sec-websocket-protocol", "")
    protocols = [part.strip() for part in header.split(",") if part.strip()]
    token = None
    if len(protocols) >= 2 and protocols[0].lower() == "bearer":
        token = protocols[1]
    if not token and settings.WS_ALLOW_QUERY_TOKEN:
        token = websocket.query_params.get("token")
    return await verify_token(token) if token else None


@sync_to_async
def scan_accessible(user_id: str, scan_id: str, is_superuser: bool = False) -> bool:
    from django_project.scans.models import Scan
    from projects.models import ProjectMembership
    if is_superuser:
        return Scan.objects.filter(pk=scan_id).exists()
    scan = Scan.objects.filter(pk=scan_id).first()
    if not scan:
        return False
    if str(scan.initiated_by_id) == str(user_id):
        return True
    return ProjectMembership.objects.filter(project_id=scan.project_id, user_id=user_id).exists()


@app.get("/metrics")
async def prometheus_metrics():
    payload, content_type = metrics_payload()
    return Response(content=payload, media_type=content_type)


@app.websocket("/ws/workflow")
async def websocket_workflow(websocket: WebSocket):
    user = await websocket_user(websocket)
    if not user:
        await websocket.close(code=4001)
        return
    await websocket_manager.connect("workflow", websocket, subprotocol="bearer")
    try:
        await websocket.send_json({"type": "workflow.connected", "user_id": user.get("id")})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect("workflow", websocket)


@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    user = await websocket_user(websocket)
    if not user or not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        await websocket.close(code=4003)
        return
    await websocket_manager.connect(scan_id, websocket, subprotocol="bearer")
    await websocket_manager.connect(f"scan_{scan_id}", websocket, subprotocol="bearer")
    await websocket_manager.connect(f"validation_{scan_id}", websocket, subprotocol="bearer")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(scan_id, websocket)
        websocket_manager.disconnect(f"scan_{scan_id}", websocket)
        websocket_manager.disconnect(f"validation_{scan_id}", websocket)


@app.websocket("/ws/validations/{validation_id}")
async def websocket_validation_progress(websocket: WebSocket, validation_id: str):
    user = await websocket_user(websocket)
    if not user:
        await websocket.close(code=4001)
        return
    await websocket_manager.connect(validation_id, websocket, subprotocol="bearer")
    await websocket_manager.connect(f"validation_{validation_id}", websocket, subprotocol="bearer")
    await websocket_manager.connect(f"scan_{validation_id}", websocket, subprotocol="bearer")
    try:
        validation = get_validation(validation_id)
        if validation:
            await websocket.send_json({"type": "snapshot", "validation_id": validation_id, "status": validation["status"], "progress": validation["progress"], "current_phase": validation["current_phase"]})
    except Exception:
        pass
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(validation_id, websocket)
        websocket_manager.disconnect(f"scan_{validation_id}", websocket)
        websocket_manager.disconnect(f"validation_{validation_id}", websocket)


@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    user = await websocket_user(websocket)
    if not user:
        await websocket.close(code=4001)
        return
    await websocket_manager.connect(f"user_{user['id']}", websocket, subprotocol="bearer")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(f"user_{user['id']}", websocket)


@app.websocket("/ws/system/monitor")
async def websocket_system_monitor(websocket: WebSocket):
    user = await websocket_user(websocket)
    if not user or not user.get("is_staff"):
        await websocket.close(code=4003)
        return
    require_permission(user, "system.monitor")
    await websocket_manager.connect("system_monitor", websocket, subprotocol="bearer")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect("system_monitor", websocket)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/ready")
async def readiness_check():
    if not _itsm_ready:
        raise HTTPException(status_code=503, detail={"ready": False, "itsm_configuration_errors": _itsm_config_errors})
    return {"ready": True, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/metrics/celery")
async def celery_metrics(user=Depends(get_current_user)):
    require_permission(user, "system.monitor")
    try:
        return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat(), "celery": get_task_metrics()}
    except Exception as exc:
        logger.exception("Celery metrics collection failed")
        raise HTTPException(status_code=503, detail="Celery metrics unavailable") from exc


app.include_router(knowledge.router, prefix="/api/v1", tags=["Knowledge"])
app.include_router(digital_twin.router, prefix="/api/v1/digital-twin", tags=["Digital Twin"])
app.include_router(posture.router, prefix="/api/v1/posture", tags=["Security Posture"])
app.include_router(system.router, prefix="/api/v1/system", tags=["System"])
app.include_router(assurance.router, prefix="/api/v1/assurance", tags=["Assurance Correlation"])
app.include_router(assurance_graph.router, prefix="/api/v1/assurance", tags=["Assurance Graph"])
app.include_router(security_decision.router, prefix="/api/v1/assurance", tags=["Security Decision"])
app.include_router(decision_actions.router, prefix="/api/v1/assurance", tags=["Decision Actions"])
app.include_router(governance.router, prefix="/api/v1/assurance", tags=["Governance"])
app.include_router(policy.router, prefix="/api/v1/assurance", tags=["Policy-as-Code"])
app.include_router(engine_capabilities.router, prefix="/api/v1", tags=["Engine Capabilities"])
app.include_router(capability_control.router, prefix="/api/v1", tags=["Capability Control Plane"])
app.include_router(security_sessions.router, prefix="/api/v1", tags=["Security Test Sessions"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])
app.include_router(dashboard_live.router, prefix="/api/v1", tags=["Dashboard Live"])
app.include_router(validation_runtime.router, prefix="/api/v1", tags=["Validation Runtime"])
app.include_router(intelligence.router, prefix="/api/v1", tags=["Security Intelligence"])
app.include_router(attack_surface.router, prefix="/api/v1", tags=["Attack Surface"])
app.include_router(orchestration.router, prefix="/api/v1/orchestration", tags=["External Orchestration"])
app.include_router(remediation_itsm.router, prefix="/api/v1", tags=["Remediation ITSM"])
app.include_router(remediation_lifecycle.router, prefix="/api/v1", tags=["Remediation Lifecycle"])


@app.post("/api/v1/scans/{scan_id}/start")
async def start_scan(scan_id: str, user=Depends(get_current_user)):
    require_permission(user, "scan.create")
    if not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await scan_orchestrator.start_scan(scan_id, user)


@app.post("/api/v1/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, user=Depends(get_current_user)):
    require_permission(user, "scan.cancel")
    if not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await scan_orchestrator.pause_scan(scan_id)


@app.post("/api/v1/scans/{scan_id}/resume")
async def resume_scan(scan_id: str, user=Depends(get_current_user)):
    require_permission(user, "scan.create")
    if not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await scan_orchestrator.resume_scan(scan_id)


@app.post("/api/v1/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, user=Depends(get_current_user)):
    require_permission(user, "scan.cancel")
    if not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await scan_orchestrator.cancel_scan(scan_id)


@app.get("/api/v1/scans/{scan_id}/progress")
async def get_scan_progress(scan_id: str, user=Depends(get_current_user)):
    require_permission(user, "scan.read")
    if not await scan_accessible(user["id"], scan_id, bool(user.get("is_superuser"))):
        raise HTTPException(status_code=404, detail="Scan not found")
    return await scan_orchestrator.get_progress(scan_id)


@app.get("/api/v1/engines")
async def list_engines(user=Depends(get_current_user)):
    require_permission(user, "scan.read")
    return await scan_orchestrator.list_engines()


@app.post("/api/v1/engines/{engine_name}/enable")
async def enable_engine(engine_name: str, user=Depends(get_current_user)):
    require_permission(user, "system.settings")
    return await scan_orchestrator.enable_engine(engine_name)


@app.post("/api/v1/engines/{engine_name}/disable")
async def disable_engine(engine_name: str, user=Depends(get_current_user)):
    require_permission(user, "system.settings")
    return await scan_orchestrator.disable_engine(engine_name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
