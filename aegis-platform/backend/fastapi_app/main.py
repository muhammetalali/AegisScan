from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
from asgiref.sync import sync_to_async
import logging
from datetime import datetime, timezone

from .routers import scans, vulnerabilities, reports, assets, compliance, knowledge, digital_twin, posture, system, dashboard, validations, audit, assurance, assurance_graph, security_decision, decision_actions, governance, policy
from .services.scan_orchestrator import ScanOrchestrator
from .services.websocket_manager import WebSocketManager
from .services.decision_action_orchestration import initialize_action_store
from .services.workflow_live_bridge import WorkflowLiveBridge
from .services.policy_engine import initialize_policy_store
from .core.config import settings
from .core.security import verify_token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
websocket_manager = WebSocketManager()
scan_orchestrator = ScanOrchestrator(websocket_manager)
workflow_bridge = WorkflowLiveBridge(lambda event: websocket_manager.broadcast('workflow', event))

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info('Starting AegisScan FastAPI server...')
    initialize_action_store()
    initialize_policy_store()
    await workflow_bridge.start()
    await scan_orchestrator.start()
    yield
    await workflow_bridge.stop()
    await scan_orchestrator.stop()
    logger.info('Shutting down AegisScan FastAPI server...')

app = FastAPI(title='AegisScan Platform API', description='Security Validation Platform - High Performance API Layer', version='1.0.0', lifespan=lifespan, docs_url='/docs', redoc_url='/redoc')
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
security = HTTPBearer(auto_error=False)

async def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials if credentials else request.cookies.get(settings.AUTH_ACCESS_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    user = await verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid token')
    return user

@sync_to_async
def _scan_access(scan_id: str, user_id: str) -> bool:
    from scans.models import Scan
    scan = Scan.objects.select_related('project').filter(pk=scan_id).first()
    return bool(scan and (str(scan.project.owner_id) == str(user_id) or scan.project.members.filter(pk=user_id).exists()))

@sync_to_async
def _validation_access(validation_id: str, user_id: str) -> bool:
    from evidence.models import ValidationRun
    return ValidationRun.objects.filter(pk=validation_id, user_id=user_id).exists()

async def _authenticate_socket(websocket: WebSocket):
    token = websocket.cookies.get(settings.AUTH_ACCESS_COOKIE)
    if not token:
        await websocket.close(code=4001)
        return None
    user = await verify_token(token)
    if not user:
        await websocket.close(code=4001)
        return None
    return user

@app.websocket('/ws/workflow')
async def websocket_workflow(websocket: WebSocket):
    user = await _authenticate_socket(websocket)
    if not user:
        return
    await websocket_manager.connect('workflow', websocket)
    try:
        await websocket.send_json({'type': 'workflow.connected', 'user_id': user.get('user_id')})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect('workflow', websocket)

@app.websocket('/ws/scan/{scan_id}')
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    user = await _authenticate_socket(websocket)
    if not user or not await _scan_access(scan_id, str(user.get('user_id'))):
        if user:
            await websocket.close(code=4003)
        return
    await websocket_manager.connect(scan_id, websocket)
    await websocket_manager.connect(f'scan_{scan_id}', websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(scan_id, websocket)
        websocket_manager.disconnect(f'scan_{scan_id}', websocket)

@app.websocket('/ws/validations/{validation_id}')
async def websocket_validation_progress(websocket: WebSocket, validation_id: str):
    user = await _authenticate_socket(websocket)
    if not user or not await _validation_access(validation_id, str(user.get('user_id'))):
        if user:
            await websocket.close(code=4003)
        return
    await websocket_manager.connect(validation_id, websocket)
    await websocket_manager.connect(f'validation_{validation_id}', websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(validation_id, websocket)
        websocket_manager.disconnect(f'validation_{validation_id}', websocket)

@app.websocket('/ws/notifications')
async def websocket_notifications(websocket: WebSocket):
    user = await _authenticate_socket(websocket)
    if not user:
        return
    await websocket_manager.connect(f"user_{user.get('user_id')}", websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(f"user_{user.get('user_id')}", websocket)

@app.websocket('/ws/system/monitor')
async def websocket_system_monitor(websocket: WebSocket):
    user = await _authenticate_socket(websocket)
    if not user or not user.get('is_staff'):
        if user:
            await websocket.close(code=4003)
        return
    await websocket_manager.connect('system_monitor', websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect('system_monitor', websocket)

@app.get('/health')
async def health_check():
    return {'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()}

@app.get('/ready')
async def readiness_check():
    return {'ready': True, 'timestamp': datetime.now(timezone.utc).isoformat()}

app.include_router(scans.router, prefix='/scans', tags=['Scans'])
app.include_router(vulnerabilities.router, prefix='/vulnerabilities', tags=['Vulnerabilities'])
app.include_router(reports.router, prefix='/reports', tags=['Reports'])
app.include_router(assets.router, prefix='/assets', tags=['Assets'])
app.include_router(compliance.router, prefix='/compliance', tags=['Compliance'])
app.include_router(knowledge.router, prefix='/knowledge', tags=['Knowledge'])
app.include_router(digital_twin.router, prefix='/digital-twin', tags=['Digital Twin'])
app.include_router(posture.router, prefix='/posture', tags=['Security Posture'])
app.include_router(system.router, prefix='/system', tags=['System'])
app.include_router(assurance.router, prefix='/api/v1/assurance', tags=['Assurance Correlation'])
app.include_router(assurance_graph.router, prefix='/api/v1/assurance', tags=['Assurance Graph'])
app.include_router(security_decision.router, prefix='/api/v1/assurance', tags=['Security Decision'])
app.include_router(decision_actions.router, prefix='/api/v1/assurance', tags=['Decision Actions'])
app.include_router(governance.router, prefix='/api/v1/assurance', tags=['Governance'])
app.include_router(policy.router, prefix='/api/v1/assurance', tags=['Policy-as-Code'])
app.include_router(dashboard.router, prefix='/api', tags=['Dashboard'])
app.include_router(dashboard.router, prefix='/api/v1', tags=['Dashboard'])
app.include_router(validations.router, prefix='/api', tags=['Validations'])
app.include_router(validations.router, prefix='/api/v1', tags=['Validations'])
app.include_router(audit.router, prefix='/api', tags=['Audit'])
app.include_router(audit.router, prefix='/api/v1', tags=['Audit'])

@app.post('/scans/{scan_id}/start')
async def start_scan(scan_id: str, user=Depends(get_current_user)):
    return await scan_orchestrator.start_scan(scan_id, user)

@app.post('/scans/{scan_id}/pause')
async def pause_scan(scan_id: str, user=Depends(get_current_user)):
    return await scan_orchestrator.pause_scan(scan_id, user)

@app.post('/scans/{scan_id}/resume')
async def resume_scan(scan_id: str, user=Depends(get_current_user)):
    return await scan_orchestrator.resume_scan(scan_id, user)

@app.post('/scans/{scan_id}/cancel')
async def cancel_scan(scan_id: str, user=Depends(get_current_user)):
    return await scan_orchestrator.cancel_scan(scan_id, user)

@app.get('/scans/{scan_id}/progress')
async def get_scan_progress(scan_id: str, user=Depends(get_current_user)):
    return await scan_orchestrator.get_progress(scan_id)

@app.get('/engines')
async def list_engines(user=Depends(get_current_user)):
    return await scan_orchestrator.list_engines()

@app.post('/engines/{engine_name}/enable')
async def enable_engine(engine_name: str, user=Depends(get_current_user)):
    return await scan_orchestrator.enable_engine(engine_name)

@app.post('/engines/{engine_name}/disable')
async def disable_engine(engine_name: str, user=Depends(get_current_user)):
    return await scan_orchestrator.disable_engine(engine_name)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8001)
