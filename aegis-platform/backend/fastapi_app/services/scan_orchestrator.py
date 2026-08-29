from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from asgiref.sync import sync_to_async
from ..core.config import settings
from ..tasks.security_scan import run_nmap_scan
from ..services.websocket_manager import WebSocketManager


ENGINES = [
    {'name': 'nmap', 'display_name': 'Nmap Service Discovery', 'category': 'recon', 'order': 1, 'timeout': 300},
]


class ScanOrchestrator:
    def __init__(self, websocket_manager: WebSocketManager):
        self.websocket_manager = websocket_manager
        self.engine_status = {'nmap': 'active'}
        self.running = False
        self.max_concurrent = settings.MAX_CONCURRENT_SCANS

    async def start(self):
        self.running = True

    async def stop(self):
        self.running = False

    async def list_engines(self) -> List[Dict]:
        return [{**engine, 'status': self.engine_status[engine['name']]} for engine in ENGINES]

    async def enable_engine(self, engine_name: str) -> Dict:
        if engine_name not in self.engine_status:
            return {'status': 'error', 'message': 'Engine not found'}
        self.engine_status[engine_name] = 'active'
        return {'status': 'enabled', 'engine': engine_name}

    async def disable_engine(self, engine_name: str) -> Dict:
        if engine_name not in self.engine_status:
            return {'status': 'error', 'message': 'Engine not found'}
        self.engine_status[engine_name] = 'inactive'
        return {'status': 'disabled', 'engine': engine_name}

    @sync_to_async
    def _queue_scan(self, scan_id: str, user_id: str):
        from scans.models import Scan
        scan = Scan.objects.select_related('project').filter(pk=scan_id).first()
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        if not scan.project.members.filter(pk=user_id).exists() and str(scan.project.owner_id) != str(user_id):
            return {'status': 'error', 'message': 'Scan access denied'}
        if scan.status in [Scan.Status.RUNNING, Scan.Status.QUEUED]:
            return {'status': 'error', 'message': 'Scan already running'}
        scan.status = Scan.Status.QUEUED
        scan.progress = 0
        scan.current_phase = 'queued'
        scan.current_engine = 'nmap'
        scan.initiated_by_id = user_id
        scan.started_at = None
        scan.completed_at = None
        scan.error_message = ''
        scan.save(update_fields=['status', 'progress', 'current_phase', 'current_engine', 'initiated_by', 'started_at', 'completed_at', 'error_message', 'updated_at'])
        task = run_nmap_scan.delay(str(scan.id))
        scan.celery_task_id = task.id
        scan.save(update_fields=['celery_task_id', 'updated_at'])
        return {'status': 'started', 'scan_id': str(scan.id), 'task_id': task.id}

    async def start_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        if not user_id:
            return {'status': 'error', 'message': 'Invalid authenticated user'}
        return await self._queue_scan(scan_id, str(user_id))

    @sync_to_async
    def _get_progress(self, scan_id: str):
        from scans.models import Scan
        scan = Scan.objects.filter(pk=scan_id).first()
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        return {
            'scan_id': str(scan.id),
            'status': scan.status,
            'progress': round(scan.progress),
            'current_phase': scan.current_phase,
            'current_engine': scan.current_engine,
            'celery_task_id': scan.celery_task_id,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'error_message': scan.error_message,
        }

    async def get_progress(self, scan_id: str) -> Dict:
        return await self._get_progress(scan_id)

    @sync_to_async
    def _set_status(self, scan_id: str, status: str):
        from scans.models import Scan
        scan = Scan.objects.filter(pk=scan_id).first()
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        if status == Scan.Status.CANCELLED and scan.status in [Scan.Status.QUEUED, Scan.Status.RUNNING, Scan.Status.PAUSED]:
            scan.status = status
            scan.completed_at = datetime.now(timezone.utc)
            scan.save(update_fields=['status', 'completed_at', 'updated_at'])
            if scan.celery_task_id:
                from celery.result import AsyncResult
                AsyncResult(scan.celery_task_id).revoke(terminate=False)
            return {'status': 'cancelled'}
        if status == Scan.Status.PAUSED and scan.status == Scan.Status.RUNNING:
            scan.status = status
            scan.save(update_fields=['status', 'updated_at'])
            return {'status': 'paused'}
        if status == Scan.Status.RUNNING and scan.status == Scan.Status.PAUSED:
            scan.status = status
            scan.save(update_fields=['status', 'updated_at'])
            return {'status': 'resumed'}
        return {'status': 'error', 'message': 'Invalid scan state transition'}

    async def pause_scan(self, scan_id: str) -> Dict:
        return await self._set_status(scan_id, 'paused')

    async def resume_scan(self, scan_id: str) -> Dict:
        return await self._set_status(scan_id, 'running')

    async def cancel_scan(self, scan_id: str) -> Dict:
        return await self._set_status(scan_id, 'cancelled')
