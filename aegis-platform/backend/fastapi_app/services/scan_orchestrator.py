from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List

from asgiref.sync import sync_to_async

from ..core.config import settings
from ..core.dependencies import project_access_q
from ..tasks.security_scan import run_nmap_scan, run_nuclei_scan
from ..tasks.advanced_scans import run_masscan_scan, run_semgrep_scan
from ..services.websocket_manager import WebSocketManager
from ..services.enterprise_gap_closure import checkpoint_scan
from ..services.authorization_guard import require_bound_scan_authorization
from ..services.scan_state_machine import prepare_restart, transition_scan
from ..services.capability_registry import CAPABILITIES

# Bind the four real, registered specialized scan engines to their existing
# Celery tasks.  The manual scan router imports this mapping rather than
# maintaining a second dispatch registry.
ENGINE_TASKS = {
    'nmap': run_nmap_scan,
    'nuclei': run_nuclei_scan,
    'masscan': run_masscan_scan,
    'semgrep': run_semgrep_scan,
}

# Fail closed if a specialized capability is added/retired without a real task,
# or if a task has no corresponding governed capability in the canonical registry.
_SPECIALIZED_CAPABILITIES = {
    item.tool: item for item in CAPABILITIES.values() if item.adapter == 'specialized'
}
if set(ENGINE_TASKS) != set(_SPECIALIZED_CAPABILITIES):
    raise RuntimeError('Primary engine tasks must match the canonical specialized capability registry')

ENGINES = [
    {
        'name': name, 'display_name': label, 'category': category,
        'order': index, 'timeout': timeout, 'execution': 'real',
        'capability_id': _SPECIALIZED_CAPABILITIES[name].id,
    }
    for index, (name, label, category, timeout) in enumerate((
        ('nmap', 'Nmap Service Discovery', 'network', 300),
        ('nuclei', 'Nuclei Web Security Scanner', 'web', 600),
        ('masscan', 'Masscan Network Discovery', 'network', 600),
        ('semgrep', 'Semgrep Source Code Analysis', 'code', 600),
    ), start=1)
]

class ScanOrchestrator:
    """Single orchestration surface for authorized security assessment jobs."""

    def __init__(self, websocket_manager: WebSocketManager):
        self.websocket_manager = websocket_manager
        self.engine_status = {name: 'active' for name in ENGINE_TASKS}
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
        if engine_name not in ENGINE_TASKS:
            return {'status': 'error', 'message': 'No real approved provider is configured for this engine'}
        self.engine_status[engine_name] = 'active'
        return {'status': 'enabled', 'engine': engine_name}

    async def disable_engine(self, engine_name: str) -> Dict:
        if engine_name not in self.engine_status:
            return {'status': 'error', 'message': 'Engine not found'}
        self.engine_status[engine_name] = 'inactive'
        return {'status': 'disabled', 'engine': engine_name}

    @sync_to_async
    def _has_scan_access(self, scan_id: str, user_id: str):
        from django_project.scans.models import Scan
        return Scan.objects.filter(pk=scan_id).filter(
            project_access_q(user_id, relation='project')
        ).exists()

    @sync_to_async
    def _queue_scan(self, scan_id: str, user_id: str):
        from django_project.scans.models import Scan
        scan = Scan.objects.select_related('project').filter(pk=scan_id).first()
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        if not Scan.objects.filter(pk=scan.pk).filter(
            project_access_q(user_id, relation='project')
        ).exists():
            return {'status': 'error', 'message': 'Scan access denied'}
        if scan.status != Scan.Status.PENDING:
            return {'status': 'error', 'message': 'Scan is not pending; use the restart endpoint for terminal scans'}
        if not scan.asset_id or not scan.authorization_decision_id:
            return {'status': 'error', 'message': 'Scan requires a persisted asset and bound authorization before dispatch'}
        if not scan.asset or not scan.asset.is_active or scan.asset.project_id != scan.project_id:
            return {'status': 'error', 'message': 'Scan asset is inactive or outside the scan project'}

        # Reuse the worker's authoritative authorization + target/egress guard.
        # A revoked or drifted grant must never be advertised as queued.
        authorized_scan, reason, _decision = require_bound_scan_authorization(str(scan.id))
        if authorized_scan is None:
            return {'status': 'error', 'message': reason}

        requested_engines = [str(engine).strip().lower() for engine in (scan.engines or []) if str(engine).strip()]
        if not requested_engines:
            return {'status': 'error', 'message': 'Scan has no requested engine'}

        # The current task model executes one concrete engine per Scan. Never silently
        # substitute Nmap when another engine was explicitly requested.
        if len(requested_engines) > 1:
            return {
                'status': 'error',
                'message': 'Multi-engine orchestration is not yet enabled for a single Scan; submit one Scan per engine.',
            }

        engine_name = requested_engines[0]
        task = ENGINE_TASKS.get(engine_name)
        if task is None:
            return {'status': 'error', 'message': f'No real task is configured for engine: {engine_name}'}
        if self.engine_status.get(engine_name) != 'active':
            return {'status': 'error', 'message': f'Engine is not active: {engine_name}'}

        scan.status = Scan.Status.QUEUED
        scan.progress = 0
        scan.current_phase = 'queued'
        scan.current_engine = engine_name
        scan.initiated_by_id = user_id
        scan.started_at = None
        scan.completed_at = None
        scan.error_message = ''
        scan.save(update_fields=['status', 'progress', 'current_phase', 'current_engine', 'initiated_by', 'started_at', 'completed_at', 'error_message', 'updated_at'])
        checkpoint_scan(scan, state=Scan.Status.QUEUED, metadata={'actor_id': str(user_id), 'engine': engine_name})

        queued_task = task.delay(str(scan.id))
        scan.celery_task_id = queued_task.id
        scan.save(update_fields=['celery_task_id', 'updated_at'])
        return {'status': 'started', 'scan_id': str(scan.id), 'task_id': queued_task.id, 'engine': engine_name}

    async def start_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        if not user_id:
            return {'status': 'error', 'message': 'Invalid authenticated user'}
        return await self._queue_scan(scan_id, str(user_id))

    async def run_scan(self, scan_id: str, user: Dict) -> Dict:
        return await self.start_scan(scan_id, user)

    @sync_to_async
    def _get_progress(self, scan_id: str, user_id: str):
        from django_project.scans.models import Scan
        scan = Scan.objects.filter(pk=scan_id).first()
        if not scan:
            return {'status': 'error', 'message': 'Scan not found'}
        if not Scan.objects.filter(pk=scan.pk).filter(
            project_access_q(user_id, relation='project')
        ).exists():
            return {'status': 'error', 'message': 'Scan access denied'}
        return {'scan_id': str(scan.id), 'status': scan.status, 'progress': round(scan.progress), 'current_phase': scan.current_phase, 'current_engine': scan.current_engine, 'celery_task_id': scan.celery_task_id, 'started_at': scan.started_at.isoformat() if scan.started_at else None, 'completed_at': scan.completed_at.isoformat() if scan.completed_at else None, 'error_message': scan.error_message}

    async def get_progress(self, scan_id: str, user: Dict | None = None) -> Dict:
        user_id = (user or {}).get('user_id') or (user or {}).get('sub')
        if not user_id:
            return {'status': 'error', 'message': 'Invalid authenticated user'}
        return await self._get_progress(scan_id, str(user_id))

    async def get_scan_status(self, scan_id: str, user: Dict | None = None) -> Dict:
        return await self.get_progress(scan_id, user)

    @sync_to_async
    def _transition(self, scan_id: str, user_id: str, status: str):
        return transition_scan(scan_id=scan_id, user_id=user_id, target_status=status)

    async def pause_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        return await self._transition(scan_id, str(user_id), 'paused') if user_id else {'status': 'error', 'message': 'Invalid authenticated user'}

    async def resume_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        return await self._transition(scan_id, str(user_id), 'running') if user_id else {'status': 'error', 'message': 'Invalid authenticated user'}

    async def cancel_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        return await self._transition(scan_id, str(user_id), 'cancelled') if user_id else {'status': 'error', 'message': 'Invalid authenticated user'}

    @sync_to_async
    def _prepare_restart(self, scan_id: str, user_id: str):
        return prepare_restart(scan_id=scan_id, user_id=user_id)

    async def restart_scan(self, scan_id: str, user: Dict) -> Dict:
        user_id = user.get('user_id') or user.get('sub')
        if not user_id:
            return {'status': 'error', 'message': 'Invalid authenticated user'}
        prepared = await self._prepare_restart(scan_id, str(user_id))
        if prepared.get('status') != 'restart_ready':
            return prepared
        queued = await self._queue_scan(scan_id, str(user_id))
        return {**prepared, **queued}
