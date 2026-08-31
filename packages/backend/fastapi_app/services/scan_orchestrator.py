from __future__ import annotations

import logging
from typing import Any

from django.utils import timezone

from .engine_adapters import SUPPORTED_REAL_ENGINES
from .websocket_manager import WebSocketManager
from ..core.config import settings

logger = logging.getLogger(__name__)

ENGINE_METADATA = {
    "recon": ("Recon & Asset Discovery", "recon", 1, 60),
    "evidence_collection": ("Evidence Collection", "analysis", 2, 60),
    "code_quality": ("Code Quality Analysis", "analysis", 3, 120),
    "runtime_analysis": ("Runtime Log Analysis", "analysis", 4, 60),
    "dependency_risk": ("Dependency Risk", "analysis", 5, 120),
    "vuln_intelligence": ("Vulnerability Intelligence", "intelligence", 6, 120),
    "validation": ("Security Validation", "validation", 7, 180),
    "control_validation": ("Control Validation", "control", 8, 180),
    "endpoint_discovery": ("Endpoint Discovery", "recon", 9, 120),
    "tls_intelligence": ("TLS Intelligence", "intelligence", 10, 120),
    "network_nmap": ("Nmap Network Discovery", "recon", 11, 180),
    "network_masscan": ("Masscan Port Discovery", "recon", 12, 120),
}


class ScanOrchestrator:
    """Thin orchestration layer. Durable state is PostgreSQL; execution is Celery."""

    def __init__(self, websocket_manager: WebSocketManager):
        self.websocket_manager = websocket_manager
        self.max_concurrent = settings.MAX_CONCURRENT_SCANS
        self.running = False

    async def start(self) -> None:
        self.running = True
        logger.info("Scan Orchestrator started (Celery-backed, PostgreSQL state)")

    async def stop(self) -> None:
        self.running = False
        logger.info("Scan Orchestrator stopped")

    async def list_engines(self) -> list[dict[str, Any]]:
        from scans.models import ScanEngine
        configured = {item.name: item for item in ScanEngine.objects.all()}
        result: list[dict[str, Any]] = []
        for name in sorted(SUPPORTED_REAL_ENGINES, key=lambda value: ENGINE_METADATA.get(value, (value, "analysis", 999, 300))[2]):
            display_name, category, order, timeout = ENGINE_METADATA.get(name, (name, "analysis", 999, 300))
            db_engine = configured.get(name)
            result.append({
                "name": name,
                "display_name": db_engine.display_name if db_engine else display_name,
                "category": db_engine.category if db_engine else category,
                "order": db_engine.order if db_engine else order,
                "status": db_engine.status if db_engine else "active",
                "timeout": db_engine.timeout if db_engine else timeout,
                "real_executor_registered": True,
                "configured_in_database": db_engine is not None,
            })
        return result

    async def enable_engine(self, engine_name: str) -> dict[str, Any]:
        from scans.models import ScanEngine
        if engine_name not in SUPPORTED_REAL_ENGINES:
            return {"status": "error", "message": "No real execution adapter is registered for this engine"}
        defaults = ENGINE_METADATA.get(engine_name, (engine_name, "analysis", 999, 300))
        engine, _ = ScanEngine.objects.get_or_create(
            name=engine_name,
            defaults={"display_name": defaults[0], "description": "Registered real execution adapter", "category": defaults[1], "version": "1.0.0", "is_core": True, "timeout": defaults[3], "order": defaults[2]},
        )
        engine.status = "active"
        engine.save(update_fields=["status", "updated_at"])
        return {"status": "enabled", "engine": engine_name}

    async def disable_engine(self, engine_name: str) -> dict[str, Any]:
        from scans.models import ScanEngine
        engine = ScanEngine.objects.filter(name=engine_name).first()
        if not engine:
            return {"status": "error", "message": "Engine is not configured in the database"}
        engine.status = "inactive"
        engine.save(update_fields=["status", "updated_at"])
        return {"status": "disabled", "engine": engine_name}

    async def start_scan(self, scan_id: str, user: dict[str, Any]) -> dict[str, Any]:
        from scans.models import Scan, ScanEngine
        from ..celery_app import celery_app
        from ..tasks.scan_tasks import run_scan
        scan = Scan.objects.select_related("project").filter(pk=scan_id).first()
        if not scan:
            return {"status": "error", "message": "Scan not found"}
        if scan.status == "running":
            return {"status": "error", "message": "Scan already running", "scan_id": scan_id}
        if scan.status == "completed":
            return {"status": "error", "message": "Completed scans are immutable; create a new scan", "scan_id": scan_id}
        engines = [str(value).strip() for value in (scan.engines or []) if str(value).strip()]
        if not engines:
            return {"status": "error", "message": "No real execution engines configured; refusing to fabricate results", "scan_id": scan_id}
        unsupported = sorted(set(engines) - set(SUPPORTED_REAL_ENGINES))
        if unsupported:
            return {"status": "error", "message": "Scan contains engines without real executors", "unsupported_engines": unsupported, "scan_id": scan_id}
        for index, engine_name in enumerate(engines, start=1):
            defaults = ENGINE_METADATA.get(engine_name, (engine_name, "analysis", index, 300))
            ScanEngine.objects.get_or_create(name=engine_name, defaults={"display_name": defaults[0], "description": "Registered real execution adapter", "category": defaults[1], "version": "1.0.0", "is_core": True, "timeout": defaults[3], "order": defaults[2]})
        task = celery_app.send_task(run_scan.name, args=[str(scan.pk)], queue="default", routing_key="default")
        scan.celery_task_id = task.id
        scan.status = "queued"
        scan.current_phase = "queued"
        scan.progress = 0
        scan.save(update_fields=["celery_task_id", "status", "current_phase", "progress", "updated_at"])
        logger.info("Queued real scan %s as Celery task %s on default queue", scan_id, task.id)
        return {"status": "queued", "scan_id": scan_id, "task_id": task.id}

    async def pause_scan(self, scan_id: str) -> dict[str, Any]:
        from scans.models import Scan
        updated = Scan.objects.filter(pk=scan_id, status__in=["queued", "running"]).update(status="paused", updated_at=timezone.now())
        return {"status": "paused", "scan_id": scan_id} if updated else {"status": "error", "message": "Scan not running or not found"}

    async def resume_scan(self, scan_id: str) -> dict[str, Any]:
        from scans.models import Scan
        scan = Scan.objects.filter(pk=scan_id).first()
        if not scan:
            return {"status": "error", "message": "Scan not found"}
        if scan.status != "paused":
            return {"status": "error", "message": "Scan is not paused"}
        scan.status = "running"
        scan.save(update_fields=["status", "updated_at"])
        return {"status": "resumed", "scan_id": scan_id}

    async def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        from scans.models import Scan
        scan = Scan.objects.filter(pk=scan_id).first()
        if not scan:
            return {"status": "error", "message": "Scan not found"}
        if scan.status in {"completed", "failed", "cancelled"}:
            return {"status": "error", "message": "Scan is already finished", "scan_id": scan_id}
        scan.status = "cancelled"
        scan.completed_at = timezone.now()
        scan.current_phase = "cancelled"
        scan.save(update_fields=["status", "completed_at", "current_phase", "updated_at"])
        return {"status": "cancelled", "scan_id": scan_id}

    async def get_progress(self, scan_id: str) -> dict[str, Any]:
        from scans.models import Scan
        scan = Scan.objects.prefetch_related("engine_executions__engine").filter(pk=scan_id).first()
        if not scan:
            return {"status": "error", "message": "Scan not found"}
        return {"scan_id": str(scan.pk), "status": scan.status, "progress": scan.progress, "current_phase": scan.current_phase, "current_engine": scan.current_engine, "engines": [{"name": execution.engine.name, "status": execution.status, "progress": execution.progress, "findings": execution.findings_found, "evidence": execution.evidences_collected} for execution in scan.engine_executions.all()], "started_at": scan.started_at.isoformat() if scan.started_at else None, "completed_at": scan.completed_at.isoformat() if scan.completed_at else None, "celery_task_id": scan.celery_task_id, "findings_count": scan.findings_count, "security_score": scan.security_score, "risk_level": scan.risk_level, "error": scan.error_message or None}
