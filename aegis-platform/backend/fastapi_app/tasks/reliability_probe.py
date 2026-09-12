from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any

from celery import shared_task
from django.db import transaction

from django_project.evidence.models import Evidence
from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from fastapi_app.services.evidence_identity import evidence_id


PROBE_ENGINE = "scanner-reliability-probe"
PROBE_SOURCE = "scanner-reliability"
_ENABLED_VALUES = {"1", "true", "yes", "on"}


def _enabled() -> bool:
    return os.getenv("AEGIS_RELIABILITY_PROBE_ENABLED", "").strip().lower() in _ENABLED_VALUES


def _hold_seconds() -> float:
    try:
        value = float(os.getenv("AEGIS_RELIABILITY_PROBE_HOLD_SECONDS", "90"))
    except ValueError as exc:
        raise RuntimeError("AEGIS_RELIABILITY_PROBE_HOLD_SECONDS must be numeric") from exc
    if value < 0 or value > 300:
        raise RuntimeError("AEGIS_RELIABILITY_PROBE_HOLD_SECONDS must be between 0 and 300 seconds")
    return value


def _engine() -> ScanEngine:
    engine, _ = ScanEngine.objects.get_or_create(
        name=PROBE_ENGINE,
        defaults={
            "display_name": "Scanner Reliability Probe",
            "description": "Fail-closed worker-loss/redelivery reliability proof.",
            "category": ScanEngine.EngineCategory.CONTROL,
            "version": "1.0",
            "status": ScanEngine.EngineStatus.ACTIVE,
            "is_core": False,
            "timeout": 300,
        },
    )
    return engine


def _complete_probe(scan_id: str, execution_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    with transaction.atomic():
        scan = Scan.objects.select_for_update().select_related("initiated_by").get(pk=scan_id)
        execution = ScanEngineExecution.objects.select_for_update().get(pk=execution_id)

        if (
            scan.status == Scan.Status.COMPLETED
            and execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
        ):
            result = execution.result_data if isinstance(execution.result_data, dict) else {}
            return {
                "status": Scan.Status.COMPLETED,
                "scan_id": str(scan.id),
                "attempts": int(result.get("probe_attempts", 1)),
                "redelivered": int(result.get("probe_attempts", 1)) > 1,
                "terminal": True,
            }

        result_data = execution.result_data if isinstance(execution.result_data, dict) else {}
        attempts = int(result_data.get("probe_attempts", 1))
        raw_output = '{"probe":"scanner-worker-loss","status":"completed"}'
        evidence, _ = Evidence.objects.update_or_create(
            id=evidence_id("scan", str(scan.id), PROBE_SOURCE, "reliability_probe"),
            defaults={
                "scan": scan,
                "asset": scan.asset,
                "source": PROBE_SOURCE,
                "evidence_type": "reliability_probe",
                "raw_output": raw_output,
                "metadata": {
                    "probe": "forced-worker-loss-redelivery",
                    "attempts": attempts,
                    "task_id": result_data.get("task_id", ""),
                },
                "collected_by": scan.initiated_by,
            },
        )
        execution.status = ScanEngineExecution.ExecutionStatus.COMPLETED
        execution.progress = 100
        execution.completed_at = now
        execution.evidences_collected = 1
        execution.error_message = ""
        execution.result_data = {
            **result_data,
            "probe_attempts": attempts,
            "evidence_id": str(evidence.id),
            "completed_after_redelivery": attempts > 1,
        }
        execution.save(
            update_fields=[
                "status",
                "progress",
                "completed_at",
                "evidences_collected",
                "error_message",
                "result_data",
                "updated_at",
            ]
        )

        scan.status = Scan.Status.COMPLETED
        scan.progress = 100
        scan.completed_at = now
        scan.current_phase = "scanner-reliability-proven"
        scan.current_engine = PROBE_ENGINE
        scan.error_message = ""
        scan.engine_results = {
            **(scan.engine_results or {}),
            PROBE_ENGINE: execution.result_data,
        }
        scan.save(
            update_fields=[
                "status",
                "progress",
                "completed_at",
                "current_phase",
                "current_engine",
                "error_message",
                "engine_results",
                "updated_at",
            ]
        )
        ScanLog.objects.create(
            scan=scan,
            engine_execution=execution,
            level=ScanLog.Level.INFO,
            message="scanner worker-loss recovery completed",
            context={
                "attempts": attempts,
                "redelivered": attempts > 1,
                "evidence_id": str(evidence.id),
            },
        )
        return {
            "status": Scan.Status.COMPLETED,
            "scan_id": str(scan.id),
            "attempts": attempts,
            "evidence_id": str(evidence.id),
            "redelivered": attempts > 1,
        }


@shared_task(
    bind=True,
    name="fastapi_app.tasks.reliability_probe.scanner_worker_loss_probe",
    max_retries=0,
    acks_late=True,
    reject_on_worker_lost=True,
)
def scanner_worker_loss_probe(self, scan_id: str) -> dict[str, Any]:
    """Prove durable scanner recovery across a forced worker-container loss.

    The task is unreachable through the public API and fails closed unless an
    explicit runtime-only reliability flag is enabled.  CI deliberately kills
    the scanner worker after the first delivery has committed RUNNING state.
    Redis then redelivers the same unacknowledged task and the second delivery
    completes the same ScanEngineExecution and deterministic Evidence record.
    """

    if not _enabled():
        raise RuntimeError("scanner worker-loss reliability probe is disabled")

    task_id = str(getattr(self.request, "id", "") or "")
    now = datetime.now(timezone.utc)
    with transaction.atomic():
        scan = Scan.objects.select_for_update().get(pk=scan_id)
        engine = _engine()
        execution, _ = ScanEngineExecution.objects.select_for_update().get_or_create(
            scan=scan,
            engine=engine,
            defaults={"status": ScanEngineExecution.ExecutionStatus.PENDING},
        )

        if (
            scan.status == Scan.Status.COMPLETED
            and execution.status == ScanEngineExecution.ExecutionStatus.COMPLETED
        ):
            result = execution.result_data if isinstance(execution.result_data, dict) else {}
            attempts = int(result.get("probe_attempts", 1))
            return {
                "status": Scan.Status.COMPLETED,
                "scan_id": str(scan.id),
                "attempts": attempts,
                "redelivered": attempts > 1,
                "terminal": True,
            }

        prior = execution.result_data if isinstance(execution.result_data, dict) else {}
        attempts = int(prior.get("probe_attempts", 0)) + 1
        execution.status = ScanEngineExecution.ExecutionStatus.RUNNING
        execution.progress = 40
        if execution.started_at is None:
            execution.started_at = now
        execution.completed_at = None
        execution.error_message = ""
        execution.result_data = {
            **prior,
            "probe_attempts": attempts,
            "task_id": task_id,
        }
        execution.save(
            update_fields=[
                "status",
                "progress",
                "started_at",
                "completed_at",
                "error_message",
                "result_data",
                "updated_at",
            ]
        )

        scan.status = Scan.Status.RUNNING
        scan.progress = 40
        if scan.started_at is None:
            scan.started_at = now
        scan.completed_at = None
        scan.current_phase = "scanner-worker-loss-probe"
        scan.current_engine = PROBE_ENGINE
        scan.error_message = ""
        scan.save(
            update_fields=[
                "status",
                "progress",
                "started_at",
                "completed_at",
                "current_phase",
                "current_engine",
                "error_message",
                "updated_at",
            ]
        )

    if attempts == 1:
        time.sleep(_hold_seconds())

    return _complete_probe(str(scan_id), str(execution.id))
