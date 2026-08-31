from __future__ import annotations

import asyncio
import hashlib
import json
import os
import traceback
import uuid
from typing import Any

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
import django
django.setup()

from django.db import transaction
from django.utils import timezone

# Bind scan execution tasks to the canonical AegisScan Celery application.
# This prevents Celery's implicit/default app from changing task routing
# depending on import order or process initialization.
from fastapi_app.celery_app import celery_app

# Import Django apps through the same module names used by INSTALLED_APPS.
# Importing the same model package as django_project.scans would create a
# second Python module identity and Django would reject those model classes
# as belonging to an uninstalled application in Celery workers.
from scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from vulnerabilities.models import Vulnerability, VulnerabilityEvidence
from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES, execute_engine

ENGINE_META = {
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
    # Network lab engines must be represented here as well as in the real
    # executor registry. Otherwise run_scan reaches execute_engine() but
    # crashes before execution with KeyError(engine_name).
    "network_nmap": ("Network Nmap", "network", 11, 900),
    "network_masscan": ("Network Masscan", "network", 12, 900),
}


def _stable_uuid(seed: str) -> uuid.UUID:
    return uuid.UUID(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32])


def _target_from_scan(scan: Scan) -> tuple[str, str]:
    config = scan.config or {}
    target_type = str(config.get("target_type") or scan.scan_type).strip().lower()
    target_value = str(config.get("target_value") or config.get("target") or "").strip()
    if not target_value and scan.asset_id:
        asset = scan.asset
        asset_cfg = asset.configuration or {}
        target_value = str(asset_cfg.get("url") or asset_cfg.get("base_url") or asset_cfg.get("spec_url") or asset_cfg.get("ip") or asset_cfg.get("domain") or "").strip()
    if target_type == "full_validation":
        target_type = str(config.get("target_type") or "").strip().lower()
    if not target_value:
        raise ValueError("Scan target is missing; AegisScan refuses to invent a target")
    if target_type not in {"url", "ip", "api", "code"}:
        raise ValueError(f"Unsupported real scan target_type: {target_type}")
    return target_type, target_value


def _engine_names(scan: Scan) -> list[str]:
    if not isinstance(scan.engines, list):
        raise ValueError("Scan engines configuration must be a JSON array")
    return [str(name).strip() for name in scan.engines if str(name).strip()]


def _evidence_model_type(evidence_type: str) -> str:
    return {
        "http_response": VulnerabilityEvidence.Type.DYNAMIC_ANALYSIS,
        "dns_resolution": VulnerabilityEvidence.Type.VALIDATION_TEST,
        "dependency_manifest": VulnerabilityEvidence.Type.DEPENDENCY_SCAN,
        "static_analysis": VulnerabilityEvidence.Type.STATIC_ANALYSIS,
        "runtime_analysis": VulnerabilityEvidence.Type.LOG_ANALYSIS,
        "threat_intelligence": VulnerabilityEvidence.Type.EXTERNAL_INTEL,
        "config_check": VulnerabilityEvidence.Type.CONFIG_CHECK,
        "validation_test": VulnerabilityEvidence.Type.VALIDATION_TEST,
    }.get(evidence_type, VulnerabilityEvidence.Type.VALIDATION_TEST)


def _confidence_value(raw: Any) -> str:
    value = float(raw or 0)
    if value >= 90:
        return Vulnerability.Confidence.HIGH
    if value >= 70:
        return Vulnerability.Confidence.MEDIUM
    if value > 0:
        return Vulnerability.Confidence.LOW
    return Vulnerability.Confidence.UNVERIFIED


def _risk_score(severity: str, confidence: Any) -> float:
    base = {"critical": 95.0, "high": 80.0, "medium": 60.0, "low": 35.0, "info": 10.0}.get(severity, 0.0)
    conf = max(0.0, min(100.0, float(confidence or 0))) / 100.0
    return round(base * (0.5 + 0.5 * conf), 2)


def _publish_event(scan_id: str, payload: dict[str, Any]) -> None:
    try:
        import redis
        from fastapi_app.core.config import settings
        client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        message = json.dumps(payload, default=str)
        client.publish(f"aegis:scan-events:{scan_id}", message)
        validation_id = payload.get("validation_id")
        if validation_id:
            client.publish(f"aegis:validation-events:{validation_id}", message)
    except Exception:
        return


def _log(scan: Scan, message: str, level: str = ScanLog.Level.INFO, execution=None, context=None) -> None:
    ScanLog.objects.create(scan=scan, engine_execution=execution, level=level, message=message, context=context or {})


def _persist_findings(scan: Scan, execution: ScanEngineExecution, findings: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> int:
    evidence_by_id = {str(item.get("id")): item for item in evidence if isinstance(item, dict) and item.get("id")}
    count = 0
    for finding in findings:
        if not isinstance(finding, dict) or not finding.get("id"):
            continue
        finding_key = str(finding["id"])
        severity = str(finding.get("severity") or "info").lower()
        if severity not in {value for value, _ in Vulnerability.Severity.choices}:
            severity = Vulnerability.Severity.INFO
        confidence = finding.get("confidence", 0)
        raw_url = str(finding.get("url") or "")
        safe_url = raw_url if raw_url.startswith(("http://", "https://")) else ""
        vuln, _ = Vulnerability.objects.update_or_create(
            id=_stable_uuid(f"scan:{scan.pk}:finding:{finding_key}"),
            defaults={
                "scan": scan,
                "project": scan.project,
                "asset": scan.asset,
                "title": str(finding.get("title") or "Unnamed finding")[:300],
                "description": str(finding.get("description") or "Live engine finding"),
                "severity": severity,
                "status": Vulnerability.Status.OPEN,
                "confidence": _confidence_value(confidence),
                "category": str(finding.get("category") or "")[:50],
                "cwe_id": str(finding.get("cwe_id") or "")[:20],
                "cve_ids": finding.get("cve_ids") if isinstance(finding.get("cve_ids"), list) else [],
                "owasp_category": str(finding.get("owasp_category") or "")[:50],
                "tags": finding.get("tags") if isinstance(finding.get("tags"), list) else [],
                "file_path": str(finding.get("file_path") or "")[:500],
                "line_start": finding.get("line_start"),
                "line_end": finding.get("line_end"),
                "function_name": str(finding.get("function_name") or "")[:200],
                "code_snippet": str(finding.get("code_snippet") or ""),
                "url": safe_url,
                "parameter": str(finding.get("parameter") or "")[:200],
                "method": str(finding.get("method") or "")[:10],
                "risk_score": _risk_score(severity, confidence),
                "validation_status": "observed",
                "source_engine": execution.engine.name,
                "raw_data": finding,
            },
        )
        for evidence_id in finding.get("evidence_ids") or []:
            evidence_item = evidence_by_id.get(str(evidence_id))
            if not evidence_item:
                continue
            VulnerabilityEvidence.objects.update_or_create(
                id=_stable_uuid(f"vuln:{vuln.pk}:evidence:{evidence_id}"),
                defaults={
                    "vulnerability": vuln,
                    "type": _evidence_model_type(str(evidence_item.get("type") or "")),
                    "quality": VulnerabilityEvidence.Quality.UNVERIFIED,
                    "source": str(evidence_item.get("engine") or execution.engine.name)[:100],
                    "description": str(evidence_item.get("description") or f"Evidence emitted by {execution.engine.name}"),
                    "location": str(evidence_item.get("data", {}).get("final_url") or evidence_item.get("data", {}).get("requested_url") or evidence_item.get("data", {}).get("target") or "")[:500],
                    "raw_data": json.dumps(evidence_item, ensure_ascii=False, default=str),
                    "confidence": max(0.0, min(1.0, float(confidence or 0) / 100.0)),
                    "tags": [execution.engine.name],
                    "metadata": {"evidence_id": str(evidence_id), "scan_id": str(scan.pk)},
                },
            )
        vuln.evidence_count = vuln.evidences.count()
        vuln.save(update_fields=["evidence_count", "updated_at"])
        count += 1
    return count


def _aggregate_scan(scan: Scan) -> None:
    qs = Vulnerability.objects.filter(scan=scan)
    counts = {key: qs.filter(severity=key).count() for key in ["critical", "high", "medium", "low", "info"]}
    weighted = counts["critical"] * 10 + counts["high"] * 6 + counts["medium"] * 3 + counts["low"]
    scan.findings_count = sum(counts.values())
    scan.critical_count = counts["critical"]
    scan.high_count = counts["high"]
    scan.medium_count = counts["medium"]
    scan.low_count = counts["low"]
    scan.info_count = counts["info"]
    scan.security_score = round(max(0.0, min(100.0, 100.0 - weighted * 2.5)), 2)
    scan.risk_level = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "info"


def _sync_validation_projection(scan: Scan) -> None:
    validation_id = (scan.config or {}).get("validation_id")
    if not validation_id:
        return
    _publish_event(
        str(scan.pk),
        {
            "type": "validation.progress",
            "validation_id": str(validation_id),
            "scan_id": str(scan.pk),
            "status": scan.status,
            "progress": scan.progress,
            "current_phase": scan.current_phase,
            "current_engine": scan.current_engine,
            "findings_count": scan.findings_count,
            "security_score": scan.security_score,
            "risk_level": scan.risk_level,
        },
    )


@celery_app.task(bind=True, name="fastapi_app.tasks.scan_tasks.run_scan", acks_late=True, reject_on_worker_lost=True, time_limit=1800, soft_time_limit=1500)
def run_scan(self, scan_id: str) -> dict[str, Any]:
    scan = Scan.objects.select_related("project", "asset", "initiated_by").get(pk=scan_id)
    started = timezone.now()
    engines = _engine_names(scan)
    unsupported = sorted(set(engines) - set(SUPPORTED_REAL_ENGINES))
    if unsupported:
        raise ValueError(f"No real executor registered for engines: {', '.join(unsupported)}")
    target_type, target_value = _target_from_scan(scan)

    with transaction.atomic():
        scan.status = Scan.Status.RUNNING
        scan.started_at = started
        scan.progress = 0
        scan.current_phase = "initializing"
        scan.current_engine = ""
        scan.error_message = ""
        scan.error_traceback = ""
        scan.save(update_fields=["status", "started_at", "progress", "current_phase", "current_engine", "error_message", "error_traceback", "updated_at"])
        _log(scan, "Real scan task started", context={"celery_task_id": self.request.id, "engines": engines, "target_type": target_type, "target_value": target_value})
    _sync_validation_projection(scan)

    try:
        if not engines:
            raise ValueError("No scan engines are configured; refusing to fabricate scan results")
        total = len(engines)
        results_summary: dict[str, Any] = {}

        for index, engine_name in enumerate(engines):
            scan.refresh_from_db(fields=["status", "progress", "current_phase", "current_engine"])
            if scan.status == Scan.Status.CANCELLED:
                return {"status": "cancelled", "scan_id": str(scan.pk)}
            while scan.status == Scan.Status.PAUSED:
                import time
                time.sleep(1)
                scan.refresh_from_db(fields=["status", "progress", "current_phase", "current_engine"])
            if scan.status == Scan.Status.CANCELLED:
                return {"status": "cancelled", "scan_id": str(scan.pk)}

            meta = ENGINE_META[engine_name]
            engine_obj, _ = ScanEngine.objects.get_or_create(
                name=engine_name,
                defaults={"display_name": meta[0], "description": "Registered real execution adapter", "category": meta[1], "version": "1.0.0", "is_core": True, "timeout": meta[3], "order": meta[2]},
            )
            execution, _ = ScanEngineExecution.objects.get_or_create(scan=scan, engine=engine_obj)
            execution.status = ScanEngineExecution.ExecutionStatus.RUNNING
            execution.started_at = timezone.now()
            execution.progress = 1
            execution.error_message = ""
            execution.save(update_fields=["status", "started_at", "progress", "error_message", "updated_at"])
            scan.current_engine = engine_name
            scan.current_phase = engine_obj.category
            scan.progress = round(index / total * 100, 2)
            scan.save(update_fields=["current_engine", "current_phase", "progress", "updated_at"])
            _publish_event(str(scan.pk), {"type": "engine.started", "scan_id": str(scan.pk), "validation_id": (scan.config or {}).get("validation_id"), "engine": engine_name, "progress": scan.progress})
            result = asyncio.run(execute_engine(engine_name, target_type, target_value, scan.config or {}))
            finished = timezone.now()
            duration = (finished - (execution.started_at or finished)).total_seconds()
            terminal_failure = result.status in {"failed", "unsupported", "unavailable"}
            with transaction.atomic():
                execution.status = ScanEngineExecution.ExecutionStatus.FAILED if terminal_failure else ScanEngineExecution.ExecutionStatus.COMPLETED
                execution.progress = 100
                execution.completed_at = finished
                execution.duration = duration
                execution.findings_found = len(result.findings)
                execution.evidences_collected = len(result.evidence)
                execution.result_data = {"status": result.status, "metrics": result.metrics, "error": result.error, "evidence": result.evidence}
                execution.error_message = result.error or ""
                execution.logs = f"Real execution completed in {duration:.3f}s"
                execution.save()
                persisted = _persist_findings(scan, execution, result.findings, result.evidence)
                results_summary[engine_name] = {"status": result.status, "metrics": result.metrics, "error": result.error, "findings_count": len(result.findings), "evidence_count": len(result.evidence), "persisted_findings": persisted}
                scan.engine_results = results_summary
                scan.progress = round((index + 1) / total * 100, 2)
                scan.current_phase = "completed" if index + 1 == total else engine_obj.category
                scan.save(update_fields=["engine_results", "progress", "current_phase", "updated_at"])
                _log(scan, f"Real engine {engine_name} completed", context=results_summary[engine_name], execution=execution)
            _publish_event(str(scan.pk), {"type": "engine.completed", "scan_id": str(scan.pk), "validation_id": (scan.config or {}).get("validation_id"), "engine": engine_name, "progress": scan.progress, "findings": len(result.findings), "evidence": len(result.evidence), "status": result.status})
            _sync_validation_projection(scan)
            if terminal_failure:
                raise RuntimeError(result.error or f"Real engine {engine_name} failed with status {result.status}")

        _aggregate_scan(scan)
        scan.status = Scan.Status.COMPLETED
        scan.completed_at = timezone.now()
        scan.current_phase = "completed"
        scan.current_engine = ""
        scan.progress = 100
        scan.save(update_fields=["status", "completed_at", "current_phase", "current_engine", "progress", "findings_count", "critical_count", "high_count", "medium_count", "low_count", "info_count", "security_score", "risk_level", "updated_at"])
        _log(scan, "Real scan task completed", context={"security_score": scan.security_score, "risk_level": scan.risk_level, "findings_count": scan.findings_count})
        _sync_validation_projection(scan)
        return {"status": "completed", "scan_id": str(scan.pk), "findings_count": scan.findings_count, "security_score": scan.security_score, "risk_level": scan.risk_level}
    except Exception as exc:
        error_text = str(exc)
        with transaction.atomic():
            scan.status = Scan.Status.FAILED
            scan.completed_at = timezone.now()
            scan.error_message = error_text
            scan.error_traceback = traceback.format_exc()
            scan.current_phase = "failed"
            scan.current_engine = ""
            _aggregate_scan(scan)
            scan.save(update_fields=["status", "completed_at", "error_message", "error_traceback", "current_phase", "current_engine", "findings_count", "critical_count", "high_count", "medium_count", "low_count", "info_count", "security_score", "risk_level", "updated_at"])
            _log(scan, "Real scan task failed", level=ScanLog.Level.ERROR, context={"error": error_text})
        _sync_validation_projection(scan)
        raise
