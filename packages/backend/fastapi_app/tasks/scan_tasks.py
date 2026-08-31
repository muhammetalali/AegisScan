from __future__ import annotations

import asyncio
import hashlib
import os
import traceback
from datetime import timedelta
from typing import Any

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")

import django

django.setup()

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from django_project.scans.models import Scan, ScanEngine, ScanEngineExecution, ScanLog
from django_project.vulnerabilities.models import Vulnerability, VulnerabilityEvidence

from fastapi_app.services.engine_adapters import SUPPORTED_REAL_ENGINES, execute_engine


ENGINE_META = {
    "recon": ("Recon & Asset Discovery", "recon"),
    "evidence_collection": ("Evidence Collection", "analysis"),
    "vuln_intelligence": ("Vulnerability Intelligence", "intelligence"),
    "validation": ("Security Validation", "validation"),
    "control_validation": ("Control Validation", "control"),
    "endpoint_discovery": ("Endpoint Discovery", "recon"),
    "tls_intelligence": ("TLS Intelligence", "intelligence"),
    "dependency_risk": ("Dependency Risk", "analysis"),
    "code_quality": ("Code Quality Analysis", "analysis"),
    "runtime_analysis": ("Runtime Log Analysis", "analysis"),
}


def _stable_uuid(seed: str):
    import uuid
    return uuid.UUID(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32])


def _target_from_scan(scan: Scan) -> tuple[str, str]:
    config = scan.config or {}
    target_type = str(config.get("target_type") or scan.scan_type).strip().lower()
    target_value = str(config.get("target_value") or config.get("target") or "").strip()
    if not target_value and scan.asset_id:
        asset = scan.asset
        asset_cfg = asset.configuration or {}
        candidates = {
            "website": asset_cfg.get("url"),
            "api_endpoint": asset_cfg.get("base_url") or asset_cfg.get("spec_url"),
            "ip_address": asset_cfg.get("ip"),
            "domain": asset_cfg.get("domain"),
        }
        target_value = str(candidates.get(asset.type) or "").strip()
    if not target_value:
        raise ValueError("Scan target is missing: set config.target_value or attach an asset with a concrete target")
    if target_type == "full_validation":
        target_type = str(config.get("target_type") or "").strip().lower()
    if target_type not in {"url", "ip", "api", "code"}:
        raise ValueError(f"Unsupported real scan target_type: {target_type}")
    return target_type, target_value


def _engine_names(scan: Scan) -> list[str]:
    configured = scan.engines or []
    if not isinstance(configured, list):
        raise ValueError("Scan engines configuration must be a JSON array")
    return [str(name).strip() for name in configured if str(name).strip()]


def _evidence_model_type(evidence_type: str) -> str:
    mapping = {
        "http_response": VulnerabilityEvidence.Type.DYNAMIC_ANALYSIS,
        "dns_resolution": VulnerabilityEvidence.Type.VALIDATION_TEST,
        "dependency_manifest": VulnerabilityEvidence.Type.DEPENDENCY_SCAN,
        "static_analysis": VulnerabilityEvidence.Type.STATIC_ANALYSIS,
        "runtime_analysis": VulnerabilityEvidence.Type.LOG_ANALYSIS,
        "threat_intelligence": VulnerabilityEvidence.Type.EXTERNAL_INTEL,
        "config_check": VulnerabilityEvidence.Type.CONFIG_CHECK,
        "validation_test": VulnerabilityEvidence.Type.VALIDATION_TEST,
    }
    return mapping.get(evidence_type, VulnerabilityEvidence.Type.VALIDATION_TEST)


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
    # The event is emitted to Redis so FastAPI and any WebSocket client can observe
    # progress from a different process/container without relying on local memory.
    try:
        import redis
        from fastapi_app.core.config import settings
        client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        client.publish(f"aegis:scan-events:{scan_id}", __import__('json').dumps(payload, default=str))
    except Exception:
        # Failure to publish must never turn a successful DB-backed scan into a fake failure.
        pass


def _log(scan: Scan, message: str, level: str = ScanLog.Level.INFO, execution=None, context=None) -> None:
    ScanLog.objects.create(scan=scan, engine_execution=execution, level=level, message=message, context=context or {})


def _persist_findings(scan: Scan, engine_execution: ScanEngineExecution, findings: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> int:
    evidence_by_id = {str(item.get("id")): item for item in evidence if isinstance(item, dict) and item.get("id")}
    count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("id") or "")
        if not finding_id:
            continue
        severity = str(finding.get("severity") or "info").lower()
        if severity not in {choice[0] for choice in Vulnerability.Severity.choices}:
            severity = "info"
        raw_confidence = finding.get("confidence", 0)
        vuln, created = Vulnerability.objects.update_or_create(
            id=_stable_uuid(f"{scan.pk}:{finding_id}"),
            defaults={
                "scan": scan,
                "project": scan.project,
                "asset": scan.asset,
                "title": str(finding.get("title") or "Unnamed finding")[:300],
                "description": str(finding.get("description") or "Live engine finding"),
                "severity": severity,
                "status": Vulnerability.Status.OPEN,
                "confidence": _confidence_value(raw_confidence),
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
                "url": str(finding.get("url") or finding.get("asset") or ""),
                "parameter": str(finding.get("parameter") or "")[:200],
                "method": str(finding.get("method") or "")[:10],
                "risk_score": _risk_score(severity, raw_confidence),
                "evidence_count": 0,
                "validation_status": "observed",
                "source_engine": engine_execution.engine.name,
                "raw_data": finding,
            },
        )
        attached = 0
        for evidence_id in finding.get("evidence_ids") or []:
            item = evidence_by_id.get(str(evidence_id))
            if not item:
                continue
            evidence_obj, _ = VulnerabilityEvidence.objects.get_or_create(
                vulnerability=vuln,
                id=_stable_uuid(f"{vuln.pk}:{evidence_id}"),
                defaults={
                    "type": _evidence_model_type(str(item.get("type") or "")),
                    "quality": VulnerabilityEvidence.Quality.UNVERIFIED,
                    "source": str(item.get("engine") or engine_execution.engine.name)[:100],
                    "description": str(item.get("description") or f"Evidence emitted by {engine_execution.engine.name}"),
                    "location": str(item.get("data", {}).get("final_url") or item.get("data", {}).get("requested_url") or "")[:500],
                    "raw_data": __import__('json').dumps(item, ensure_ascii=False, default=str),
                    "confidence": max(0.0, min(1.0, float(raw_confidence or 0) / 100.0)),
                    "tags": [engine_execution.engine.name],
                    "metadata": {"evidence_id": str(evidence_id), "scan_id": str(scan.pk)},
                },
            )
            attached += 1
        if vuln.evidence_count != attached:
            vuln.evidence_count = vuln.evidences.count()
            vuln.save(update_fields=["evidence_count", "updated_at"])
        count += 1
    return count


def _aggregate_scan(scan: Scan) -> None:
    qs = scan.vulnerabilities.all()
    counts = {key: qs.filter(severity=key).count() for key in ["critical", "high", "medium", "low", "info"]}
    total = sum(counts.values())
    weighted = counts["critical"] * 10 + counts["high"] * 6 + counts["medium"] * 3 + counts["low"] * 1
    score = max(0.0, min(100.0, 100.0 - weighted * 2.5))
    risk = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "info"
    scan.findings_count = total
    scan.critical_count = counts["critical"]
    scan.high_count = counts["high"]
    scan.medium_count = counts["medium"]
    scan.low_count = counts["low"]
    scan.info_count = counts["info"]
    scan.security_score = round(score, 2)
    scan.risk_level = risk


@shared_task(bind=True, name="fastapi_app.tasks.scan_tasks.run_scan", acks_late=True, reject_on_worker_lost=True, time_limit=1800, soft_time_limit=1500)
def run_scan(self, scan_id: str) -> dict[str, Any]:
    scan = Scan.objects.select_related("project", "asset", "initiated_by").get(pk=scan_id)
    started = timezone.now()
    engines = _engine_names(scan)
    supported = set(SUPPORTED_REAL_ENGINES)

    with transaction.atomic():
        scan.status = Scan.Status.RUNNING
        scan.started_at = started
        scan.progress = 0
        scan.current_phase = "initializing"
        scan.error_message = ""
        scan.error_traceback = ""
        scan.save(update_fields=["status", "started_at", "progress", "current_phase", "error_message", "error_traceback", "updated_at"])
        _log(scan, "Scan started with real execution adapters", context={"celery_task_id": self.request.id, "engines": engines})

    _publish_event(str(scan.pk), {"type": "scan.started", "scan_id": str(scan.pk), "task_id": self.request.id})

    try:
        if not engines:
            raise ValueError("No scan engines are configured; refusing to fabricate scan results")
        target_type, target_value = _target_from_scan(scan)
        total = len(engines)
        engine_results: dict[str, Any] = {}

        for index, engine_name in enumerate(engines):
            with transaction.atomic():
                if Scan.objects.filter(pk=scan.pk, status=Scan.Status.CANCELLED).exists():
                    _log(scan, "Scan cancelled before next engine", ScanLog.Level.WARNING)
                    return {"status": "cancelled", "scan_id": str(scan.pk)}
                scan.refresh_from_db(fields=["status", "progress", "current_phase", "current_engine"])
                while scan.status == Scan.Status.PAUSED:
                    import time
                    time.sleep(1)
                    scan.refresh_from_db(fields=["status", "progress", "current_phase", "current_engine"])
                if scan.status == Scan.Status.CANCELLED:
                    return {"status": "cancelled", "scan_id": str(scan.pk)}

                engine_obj, _ = ScanEngine.objects.get_or_create(
                    name=engine_name,
                    defaults={
                        "display_name": ENGINE_META.get(engine_name, (engine_name, "analysis"))[0],
                        "description": "Registered real execution adapter",
                        "category": ENGINE_META.get(engine_name, (engine_name, "analysis"))[1],
                        "version": "1.0.0",
                        "is_core": engine_name in supported,
                        "timeout": 300,
                        "order": index + 1,
                    },
                )
                execution, _ = ScanEngineExecution.objects.get_or_create(scan=scan, engine=engine_obj)
                execution.status = ScanEngineExecution.ExecutionStatus.RUNNING
                execution.started_at = timezone.now()
                execution.progress = 1
                execution.logs = f"Celery task {self.request.id} started engine {engine_name}"
                execution.save(update_fields=["status", "started_at", "progress", "logs", "updated_at"])
                scan.current_engine = engine_name
                scan.current_phase = engine_obj.category
                scan.progress = round((index / total) * 100, 2)
                scan.save(update_fields=["current_engine", "current_phase", "progress", "updated_at"])

            _publish_event(str(scan.pk), {"type": "engine.started", "scan_id": str(scan.pk), "engine": engine_name, "progress": scan.progress})
            _log(scan, f"Engine {engine_name} started", context={"target_type": target_type, "target_value": target_value}, execution=execution)

            if engine_name not in supported:
                result = type("UnsupportedResult", (), {"status": "skipped", "findings": [], "evidence": [], "metrics": {"engine": engine_name, "execution": "unsupported"}, "error": "No real execution adapter is registered for this engine"})()
            else:
                result = asyncio.run(execute_engine(engine_name, target_type, target_value, scan.config or {}))

            finished = timezone.now()
            duration = (finished - (execution.started_at or finished)).total_seconds()
            with transaction.atomic():
                execution.status = ScanEngineExecution.ExecutionStatus.FAILED if result.status == "failed" else ScanEngineExecution.ExecutionStatus.COMPLETED
                execution.progress = 100
                execution.completed_at = finished
                execution.duration = duration
                execution.findings_found = len(result.findings)
                execution.evidences_collected = len(result.evidence)
                execution.result_data = {"status": result.status, "metrics": result.metrics, "error": result.error, "evidence": result.evidence}
                execution.error_message = result.error or ""
                execution.logs = f"Completed real engine execution in {duration:.3f}s"
                execution.save()
                persisted = _persist_findings(scan, execution, result.findings, result.evidence)
                engine_results[engine_name] = {"status": result.status, "metrics": result.metrics, "error": result.error, "findings_count": len(result.findings), "persisted_findings": persisted, "evidence_count": len(result.evidence)}
                scan.engine_results = engine_results
                scan.progress = round(((index + 1) / total) * 100, 2)
                scan.current_phase = "completed" if index + 1 == total else engine_obj.category
                scan.save(update_fields=["engine_results", "progress", "current_phase", "updated_at"])
                _log(scan, f"Engine {engine_name} completed", context=engine_results[engine_name], execution=execution)

            _publish_event(str(scan.pk), {"type": "engine.completed", "scan_id": str(scan.pk), "engine": engine_name, "progress": scan.progress, "findings": len(result.findings), "evidence": len(result.evidence), "status": result.status})

            if result.status == "failed":
                raise RuntimeError(result.error or f"Real engine {engine_name} failed")

        with transaction.atomic():
            scan.refresh_from_db()
            _aggregate_scan(scan)
            scan.status = Scan.Status.COMPLETED
            scan.progress = 100
            scan.current_phase = "completed"
            scan.current_engine = ""
            scan.completed_at = timezone.now()
            scan.duration = (scan.completed_at - started).total_seconds()
            scan.save()
            if scan.asset_id:
                scan.asset.scan_count = scan.asset.scan_count + 1
                scan.asset.last_scanned_at = scan.completed_at
                scan.asset.save(update_fields=["scan_count", "last_scanned_at", "updated_at"])
            _log(scan, "Scan completed from real engine execution", context={"findings": scan.findings_count, "security_score": scan.security_score, "risk_level": scan.risk_level})

        payload = {"status": "completed", "scan_id": str(scan.pk), "findings_count": scan.findings_count, "security_score": scan.security_score, "risk_level": scan.risk_level}
        _publish_event(str(scan.pk), {"type": "scan.completed", **payload})
        return payload
    except Exception as exc:
        tb = traceback.format_exc()
        with transaction.atomic():
            scan.refresh_from_db()
            scan.status = Scan.Status.FAILED
            scan.completed_at = timezone.now()
            scan.duration = (scan.completed_at - started).total_seconds()
            scan.error_message = str(exc)
            scan.error_traceback = tb
            scan.current_phase = "failed"
            scan.save()
            _log(scan, "Real scan execution failed", ScanLog.Level.ERROR, context={"error": str(exc), "task_id": self.request.id})
        _publish_event(str(scan.pk), {"type": "scan.failed", "scan_id": str(scan.pk), "error": str(exc)})
        raise
