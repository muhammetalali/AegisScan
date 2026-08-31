from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from scans.models import Scan
from vulnerabilities.models import Vulnerability
from vulnerabilities.serializers import VulnerabilitySerializer

from ..core.security import verify_token
from ..services.engine_adapters import SUPPORTED_REAL_ENGINES
from ..services.remediation_validation import RemediationValidationSuite

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


class ValidationCreate(BaseModel):
    project_id: str = Field(min_length=1)
    target_type: str = Field(description="url | ip | code | api")
    target_value: str
    profile: str = "full"
    engines: list[str] = Field(default_factory=list)
    scope: str | None = None
    authorized: bool
    include_subdomains: bool = False
    duration_minutes: int = Field(default=60, ge=1, le=1440)
    rate_limit: int = Field(default=5, ge=1, le=1000)
    extra: dict[str, Any] = Field(default_factory=dict)


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
    scan_id: str
    project_id: str
    target_type: str
    target_value: str
    profile: str
    engines: list[str]
    scope: str | None
    status: str
    progress: float
    current_phase: str
    created_at: str
    audit_note: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@sync_to_async
def _project_accessible(project_id: str, user: dict) -> bool:
    from projects.models import Project, ProjectMembership

    if user.get("is_superuser"):
        return Project.objects.filter(pk=project_id).exists()
    return Project.objects.filter(pk=project_id).filter(
        owner=user.get("id")
    ).exists() or ProjectMembership.objects.filter(
        project_id=project_id,
        user_id=user.get("id"),
    ).exists()


@sync_to_async
def _create_scan(
    body: ValidationCreate,
    user: dict,
    validation_id: str,
) -> tuple[Scan, str]:
    from projects.models import Project

    try:
        project = Project.objects.get(pk=body.project_id)
    except Project.DoesNotExist as exc:
        raise ValueError("Project not found") from exc

    if not user.get("is_superuser"):
        is_owner = str(project.owner_id) == str(user.get("id"))
        is_admin = project.memberships.filter(
            user_id=user.get("id"),
            role__in=["owner", "admin"],
        ).exists()
        if not (is_owner or is_admin):
            raise PermissionError("Only project owners and administrators can start validations")

    scan = Scan.objects.create(
        project=project,
        name=f"Validation {validation_id}",
        scan_type=body.target_type,
        status=Scan.Status.QUEUED,
        depth=Scan.Depth.STANDARD,
        engines=list(body.engines),
        config={
            **body.extra,
            "validation_id": validation_id,
            "target_type": body.target_type,
            "target_value": body.target_value.strip(),
            "scope": body.scope or body.target_value.strip(),
            "profile": body.profile,
            "authorized": True,
            "include_subdomains": body.include_subdomains,
            "duration_minutes": body.duration_minutes,
            "rate_limit": body.rate_limit,
            "execution_mode": "real-celery-postgresql",
        },
        initiated_by_id=user.get("id"),
    )
    return scan, str(project.pk)


@sync_to_async
def _queue_scan(scan_id: str):
    from ..tasks.scan_tasks import run_scan
    task = run_scan.delay(scan_id)
    Scan.objects.filter(pk=scan_id).update(celery_task_id=task.id)
    return task.id


@sync_to_async
def _get_validation(vid: str, user: dict) -> dict[str, Any] | None:
    scan = Scan.objects.select_related("project").prefetch_related("engine_executions__engine").filter(
        config__validation_id=vid,
    ).first()
    if not scan:
        return None
    if not user.get("is_superuser"):
        allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
        if not allowed:
            return None
    return {
        "id": vid,
        "scan_id": str(scan.pk),
        "project_id": str(scan.project_id),
        "target_type": scan.config.get("target_type", scan.scan_type),
        "target_value": scan.config.get("target_value", ""),
        "profile": scan.config.get("profile", "full"),
        "engines": scan.engines or [],
        "scope": scan.config.get("scope"),
        "status": scan.status,
        "progress": float(scan.progress),
        "current_phase": scan.current_phase or "queued",
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "celery_task_id": scan.celery_task_id,
        "audit_note": "REAL_EXECUTION scope authorization enforced; persisted in PostgreSQL",
        "engine_executions": [
            {
                "id": str(item.pk),
                "engine": item.engine.name,
                "status": item.status,
                "progress": item.progress,
                "findings": item.findings_found,
                "evidence": item.evidences_collected,
                "error": item.error_message or None,
                "started_at": item.started_at.isoformat() if item.started_at else None,
                "completed_at": item.completed_at.isoformat() if item.completed_at else None,
            }
            for item in scan.engine_executions.all()
        ],
        "error": scan.error_message or None,
        "findings_count": scan.findings_count,
        "security_score": scan.security_score,
        "risk_level": scan.risk_level,
    }


@sync_to_async
def _get_findings(vid: str, user: dict) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    scan = Scan.objects.select_related("project").filter(config__validation_id=vid).first()
    if not scan:
        return None
    if not user.get("is_superuser"):
        allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
        if not allowed:
            return None
    findings = Vulnerability.objects.filter(scan=scan).select_related("asset").order_by("-risk_score", "-created_at")
    return (
        {
            "validation_id": vid,
            "scan_id": str(scan.pk),
            "status": scan.status,
            "count": findings.count(),
        },
        VulnerabilitySerializer(findings, many=True).data,
    )


@sync_to_async
def _get_finding_detail(finding_id: str, user: dict) -> dict[str, Any] | None:
    qs = Vulnerability.objects.select_related("scan", "project", "asset").filter(raw_data__id=finding_id)
    if not user.get("is_superuser"):
        qs = qs.filter(project__owner_id=user.get("id")) | qs.filter(project__members=user.get("id"))
    finding = qs.first()
    if not finding:
        return None
    return {
        "finding": VulnerabilitySerializer(finding).data,
        "validation_id": finding.scan.config.get("validation_id"),
        "scan_id": str(finding.scan_id),
    }


@sync_to_async
def _get_results(vid: str, user: dict) -> dict[str, Any] | None:
    scan = Scan.objects.select_related("project").filter(config__validation_id=vid).first()
    if not scan:
        return None
    if not user.get("is_superuser"):
        allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
        if not allowed:
            return None
    findings = Vulnerability.objects.filter(scan=scan).select_related("asset").prefetch_related("evidences").order_by("-risk_score", "-created_at")
    evidence = [
        {
            "id": str(item.pk),
            "vulnerability_id": str(item.vulnerability_id),
            "type": item.type,
            "quality": item.quality,
            "source": item.source,
            "description": item.description,
            "location": item.location,
            "confidence": item.confidence,
            "collected_at": item.collected_at.isoformat(),
        }
        for finding in findings
        for item in finding.evidences.all()
    ]
    return {
        "id": vid,
        "scan_id": str(scan.pk),
        "status": scan.status,
        "target_type": scan.config.get("target_type", scan.scan_type),
        "target_value": scan.config.get("target_value", ""),
        "scope": scan.config.get("scope"),
        "profile": scan.config.get("profile", "full"),
        "findings": VulnerabilitySerializer(findings, many=True).data,
        "evidence": evidence,
        "metrics": scan.engine_results or {},
        "error": scan.error_message or None,
        "security_score": scan.security_score,
        "risk_level": scan.risk_level,
        "celery_task_id": scan.celery_task_id,
    }


@router.post("/validations", response_model=ValidationOut, status_code=201)
async def create_real_validation(body: ValidationCreate, user: dict = Depends(current_user)):
    if body.target_type not in {"url", "ip", "code", "api"}:
        raise HTTPException(status_code=400, detail="Unsupported target_type")
    if not body.authorized:
        raise HTTPException(status_code=400, detail="authorized must be true - scope authorization required")
    if not body.target_value.strip():
        raise HTTPException(status_code=400, detail="target_value is required")
    if not body.engines:
        raise HTTPException(status_code=400, detail="At least one real execution engine is required")
    invalid = sorted(set(body.engines) - SUPPORTED_REAL_ENGINES)
    if invalid:
        raise HTTPException(status_code=400, detail={"message": "Requested engine has no real executor", "unsupported_engines": invalid})
    if not await _project_accessible(body.project_id, user):
        raise HTTPException(status_code=403, detail="You do not have access to this project")

    validation_id = f"val-{uuid4().hex[:8]}"
    try:
        scan, project_id = await _create_scan(body, user, validation_id)
        task_id = await _queue_scan(str(scan.pk))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ValidationOut(
        id=validation_id,
        scan_id=str(scan.pk),
        project_id=project_id,
        target_type=body.target_type,
        target_value=body.target_value.strip(),
        profile=body.profile,
        engines=body.engines,
        scope=body.scope or body.target_value.strip(),
        status="queued",
        progress=0,
        current_phase="queued",
        created_at=scan.created_at.isoformat(),
        audit_note=f"REAL_EXECUTION celery_task={task_id}",
    )


@router.get("/validations/{vid}/progress")
async def validation_progress(vid: str, user: dict = Depends(current_user)):
    item = await _get_validation(vid, user)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return item


@router.post("/validations/{vid}/pause")
async def pause_validation(vid: str, user: dict = Depends(current_user)):
    item = await _get_validation(vid, user)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    if item["status"] in {"queued", "running"}:
        await _set_scan_status(item["scan_id"], "paused")
    return await _get_validation(vid, user)


@router.post("/validations/{vid}/resume")
async def resume_validation(vid: str, user: dict = Depends(current_user)):
    item = await _get_validation(vid, user)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    if item["status"] == "paused":
        await _set_scan_status(item["scan_id"], "running")
    return await _get_validation(vid, user)


@router.post("/validations/{vid}/cancel")
async def cancel_validation(vid: str, user: dict = Depends(current_user)):
    item = await _get_validation(vid, user)
    if item is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    if item["status"] not in {"completed", "failed", "cancelled"}:
        await _set_scan_status(item["scan_id"], "cancelled")
    return await _get_validation(vid, user)


@sync_to_async
def _set_scan_status(scan_id: str, status: str) -> None:
    Scan.objects.filter(pk=scan_id).update(status=status, updated_at=datetime.now(timezone.utc))


@router.get("/validations/{vid}/results")
async def validation_results(vid: str, user: dict = Depends(current_user)):
    result = await _get_results(vid, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return result


@router.get("/validations/{vid}/findings")
async def validation_findings(vid: str, user: dict = Depends(current_user)):
    result = await _get_findings(vid, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    meta, findings = result
    return {**meta, "findings": findings}


@router.get("/findings/{finding_id}")
async def validation_finding_detail(finding_id: str, user: dict = Depends(current_user)):
    result = await _get_finding_detail(finding_id, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


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
