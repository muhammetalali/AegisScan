from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from scans.models import Scan
from vulnerabilities.models import Vulnerability
from vulnerabilities.serializers import VulnerabilitySerializer

from ..core.security import verify_token
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter()
security = HTTPBearer(auto_error=False)


async def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@sync_to_async
def _get_scan(validation_id: str, user: dict[str, Any]) -> Scan | None:
    scan = Scan.objects.select_related("project").filter(config__validation_id=validation_id).first()
    if not scan:
        return None
    if user.get("is_superuser"):
        return scan
    allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
    return scan if allowed else None


def _target(scan: Scan) -> dict[str, Any]:
    config = scan.config or {}
    return {
        "type": config.get("target_type", scan.scan_type),
        "value": config.get("target_value", ""),
        "scope": config.get("scope"),
    }


@sync_to_async
def _provenance(validation_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
    scan = Scan.objects.select_related("project").filter(config__validation_id=validation_id).first()
    if not scan:
        return None
    if not user.get("is_superuser"):
        allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
        if not allowed:
            return None

    findings = (
        Vulnerability.objects.filter(scan=scan)
        .prefetch_related("evidences")
        .order_by("-risk_score", "-created_at")
    )
    finding_rows: list[dict[str, Any]] = []
    for finding in findings:
        evidences = list(finding.evidences.all())
        finding_rows.append(
            {
                "finding_id": str(finding.pk),
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": finding.status,
                "validation_status": finding.validation_status,
                "source_engine": finding.source_engine,
                "raw_data": finding.raw_data,
                "target": _target(scan),
                "timestamps": {
                    "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                    "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None,
                    "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
                    "validated_at": finding.validated_at.isoformat() if finding.validated_at else None,
                },
                "risk": {
                    "risk_score": finding.risk_score,
                    "cvss_score": finding.cvss_score,
                    "exploitability": finding.exploitability,
                    "business_impact": finding.business_impact,
                },
                "evidence": [
                    {
                        "evidence_id": str(evidence.pk),
                        "type": evidence.type,
                        "quality": evidence.quality,
                        "source": evidence.source,
                        "description": evidence.description,
                        "location": evidence.location,
                        "confidence": evidence.confidence,
                        "corroboration_count": evidence.corroboration_count,
                        "collected_at": evidence.collected_at.isoformat() if evidence.collected_at else None,
                        "verified_at": evidence.verified_at.isoformat() if evidence.verified_at else None,
                        "metadata": evidence.metadata,
                    }
                    for evidence in evidences
                ],
            }
        )

    return {
        "validation_id": validation_id,
        "scan_id": str(scan.pk),
        "project_id": str(scan.project_id),
        "scan_status": scan.status,
        "scan_started_at": scan.started_at.isoformat() if scan.started_at else None,
        "scan_completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "target": _target(scan),
        "finding_count": len(finding_rows),
        "findings": finding_rows,
    }


@router.get("/validations/{validation_id}/provenance")
async def finding_provenance(validation_id: str, user: dict[str, Any] = Depends(current_user)):
    result = await _provenance(validation_id, user)
    if result is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return result


@router.get("/findings/{finding_id}/provenance")
async def finding_detail_provenance(finding_id: str, user: dict[str, Any] = Depends(current_user)):
    finding = await _get_finding(finding_id, user)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@sync_to_async
def _get_finding(finding_id: str, user: dict[str, Any]) -> dict[str, Any] | None:
    finding = Vulnerability.objects.select_related("scan", "scan__project").prefetch_related("evidences").filter(pk=finding_id).first()
    if not finding:
        return None
    scan = finding.scan
    if not user.get("is_superuser"):
        allowed = scan.project.owner_id == user.get("id") or scan.project.memberships.filter(user_id=user.get("id")).exists()
        if not allowed:
            return None
    evidences = list(finding.evidences.all())
    config = scan.config or {}
    return {
        "finding_id": str(finding.pk),
        "finding": VulnerabilitySerializer(finding).data,
        "source_engine": finding.source_engine,
        "raw_data": finding.raw_data,
        "target": {
            "type": config.get("target_type", scan.scan_type),
            "value": config.get("target_value", ""),
            "scope": config.get("scope"),
        },
        "timestamps": {
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
            "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
            "validated_at": finding.validated_at.isoformat() if finding.validated_at else None,
        },
        "risk": {
            "risk_score": finding.risk_score,
            "cvss_score": finding.cvss_score,
            "exploitability": finding.exploitability,
            "business_impact": finding.business_impact,
        },
        "evidence": [
            {
                "evidence_id": str(evidence.pk),
                "type": evidence.type,
                "quality": evidence.quality,
                "source": evidence.source,
                "description": evidence.description,
                "location": evidence.location,
                "confidence": evidence.confidence,
                "corroboration_count": evidence.corroboration_count,
                "collected_at": evidence.collected_at.isoformat() if evidence.collected_at else None,
                "verified_at": evidence.verified_at.isoformat() if evidence.verified_at else None,
                "metadata": evidence.metadata,
            }
            for evidence in evidences
        ],
    }
