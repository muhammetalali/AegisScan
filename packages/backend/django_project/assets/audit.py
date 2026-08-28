from __future__ import annotations

from typing import Any

from audit.models import AuditLog
from audit.services import append_audit


def _request_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (forwarded.split(",", 1)[0].strip() if forwarded else request.META.get("REMOTE_ADDR")) or "0.0.0.0"


def record_asset_audit(request, *, action: str, asset, changes: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None):
    return append_audit(
        action=action,
        ip_address=_request_ip(request),
        user=request.user,
        result=AuditLog.Result.SUCCESS,
        resource_type="Asset",
        resource_id=str(asset.pk),
        resource_repr=asset.name,
        changes=changes or {},
        metadata={
            "project_id": str(asset.project_id),
            "asset_type": asset.type,
            "environment": asset.environment,
            **(metadata or {}),
        },
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        session_id=request.session.session_key or "",
        request_id=getattr(request, "request_id", None),
    )


def record_asset_relationship_audit(request, *, action: str, relationship, changes: dict[str, Any] | None = None):
    return append_audit(
        action=action,
        ip_address=_request_ip(request),
        user=request.user,
        result=AuditLog.Result.SUCCESS,
        resource_type="AssetRelationship",
        resource_id=str(relationship.pk),
        resource_repr=f"{relationship.source_id}->{relationship.target_id}",
        changes=changes or {},
        metadata={
            "project_id": str(relationship.project_id),
            "source_asset_id": str(relationship.source_id),
            "target_asset_id": str(relationship.target_id),
            "relationship_type": relationship.relationship_type,
        },
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        session_id=request.session.session_key or "",
        request_id=getattr(request, "request_id", None),
    )


def record_asset_technology_audit(request, *, action: str, technology, changes: dict[str, Any] | None = None):
    return append_audit(
        action=action,
        ip_address=_request_ip(request),
        user=request.user,
        result=AuditLog.Result.SUCCESS,
        resource_type="TechnologyFingerprint",
        resource_id=str(technology.pk),
        resource_repr=technology.name,
        changes=changes or {},
        metadata={"asset_id": str(technology.asset_id)},
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        session_id=request.session.session_key or "",
        request_id=getattr(request, "request_id", None),
    )