from typing import List, Optional
from uuid import UUID, uuid4
from asgiref.sync import sync_to_async
from django.db import IntegrityError, transaction
from django.utils.text import slugify
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from fastapi_app.core.security import verify_token

router = APIRouter(); _bearer = HTTPBearer(auto_error=False)


class AssetCreate(BaseModel):
    project_id: str; name: str; type: str; description: str = ""; environment: str = "development"; criticality: str = "medium"; configuration: dict = Field(default_factory=dict); tags: List[str] = Field(default_factory=list)


class AssetResponse(BaseModel):
    id: str; project_id: str; name: str; slug: str; type: str; description: str; environment: str; criticality: str; configuration: dict; tags: List[str]; is_active: bool; scan_count: int; last_scanned_at: Optional[str] = None; created_at: str; updated_at: str


class AssetUpdate(BaseModel):
    name: Optional[str] = None; description: Optional[str] = None; environment: Optional[str] = None; criticality: Optional[str] = None; configuration: Optional[dict] = None; tags: Optional[List[str]] = None; is_active: Optional[bool] = None


class AssetAuthorizationUpdate(BaseModel):
    authorized: bool
    reason: str = Field(default="", max_length=500)
    correlation_id: Optional[UUID] = None
    expires_at: Optional[str] = None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)):
    if not credentials: raise HTTPException(status_code=401, detail="Not authenticated")
    user = await verify_token(credentials.credentials)
    if not user: raise HTTPException(status_code=401, detail="Invalid token")
    return user


def _asset_response(asset) -> AssetResponse:
    return AssetResponse(id=str(asset.id), project_id=str(asset.project_id), name=asset.name, slug=asset.slug, type=asset.type, description=asset.description, environment=asset.environment, criticality=asset.criticality, configuration=asset.configuration or {}, tags=asset.tags or [], is_active=asset.is_active, scan_count=asset.scan_count, last_scanned_at=asset.last_scanned_at.isoformat() if asset.last_scanned_at else None, created_at=asset.created_at.isoformat(), updated_at=asset.updated_at.isoformat())


def _request_id_from_headers(request: Request) -> UUID:
    raw = request.headers.get("X-Request-ID")
    if raw:
        try: return UUID(raw)
        except ValueError: raise HTTPException(status_code=422, detail="X-Request-ID must be a valid UUID")
    return uuid4()


def _request_ip(request: Request) -> str:
    """Return a database-safe source address for audit logging.

    ASGI test clients and some upstream adapters can expose a symbolic host
    (for example, ``testclient``) instead of an actual IP. AuditLog stores this
    field in PostgreSQL's ``inet`` type, so invalid values must never reach the
    database. We fail closed to the unspecified IPv4 address when no valid
    source IP is available.
    """
    import ipaddress

    host = request.client.host if request.client and request.client.host else ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return "0.0.0.0"


@sync_to_async
def _accessible_assets(user_id: str, project_id: Optional[str] = None):
    from django_project.assets.models import Asset
    qs = (Asset.objects.select_related("project", "owner").filter(project__owner_id=user_id) | Asset.objects.select_related("project", "owner").filter(project__members__id=user_id)).distinct()
    if project_id: qs = qs.filter(project_id=project_id)
    return list(qs.order_by("-created_at"))


@sync_to_async
def _has_project_access(project_id: str, user_id: str) -> bool:
    from django_project.projects.models import Project
    return Project.objects.filter(id=project_id).filter(owner_id=user_id).exists() or Project.objects.filter(id=project_id, members__id=user_id).exists()


@sync_to_async
def _get_asset(asset_id: str, user_id: str):
    from django_project.assets.models import Asset
    return Asset.objects.select_related("project", "owner").filter(pk=asset_id, project__owner_id=user_id).first() or Asset.objects.select_related("project", "owner").filter(pk=asset_id, project__members__id=user_id).first()


@router.get("/", response_model=List[AssetResponse])
async def list_assets(project_id: Optional[str] = None, asset_type: Optional[str] = None, environment: Optional[str] = None, criticality: Optional[str] = None, is_active: Optional[bool] = None, search: Optional[str] = None, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(get_current_user)):
    assets = await _accessible_assets(str(user.get("user_id")), project_id)
    if asset_type: assets = [a for a in assets if a.type == asset_type]
    if environment: assets = [a for a in assets if a.environment == environment]
    if criticality: assets = [a for a in assets if a.criticality == criticality]
    if is_active is not None: assets = [a for a in assets if a.is_active == is_active]
    if search:
        needle = search.casefold(); assets = [a for a in assets if needle in a.name.casefold() or needle in a.description.casefold() or any(needle in str(t).casefold() for t in (a.tags or []))]
    return [_asset_response(a) for a in assets[offset:offset + limit]]


@sync_to_async
def _create_asset(data: AssetCreate, user_id: str):
    from django_project.assets.models import Asset
    from django_project.projects.models import Project
    project = Project.objects.filter(id=data.project_id).filter(owner_id=user_id).first() or Project.objects.filter(id=data.project_id, members__id=user_id).first()
    if not project: raise HTTPException(status_code=404, detail="Project not found or inaccessible")
    if (data.configuration or {}).get("authorized") is not None: raise HTTPException(status_code=403, detail="Asset authorization can only be changed through the authorization endpoint")
    base_slug = slugify(data.name) or "asset"; slug = base_slug; suffix = 2
    while Asset.objects.filter(project=project, slug=slug).exists(): slug = f"{base_slug}-{suffix}"; suffix += 1
    return Asset.objects.create(project=project, owner_id=user_id, name=data.name, slug=slug, type=data.type, description=data.description, environment=data.environment, criticality=data.criticality, configuration=data.configuration, tags=data.tags)


@router.post("/", response_model=AssetResponse, status_code=201)
async def create_asset(asset: AssetCreate, user=Depends(get_current_user)):
    return _asset_response(await _create_asset(asset, str(user.get("user_id"))))


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, user=Depends(get_current_user)):
    asset = await _get_asset(asset_id, str(user.get("user_id")))
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_response(asset)


@sync_to_async
def _update_asset(asset_id: str, update: AssetUpdate, user_id: str, request_id: UUID, ip_address: str, user_agent: str):
    from django_project.audit.models import AuditLog
    from django_project.assets.models import Asset, AssetAuthorization
    with transaction.atomic():
        asset = Asset.objects.select_for_update().filter(pk=asset_id, project__owner_id=user_id).first() or Asset.objects.select_for_update().filter(pk=asset_id, project__members__id=user_id).first()
        if not asset: raise HTTPException(status_code=404, detail="Asset not found")
        data = update.model_dump(exclude_unset=True)
        if "configuration" in data and data["configuration"] is not None and "authorized" in data["configuration"]: raise HTTPException(status_code=403, detail="Asset authorization can only be changed through the authorization endpoint")
        if "configuration" in data and data["configuration"] is not None:
            latest = AssetAuthorization.objects.filter(asset=asset).order_by("-created_at", "-id").first()
            if latest and latest.authorized and latest.is_currently_valid:
                request_bound = AssetAuthorization.objects.filter(request_id=request_id).first()
                if request_bound: raise HTTPException(status_code=409, detail="Request ID is already bound to an authorization decision")
                data["configuration"] = dict(data["configuration"]); data["configuration"]["authorized"] = False
                decision = AssetAuthorization.objects.create(asset=asset, actor_id=user_id, authorized=False, target_snapshot=(latest.target_snapshot or _asset_target(asset))[:500], reason="Authorization revoked because asset configuration changed", correlation_id=uuid4(), request_id=request_id, supersedes=latest)
                AuditLog.objects.create(
                    user_id=user_id,
                    action="asset_authorization_revoke",
                    result=AuditLog.Result.SUCCESS,
                    resource_type="AssetAuthorization",
                    resource_id=str(decision.id),
                    resource_repr=f"Asset {asset.id} authorization decision",
                    changes={"authorized": False, "supersedes": str(latest.id)},
                    metadata={"asset_id": str(asset.id), "asset_identity_snapshot": str(decision.asset_identity_snapshot), "target_snapshot": decision.target_snapshot, "reason": decision.reason, "correlation_id": str(decision.correlation_id), "request_id": str(decision.request_id), "trigger": "asset_configuration_change"},
                    ip_address=ip_address,
                    user_agent=user_agent[:10000],
                    request_id=decision.request_id,
                )
        if "name" in data: data["slug"] = slugify(data["name"]) or asset.slug
        for key, value in data.items(): setattr(asset, key, value)
        asset.save(); return asset


def _asset_target(asset) -> str:
    c = asset.configuration or {}; return str(c.get("url") or c.get("host") or c.get("ip") or c.get("domain") or c.get("cidr") or "")


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, update: AssetUpdate, request: Request, user=Depends(get_current_user)):
    request_id = _request_id_from_headers(request)
    return _asset_response(await _update_asset(asset_id, update, str(user.get("user_id")), request_id, _request_ip(request), request.headers.get("User-Agent", "")))


@sync_to_async
def _set_asset_authorization(asset_id: str, user_id: str, authorized: bool, reason: str, is_staff: bool, correlation_id: Optional[UUID], expires_at, request_id: UUID, ip_address: str, user_agent: str):
    from datetime import datetime, timezone as dt_timezone
    from django_project.audit.models import AuditLog
    from django_project.assets.models import Asset, AssetAuthorization
    with transaction.atomic():
        asset = Asset.objects.select_related("project").select_for_update(of=("self",)).filter(pk=asset_id).first()
        if not asset: raise HTTPException(status_code=404, detail="Asset not found")
        if not is_staff and str(asset.project.owner_id) != str(user_id): raise HTTPException(status_code=403, detail="Only the project owner or staff may change asset network authorization")
        effective_correlation = correlation_id or uuid4()
        existing = AssetAuthorization.objects.filter(correlation_id=effective_correlation).first()
        if existing:
            if existing.asset_id != asset.id or existing.authorized != authorized or existing.reason != reason: raise HTTPException(status_code=409, detail="Correlation ID is already bound to a different authorization decision")
            return asset
        request_bound = AssetAuthorization.objects.filter(request_id=request_id).first()
        if request_bound: raise HTTPException(status_code=409, detail="Request ID is already bound to an authorization decision")
        expiry = None
        if expires_at:
            try: expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            except ValueError: raise HTTPException(status_code=422, detail="expires_at must be a valid ISO-8601 timestamp")
            if expiry <= datetime.now(dt_timezone.utc): raise HTTPException(status_code=422, detail="expires_at must be in the future")
        latest = AssetAuthorization.objects.filter(asset=asset).order_by("-created_at", "-id").first()
        target = _asset_target(asset); configuration = dict(asset.configuration or {}); configuration["authorized"] = authorized; asset.configuration = configuration
        asset.save(update_fields=["configuration", "updated_at"])
        try:
            with transaction.atomic():
                decision = AssetAuthorization.objects.create(asset=asset, actor_id=user_id, authorized=authorized, target_snapshot=target[:500], reason=reason, correlation_id=effective_correlation, request_id=request_id, supersedes=latest, expires_at=expiry)
        except IntegrityError:
            existing = AssetAuthorization.objects.filter(correlation_id=effective_correlation).first()
            if existing and existing.asset_id == asset.id and existing.authorized == authorized and existing.reason == reason: return asset
            raise
        action = "asset_authorization_grant" if authorized else "asset_authorization_revoke"
        AuditLog.objects.create(
            user_id=user_id,
            action=action,
            result=AuditLog.Result.SUCCESS,
            resource_type="AssetAuthorization",
            resource_id=str(decision.id),
            resource_repr=f"Asset {asset.id} authorization decision",
            changes={"authorized": authorized, "supersedes": str(latest.id) if latest else None},
            metadata={"asset_id": str(asset.id), "asset_identity_snapshot": str(decision.asset_identity_snapshot), "target_snapshot": decision.target_snapshot, "reason": reason, "correlation_id": str(decision.correlation_id), "request_id": str(decision.request_id), "expires_at": decision.expires_at.isoformat() if decision.expires_at else None},
            ip_address=ip_address,
            user_agent=user_agent[:10000],
            request_id=decision.request_id,
        )
        return asset


@router.post("/{asset_id}/authorization", response_model=AssetResponse)
async def set_asset_authorization(asset_id: str, update: AssetAuthorizationUpdate, request: Request, user=Depends(get_current_user)):
    request_id = _request_id_from_headers(request)
    return _asset_response(await _set_asset_authorization(asset_id, str(user.get("user_id")), update.authorized, update.reason, bool(user.get("is_staff")), update.correlation_id, update.expires_at, request_id, _request_ip(request), request.headers.get("User-Agent", "")))


@sync_to_async
def _delete_asset(asset_id: str, user_id: str):
    from django_project.assets.models import Asset
    asset = Asset.objects.filter(pk=asset_id, project__owner_id=user_id).first() or Asset.objects.filter(pk=asset_id, project__members__id=user_id).first()
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    asset.delete()


@router.delete("/{asset_id}")
async def delete_asset(asset_id: str, user=Depends(get_current_user)):
    await _delete_asset(asset_id, str(user.get("user_id"))); return {"deleted": True, "asset_id": asset_id}


@router.post("/{asset_id}/scan")
async def scan_asset(asset_id: str, scan_type: str = "full_validation", depth: str = "standard", user=Depends(get_current_user)):
    asset = await _get_asset(asset_id, str(user.get("user_id")))
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    raise HTTPException(status_code=501, detail="Asset scanning is provided by the scan orchestration service; no synthetic scan is returned here")


@sync_to_async
def _technologies(asset_id: str, user_id: str):
    asset = _get_asset_sync(asset_id, user_id); return list(asset.technologies.all()) if asset else None


def _get_asset_sync(asset_id: str, user_id: str):
    from django_project.assets.models import Asset
    return Asset.objects.filter(pk=asset_id).filter(project__owner_id=user_id).first() or Asset.objects.filter(pk=asset_id, project__members__id=user_id).first()


@router.get("/{asset_id}/technologies")
async def get_asset_technologies(asset_id: str, user=Depends(get_current_user)):
    technologies = await _technologies(asset_id, str(user.get("user_id")))
    if technologies is None: raise HTTPException(status_code=404, detail="Asset not found")
    return [{"id": str(t.id), "name": t.name, "version": t.version, "category": t.category, "confidence": t.confidence, "source": t.source, "evidence": t.evidence, "detected_at": t.detected_at.isoformat()} for t in technologies]


@router.post("/{asset_id}/technologies")
async def add_technology(asset_id: str, name: str, version: str = "", category: str = "unknown", confidence: float = 0.0, user=Depends(get_current_user)):
    from django_project.assets.models import TechnologyFingerprint
    asset = await _get_asset(asset_id, str(user.get("user_id")))
    if not asset: raise HTTPException(status_code=404, detail="Asset not found")
    return {"id": str((await sync_to_async(TechnologyFingerprint.objects.create)(asset=asset, name=name, version=version, category=category, confidence=confidence)).id), "name": name, "version": version, "category": category, "confidence": confidence}