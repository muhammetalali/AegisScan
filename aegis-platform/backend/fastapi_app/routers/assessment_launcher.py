from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import socket
import uuid
import zipfile
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from asgiref.sync import sync_to_async
from django.db import transaction
from django.utils.text import slugify
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project
from ..core.dependencies import get_current_user
from ..services.asset_authorization_governance import (
    AssetAuthorizationGovernanceError,
    asset_authorization_version,
    govern_asset_authorization,
    initialize_asset_configuration,
    replace_asset_configuration_preserving_authorization,
)
from ..services.authorization_guard import asset_target
from ..services.capability_planner import plan_capabilities
from ..services.capability_registry import get_capability
from ..services.governed_action_requests import (
    GovernedActionRequestConflict,
    GovernedActionRequestError,
    create_governed_action_request,
    governed_action_request_view,
)

router = APIRouter()

Depth = Literal['quick', 'standard', 'deep', 'comprehensive']
TargetMode = Literal['network', 'ip', 'url']
_MAX_UPLOAD_BYTES = int(os.getenv('AEGIS_ASSESSMENT_UPLOAD_MAX_BYTES', str(64 * 1024 * 1024)))
_MAX_ZIP_FILES = 5000
_MAX_ZIP_BYTES = 256 * 1024 * 1024


class PrepareAssessmentRequest(BaseModel):
    project_id: str
    mode: TargetMode
    target: str = Field(min_length=1, max_length=2048)
    depth: Depth = 'standard'
    name: str = Field(default='', max_length=200)


def _project_for_launcher(project_id: str, user_id: str, is_staff: bool) -> Project:
    project = Project.objects.filter(pk=project_id, status=Project.Status.ACTIVE).first()
    if project is None:
        raise HTTPException(status_code=404, detail='Project not found')
    if not is_staff and str(project.owner_id) != str(user_id):
        raise HTTPException(
            status_code=403,
            detail='Assessment Launcher is available to the project owner or staff.',
        )
    return project


def _normalize_web_target(value: str) -> str:
    candidate = str(value or '').strip()
    if not candidate:
        raise HTTPException(status_code=422, detail='URL or domain is required')
    if '://' not in candidate:
        candidate = 'https://' + candidate
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {'http', 'https'}:
            raise HTTPException(status_code=422, detail='Only HTTP and HTTPS targets are supported')
        if parsed.username is not None or parsed.password is not None:
            raise HTTPException(status_code=422, detail='Target credentials must not be embedded in the URL')
        if parsed.query or parsed.fragment:
            raise HTTPException(status_code=422, detail='Use a base URL without query strings or fragments')
        if not parsed.hostname:
            raise HTTPException(status_code=422, detail='Target hostname is missing')
        host = parsed.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail='Target URL is invalid') from exc
    netloc = host
    if ':' in host and not host.startswith('['):
        netloc = f'[{host}]'
    if port is not None:
        netloc = f'{netloc}:{port}'
    path = parsed.path or ''
    return urlunsplit((parsed.scheme.lower(), netloc, path, '', ''))


def _normalize_target(mode: TargetMode, value: str) -> tuple[str, str, dict]:
    candidate = str(value or '').strip()
    if mode == 'network':
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail='Network target must be a valid CIDR') from exc
        target = str(network)
        return 'network_range', target, {'cidr': target}
    if mode == 'ip':
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail='IP target must be a valid IPv4 or IPv6 address') from exc
        target = str(address)
        return 'ip_address', target, {'ip': target}
    target = _normalize_web_target(candidate)
    host = urlsplit(target).hostname or ''
    try:
        direct = ipaddress.ip_address(host)
        resolved_ips = [str(direct)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise HTTPException(status_code=422, detail='Target DNS resolution failed') from exc
        resolved_ips = sorted({
            str(ipaddress.ip_address(str(answer[4][0]).split('%', 1)[0]))
            for answer in answers if answer[4]
        })
        if not resolved_ips:
            raise HTTPException(status_code=422, detail='Target DNS resolution returned no addresses')
    return 'website', target, {'url': target, 'resolved_ips': resolved_ips}


def _unique_slug(project: Project, name: str) -> str:
    base = slugify(name) or 'assessment-target'
    slug = base[:220]
    suffix = 2
    while Asset.objects.filter(project=project, slug=slug).exists():
        tail = f'-{suffix}'
        slug = f'{base[:220-len(tail)]}{tail}'
        suffix += 1
    return slug


def _existing_asset(project: Project, asset_type: str, target: str) -> Asset | None:
    for asset in Asset.objects.filter(project=project, type=asset_type, is_active=True).order_by('-created_at'):
        if asset_target(asset) == target:
            return asset
    return None


def _scope_mode() -> str:
    mode = os.getenv('AEGIS_SCAN_SCOPE_MODE', 'asset-authorization').strip().lower()
    if mode not in {'asset-authorization', 'single-operator-lab'}:
        raise HTTPException(status_code=500, detail='AEGIS_SCAN_SCOPE_MODE is invalid')
    return mode


def _current_authorization(asset: Asset) -> AssetAuthorization | None:
    latest = AssetAuthorization.objects.filter(asset=asset).order_by('-created_at', '-id').first()
    target = asset_target(asset)
    if (
        latest is not None
        and latest.authorized is True
        and latest.is_currently_valid
        and latest.target_snapshot == target
    ):
        return latest
    return None


def _ensure_authorization(asset: Asset, actor_id: str) -> dict:
    latest = _current_authorization(asset)
    if latest is not None:
        return {
            'state': 'authorized',
            'source': 'existing-governed-decision',
            'decision': latest,
            'request': None,
        }

    request_id = uuid.uuid4()
    correlation_id = uuid.uuid4()
    mode = _scope_mode()

    if mode == 'single-operator-lab':
        try:
            result = govern_asset_authorization(
                asset_id=str(asset.id),
                project_id=str(asset.project_id),
                actor_id=str(actor_id),
                expected_version=asset_authorization_version(asset),
                authorized=True,
                reason='Single-operator lab mode: Assessment Launcher target activation',
                governed_request_id=str(request_id),
                correlation_id=str(correlation_id),
            )
        except AssetAuthorizationGovernanceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            'state': 'authorized',
            'source': 'single-operator-lab',
            'decision': result.decision,
            'request': None,
        }

    try:
        submitted = create_governed_action_request(
            project_id=str(asset.project_id),
            requested_by_id=str(actor_id),
            action_id='asset.authorization.approve',
            entity_type='asset',
            entity_id=str(asset.id),
            expected_version=asset_authorization_version(asset),
            idempotency_key=f'assessment-launcher-authorization:{request_id}',
            parameters={'reason': 'Assessment Launcher target activation request'},
            correlation_id=correlation_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except GovernedActionRequestConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GovernedActionRequestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        'state': 'pending',
        'source': 'governed-action-request',
        'decision': None,
        'request': governed_action_request_view(submitted),
    }


def _capability_plan(asset: Asset, depth: Depth) -> dict:
    planned = plan_capabilities(asset.type, depth)
    plan = []
    recommended = []
    for item in planned:
        cap = get_capability(item.capability_id)
        row = item.public_dict()
        row['credential_required'] = bool(cap.credential_required)
        plan.append(row)
        if item.execution_ready and not cap.credential_required:
            recommended.append(item.capability_id)
    if not recommended:
        raise HTTPException(
            status_code=409,
            detail=f'No credential-free execution-ready capability is available for {asset.type} at depth {depth}.',
        )
    return {
        'asset_type': asset.type,
        'depth': depth,
        'plan': plan,
        'recommended_capabilities': recommended,
    }


@transaction.atomic
def _prepare_asset(
    *,
    project_id: str,
    user_id: str,
    is_staff: bool,
    asset_type: str,
    target: str,
    configuration: dict,
    depth: Depth,
    name: str,
    tags: list[str],
) -> dict:
    project = _project_for_launcher(project_id, user_id, is_staff)
    asset = _existing_asset(project, asset_type, target)
    created = False
    if asset is None:
        display = name.strip() or target
        config = initialize_asset_configuration(configuration)
        asset = Asset.objects.create(
            project=project,
            owner=project.owner,
            name=display[:200],
            slug=_unique_slug(project, display),
            type=asset_type,
            description='Created automatically by Assessment Launcher',
            environment=project.environment,
            criticality=Asset.Criticality.MEDIUM,
            configuration=config,
            tags=list(dict.fromkeys(['assessment-launcher', *tags])),
        )
        created = True
    else:
        current = _current_authorization(asset)
        if _scope_mode() == 'single-operator-lab' or current is None:
            refreshed = replace_asset_configuration_preserving_authorization(
                asset.configuration,
                configuration,
            )
            if refreshed != (asset.configuration or {}):
                Asset.objects.filter(pk=asset.pk).update(configuration=refreshed)
                asset.configuration = refreshed

    authorization = _ensure_authorization(asset, user_id)
    plan = _capability_plan(asset, depth)
    decision = authorization['decision']
    if authorization['state'] != 'authorized':
        plan['recommended_capabilities'] = []

    return {
        'project_id': str(project.id),
        'scope_mode': _scope_mode(),
        'asset': {
            'id': str(asset.id),
            'name': asset.name,
            'type': asset.type,
            'target': asset_target(asset),
            'created': created,
        },
        'authorization': {
            'state': authorization['state'],
            'source': authorization['source'],
            'id': str(decision.id) if decision is not None else None,
            'target': decision.target_snapshot if decision is not None else asset_target(asset),
            'authorized': bool(decision and decision.authorized),
            'request': authorization['request'],
        },
        **plan,
    }


@router.get('/context')
async def assessment_context(project_id: str, user=Depends(get_current_user)):
    user_id = str(user.get('user_id'))
    is_staff = bool(user.get('is_staff'))
    await sync_to_async(_project_for_launcher)(project_id, user_id, is_staff)

    suggestions: list[str] = []
    configured = [
        item.strip()
        for item in os.getenv('AEGIS_LAB_NETWORK_CIDRS', '').split(',')
        if item.strip()
    ]
    for item in configured:
        try:
            suggestions.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue

    if not suggestions:
        origins = [
            item.strip()
            for item in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',')
            if item.strip()
        ]
        for origin in origins:
            try:
                host = urlsplit(origin).hostname
                if not host:
                    continue
                for answer in socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM):
                    address = ipaddress.ip_address(answer[4][0])
                    if address.is_private:
                        suggestions.append(str(ipaddress.ip_network(f'{address}/24', strict=False)))
                        break
            except (OSError, ValueError):
                continue
            if suggestions:
                break

    return {
        'project_id': project_id,
        'suggested_networks': list(dict.fromkeys(suggestions)),
        'modes': ['network', 'ip', 'url', 'file'],
        'default_depth': 'standard',
        'scope_mode': _scope_mode(),
        'automatic_scope_activation': _scope_mode() == 'single-operator-lab',
    }


@router.post('/prepare', status_code=201)
async def prepare_assessment(request: PrepareAssessmentRequest, user=Depends(get_current_user)):
    asset_type, target, configuration = _normalize_target(request.mode, request.target)
    return await sync_to_async(_prepare_asset)(
        project_id=request.project_id,
        user_id=str(user.get('user_id')),
        is_staff=bool(user.get('is_staff')),
        asset_type=asset_type,
        target=target,
        configuration=configuration,
        depth=request.depth,
        name=request.name,
        tags=[request.mode],
    )


def _safe_extract_zip(data: bytes, destination: Path) -> Path:
    content = destination / 'content'
    content.mkdir(mode=0o750)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > _MAX_ZIP_FILES:
            raise HTTPException(status_code=413, detail=f'Archive contains more than {_MAX_ZIP_FILES} entries')
        total = sum(max(0, int(item.file_size)) for item in infos)
        if total > _MAX_ZIP_BYTES:
            raise HTTPException(status_code=413, detail='Archive expands beyond the bounded scan workspace')
        for info in infos:
            relative = Path(info.filename)
            if relative.is_absolute() or '..' in relative.parts:
                raise HTTPException(status_code=422, detail='Archive contains an unsafe path')
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise HTTPException(status_code=422, detail='Archive symlinks are not supported')
            target = content / relative
            resolved = target.resolve()
            if content.resolve() not in resolved.parents and resolved != content.resolve():
                raise HTTPException(status_code=422, detail='Archive path escapes the scan workspace')
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open('wb') as sink:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sink.write(chunk)
            os.chmod(target, 0o640)
    if not any(path.is_file() for path in content.rglob('*')):
        raise HTTPException(status_code=422, detail='Archive contains no regular files')
    return content


@router.post('/file', status_code=201)
async def prepare_file_assessment(
    project_id: str = Form(...),
    depth: Depth = Form('standard'),
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f'File exceeds {_MAX_UPLOAD_BYTES} bytes')
    if not raw:
        raise HTTPException(status_code=422, detail='Uploaded file is empty')

    original_name = Path(file.filename or 'upload.bin').name
    if original_name in {'', '.', '..'}:
        original_name = 'upload.bin'
    root = Path(os.getenv('AEGIS_SEMGREP_UPLOAD_ROOT', '/var/lib/aegis-semgrep/uploads')).resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o750)
    upload_dir = root / uuid.uuid4().hex
    upload_dir.mkdir(mode=0o750)

    digest = hashlib.sha256(raw).hexdigest()
    try:
        if zipfile.is_zipfile(io.BytesIO(raw)):
            scan_path = _safe_extract_zip(raw, upload_dir)
        else:
            content_dir = upload_dir / 'content'
            content_dir.mkdir(mode=0o750)
            scan_path = content_dir / original_name
            scan_path.write_bytes(raw)
            os.chmod(scan_path, 0o640)

        result = await sync_to_async(_prepare_asset)(
            project_id=project_id,
            user_id=str(user.get('user_id')),
            is_staff=bool(user.get('is_staff')),
            asset_type='file',
            target=str(scan_path),
            configuration={
                'path': str(scan_path),
                'original_name': original_name,
                'sha256': digest,
                'size': len(raw),
            },
            depth=depth,
            name=original_name,
            tags=['file', 'uploaded'],
        )
        result['upload'] = {
            'name': original_name,
            'sha256': digest,
            'size': len(raw),
            'path': str(scan_path),
        }
        return result
    except Exception:
        if upload_dir.exists():
            import shutil
            shutil.rmtree(upload_dir, ignore_errors=True)
        raise
