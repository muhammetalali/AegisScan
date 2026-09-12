from __future__ import annotations

from typing import Any, Literal

from asgiref.sync import sync_to_async
from django.db import transaction
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from django_project.assets.models import Asset, AssetAuthorization
from django_project.scans.models import Scan
from django_project.system.credential_vault import CredentialVaultDenied

from ..core.dependencies import get_current_user
from ..celery_app import BROWSER_QUEUE
from ..services.authorization_guard import asset_target
from ..services.capability_planner import planning_summary
from ..services.capability_registry import RETIRED_CAPABILITIES, RetiredCapabilityError, get_capability, list_capabilities, validate_capability_options
from ..services.credential_execution import (
    authorize_credential_refs_for_execution,
    empty_credential_context,
    normalize_credential_refs,
)
from ..services.native_packaging import PACKAGED_NATIVE_CAPABILITIES, is_packaged_native_capability
from ..services.native_tool_runtime import NATIVE_TOOL_SPECS
from ..services.external_fabric import ExternalFabricError, dynamic_plugin_capabilities, resolve_dynamic_capability
from ..tasks.advanced_scans import run_masscan_scan, run_semgrep_scan
from ..tasks.native_capabilities import run_native_capability_scan
from ..tasks.security_scan import run_nmap_scan, run_nuclei_scan
from .scans import ScanCreate, _attach_celery_task, _create_scan, _serialize_scan

router = APIRouter()
_POLICY_VERSION = 'capability-execution.v3'
_TASKS = {
    'nmap': run_nmap_scan,
    'masscan': run_masscan_scan,
    'nuclei': run_nuclei_scan,
    'semgrep': run_semgrep_scan,
}


class CapabilityExecutionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    project_id: str
    asset_id: str
    depth: Literal['quick', 'standard', 'deep', 'comprehensive'] = 'standard'
    options: dict[str, Any] = Field(default_factory=dict)
    credential_refs: list[str] = Field(default_factory=list, max_length=3)


@sync_to_async
def _asset_for_execution(asset_id: str, project_id: str, user_id: str):
    return (
        Asset.objects.select_related('project')
        .filter(pk=asset_id, project_id=project_id)
        .filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id))
        .distinct()
        .first()
    )


@sync_to_async
def _authorize_credential_bindings(
    *,
    project_id: str,
    user_id: str,
    refs: list[str],
    capability_id: str,
    allowed_kinds: tuple[str, ...],
    target: str,
) -> dict[str, Any]:
    return authorize_credential_refs_for_execution(
        project_id=project_id,
        actor_id=user_id,
        refs=refs,
        capability_id=capability_id,
        allowed_kinds=allowed_kinds,
        purpose=f'capability:{capability_id}:schedule',
        target=target,
    )


@sync_to_async
def _create_native_scan(
    capability_id: str,
    project_id: str,
    asset_id: str,
    user_id: str,
    depth: str,
    config: dict[str, Any],
) -> Scan:
    capability = get_capability(capability_id)
    with transaction.atomic():
        asset = Asset.objects.select_for_update().filter(pk=asset_id, project_id=project_id).first()
        if asset is None:
            raise HTTPException(status_code=404, detail='Asset not found or inaccessible')
        project = asset.project
        if str(project.owner_id) != str(user_id) and not project.members.filter(pk=user_id).exists():
            raise HTTPException(status_code=404, detail='Asset not found or inaccessible')
        target = asset_target(asset)
        if not target:
            raise HTTPException(status_code=409, detail='Asset has no executable target')
        decision = (
            AssetAuthorization.objects.select_for_update()
            .filter(asset=asset)
            .order_by('-created_at', '-id')
            .first()
        )
        if decision is None or decision.authorized is not True or not decision.is_currently_valid:
            raise HTTPException(status_code=403, detail='Asset has no currently valid authorization decision')
        if decision.asset_identity_snapshot != asset.id or decision.target_snapshot != target:
            raise HTTPException(status_code=409, detail='Asset authorization no longer matches the current asset target')
        return Scan.objects.create(
            project=project,
            name=f'{capability.id} validation for {asset.name}',
            scan_type=capability.scan_type,
            asset=asset,
            authorization_decision=decision,
            engines=[capability.tool],
            depth=depth,
            config=config,
            initiated_by_id=user_id,
            status=Scan.Status.QUEUED,
        )


@router.get('/')
async def capabilities(user=Depends(get_current_user)):
    try:
        plugin_items=await sync_to_async(dynamic_plugin_capabilities)()
    except ExternalFabricError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    return {
        'policy_version': _POLICY_VERSION,
        'execution_model': 'authorized-asset -> isolated-celery -> evidence -> governance',
        'credential_model': 'credential_ref -> target-scope check -> worker resolve -> redacted adapter binding',
        'capabilities': [item.public_dict() for item in list_capabilities()],
        'plugin_capabilities': plugin_items,
    }


@router.get('/packaging')
async def capability_packaging(user=Depends(get_current_user)):
    try:
        plugin_items=await sync_to_async(dynamic_plugin_capabilities)()
    except ExternalFabricError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    return {
        'policy_version': _POLICY_VERSION,
        'specialized': sorted(_TASKS),
        'native_packaged': sorted(PACKAGED_NATIVE_CAPABILITIES),
        'native_registered': sorted(NATIVE_TOOL_SPECS),
        'plugin_delegated': plugin_items,
        'retired': RETIRED_CAPABILITIES,
    }


@router.get('/plan/{asset_id}')
async def capability_plan(
    asset_id: str,
    project_id: str,
    depth: Literal['quick', 'standard', 'deep', 'comprehensive'] = 'standard',
    user=Depends(get_current_user),
):
    asset = await _asset_for_execution(asset_id, project_id, str(user.get('user_id')))
    if asset is None:
        raise HTTPException(status_code=404, detail='Asset not found or inaccessible')
    return {
        'policy_version': _POLICY_VERSION,
        **planning_summary(asset.type, depth),
    }


@router.post('/{capability_id}/execute', status_code=202)
async def execute_capability(
    capability_id: str,
    request: CapabilityExecutionRequest,
    user=Depends(get_current_user),
):
    requested_capability_id=capability_id
    dynamic=None
    try:
        try:
            capability=get_capability(capability_id)
            resolved_capability_id=capability_id
        except RetiredCapabilityError:
            raise
        except ValueError:
            dynamic=await sync_to_async(resolve_dynamic_capability)(capability_id)
            if dynamic is None:
                raise ValueError(f'Unknown capability: {capability_id}')
            resolved_capability_id=dynamic['delegate']
            capability=get_capability(resolved_capability_id)
        options = validate_capability_options(capability, request.options)
        credential_refs = normalize_credential_refs(request.credential_refs)
    except ExternalFabricError as exc:
        raise HTTPException(status_code=409,detail=str(exc)) from exc
    except RetiredCapabilityError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if capability.credential_required and len(credential_refs) != 1:
        raise HTTPException(
            status_code=409,
            detail=f'Capability {capability.id} requires exactly one credential reference',
        )
    single_ref_modes = {
        'curl-bearer-config',
        'kubeconfig-file',
        'cloud-credentials-file',
        'browser-session-file',
    }
    if credential_refs and capability.credential_mode in single_ref_modes and len(credential_refs) != 1:
        raise HTTPException(
            status_code=409,
            detail=f'Capability {capability.id} accepts at most one credential reference',
        )
    if credential_refs and capability.credential_mode == 'none':
        raise HTTPException(status_code=409, detail=f'Capability {capability.id} does not support credential-bound execution')

    if capability.id in NATIVE_TOOL_SPECS and not is_packaged_native_capability(capability.id):
        raise HTTPException(
            status_code=409,
            detail='Capability adapter is registered but its binary is not yet part of the proven scanner image.',
        )

    user_id = str(user.get('user_id'))
    asset = await _asset_for_execution(request.asset_id, request.project_id, user_id)
    if asset is None:
        raise HTTPException(status_code=404, detail='Asset not found or inaccessible')
    if asset.type not in capability.asset_types:
        raise HTTPException(
            status_code=409,
            detail=f'Capability {capability.id} does not support asset type {asset.type}',
        )

    target = asset_target(asset)
    if not target:
        raise HTTPException(status_code=409, detail='Asset has no executable target')

    try:
        credential_context = (
            await _authorize_credential_bindings(
                project_id=request.project_id,
                user_id=user_id,
                refs=credential_refs,
                capability_id=capability.id,
                allowed_kinds=capability.credential_kinds,
                target=target,
            )
            if credential_refs
            else empty_credential_context()
        )
    except CredentialVaultDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if capability.id == 'browser.spa-discovery':
        requested_identity = str(options.get('identity_ref') or 'anonymous').strip()
        if credential_refs:
            bindings = (
                credential_context.get('credential_refs')
                if isinstance(credential_context.get('credential_refs'), list)
                else []
            )
            bound_identity = (
                str(bindings[0].get('browser_identity_ref') or '').strip()
                if bindings and isinstance(bindings[0], dict)
                else ''
            )
            if not bound_identity:
                raise HTTPException(status_code=409, detail='Browser credential has no durable identity binding')
            if requested_identity not in {'anonymous', bound_identity}:
                raise HTTPException(
                    status_code=409,
                    detail='Requested browser identity does not match the bound credential identity',
                )
            options = {**options, 'identity_ref': bound_identity}
        else:
            if requested_identity != 'anonymous':
                raise HTTPException(
                    status_code=409,
                    detail='Non-anonymous browser identity requires a bound browser session credential',
                )
            options = {**options, 'identity_ref': 'anonymous'}

    config = {
        'target': target,
        'capability_options': options,
        **options,
        'credential_refs': credential_refs,
        'credential_context': credential_context,
        'capability_id': requested_capability_id,
        'delegate_capability_id': capability.id if dynamic else None,
        'plugin_capability': dynamic if dynamic else None,
        'capability_category': capability.category,
        'capability_risk': capability.risk,
        'capability_policy_version': _POLICY_VERSION,
        'capability_source': capability.source,
        'capability_adapter': capability.adapter,
        'credential_mode': capability.credential_mode,
        'credential_required': capability.credential_required,
    }

    if capability.id in NATIVE_TOOL_SPECS:
        created = await _create_native_scan(
            capability.id,
            request.project_id,
            request.asset_id,
            user_id,
            request.depth,
            config,
        )
        if capability.id == 'browser.spa-discovery':
            task = run_native_capability_scan.apply_async(
                args=[str(created.id)],
                queue=BROWSER_QUEUE,
                routing_key=BROWSER_QUEUE,
            )
        else:
            task = run_native_capability_scan.delay(str(created.id))
    else:
        scan_request = ScanCreate(
            project_id=request.project_id,
            asset_id=request.asset_id,
            name=f'{capability.id} validation for {asset.name}',
            scan_type=capability.scan_type,
            engines=[capability.tool],
            depth=request.depth,
            config=config,
        )
        created, engines = await _create_scan(scan_request, user_id)
        task = _TASKS[engines[0]].delay(str(created.id))

    created = await _attach_celery_task(str(created.id), task.id)
    serialized = await _serialize_scan(created)
    return {
        'capability_id': requested_capability_id,
        'delegate_capability_id': capability.id if dynamic else None,
        'plugin': dynamic if dynamic else None,
        'policy_version': _POLICY_VERSION,
        'authorization_required': capability.authorization_required,
        'evidence_required': capability.evidence_required,
        'execution_mode': capability.execution_mode,
        'credential_context': credential_context,
        'scan': serialized,
    }
