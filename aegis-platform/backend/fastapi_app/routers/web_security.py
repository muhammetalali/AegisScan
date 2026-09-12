from __future__ import annotations

from typing import Any

from asgiref.sync import sync_to_async
from django.db.models import Q
from fastapi import APIRouter, Depends, HTTPException, Query

from django_project.projects.models import Project, ProjectMembership
from django_project.users.models import Permission, User
from enterprise.web_security_models import (
    AuthorizationPolicyManifest,
    ExecutionBudgetProfile,
    ProviderApprovalRecord,
    SecurityGraphEdge,
    SecurityGraphNode,
    WebSecurityValidationRun,
)
from fastapi_app.contracts.web_security_v2 import (
    AuthorizationMatrixIn,
    AuthorizationPolicyIn,
    ExecutionBudgetIn,
    ExecutionRequestIn,
    GraphSnapshotIn,
    GraphQLSecurityBatchIn,
    CrossProtocolTransitionBatchIn,
    NegativePathBatchIn,
    ProviderApprovalIn,
    ProviderGateCheckIn,
    ResponseComparisonIn,
    WebSocketSecurityBatchIn,
)
from fastapi_app.contracts.identity_protocol_security import IdentityProtocolBatchIn
from fastapi_app.core.dependencies import get_current_user
from django_project.system.credential_vault import CredentialVaultDenied
from fastapi_app.services.credential_execution import authorize_credential_refs_for_execution
from fastapi_app.services.identity_protocol_security import run_identity_protocol_security
from fastapi_app.services.stateful_protocol_security import (
    run_cross_protocol_security,
    run_graphql_security,
    run_websocket_security,
)
from fastapi_app.services.web_security_foundation import (
    CONTRACT_VERSION,
    analyze_response_pair,
    canonical_digest,
    evaluate_execution_budget,
    evaluate_provider_gate,
    persist_budget,
    persist_policy,
    persist_provider_approval,
    run_authorization_matrix,
    run_negative_paths,
    upsert_graph_snapshot,
)

router = APIRouter()


def _uid(user: dict[str, Any]) -> str:
    value = user.get('user_id') or user.get('sub')
    if not value:
        raise HTTPException(status_code=401, detail='Invalid authenticated user')
    return str(value)


def _project_for_user_sync(project_id: str, user_id: str) -> Project | None:
    return (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )


def _project_admin_for_user_sync(project_id: str, user_id: str) -> Project | None:
    project = Project.objects.filter(pk=project_id).first()
    if project is None:
        return None
    if str(project.owner_id) == str(user_id):
        return project
    allowed = ProjectMembership.objects.filter(
        project=project,
        user_id=user_id,
        role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN],
    ).exists()
    return project if allowed else None


def _project_security_operator_for_user_sync(project_id: str, user_id: str) -> Project | None:
    project = _project_for_user_sync(project_id, user_id)
    if project is None:
        return None
    if str(project.owner_id) == str(user_id):
        return project
    membership = ProjectMembership.objects.filter(project=project, user_id=user_id).first()
    if membership and membership.role in {ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN}:
        return project
    actor = User.objects.filter(pk=user_id, is_active=True).first()
    if membership and actor and actor.has_permission(Permission.SCAN_CREATE):
        return project
    return None


async def _project_for_user(project_id: str, user_id: str) -> Project:
    project = await sync_to_async(_project_for_user_sync)(project_id, user_id)
    if project is None:
        raise HTTPException(status_code=404, detail='Project not found or inaccessible')
    return project


async def _project_admin_for_user(project_id: str, user_id: str) -> Project:
    project = await sync_to_async(_project_admin_for_user_sync)(project_id, user_id)
    if project is None:
        raise HTTPException(status_code=403, detail='Project owner or admin role required')
    return project


async def _project_security_operator_for_user(project_id: str, user_id: str) -> Project:
    project = await sync_to_async(_project_security_operator_for_user_sync)(project_id, user_id)
    if project is None:
        raise HTTPException(status_code=403, detail='Project security-operator authority required')
    return project


async def _protocol_credential_governance(
    project: Project,
    actor_id: str,
    *,
    capability_id: str,
    target_origin: str,
    cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bindings: dict[str, str] = {}
    for case in cases:
        identity = case.get('identity') if isinstance(case.get('identity'), dict) else {}
        identity_ref = str(identity.get('ref') or '').strip()
        credential_ref = str(identity.get('credential_ref') or '').strip()
        if identity_ref == 'anonymous':
            if credential_ref:
                raise HTTPException(
                    status_code=409,
                    detail='Anonymous protocol identity must not carry a credential reference',
                )
            continue
        if not identity_ref or not credential_ref:
            raise HTTPException(
                status_code=409,
                detail='Non-anonymous protocol identity requires a Vault credential reference',
            )
        existing = bindings.get(credential_ref)
        if existing and existing != identity_ref:
            raise HTTPException(
                status_code=409,
                detail='One protocol credential cannot bind multiple identity references',
            )
        bindings[credential_ref] = identity_ref

    metadata: list[dict[str, Any]] = []
    for credential_ref, identity_ref in sorted(bindings.items()):
        try:
            context = await sync_to_async(authorize_credential_refs_for_execution)(
                project_id=project.id,
                actor_id=actor_id,
                refs=[credential_ref],
                capability_id=capability_id,
                allowed_kinds=('token', 'api_key', 'generic'),
                purpose=f'protocol:{capability_id}:evaluate',
                target=target_origin,
                identity_ref=identity_ref,
            )
        except (CredentialVaultDenied, ValueError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        items = (
            context.get('credential_refs')
            if isinstance(context.get('credential_refs'), list)
            else []
        )
        item = items[0] if items and isinstance(items[0], dict) else {}
        bound_identity = str(item.get('protocol_identity_ref') or '').strip()
        if not bound_identity or bound_identity != identity_ref:
            raise HTTPException(
                status_code=409,
                detail='Protocol identity does not match the Vault credential identity binding',
            )
        metadata.append({
            'credential_ref': str(item.get('credential_ref') or credential_ref),
            'kind': str(item.get('kind') or ''),
            'version': int(item.get('version') or 0),
            'protocol_identity_ref': bound_identity,
        })
    return metadata


async def _protocol_budget_governance(
    project: Project,
    budget_id: Any,
    *,
    capability: str,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    profile = await sync_to_async(
        lambda: ExecutionBudgetProfile.objects.filter(
            pk=budget_id,
            project=project,
        ).first()
    )()
    if profile is None:
        raise HTTPException(status_code=404, detail='Execution budget not found')

    identity_refs = {
        str((case.get('identity') or {}).get('ref') or '')
        for case in cases
        if str((case.get('identity') or {}).get('ref') or '')
    }
    result = evaluate_execution_budget(profile, {
        'capabilities': [capability],
        'requests': len(cases),
        'network_io_bytes': 0,
        'browser_sessions': 0,
        'identities': len(identity_refs),
        'object_mutations': 0,
        'parallelism': 1,
        'cpu_seconds': 0,
        'memory_mb': 64,
        'duration_seconds': 1,
        'state_changes': False,
        'destructive_operations': False,
    })
    if not result['allowed']:
        raise HTTPException(
            status_code=403,
            detail={
                'message': 'Execution budget denied protocol validation',
                'failures': result['failures'],
                'profile_id': result['profile_id'],
            },
        )
    return result


def _policy_dict(row: AuthorizationPolicyManifest) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'project_id': str(row.project_id),
        'identity_type': row.identity_type,
        'role': row.role,
        'tenant_ref': row.tenant_ref,
        'endpoint': row.endpoint,
        'method': row.method,
        'operation': row.operation,
        'resource_type': row.resource_type,
        'allowed': row.allowed,
        'ownership_rule': row.ownership_rule,
        'tenant_rule': row.tenant_rule,
        'sensitive_operation': row.sensitive_operation,
        'required_scopes': row.required_scopes,
        'conditions': row.conditions,
        'policy_source': row.policy_source,
        'provenance': row.provenance,
        'confidence': row.confidence,
        'last_verified_at': row.last_verified_at.isoformat() if row.last_verified_at else None,
        'version': row.version,
        'canonical_sha256': row.canonical_sha256,
        'created_by_id': str(row.created_by_id),
        'created_at': row.created_at.isoformat(),
    }


def _budget_dict(row: ExecutionBudgetProfile) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'project_id': str(row.project_id),
        'name': row.name,
        'environment': row.environment,
        'allowed_capabilities': row.allowed_capabilities,
        'max_requests': row.max_requests,
        'network_io_bytes': row.network_io_bytes,
        'browser_sessions': row.browser_sessions,
        'identities': row.identities,
        'object_mutations': row.object_mutations,
        'parallelism': row.parallelism,
        'cpu_seconds': row.cpu_seconds,
        'memory_mb': row.memory_mb,
        'duration_seconds': row.duration_seconds,
        'state_changes': row.state_changes,
        'destructive_operations': row.destructive_operations,
        'state_change_policy': row.state_change_policy,
        'version': row.version,
        'canonical_sha256': row.canonical_sha256,
        'created_by_id': str(row.created_by_id),
        'created_at': row.created_at.isoformat(),
    }


def _provider_dict(row: ProviderApprovalRecord) -> dict[str, Any]:
    return {
        'id': str(row.id),
        'project_id': str(row.project_id),
        'provider_name': row.provider_name,
        'provider_version': row.provider_version,
        'status': row.status,
        'capability': row.capability,
        'manifest': row.manifest,
        'rationale': row.rationale,
        'manifest_sha256': row.manifest_sha256,
        'reviewed_by_id': str(row.reviewed_by_id),
        'created_at': row.created_at.isoformat(),
    }


@router.get('/contract')
async def web_security_contract(user=Depends(get_current_user)):
    _uid(user)
    return {
        'contract_version': CONTRACT_VERSION,
        'canonical_model': [
            'identity', 'session', 'role', 'tenant', 'resource', 'endpoint_or_channel',
            'operation', 'policy', 'observation', 'evidence', 'finding', 'attack_chain',
            'detection', 'risk', 'control', 'remediation', 'revalidation',
        ],
        'foundation_capabilities': {
            'security_graph': True,
            'authorization_policy_manifest': True,
            'authorization_matrix': True,
            'identity_object_tenant_graph': True,
            'response_semantic_analyzer': True,
            'privacy_preserving_evidence_comparison': True,
            'negative_path_engine': True,
            'execution_budget': True,
            'provider_approval_gate': True,
            'websocket_stateful_validation': True,
            'graphql_security_validation': True,
            'cross_protocol_state_validation': True,
            'identity_protocol_security': True,
        },
        'policy_sources': [value for value, _label in AuthorizationPolicyManifest.Source.choices],
        'provider_states': [value for value, _label in ProviderApprovalRecord.Status.choices],
        'observation_source': 'persisted deterministic validation',
    }


@router.post('/projects/{project_id}/graph/snapshot')
async def persist_graph(
    project_id: str,
    payload: GraphSnapshotIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    try:
        result = await sync_to_async(upsert_graph_snapshot)(
            project,
            [item.model_dump(mode='json') for item in payload.nodes],
            [item.model_dump(mode='json') for item in payload.edges],
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {'contract_version': CONTRACT_VERSION, 'project_id': str(project.id), **result}


@router.get('/projects/{project_id}/graph')
async def read_graph(
    project_id: str,
    node_limit: int = Query(default=2000, ge=1, le=10000),
    edge_limit: int = Query(default=5000, ge=1, le=25000),
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)

    @sync_to_async
    def load():
        nodes = list(
            SecurityGraphNode.objects.filter(project=project)
            .order_by('kind', 'external_ref')
            .values(
                'id', 'plane', 'kind', 'external_ref', 'label', 'protocol',
                'tenant_ref', 'properties', 'provenance', 'first_seen', 'last_seen',
            )[:node_limit]
        )
        edges = list(
            SecurityGraphEdge.objects.filter(project=project)
            .select_related('source', 'target')
            .order_by('relation', 'id')[:edge_limit]
        )
        return nodes, edges

    nodes, edges = await load()
    return {
        'contract_version': CONTRACT_VERSION,
        'project_id': str(project.id),
        'nodes': [
            {
                **{k: v for k, v in item.items() if k not in {'id', 'first_seen', 'last_seen'}},
                'id': str(item['id']),
                'first_seen': item['first_seen'].isoformat(),
                'last_seen': item['last_seen'].isoformat(),
            }
            for item in nodes
        ],
        'edges': [
            {
                'id': str(row.id),
                'source_id': str(row.source_id),
                'source_ref': row.source.external_ref,
                'target_id': str(row.target_id),
                'target_ref': row.target.external_ref,
                'relation': row.relation,
                'evidence_refs': row.evidence_refs,
                'properties': row.properties,
                'provenance': row.provenance,
                'first_seen': row.first_seen.isoformat(),
                'last_seen': row.last_seen.isoformat(),
            }
            for row in edges
        ],
    }


@router.post('/projects/{project_id}/authorization/policies', status_code=201)
async def create_policy(
    project_id: str,
    payload: AuthorizationPolicyIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_admin_for_user(project_id, uid)
    try:
        row, created = await sync_to_async(persist_policy)(
            project,
            uid,
            payload.model_dump(mode='json'),
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {'created': created, **_policy_dict(row)}


@router.get('/projects/{project_id}/authorization/policies')
async def list_policies(
    project_id: str,
    limit: int = Query(default=500, ge=1, le=5000),
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)
    rows = await sync_to_async(
        lambda: list(AuthorizationPolicyManifest.objects.filter(project=project).order_by('-version', '-created_at')[:limit])
    )()
    return [_policy_dict(row) for row in rows]


@router.post('/projects/{project_id}/authorization/evaluate')
async def evaluate_authorization(
    project_id: str,
    payload: AuthorizationMatrixIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    run, observations = await sync_to_async(run_authorization_matrix)(project, uid, cases)
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [
            {
                'id': str(item.id),
                'case_ref': item.case_ref,
                'policy_id': str(item.policy_id) if item.policy_id else None,
                'identity_ref': item.identity_ref,
                'tenant_ref': item.tenant_ref,
                'resource_ref': item.resource_ref,
                'resource_tenant_ref': item.resource_tenant_ref,
                'endpoint': item.endpoint,
                'method': item.method,
                'operation': item.operation,
                'expected_allowed': item.expected_allowed,
                'observed_decision': item.observed_decision,
                'passed': item.passed,
                'semantic': item.semantic,
                'evidence_fingerprint': item.evidence_fingerprint,
                'reason': item.reason,
            }
            for item in observations
        ],
    }


@router.post('/projects/{project_id}/responses/compare')
async def compare_responses(
    project_id: str,
    payload: ResponseComparisonIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    raw = payload.model_dump(mode='json')
    result = analyze_response_pair(raw['baseline'], raw['candidate'])

    @sync_to_async
    def persist():
        return WebSecurityValidationRun.objects.create(
            project=project,
            kind=WebSecurityValidationRun.Kind.RESPONSE_COMPARISON,
            status=WebSecurityValidationRun.Status.COMPLETED,
            contract_version=CONTRACT_VERSION,
            input_sha256=canonical_digest(raw),
            summary=result,
            created_by_id=uid,
        )

    run = await persist()
    return {'run_id': str(run.id), **result}


@router.post('/projects/{project_id}/negative-path/evaluate')
async def evaluate_negative_path(
    project_id: str,
    payload: NegativePathBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    run, results = await sync_to_async(run_negative_paths)(
        project,
        uid,
        [item.model_dump(mode='json') for item in payload.invariants],
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'results': results,
    }


@router.post('/projects/{project_id}/execution-budgets', status_code=201)
async def create_budget(
    project_id: str,
    payload: ExecutionBudgetIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_admin_for_user(project_id, uid)
    row, created = await sync_to_async(persist_budget)(
        project,
        uid,
        payload.model_dump(mode='json'),
    )
    return {'created': created, **_budget_dict(row)}


@router.get('/projects/{project_id}/execution-budgets')
async def list_budgets(
    project_id: str,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)
    rows = await sync_to_async(
        lambda: list(ExecutionBudgetProfile.objects.filter(project=project).order_by('-created_at')[:limit])
    )()
    return [_budget_dict(row) for row in rows]


@router.post('/projects/{project_id}/execution-budgets/{budget_id}/evaluate')
async def evaluate_budget(
    project_id: str,
    budget_id: str,
    payload: ExecutionRequestIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)
    row = await sync_to_async(
        lambda: ExecutionBudgetProfile.objects.filter(pk=budget_id, project=project).first()
    )()
    if row is None:
        raise HTTPException(status_code=404, detail='Execution budget not found')
    return evaluate_execution_budget(row, payload.model_dump(mode='json'))


@router.post('/projects/{project_id}/providers/approvals', status_code=201)
async def create_provider_approval(
    project_id: str,
    payload: ProviderApprovalIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_admin_for_user(project_id, uid)
    row, created = await sync_to_async(persist_provider_approval)(
        project,
        uid,
        payload.model_dump(mode='json'),
    )
    return {'created': created, **_provider_dict(row)}


@router.get('/projects/{project_id}/providers/approvals')
async def list_provider_approvals(
    project_id: str,
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)
    rows = await sync_to_async(
        lambda: list(ProviderApprovalRecord.objects.filter(project=project).order_by('-created_at')[:limit])
    )()
    return [_provider_dict(row) for row in rows]


@router.post('/projects/{project_id}/providers/evaluate')
async def evaluate_provider(
    project_id: str,
    payload: ProviderGateCheckIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_for_user(project_id, uid)
    row = await sync_to_async(
        lambda: ProviderApprovalRecord.objects.filter(pk=payload.approval_id, project=project).first()
    )()
    if row is None:
        raise HTTPException(status_code=404, detail='Provider approval record not found')
    return evaluate_provider_gate(row, payload.requested_capability)


def _protocol_observation_dict(item):
    return {
        'id': str(item.id),
        'case_ref': item.case_ref,
        'identity_ref': item.identity_ref,
        'identity_type': item.identity_type,
        'role': item.role,
        'tenant_ref': item.tenant_ref,
        'resource_ref': item.resource_ref,
        'resource_tenant_ref': item.resource_tenant_ref,
        'endpoint': item.endpoint,
        'method': item.method,
        'operation': item.operation,
        'expected_allowed': item.expected_allowed,
        'observed_decision': item.observed_decision,
        'passed': item.passed,
        'semantic': item.semantic,
        'evidence_fingerprint': item.evidence_fingerprint,
        'reason': item.reason,
    }


@router.post('/projects/{project_id}/protocols/websocket/evaluate')
async def evaluate_websocket_protocol(
    project_id: str,
    payload: WebSocketSecurityBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project,
        payload.budget_id,
        capability='websocket_security',
        cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project,
        uid,
        capability_id='websocket.security-validation',
        target_origin=payload.target_origin,
        cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_websocket_security)(
        project,
        uid,
        cases,
        governance,
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }


@router.post('/projects/{project_id}/protocols/graphql/evaluate')
async def evaluate_graphql_protocol(
    project_id: str,
    payload: GraphQLSecurityBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project,
        payload.budget_id,
        capability='graphql_security',
        cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project,
        uid,
        capability_id='graphql.security-validation',
        target_origin=payload.target_origin,
        cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_graphql_security)(
        project,
        uid,
        cases,
        governance,
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }


@router.post('/projects/{project_id}/protocols/cross-protocol/evaluate')
async def evaluate_cross_protocol(
    project_id: str,
    payload: CrossProtocolTransitionBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project,
        payload.budget_id,
        capability='cross_protocol_state',
        cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project,
        uid,
        capability_id='cross-protocol.security-validation',
        target_origin=payload.target_origin,
        cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_cross_protocol_security)(
        project,
        uid,
        cases,
        governance,
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }

@router.post('/projects/{project_id}/identity-protocols/evaluate')
async def evaluate_identity_protocol_security(
    project_id: str,
    payload: IdentityProtocolBatchIn,
    user=Depends(get_current_user),
):
    uid = _uid(user)
    project = await _project_security_operator_for_user(project_id, uid)
    cases = [item.model_dump(mode='json') for item in payload.cases]
    governance = await _protocol_budget_governance(
        project,
        payload.budget_id,
        capability='identity_protocol_security',
        cases=cases,
    )
    credential_bindings = await _protocol_credential_governance(
        project,
        uid,
        capability_id='identity-protocol.security-validation',
        target_origin=payload.target_origin,
        cases=cases,
    )
    governance = {**governance, 'credential_bindings': credential_bindings}
    run, observations = await sync_to_async(run_identity_protocol_security)(
        project,
        uid,
        cases,
        governance,
    )
    return {
        'contract_version': CONTRACT_VERSION,
        'run_id': str(run.id),
        'kind': run.kind,
        'input_sha256': run.input_sha256,
        'summary': run.summary,
        'observations': [_protocol_observation_dict(item) for item in observations],
    }
