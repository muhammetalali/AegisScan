from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import os
import re
from typing import Any

from django.conf import settings
from django.db import transaction

from enterprise.web_security_models import (
    AuthorizationPolicyManifest,
    ExecutionBudgetProfile,
    ProviderApprovalRecord,
    SecurityGraphEdge,
    SecurityGraphNode,
    WebSecurityObservation,
    WebSecurityValidationRun,
)

CONTRACT_VERSION = '2.0'
VOLATILE_KEYS = {
    'timestamp', 'created_at', 'updated_at', 'request_id', 'trace_id', 'span_id',
    'csrf', 'csrf_token', 'nonce', 'etag', 'expires_at', 'issued_at', 'iat', 'exp',
}
SENSITIVE_KEY_RE = re.compile(
    r'(password|passwd|secret|token|authorization|api[_-]?key|private[_-]?key|'
    r'ssn|credit[_-]?card|card[_-]?number|cvv|session[_-]?id)',
    re.IGNORECASE,
)
TENANT_KEY_RE = re.compile(r'(^|_)(tenant|organization|org)(_|$)', re.IGNORECASE)
OWNER_KEY_RE = re.compile(r'(^|_)(owner|user|account)(_|$)', re.IGNORECASE)
LEAK_PATTERNS = (
    'traceback (most recent call last)',
    'sqlstate',
    'django.core.exceptions',
    'werkzeug debugger',
    'stack trace',
    'exception in thread',
    'psycopg2.',
)
SECURITY_HEADERS = (
    'content-security-policy',
    'x-content-type-options',
    'referrer-policy',
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _hmac_key() -> bytes:
    configured = os.getenv('AEGIS_EVIDENCE_HMAC_KEY', '').strip()
    material = configured or str(settings.SECRET_KEY)
    if not material:
        raise RuntimeError('Evidence comparison requires a server HMAC key')
    return hashlib.sha256(('aegis-evidence-comparison-v1:' + material).encode()).digest()


def privacy_fingerprint(value: Any) -> str:
    return hmac.new(_hmac_key(), canonical_json(value), hashlib.sha256).hexdigest()


def _normalize(value: Any, *, path: str = '') -> tuple[Any, list[str], dict[str, list[str]]]:
    sensitive_paths: list[str] = []
    identities: dict[str, list[str]] = {'tenant': [], 'owner': []}

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key in sorted(value, key=lambda item: str(item)):
            key = str(raw_key)
            key_lower = key.lower()
            child_path = f'{path}.{key}' if path else key
            if key_lower in VOLATILE_KEYS:
                result[key] = '__volatile__'
                continue
            item = value[raw_key]
            if SENSITIVE_KEY_RE.search(key):
                sensitive_paths.append(child_path)
                result[key] = '__redacted__'
                continue
            if TENANT_KEY_RE.search(key) and item is not None:
                identities['tenant'].append(privacy_fingerprint(str(item)))
            if OWNER_KEY_RE.search(key) and item is not None:
                identities['owner'].append(privacy_fingerprint(str(item)))
            normalized, nested_sensitive, nested_ids = _normalize(item, path=child_path)
            result[key] = normalized
            sensitive_paths.extend(nested_sensitive)
            identities['tenant'].extend(nested_ids['tenant'])
            identities['owner'].extend(nested_ids['owner'])
        return result, sensitive_paths, identities

    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            normalized, nested_sensitive, nested_ids = _normalize(item, path=f'{path}[{index}]')
            result.append(normalized)
            sensitive_paths.extend(nested_sensitive)
            identities['tenant'].extend(nested_ids['tenant'])
            identities['owner'].extend(nested_ids['owner'])
        return result, sensitive_paths, identities

    if isinstance(value, float):
        return round(value, 8), sensitive_paths, identities
    return value, sensitive_paths, identities


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _shape(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, list):
        shapes = [_shape(item) for item in value[:25]]
        unique: list[Any] = []
        seen: set[str] = set()
        for item in shapes:
            digest = canonical_digest(item)
            if digest not in seen:
                seen.add(digest)
                unique.append(item)
        return {'type': 'array', 'item_shapes': unique, 'sampled': min(len(value), 25)}
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, int):
        return 'integer'
    if isinstance(value, float):
        return 'number'
    if isinstance(value, str):
        return 'string'
    return type(value).__name__


def _record_volume(body: Any) -> int | None:
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        for key in ('results', 'items', 'records', 'data'):
            value = body.get(key)
            if isinstance(value, list):
                return len(value)
    return None


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in value.items()}


def classify_response(response: dict[str, Any]) -> str:
    try:
        status = int(response.get('status_code'))
    except (TypeError, ValueError):
        return WebSecurityObservation.Decision.INDETERMINATE
    if 200 <= status < 300:
        return WebSecurityObservation.Decision.ALLOWED
    if status in {401, 403, 404}:
        return WebSecurityObservation.Decision.DENIED
    if 500 <= status < 600:
        return WebSecurityObservation.Decision.ERROR
    return WebSecurityObservation.Decision.INDETERMINATE


def response_semantics(response: dict[str, Any]) -> dict[str, Any]:
    body = response.get('body')
    normalized, sensitive_paths, identities = _normalize(body)
    headers = _headers(response.get('headers'))
    text = json.dumps(body, ensure_ascii=False, default=str).lower()
    leakage = sorted({pattern for pattern in LEAK_PATTERNS if pattern in text})
    timing = response.get('timing_ms')
    try:
        timing_ms = round(float(timing), 3) if timing is not None else None
    except (TypeError, ValueError):
        timing_ms = None

    return {
        'decision': classify_response(response),
        'status_code': response.get('status_code'),
        'body_fingerprint': privacy_fingerprint(normalized),
        'structural_fingerprint': canonical_digest(_shape(normalized)),
        'record_volume': _record_volume(body),
        'sensitive_field_paths': sorted(set(sensitive_paths)),
        'tenant_value_hmacs': sorted(set(identities['tenant'])),
        'owner_value_hmacs': sorted(set(identities['owner'])),
        'security_headers': {name: headers.get(name) for name in SECURITY_HEADERS if name in headers},
        'set_cookie_present': 'set-cookie' in headers,
        'leakage_signals': leakage,
        'timing_ms': timing_ms,
    }


def analyze_response_pair(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    left = response_semantics(baseline)
    right = response_semantics(candidate)
    left_headers = _headers(baseline.get('headers'))
    right_headers = _headers(candidate.get('headers'))
    header_names = sorted(set(left_headers) | set(right_headers))
    header_diff = [
        name for name in header_names
        if name not in {'date', 'server', 'content-length', 'etag'}
        and left_headers.get(name) != right_headers.get(name)
    ]
    timing_delta = None
    if left['timing_ms'] is not None and right['timing_ms'] is not None:
        timing_delta = round(right['timing_ms'] - left['timing_ms'], 3)
    volume_delta = None
    if left['record_volume'] is not None and right['record_volume'] is not None:
        volume_delta = right['record_volume'] - left['record_volume']
    return {
        'contract_version': CONTRACT_VERSION,
        'same_semantic_body': left['body_fingerprint'] == right['body_fingerprint'],
        'same_structure': left['structural_fingerprint'] == right['structural_fingerprint'],
        'status_changed': left['status_code'] != right['status_code'],
        'decision_changed': left['decision'] != right['decision'],
        'record_volume_delta': volume_delta,
        'header_differences': header_diff,
        'timing_delta_ms': timing_delta,
        'baseline': left,
        'candidate': right,
    }


def _policy_value_matches(policy_value: str, case_value: str, *, endpoint: bool = False) -> bool:
    value = (policy_value or '').strip()
    if value in {'', '*'}:
        return True
    if endpoint:
        return fnmatch.fnmatch(case_value, value)
    return value == case_value


def resolve_policy(
    policies: list[AuthorizationPolicyManifest],
    case: dict[str, Any],
) -> AuthorizationPolicyManifest | None:
    identity = case.get('identity') or {}
    resource = case.get('resource') or {}
    endpoint = str(case.get('endpoint') or '')
    method = str(case.get('method') or '').upper()
    operation = str(case.get('operation') or '')
    resource_type = str(resource.get('type') or '')
    matches: list[tuple[int, int, AuthorizationPolicyManifest]] = []

    for policy in policies:
        fields = (
            (policy.identity_type, str(identity.get('type') or '')),
            (policy.role, str(identity.get('role') or '')),
            (policy.tenant_ref, str(identity.get('tenant_ref') or '')),
            (policy.method, method),
            (policy.operation, operation),
            (policy.resource_type, resource_type),
        )
        if not all(_policy_value_matches(left, right) for left, right in fields):
            continue
        if not _policy_value_matches(policy.endpoint, endpoint, endpoint=True):
            continue
        specificity = sum(1 for left, _right in fields if str(left or '') not in {'', '*'})
        if str(policy.endpoint or '') not in {'', '*'}:
            specificity += 2
        matches.append((specificity, int(policy.version), policy))

    if not matches:
        return None
    matches.sort(key=lambda item: (item[0], item[1], item[2].created_at, str(item[2].id)), reverse=True)
    return matches[0][2]


def expected_authorization(policy: AuthorizationPolicyManifest | None, case: dict[str, Any]) -> tuple[bool, str]:
    if policy is None:
        return False, 'No matching policy manifest; fail-closed deny'

    identity = case.get('identity') or {}
    resource = case.get('resource') or {}
    scopes = {str(scope) for scope in (identity.get('scopes') or [])}
    required_scopes = {str(scope) for scope in (policy.required_scopes or [])}
    if not required_scopes.issubset(scopes):
        return False, 'Required scopes are not satisfied'

    identity_tenant = str(identity.get('tenant_ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')
    if policy.tenant_rule in {'same_tenant', 'tenant_match', 'deny_cross_tenant'}:
        if not identity_tenant or not resource_tenant:
            return False, 'Tenant-bound policy requires both identity and resource tenant bindings'
        if identity_tenant != resource_tenant:
            return False, 'Cross-tenant access is forbidden by tenant rule'

    owner_ref = str(resource.get('owner_ref') or '')
    identity_ref = str(identity.get('ref') or '')
    if policy.ownership_rule in {'owner_only', 'same_owner'}:
        if not identity_ref or not owner_ref:
            return False, 'Owner-bound policy requires both identity and resource owner bindings'
        if identity_ref != owner_ref:
            return False, 'Cross-owner access is forbidden by ownership rule'

    if policy.conditions:
        return False, 'Policy has conditions without a registered deterministic evaluator; fail-closed deny'

    return bool(policy.allowed), 'Matched authorization policy manifest'


def evaluate_authorization_case(
    policies: list[AuthorizationPolicyManifest],
    case: dict[str, Any],
) -> dict[str, Any]:
    policy = resolve_policy(policies, case)
    expected_allowed, reason = expected_authorization(policy, case)
    response = case.get('response') or {}
    semantic = response_semantics(response)
    observed = semantic['decision']
    observed_allowed = observed == WebSecurityObservation.Decision.ALLOWED
    passed = observed_allowed == expected_allowed and observed not in {
        WebSecurityObservation.Decision.ERROR,
        WebSecurityObservation.Decision.INDETERMINATE,
    }
    if semantic['leakage_signals']:
        passed = False
        reason = reason + '; response leakage detected'
    return {
        'policy': policy,
        'expected_allowed': expected_allowed,
        'observed_decision': observed,
        'passed': passed,
        'semantic': semantic,
        'evidence_fingerprint': semantic['body_fingerprint'],
        'reason': reason,
    }


def evaluate_negative_invariant(invariant: dict[str, Any]) -> dict[str, Any]:
    response = invariant.get('response') or {}
    semantic = response_semantics(response)
    invariant_type = str(invariant.get('type') or 'deny_access')
    failures: list[str] = []

    if invariant_type == 'deny_access':
        if semantic['decision'] != WebSecurityObservation.Decision.DENIED:
            failures.append('negative path was not denied')
    elif invariant_type == 'security_headers':
        required = [str(x).lower() for x in (invariant.get('required_headers') or SECURITY_HEADERS)]
        headers = _headers(response.get('headers'))
        failures.extend(f'missing security header: {name}' for name in required if not headers.get(name))
    elif invariant_type == 'cookie_flags':
        cookie = _headers(response.get('headers')).get('set-cookie', '').lower()
        for flag in ('secure', 'httponly', 'samesite='):
            if flag not in cookie:
                failures.append(f'missing cookie flag: {flag}')
    elif invariant_type == 'timing_consistency':
        reference = float(invariant.get('reference_timing_ms') or 0.0)
        tolerance = float(invariant.get('tolerance_ms') or max(25.0, reference * 0.25))
        current = semantic['timing_ms']
        if current is None or abs(current - reference) > tolerance:
            failures.append('timing deviation exceeds invariant tolerance')
    else:
        failures.append(f'unsupported invariant type: {invariant_type}')

    if semantic['leakage_signals']:
        failures.append('error/stack leakage detected')

    return {
        'contract_version': CONTRACT_VERSION,
        'invariant_ref': str(invariant.get('ref') or ''),
        'type': invariant_type,
        'passed': not failures,
        'failures': failures,
        'semantic': semantic,
    }


BUDGET_FIELDS = (
    'max_requests', 'network_io_bytes', 'browser_sessions', 'identities',
    'object_mutations', 'parallelism', 'cpu_seconds', 'memory_mb', 'duration_seconds',
)


def evaluate_execution_budget(profile: ExecutionBudgetProfile, requested: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    mapping = {
        'max_requests': 'requests',
        'network_io_bytes': 'network_io_bytes',
        'browser_sessions': 'browser_sessions',
        'identities': 'identities',
        'object_mutations': 'object_mutations',
        'parallelism': 'parallelism',
        'cpu_seconds': 'cpu_seconds',
        'memory_mb': 'memory_mb',
        'duration_seconds': 'duration_seconds',
    }
    for limit_field in BUDGET_FIELDS:
        request_field = mapping[limit_field]
        try:
            used = int(requested.get(request_field) or 0)
        except (TypeError, ValueError):
            failures.append(f'invalid budget value: {request_field}')
            continue
        limit = int(getattr(profile, limit_field))
        if used > limit:
            failures.append(f'{request_field} exceeds budget ({used}>{limit})')

    requested_capabilities = {str(x) for x in (requested.get('capabilities') or [])}
    allowed_capabilities = {str(x) for x in (profile.allowed_capabilities or [])}
    denied = sorted(requested_capabilities - allowed_capabilities)
    if denied:
        failures.append('capabilities not allowed: ' + ', '.join(denied))

    if bool(requested.get('state_changes')) and (
        not profile.state_changes or profile.state_change_policy == 'deny'
    ):
        failures.append('state changes are not authorized by this budget')
    if bool(requested.get('destructive_operations')) and not profile.destructive_operations:
        failures.append('destructive operations are not authorized by this budget')
    if profile.environment == ExecutionBudgetProfile.Environment.PRODUCTION:
        if bool(requested.get('destructive_operations')):
            failures.append('destructive operations are fail-closed in production')
        if requested_capabilities.intersection({'race', 'destructive', 'credential_bruteforce'}):
            failures.append('high-impact capability is not permitted in production budget')

    return {
        'contract_version': CONTRACT_VERSION,
        'allowed': not failures,
        'failures': sorted(set(failures)),
        'profile_id': str(profile.id),
        'profile_sha256': profile.canonical_sha256,
        'environment': profile.environment,
    }


PROVIDER_REQUIRED_FIELDS = {
    'license', 'maintenance', 'sbom', 'supply_chain_integrity', 'known_cves',
    'container_privileges', 'network_permissions', 'output_quality', 'determinism',
    'evidence_quality', 'ci_reproducibility',
}


def evaluate_provider_gate(record: ProviderApprovalRecord, requested_capability: str) -> dict[str, Any]:
    manifest = record.manifest or {}
    failures: list[str] = []
    missing = sorted(PROVIDER_REQUIRED_FIELDS - set(manifest))
    if missing:
        failures.append('missing approval fields: ' + ', '.join(missing))
    if record.status != ProviderApprovalRecord.Status.APPROVED:
        failures.append(f'provider status is {record.status}, not approved')
    if requested_capability and record.capability != requested_capability:
        failures.append('provider capability does not match requested capability')

    for field in ('sbom', 'supply_chain_integrity', 'determinism', 'evidence_quality', 'ci_reproducibility'):
        if field in manifest and manifest.get(field) is not True:
            failures.append(f'{field} is not proven')

    maintenance = manifest.get('maintenance')
    if isinstance(maintenance, dict) and maintenance.get('status') not in {'active', 'maintained'}:
        failures.append('provider is not actively maintained')
    elif maintenance in {False, None, ''} and 'maintenance' in manifest:
        failures.append('provider maintenance is not proven')

    privileges = {str(x).lower() for x in (manifest.get('container_privileges') or [])}
    forbidden = privileges.intersection({'privileged', 'hostnetwork', 'hostpid', 'hostipc', 'docker-socket'})
    if forbidden:
        failures.append('forbidden container privileges: ' + ', '.join(sorted(forbidden)))
    if manifest.get('unmitigated_critical_cves'):
        failures.append('provider has unmitigated critical CVEs')

    return {
        'contract_version': CONTRACT_VERSION,
        'allowed': not failures,
        'failures': failures,
        'approval_id': str(record.id),
        'manifest_sha256': record.manifest_sha256,
        'status': record.status,
    }


def policy_payload_digest(payload: dict[str, Any]) -> str:
    fields = {
        key: payload.get(key)
        for key in (
            'project_id', 'identity_type', 'role', 'tenant_ref', 'endpoint', 'method',
            'operation', 'resource_type', 'allowed', 'ownership_rule', 'tenant_rule',
            'sensitive_operation', 'required_scopes', 'conditions', 'policy_source',
            'provenance', 'confidence', 'version',
        )
    }
    fields['method'] = str(fields.get('method') or '*').upper()
    return canonical_digest(fields)


@transaction.atomic
def persist_policy(project, actor_id: str, payload: dict[str, Any]) -> tuple[AuthorizationPolicyManifest, bool]:
    digest = policy_payload_digest({**payload, 'project_id': str(project.id)})
    defaults = dict(payload)
    defaults.pop('project_id', None)
    defaults['method'] = str(defaults.get('method') or '*').upper()
    row, created = AuthorizationPolicyManifest.objects.get_or_create(
        canonical_sha256=digest,
        defaults={
            'project': project,
            'created_by_id': actor_id,
            **defaults,
        },
    )
    if row.project_id != project.id:
        raise ValueError('policy digest collision across projects')
    return row, created


def budget_payload_digest(project_id: str, payload: dict[str, Any]) -> str:
    return canonical_digest({'project_id': project_id, **payload})


@transaction.atomic
def persist_budget(project, actor_id: str, payload: dict[str, Any]) -> tuple[ExecutionBudgetProfile, bool]:
    digest = budget_payload_digest(str(project.id), payload)
    row, created = ExecutionBudgetProfile.objects.get_or_create(
        canonical_sha256=digest,
        defaults={'project': project, 'created_by_id': actor_id, **payload},
    )
    if row.project_id != project.id:
        raise ValueError('budget digest collision across projects')
    return row, created


@transaction.atomic
def persist_provider_approval(project, actor_id: str, payload: dict[str, Any]) -> tuple[ProviderApprovalRecord, bool]:
    manifest = payload.get('manifest') or {}
    digest = canonical_digest({
        'provider_name': payload.get('provider_name'),
        'provider_version': payload.get('provider_version'),
        'capability': payload.get('capability'),
        'manifest': manifest,
    })
    row, created = ProviderApprovalRecord.objects.get_or_create(
        project=project,
        provider_name=payload['provider_name'],
        provider_version=payload['provider_version'],
        manifest_sha256=digest,
        defaults={
            'status': payload['status'],
            'capability': payload['capability'],
            'manifest': manifest,
            'rationale': payload.get('rationale', ''),
            'reviewed_by_id': actor_id,
        },
    )
    return row, created


@transaction.atomic
def upsert_graph_snapshot(project, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    node_map: dict[str, SecurityGraphNode] = {}
    created_nodes = 0
    updated_nodes = 0
    for item in nodes:
        external_ref = str(item['external_ref'])
        row, created = SecurityGraphNode.objects.update_or_create(
            project=project,
            kind=item['kind'],
            external_ref=external_ref,
            defaults={
                'plane': item.get('plane') or SecurityGraphNode.Plane.APPLICATION,
                'label': item.get('label') or external_ref,
                'protocol': item.get('protocol') or '',
                'tenant_ref': item.get('tenant_ref') or '',
                'properties': item.get('properties') or {},
                'provenance': item.get('provenance') or {},
            },
        )
        node_map[external_ref] = row
        created_nodes += int(created)
        updated_nodes += int(not created)

    created_edges = 0
    updated_edges = 0
    for item in edges:
        source_ref = str(item['source_ref'])
        target_ref = str(item['target_ref'])
        source = node_map.get(source_ref) or SecurityGraphNode.objects.filter(project=project, external_ref=source_ref).first()
        target = node_map.get(target_ref) or SecurityGraphNode.objects.filter(project=project, external_ref=target_ref).first()
        if source is None or target is None:
            raise ValueError(f'graph edge references unknown node: {source_ref}->{target_ref}')
        row, created = SecurityGraphEdge.objects.update_or_create(
            project=project,
            source=source,
            target=target,
            relation=item['relation'],
            defaults={
                'evidence_refs': item.get('evidence_refs') or [],
                'properties': item.get('properties') or {},
                'provenance': item.get('provenance') or {},
            },
        )
        created_edges += int(created)
        updated_edges += int(not created)

    return {
        'nodes_created': created_nodes,
        'nodes_updated': updated_nodes,
        'edges_created': created_edges,
        'edges_updated': updated_edges,
    }


def _case_graph(project, case: dict[str, Any], policy: AuthorizationPolicyManifest | None) -> None:
    identity = case.get('identity') or {}
    resource = case.get('resource') or {}
    identity_ref = str(identity.get('ref') or '')
    tenant_ref = str(identity.get('tenant_ref') or '')
    resource_ref = str(resource.get('ref') or '')
    resource_tenant = str(resource.get('tenant_ref') or '')
    endpoint = str(case.get('endpoint') or '')
    nodes = [
        {'plane': 'identity', 'kind': 'identity', 'external_ref': f'identity:{identity_ref}', 'label': identity_ref, 'tenant_ref': tenant_ref, 'properties': {'identity_type': identity.get('type'), 'role': identity.get('role')}, 'provenance': {'source': 'authorization_matrix'}},
        {'plane': 'application', 'kind': 'resource', 'external_ref': f'resource:{resource_ref}', 'label': resource_ref, 'tenant_ref': resource_tenant, 'properties': {'resource_type': resource.get('type'), 'owner_ref_hmac': privacy_fingerprint(str(resource.get('owner_ref') or ''))}, 'provenance': {'source': 'authorization_matrix'}},
        {'plane': 'application', 'kind': 'endpoint', 'external_ref': f'endpoint:{case.get("method")}:{endpoint}', 'label': endpoint, 'protocol': str(case.get('protocol') or 'http'), 'properties': {'method': case.get('method'), 'operation': case.get('operation')}, 'provenance': {'source': 'authorization_matrix'}},
    ]
    if tenant_ref:
        nodes.append({'plane': 'identity', 'kind': 'tenant', 'external_ref': f'tenant:{tenant_ref}', 'label': tenant_ref, 'tenant_ref': tenant_ref, 'properties': {}, 'provenance': {'source': 'authorization_matrix'}})
    if resource_tenant and resource_tenant != tenant_ref:
        nodes.append({'plane': 'identity', 'kind': 'tenant', 'external_ref': f'tenant:{resource_tenant}', 'label': resource_tenant, 'tenant_ref': resource_tenant, 'properties': {}, 'provenance': {'source': 'authorization_matrix'}})
    edges = [
        {'source_ref': f'identity:{identity_ref}', 'target_ref': f'endpoint:{case.get("method")}:{endpoint}', 'relation': 'attempts_operation', 'properties': {'case_ref': case.get('ref')}, 'evidence_refs': [], 'provenance': {'source': 'authorization_matrix'}},
        {'source_ref': f'endpoint:{case.get("method")}:{endpoint}', 'target_ref': f'resource:{resource_ref}', 'relation': 'operates_on', 'properties': {}, 'evidence_refs': [], 'provenance': {'source': 'authorization_matrix'}},
    ]
    if tenant_ref:
        edges.append({'source_ref': f'identity:{identity_ref}', 'target_ref': f'tenant:{tenant_ref}', 'relation': 'member_of', 'properties': {}, 'evidence_refs': [], 'provenance': {'source': 'authorization_matrix'}})
    if resource_tenant:
        edges.append({'source_ref': f'resource:{resource_ref}', 'target_ref': f'tenant:{resource_tenant}', 'relation': 'belongs_to', 'properties': {}, 'evidence_refs': [], 'provenance': {'source': 'authorization_matrix'}})
    if policy is not None:
        policy_ref = f'policy:{policy.id}'
        nodes.append({'plane': 'identity', 'kind': 'policy', 'external_ref': policy_ref, 'label': policy_ref, 'properties': {'canonical_sha256': policy.canonical_sha256}, 'provenance': {'source': policy.policy_source}})
        edges.append({'source_ref': policy_ref, 'target_ref': f'endpoint:{case.get("method")}:{endpoint}', 'relation': 'governs', 'properties': {}, 'evidence_refs': [], 'provenance': {'source': policy.policy_source}})
    upsert_graph_snapshot(project, nodes, edges)


@transaction.atomic
def run_authorization_matrix(project, actor_id: str, cases: list[dict[str, Any]]) -> tuple[WebSecurityValidationRun, list[WebSecurityObservation]]:
    policies = list(AuthorizationPolicyManifest.objects.filter(project=project).order_by('-version', '-created_at'))
    results = []
    for case in cases:
        result = evaluate_authorization_case(policies, case)
        results.append((case, result))
        _case_graph(project, case, result['policy'])

    summary = {
        'total': len(results),
        'passed': sum(1 for _case, result in results if result['passed']),
        'failed': sum(1 for _case, result in results if not result['passed']),
        'cross_tenant_cases': sum(
            1 for case, _result in results
            if str((case.get('identity') or {}).get('tenant_ref') or '')
            and str((case.get('resource') or {}).get('tenant_ref') or '')
            and str((case.get('identity') or {}).get('tenant_ref')) != str((case.get('resource') or {}).get('tenant_ref'))
        ),
    }
    run = WebSecurityValidationRun.objects.create(
        project=project,
        kind=WebSecurityValidationRun.Kind.AUTHORIZATION_MATRIX,
        status=WebSecurityValidationRun.Status.COMPLETED,
        input_sha256=canonical_digest(cases),
        summary=summary,
        created_by_id=actor_id,
    )
    observations: list[WebSecurityObservation] = []
    for case, result in results:
        identity = case.get('identity') or {}
        resource = case.get('resource') or {}
        observations.append(WebSecurityObservation(
            run=run,
            policy=result['policy'],
            case_ref=str(case.get('ref') or ''),
            identity_ref=str(identity.get('ref') or ''),
            identity_type=str(identity.get('type') or ''),
            role=str(identity.get('role') or ''),
            tenant_ref=str(identity.get('tenant_ref') or ''),
            resource_ref=str(resource.get('ref') or ''),
            resource_tenant_ref=str(resource.get('tenant_ref') or ''),
            endpoint=str(case.get('endpoint') or ''),
            method=str(case.get('method') or '').upper(),
            operation=str(case.get('operation') or ''),
            expected_allowed=result['expected_allowed'],
            observed_decision=result['observed_decision'],
            passed=result['passed'],
            semantic=result['semantic'],
            evidence_fingerprint=result['evidence_fingerprint'],
            reason=result['reason'],
        ))
    WebSecurityObservation.objects.bulk_create(observations)
    return run, observations


@transaction.atomic
def run_negative_paths(project, actor_id: str, invariants: list[dict[str, Any]]) -> tuple[WebSecurityValidationRun, list[dict[str, Any]]]:
    results = [evaluate_negative_invariant(item) for item in invariants]
    summary = {
        'total': len(results),
        'passed': sum(1 for item in results if item['passed']),
        'failed': sum(1 for item in results if not item['passed']),
    }
    run = WebSecurityValidationRun.objects.create(
        project=project,
        kind=WebSecurityValidationRun.Kind.NEGATIVE_PATH,
        status=WebSecurityValidationRun.Status.COMPLETED,
        input_sha256=canonical_digest(invariants),
        summary=summary,
        created_by_id=actor_id,
    )
    return run, results
