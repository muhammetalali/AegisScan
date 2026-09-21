from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from django.db import IntegrityError, transaction
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from django_project.system.credential_models import CredentialSecret
from enterprise.burp_mcp_models import BurpMCPInvocation, BurpMCPSession
from enterprise.models import Organization, OrganizationMembership, TenantProject
from enterprise.web_security_models import ProviderApprovalRecord

from .audit_writer import add_audit_entry
from .authorization_guard import asset_target
from .credential_execution import (
    assert_no_credential_material_leaked,
    authorize_credential_refs_for_execution,
    resolve_credential_refs_for_worker,
)
from .evidence_identity import evidence_id
from .evidence_qualification import EvidenceQualificationPolicy, qualify_evidence
from .web_security_foundation import evaluate_provider_gate


BURP_MCP_POLICY_VERSION = 'burp-mcp-gateway.v1'
BURP_MCP_EVIDENCE_POLICY_VERSION = 'burp-mcp-evidence.v1'
BURP_MCP_CAPABILITY_ID = 'burp.mcp.gateway'

_OPERATION_ARGUMENTS: dict[str, set[str]] = {
    'burp.site_map': {'path_prefix', 'max_items'},
    'burp.passive_scan': {'url'},
    'burp.active_scan': {'url', 'profile'},
    'burp.issue_details': {'issue_id'},
}
_ACTIVE_SCAN_PROFILES = {'default', 'audit', 'crawl'}
_PROVIDER_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,179}$')
_TOOL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}$')
_IDEMPOTENCY_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$')
_ISSUE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$')
_FORBIDDEN_ARGUMENT_KEYS = {
    'argv', 'command', 'commands', 'env', 'environment', 'executable', 'file',
    'headers', 'raw', 'raw_body', 'request', 'request_body', 'response_body',
    'script', 'shell', 'stdin', 'token', 'password', 'secret', 'authorization',
}


class BurpMCPError(ValueError):
    pass


class BurpMCPAuthorizationError(BurpMCPError):
    pass


class BurpMCPProviderError(BurpMCPError):
    pass


class BurpMCPConflict(BurpMCPError):
    pass


class BurpMCPRateLimit(BurpMCPError):
    pass


@dataclass(frozen=True)
class BurpMCPSessionResult:
    session: BurpMCPSession
    replayed: bool


@dataclass(frozen=True)
class BurpMCPInvocationResult:
    invocation: BurpMCPInvocation
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    ).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int, required: bool = True) -> str:
    normalized = ' '.join(str(value or '').split())
    if required and not normalized:
        raise BurpMCPError(f'{field} is required.')
    if len(normalized) > maximum:
        raise BurpMCPError(f'{field} exceeds {maximum} characters.')
    if any(ch in normalized for ch in '\r\n\x00'):
        raise BurpMCPError(f'{field} contains invalid control characters.')
    return normalized


def _idempotency(value: str) -> str:
    normalized = _text(value, field='idempotency_key', maximum=128)
    if not _IDEMPOTENCY_RE.fullmatch(normalized):
        raise BurpMCPError('idempotency_key contains unsupported characters.')
    return normalized


def _project_access(project: Project, actor_id: str) -> bool:
    if str(project.owner_id) == str(actor_id):
        return True
    return project.members.filter(pk=actor_id).exists()


def _lock_context(
    *,
    project_id: str,
    asset_id: str,
    scan_id: str,
    authorization_id: str,
    actor_id: str,
) -> tuple[Organization, Project, Asset, Scan, AssetAuthorization]:
    link_identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if link_identity is None:
        raise BurpMCPAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=link_identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise BurpMCPAuthorizationError('Enterprise tenant is not active.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=link_identity['id'], organization_id=organization.id, project_id=project_id)
        .first()
    )
    if link is None:
        raise BurpMCPAuthorizationError('Enterprise tenant/project binding changed during gateway authorization.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None or not _project_access(project, actor_id):
        raise BurpMCPAuthorizationError('Actor is not authorized for the requested project.')
    if not OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
    ).exists():
        raise BurpMCPAuthorizationError('Actor has no active enterprise tenant membership.')

    asset = (
        Asset.objects.select_for_update(of=('self',))
        .filter(pk=asset_id, project_id=project.id, is_active=True)
        .first()
    )
    if asset is None:
        raise BurpMCPAuthorizationError('Active Burp MCP asset was not found in the requested project.')

    scan = (
        Scan.objects.select_for_update(of=('self',))
        .filter(pk=scan_id, project_id=project.id, asset_id=asset.id)
        .first()
    )
    if scan is None:
        raise BurpMCPAuthorizationError('Burp MCP scan is not bound to the requested project and asset.')

    decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(pk=authorization_id, asset_id=asset.id)
        .first()
    )
    if decision is None:
        raise BurpMCPAuthorizationError('Authorization decision is not bound to the requested asset.')

    latest = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset_id=asset.id)
        .order_by('-created_at', '-id')
        .first()
    )
    target = asset_target(asset)
    if latest is None or latest.id != decision.id:
        raise BurpMCPAuthorizationError('Burp MCP authorization has been superseded.')
    if decision.asset_identity_snapshot != asset.id:
        raise BurpMCPAuthorizationError('Authorization asset identity no longer matches.')
    if decision.authorized is not True or not decision.is_currently_valid:
        raise BurpMCPAuthorizationError('Burp MCP authorization is not currently valid.')
    if not target or decision.target_snapshot != target:
        raise BurpMCPAuthorizationError('Burp MCP target no longer matches the authorization snapshot.')
    if scan.authorization_decision_id != decision.id:
        raise BurpMCPAuthorizationError('Burp MCP scan is not bound to the current authorization decision.')
    if dict(asset.configuration or {}).get('authorized') is not True:
        raise BurpMCPAuthorizationError('Asset authorization projection is not enabled.')

    return organization, project, asset, scan, decision


def _provider_name(value: str, field: str) -> str:
    normalized = _text(value, field=field, maximum=180 if field == 'provider_name' else 120)
    if not _PROVIDER_RE.fullmatch(normalized):
        raise BurpMCPError(f'{field} contains unsupported characters.')
    return normalized


def _endpoint(manifest: dict[str, Any]) -> str:
    raw = str(manifest.get('mcp_endpoint') or '').strip()
    parsed = urlsplit(raw)
    host = (parsed.hostname or '').lower().rstrip('.')
    if not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise BurpMCPProviderError('Approved Burp MCP endpoint must be a credential-free absolute URL.')
    local_http = (
        parsed.scheme == 'http'
        and host in {'127.0.0.1', 'localhost', '::1'}
        and os.getenv('BURP_MCP_ALLOW_INSECURE_LOCAL', '').strip().lower() in {'1', 'true', 'yes'}
    )
    if parsed.scheme != 'https' and not local_http:
        raise BurpMCPProviderError('Approved Burp MCP endpoint must use HTTPS outside explicit local Reality mode.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise BurpMCPProviderError('Approved Burp MCP endpoint contains an invalid port.') from exc
    default = 443 if parsed.scheme == 'https' else 80
    authority = host if port in {None, default} else f'{host}:{port}'
    path = parsed.path or '/'
    if not path.startswith('/') or len(path) > 300:
        raise BurpMCPProviderError('Approved Burp MCP endpoint path is invalid.')
    return urlunsplit((parsed.scheme, authority, path, '', ''))


def _current_provider_approval(
    *,
    project_id: str,
    provider_name: str,
    provider_version: str,
) -> tuple[ProviderApprovalRecord, dict[str, str], str]:
    record = (
        ProviderApprovalRecord.objects.select_for_update()
        .filter(
            project_id=project_id,
            provider_name=provider_name,
            provider_version=provider_version,
            capability=BURP_MCP_CAPABILITY_ID,
        )
        .order_by('-created_at', '-id')
        .first()
    )
    if record is None:
        raise BurpMCPProviderError('No governed Burp MCP provider approval exists for this project/version.')

    gate = evaluate_provider_gate(record, BURP_MCP_CAPABILITY_ID)
    if not gate['allowed']:
        raise BurpMCPProviderError('Burp MCP provider approval is not currently admissible: ' + '; '.join(gate['failures']))

    manifest = record.manifest if isinstance(record.manifest, dict) else {}
    mapping = manifest.get('mcp_tools')
    if not isinstance(mapping, dict) or not mapping:
        raise BurpMCPProviderError('Approved Burp MCP provider manifest has no mcp_tools mapping.')

    normalized: dict[str, str] = {}
    for operation, provider_tool in mapping.items():
        op = str(operation or '').strip()
        tool = str(provider_tool or '').strip()
        if op not in _OPERATION_ARGUMENTS or not _TOOL_RE.fullmatch(tool):
            raise BurpMCPProviderError('Approved Burp MCP provider manifest contains an unsupported tool mapping.')
        normalized[op] = tool

    return record, normalized, _endpoint(manifest)


def _credential(
    *,
    project_id: str,
    actor_id: str,
    credential_ref: str | None,
    provider_name: str,
    provider_version: str,
) -> CredentialSecret | None:
    if not credential_ref:
        return None
    credential = (
        CredentialSecret.objects.select_for_update()
        .filter(
            pk=credential_ref,
            project_id=project_id,
            status=CredentialSecret.Status.ACTIVE,
        )
        .first()
    )
    if credential is None:
        raise BurpMCPAuthorizationError('Burp MCP credential reference is unavailable or revoked.')
    if credential.kind not in {CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.TOKEN}:
        raise BurpMCPAuthorizationError('Burp MCP provider credentials must be API key or token references.')
    scope = credential.scope if isinstance(credential.scope, dict) else {}
    scoped_name = str(scope.get('burp_provider_name') or '').strip()
    scoped_version = str(scope.get('burp_provider_version') or '').strip()
    if scoped_name and scoped_name != provider_name:
        raise BurpMCPAuthorizationError('Burp MCP credential is scoped to another provider.')
    if scoped_version and scoped_version != provider_version:
        raise BurpMCPAuthorizationError('Burp MCP credential is scoped to another provider version.')

    authorize_credential_refs_for_execution(
        project_id=project_id,
        actor_id=actor_id,
        refs=[str(credential.id)],
        capability_id=BURP_MCP_CAPABILITY_ID,
        allowed_kinds=(CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.TOKEN),
        purpose='burp-mcp:authorize-provider',
    )
    return credential


def _positive_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise BurpMCPError(f'{field} must be an integer.') from exc
    if number < minimum or number > maximum:
        raise BurpMCPError(f'{field} must be between {minimum} and {maximum}.')
    return number


def _target_scope(target: str) -> tuple[str, str, int | None]:
    raw = str(target or '').strip()
    if '/' in raw and '://' not in raw:
        raise BurpMCPAuthorizationError('Burp MCP gateway does not admit CIDR/path targets; use a web origin asset.')
    parsed = urlsplit(raw if '://' in raw else f'https://{raw}')
    host = (parsed.hostname or '').lower().rstrip('.')
    if not host:
        raise BurpMCPAuthorizationError('Burp MCP target is not a valid web host/origin.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise BurpMCPAuthorizationError('Burp MCP target has an invalid port.') from exc
    scheme = parsed.scheme.lower()
    if scheme not in {'http', 'https'}:
        raise BurpMCPAuthorizationError('Burp MCP target must use HTTP or HTTPS semantics.')
    return scheme, host, port


def _url_within_target(url: str, target: str) -> str:
    raw = _text(url, field='url', maximum=2048)
    parsed = urlsplit(raw)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise BurpMCPAuthorizationError('Burp MCP URL argument must be an absolute credential-free HTTP(S) URL.')
    target_scheme, target_host, target_port = _target_scope(target)
    host = (parsed.hostname or '').lower().rstrip('.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise BurpMCPAuthorizationError('Burp MCP URL argument contains an invalid port.') from exc

    raw_target = str(target or '')
    target_is_url = '://' in raw_target
    if host != target_host:
        raise BurpMCPAuthorizationError('Burp MCP URL argument escapes the authorized target host.')
    if target_is_url and (parsed.scheme.lower() != target_scheme or port != target_port):
        raise BurpMCPAuthorizationError('Burp MCP URL argument escapes the authorized target origin.')
    if parsed.fragment:
        parsed = parsed._replace(fragment='')
    return urlunsplit(parsed)


def _safe_arguments(operation: str, arguments: dict[str, Any] | None, target: str) -> dict[str, Any]:
    if operation not in _OPERATION_ARGUMENTS:
        raise BurpMCPAuthorizationError('Burp MCP operation is not allowlisted.')
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise BurpMCPError('arguments must be a JSON object.')
    if len(_canonical(arguments)) > 16_384:
        raise BurpMCPError('Burp MCP arguments exceed the 16 KiB policy limit.')

    keys = {str(key) for key in arguments}
    forbidden = sorted(keys & _FORBIDDEN_ARGUMENT_KEYS)
    if forbidden:
        raise BurpMCPAuthorizationError('Burp MCP arguments contain forbidden raw/arbitrary execution fields: ' + ', '.join(forbidden))
    unknown = sorted(keys - _OPERATION_ARGUMENTS[operation])
    if unknown:
        raise BurpMCPAuthorizationError('Burp MCP operation contains unsupported arguments: ' + ', '.join(unknown))

    result: dict[str, Any] = {'target': target}
    if operation == 'burp.site_map':
        path_prefix = str(arguments.get('path_prefix') or '/').strip()
        if not path_prefix.startswith('/') or len(path_prefix) > 500 or any(ch in path_prefix for ch in '\r\n\x00'):
            raise BurpMCPError('path_prefix must be a bounded absolute path.')
        result['path_prefix'] = path_prefix
        result['max_items'] = _positive_int(arguments.get('max_items', 100), field='max_items', minimum=1, maximum=500)
    elif operation in {'burp.passive_scan', 'burp.active_scan'}:
        result['url'] = _url_within_target(str(arguments.get('url') or target), target)
        if operation == 'burp.active_scan':
            profile = str(arguments.get('profile') or 'default').strip().lower()
            if profile not in _ACTIVE_SCAN_PROFILES:
                raise BurpMCPError('active scan profile is not allowlisted.')
            result['profile'] = profile
    elif operation == 'burp.issue_details':
        issue_id = str(arguments.get('issue_id') or '').strip()
        if not _ISSUE_RE.fullmatch(issue_id):
            raise BurpMCPError('issue_id is required and contains unsupported characters.')
        result['issue_id'] = issue_id

    return result


def _redact_result(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return '__depth_limited__'
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:100]:
            key = str(raw_key)[:120]
            lowered = key.lower()
            if any(token in lowered for token in ('authorization', 'cookie', 'password', 'secret', 'token', 'api_key', 'body', 'raw_request', 'raw_response')):
                output[key] = '__redacted__'
            else:
                output[key] = _redact_result(item, depth=depth + 1)
        return output
    if isinstance(value, list):
        return [_redact_result(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:1000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:500]


def _perform_mcp_call(
    *,
    endpoint: str,
    provider_tool_name: str,
    arguments: dict[str, Any],
    request_id: str,
    bearer_token: str = '',
) -> tuple[Any, str]:
    payload = {
        'jsonrpc': '2.0',
        'id': request_id,
        'method': 'tools/call',
        'params': {
            'name': provider_tool_name,
            'arguments': arguments,
        },
    }
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
    if bearer_token:
        headers['Authorization'] = f'Bearer {bearer_token}'
    try:
        with httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False) as client:
            response = client.post(endpoint, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise BurpMCPProviderError('Burp MCP provider transport failed.') from exc
    if not isinstance(body, dict):
        raise BurpMCPProviderError('Burp MCP provider returned a non-object JSON-RPC response.')
    if str(body.get('id')) != str(request_id):
        raise BurpMCPProviderError('Burp MCP provider returned a mismatched JSON-RPC request id.')
    if body.get('error') not in {None, {}}:
        raise BurpMCPProviderError('Burp MCP provider returned a JSON-RPC error.')
    if 'result' not in body:
        raise BurpMCPProviderError('Burp MCP provider response has no result.')
    return body['result'], str(body.get('id') or '')[:128]


def _session_contract(
    *,
    provider_name: str,
    provider_version: str,
    approval: ProviderApprovalRecord,
    endpoint: str,
    target: str,
    allowed_tools: dict[str, str],
    credential_ref: str,
    max_invocations: int,
    rate_limit_per_minute: int,
    ttl_seconds: int,
) -> dict[str, Any]:
    return {
        'schema': 'aegis.burp-mcp-session.v1',
        'policy_version': BURP_MCP_POLICY_VERSION,
        'capability_id': BURP_MCP_CAPABILITY_ID,
        'provider': {
            'name': provider_name,
            'version': provider_version,
            'approval_id': str(approval.id),
            'approval_manifest_sha256': approval.manifest_sha256,
            'endpoint_sha256': hashlib.sha256(endpoint.encode('utf-8')).hexdigest(),
        },
        'target': target,
        'allowed_tools': dict(sorted(allowed_tools.items())),
        'credential_ref': credential_ref,
        'limits': {
            'max_invocations': max_invocations,
            'rate_limit_per_minute': rate_limit_per_minute,
            'ttl_seconds': ttl_seconds,
            'provider_timeout_seconds': 15,
        },
        'arbitrary_execution': False,
        'raw_secret_persistence': False,
        'raw_request_response_persistence': False,
    }


def start_burp_mcp_session(
    *,
    project_id: str,
    asset_id: str,
    scan_id: str,
    authorization_id: str,
    actor_id: str,
    provider_name: str,
    provider_version: str,
    requested_operations: list[str] | tuple[str, ...],
    idempotency_key: str,
    credential_ref: str | None = None,
    max_invocations: int = 20,
    rate_limit_per_minute: int = 10,
    ttl_seconds: int = 1800,
) -> BurpMCPSessionResult:
    name = _provider_name(provider_name, 'provider_name')
    version = _provider_name(provider_version, 'provider_version')
    idem = _idempotency(idempotency_key)
    maximum = _positive_int(max_invocations, field='max_invocations', minimum=1, maximum=100)
    per_minute = _positive_int(rate_limit_per_minute, field='rate_limit_per_minute', minimum=1, maximum=60)
    ttl = _positive_int(ttl_seconds, field='ttl_seconds', minimum=60, maximum=3600)
    requested = sorted({str(item or '').strip() for item in requested_operations if str(item or '').strip()})
    if not requested or len(requested) > len(_OPERATION_ARGUMENTS):
        raise BurpMCPError('requested_operations must contain one or more bounded Burp gateway operations.')
    unknown = sorted(set(requested) - set(_OPERATION_ARGUMENTS))
    if unknown:
        raise BurpMCPAuthorizationError('Requested Burp MCP operations are not allowlisted: ' + ', '.join(unknown))

    with transaction.atomic():
        organization, project, asset, scan, decision = _lock_context(
            project_id=str(project_id),
            asset_id=str(asset_id),
            scan_id=str(scan_id),
            authorization_id=str(authorization_id),
            actor_id=str(actor_id),
        )
        approval, mapping, endpoint = _current_provider_approval(
            project_id=str(project.id),
            provider_name=name,
            provider_version=version,
        )
        missing = sorted(set(requested) - set(mapping))
        if missing:
            raise BurpMCPProviderError('Approved provider does not expose requested operations: ' + ', '.join(missing))
        selected_tools = {operation: mapping[operation] for operation in requested}

        credential = _credential(
            project_id=str(project.id),
            actor_id=str(actor_id),
            credential_ref=str(credential_ref) if credential_ref else None,
            provider_name=name,
            provider_version=version,
        )
        credential_id = str(credential.id) if credential is not None else ''
        contract = _session_contract(
            provider_name=name,
            provider_version=version,
            approval=approval,
            endpoint=endpoint,
            target=decision.target_snapshot,
            allowed_tools=selected_tools,
            credential_ref=credential_id,
            max_invocations=maximum,
            rate_limit_per_minute=per_minute,
            ttl_seconds=ttl,
        )
        contract_fingerprint = _sha(contract)
        request = {
            'organization_id': str(organization.id),
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id),
            'authorization_id': str(decision.id),
            'actor_id': str(actor_id),
            'provider_name': name,
            'provider_version': version,
            'idempotency_key': idem,
            'contract_fingerprint': contract_fingerprint,
        }
        request_fingerprint = _sha(request)

        existing = (
            BurpMCPSession.objects.filter(organization=organization, idempotency_key=idem)
            .select_related('provider_approval', 'credential_ref')
            .first()
        )
        if existing is not None:
            if existing.request_fingerprint != request_fingerprint:
                raise BurpMCPConflict('Burp MCP session idempotency key is bound to a different request.')
            return BurpMCPSessionResult(session=existing, replayed=True)

        provider_identity_sha256 = _sha({
            'provider_name': name,
            'provider_version': version,
            'approval_manifest_sha256': approval.manifest_sha256,
        })
        try:
            session = BurpMCPSession.objects.create(
                organization=organization,
                project=project,
                asset=asset,
                scan=scan,
                authorization_decision=decision,
                provider_approval=approval,
                created_by_id=actor_id,
                credential_ref=credential,
                provider_name=name,
                provider_version=version,
                provider_identity_sha256=provider_identity_sha256,
                endpoint_origin=endpoint,
                target_snapshot=decision.target_snapshot,
                allowed_tools=selected_tools,
                max_invocations=maximum,
                rate_limit_per_minute=per_minute,
                expires_at=timezone.now() + timedelta(seconds=ttl),
                idempotency_key=idem,
                request_fingerprint=request_fingerprint,
                policy_version=BURP_MCP_POLICY_VERSION,
                contract_snapshot=contract,
                contract_fingerprint=contract_fingerprint,
            )
        except IntegrityError as exc:
            raise BurpMCPConflict('Burp MCP session could not be committed idempotently.') from exc

        add_audit_entry(
            user=actor_id,
            action='burp_mcp.session.create',
            target=str(session.id),
            project=str(project.id),
            resource_type='burp_mcp_session',
            resource_repr=f'{name}@{version}',
            metadata={
                'organization_id': str(organization.id),
                'asset_id': str(asset.id),
                'scan_id': str(scan.id),
                'authorization_decision_id': str(decision.id),
                'provider_approval_id': str(approval.id),
                'provider_identity_sha256': provider_identity_sha256,
                'contract_fingerprint': contract_fingerprint,
                'policy_version': BURP_MCP_POLICY_VERSION,
            },
        )
        return BurpMCPSessionResult(session=session, replayed=False)


def _replay(
    *,
    session: BurpMCPSession,
    idempotency_key: str,
    request_fingerprint: str,
) -> BurpMCPInvocationResult | None:
    existing = (
        BurpMCPInvocation.objects.select_related('evidence', 'qualification')
        .filter(session=session, idempotency_key=idempotency_key)
        .first()
    )
    if existing is None:
        return None
    if existing.request_fingerprint != request_fingerprint:
        raise BurpMCPConflict('Burp MCP invocation idempotency key is bound to a different request.')
    return BurpMCPInvocationResult(invocation=existing, replayed=True)


def _audit_failure(session_id: str, actor_id: str, message: str) -> None:
    try:
        session = BurpMCPSession.objects.filter(pk=session_id).only('id', 'project_id', 'provider_name', 'provider_version').first()
        if session is None:
            return
        add_audit_entry(
            user=actor_id,
            action='burp_mcp.invocation.reject',
            target=str(session.id),
            project=str(session.project_id),
            result='failure',
            resource_type='burp_mcp_session',
            resource_repr=f'{session.provider_name}@{session.provider_version}',
            error_message=str(message)[:1000],
            metadata={'policy_version': BURP_MCP_POLICY_VERSION},
        )
    except Exception:
        return


def invoke_burp_mcp(
    *,
    session_id: str,
    actor_id: str,
    operation: str,
    arguments: dict[str, Any] | None,
    idempotency_key: str,
) -> BurpMCPInvocationResult:
    op = _text(operation, field='operation', maximum=80)
    if op not in _OPERATION_ARGUMENTS:
        raise BurpMCPAuthorizationError('Burp MCP operation is not allowlisted.')
    idem = _idempotency(idempotency_key)

    try:
        with transaction.atomic():
            session = (
                BurpMCPSession.objects.select_for_update(of=('self',))
                .select_related(
                    'organization', 'project', 'asset', 'scan', 'authorization_decision',
                    'provider_approval', 'credential_ref',
                )
                .filter(pk=session_id)
                .first()
            )
            if session is None:
                raise BurpMCPAuthorizationError('Burp MCP session was not found.')

            organization, project, asset, scan, decision = _lock_context(
                project_id=str(session.project_id),
                asset_id=str(session.asset_id),
                scan_id=str(session.scan_id),
                authorization_id=str(session.authorization_decision_id),
                actor_id=str(actor_id),
            )
            if organization.id != session.organization_id:
                raise BurpMCPAuthorizationError('Burp MCP tenant lineage changed before invocation.')
            if decision.target_snapshot != session.target_snapshot:
                raise BurpMCPAuthorizationError('Burp MCP target lineage changed before invocation.')
            if session.policy_version != BURP_MCP_POLICY_VERSION:
                raise BurpMCPAuthorizationError('Burp MCP session policy version is no longer accepted.')
            if session.expires_at <= timezone.now():
                raise BurpMCPAuthorizationError('Burp MCP session has expired.')

            approval, mapping, endpoint = _current_provider_approval(
                project_id=str(project.id),
                provider_name=session.provider_name,
                provider_version=session.provider_version,
            )
            if approval.id != session.provider_approval_id or approval.manifest_sha256 != session.provider_approval.manifest_sha256:
                raise BurpMCPProviderError('Pinned Burp MCP provider approval is no longer current.')
            if endpoint != session.endpoint_origin:
                raise BurpMCPProviderError('Approved Burp MCP endpoint changed after session creation.')

            allowed = session.allowed_tools if isinstance(session.allowed_tools, dict) else {}
            if op not in allowed or mapping.get(op) != allowed.get(op):
                raise BurpMCPAuthorizationError('Burp MCP operation is not admitted by the pinned session contract.')
            provider_tool_name = str(allowed[op])
            safe_arguments = _safe_arguments(op, arguments, session.target_snapshot)
            arguments_sha256 = _sha(safe_arguments)
            request_fingerprint = _sha({
                'session_id': str(session.id),
                'actor_id': str(actor_id),
                'operation': op,
                'provider_tool_name': provider_tool_name,
                'idempotency_key': idem,
                'arguments_sha256': arguments_sha256,
            })

            replay = _replay(
                session=session,
                idempotency_key=idem,
                request_fingerprint=request_fingerprint,
            )
            if replay is not None:
                return replay

            total = session.invocations.count()
            if total >= int(session.max_invocations):
                raise BurpMCPRateLimit('Burp MCP session invocation budget is exhausted.')
            recent = session.invocations.filter(created_at__gte=timezone.now() - timedelta(minutes=1)).count()
            if recent >= int(session.rate_limit_per_minute):
                raise BurpMCPRateLimit('Burp MCP per-minute invocation rate limit is exhausted.')
            sequence = total + 1

            materials: tuple[dict[str, Any], ...] = ()
            if session.credential_ref_id:
                materials, _credential_context = resolve_credential_refs_for_worker(
                    project_id=str(project.id),
                    actor_id=str(actor_id),
                    refs=[str(session.credential_ref_id)],
                    capability_id=BURP_MCP_CAPABILITY_ID,
                    allowed_kinds=(CredentialSecret.Kind.API_KEY, CredentialSecret.Kind.TOKEN),
                    purpose='burp-mcp:provider-call',
                )
            bearer = str(materials[0]['secret']) if materials else ''

            provider_request_id = _sha({
                'session_id': str(session.id),
                'sequence': sequence,
                'request_fingerprint': request_fingerprint,
            })[:32]
            raw_result, response_request_id = _perform_mcp_call(
                endpoint=session.endpoint_origin,
                provider_tool_name=provider_tool_name,
                arguments=safe_arguments,
                request_id=provider_request_id,
                bearer_token=bearer,
            )
            provider_result_sha256 = _sha(raw_result)
            result_summary = _redact_result(raw_result)
            assert_no_credential_material_leaked(materials, result_summary)

            evidence_payload = {
                'schema': 'aegis.burp-mcp-evidence.v1',
                'policy_version': BURP_MCP_EVIDENCE_POLICY_VERSION,
                'session_id': str(session.id),
                'organization_id': str(organization.id),
                'project_id': str(project.id),
                'asset_id': str(asset.id),
                'scan_id': str(scan.id),
                'authorization_decision_id': str(decision.id),
                'provider_approval_id': str(approval.id),
                'provider_identity_sha256': session.provider_identity_sha256,
                'operation': op,
                'provider_tool_name': provider_tool_name,
                'arguments_sha256': arguments_sha256,
                'provider_result_sha256': provider_result_sha256,
                'result_summary': result_summary,
                'raw_secret_persisted': False,
                'raw_request_response_persisted': False,
                'arbitrary_execution': False,
            }
            assert_no_credential_material_leaked(materials, evidence_payload)
            evidence_pk = evidence_id(
                'burp_mcp',
                f'{session.id}:{request_fingerprint}',
                'burp_mcp',
                'provider_execution',
                None,
            )
            evidence = Evidence.objects.create(
                id=evidence_pk,
                scan=scan,
                asset=asset,
                source='burp_mcp',
                evidence_type='provider_execution',
                raw_output=_canonical(evidence_payload).decode('utf-8'),
                metadata={
                    'schema': 'aegis.burp-mcp-evidence.v1',
                    'source_capability': BURP_MCP_CAPABILITY_ID,
                    'capability_id': BURP_MCP_CAPABILITY_ID,
                    'organization_id': str(organization.id),
                    'project_id': str(project.id),
                    'subject_type': 'asset',
                    'subject_id': str(asset.id),
                    'target': session.target_snapshot,
                    'authorization_decision_id': str(decision.id),
                    'execution_ref': str(session.id),
                    'provider_approval_id': str(approval.id),
                    'provider_identity_sha256': session.provider_identity_sha256,
                    'request_fingerprint': request_fingerprint,
                    'raw_secret_persisted': False,
                },
                collected_by_id=actor_id,
            )

            qualification = qualify_evidence(
                project_id=str(project.id),
                organization_id=str(organization.id),
                evidence_ids=[str(evidence.id)],
                subject_type='asset',
                subject_id=str(asset.id),
                target=session.target_snapshot,
                authorization_ref=str(decision.id),
                execution_ref=str(session.id),
                requested_by_id=str(actor_id),
                policy=EvidenceQualificationPolicy(
                    policy_version=BURP_MCP_EVIDENCE_POLICY_VERSION,
                    min_count=1,
                    evidence_types=('provider_execution',),
                    source_capabilities=(BURP_MCP_CAPABILITY_ID,),
                    require_subject=True,
                    require_target=True,
                    require_authorization=True,
                    require_execution=True,
                    require_producer=True,
                ),
            )
            if not qualification.qualified:
                raise BurpMCPAuthorizationError(
                    f'Burp MCP evidence failed qualification: {qualification.evaluation.decision}.'
                )

            try:
                invocation = BurpMCPInvocation.objects.create(
                    session=session,
                    evidence=evidence,
                    qualification=qualification.evaluation,
                    invoked_by_id=actor_id,
                    operation=op,
                    provider_tool_name=provider_tool_name,
                    invocation_sequence=sequence,
                    idempotency_key=idem,
                    request_fingerprint=request_fingerprint,
                    arguments_sha256=arguments_sha256,
                    provider_result_sha256=provider_result_sha256,
                    evidence_sha256=evidence.sha256,
                    provider_request_id=response_request_id,
                    result_summary=result_summary,
                )
            except IntegrityError as exc:
                raise BurpMCPConflict('Burp MCP invocation could not be committed idempotently.') from exc

            add_audit_entry(
                user=actor_id,
                action='burp_mcp.invocation.commit',
                target=str(invocation.id),
                project=str(project.id),
                resource_type='burp_mcp_invocation',
                resource_repr=op,
                metadata={
                    'organization_id': str(organization.id),
                    'session_id': str(session.id),
                    'asset_id': str(asset.id),
                    'scan_id': str(scan.id),
                    'evidence_id': str(evidence.id),
                    'qualification_id': str(qualification.evaluation.id),
                    'authorization_decision_id': str(decision.id),
                    'provider_approval_id': str(approval.id),
                    'request_fingerprint': request_fingerprint,
                    'provider_result_sha256': provider_result_sha256,
                    'policy_version': BURP_MCP_POLICY_VERSION,
                },
            )
            return BurpMCPInvocationResult(invocation=invocation, replayed=False)
    except Exception as exc:
        _audit_failure(str(session_id), str(actor_id), str(exc))
        raise
