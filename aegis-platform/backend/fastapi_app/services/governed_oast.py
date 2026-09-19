from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
from datetime import timedelta
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid5

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from django_project.assets.models import Asset, AssetAuthorization
from django_project.audit.models import AuditLog
from django_project.audit.services import append_audit
from django_project.evidence.models import (
    Evidence,
    GovernedOASTInteraction,
    GovernedOASTSession,
)
from django_project.projects.models import Project
from django_project.scans.models import Scan

from .authorization_guard import asset_target
from .evidence_identity import evidence_id


OAST_NAMESPACE = UUID('997c4411-6714-4d21-b1a4-4556c1dc8404')
OAST_POLICY_VERSION = 'governed-oast.v1'
_MIN_TTL_SECONDS = 30
_MAX_TTL_SECONDS = 1800
_MAX_INTERACTIONS = 64
_MAX_BODY_BYTES = 16 * 1024
_MAX_QUERY_BYTES = 4096
_IDEMPOTENCY_RE = re.compile(r'^[A-Za-z0-9._:-]{16,128}$')
_DNS_LABEL_RE = re.compile(r'^[a-z0-9-]{1,63}$')
_SAFE_HTTP_HEADERS = frozenset({
    'accept',
    'content-type',
    'user-agent',
})


class OASTRuntimeError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        self.code = code
        self.status_code = status_code
        super().__init__(message)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), default=str)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()


def _signing_key() -> bytes:
    raw = os.getenv('OAST_TOKEN_SIGNING_KEY', '')
    encoded = raw.encode('utf-8')
    if len(encoded) < 32:
        raise OASTRuntimeError(
            'oast_not_configured',
            'OAST_TOKEN_SIGNING_KEY must contain at least 32 bytes.',
            503,
        )
    return encoded


def _http_callback_base() -> str:
    raw = os.getenv('OAST_PUBLIC_HTTP_BASE', '').strip()
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or '').lower().rstrip('.')
        port = parsed.port
    except ValueError as exc:
        raise OASTRuntimeError('oast_not_configured', 'OAST_PUBLIC_HTTP_BASE is invalid.', 503) from exc
    if not host or parsed.username is not None or parsed.password is not None:
        raise OASTRuntimeError('oast_not_configured', 'OAST_PUBLIC_HTTP_BASE is invalid.', 503)
    if parsed.query or parsed.fragment:
        raise OASTRuntimeError('oast_not_configured', 'OAST_PUBLIC_HTTP_BASE cannot contain query or fragment.', 503)
    allow_local_http = os.getenv('OAST_ALLOW_INSECURE_LOCAL', '').strip().lower() in {'1', 'true', 'yes', 'on'}
    if parsed.scheme != 'https':
        local = host in {'127.0.0.1', 'localhost', '::1'}
        if not (allow_local_http and parsed.scheme == 'http' and local):
            raise OASTRuntimeError('oast_not_configured', 'OAST callback base must use HTTPS.', 503)
    authority_host = f'[{host}]' if ':' in host else host
    authority = authority_host
    if port is not None and not (
        (parsed.scheme == 'https' and port == 443)
        or (parsed.scheme == 'http' and port == 80)
    ):
        authority = f'{authority_host}:{port}'
    path = '/' + parsed.path.strip('/') if parsed.path.strip('/') else ''
    return urlunsplit((parsed.scheme, authority, path, '', '')).rstrip('/')


def _dns_domain() -> str:
    raw = os.getenv('OAST_PUBLIC_DNS_DOMAIN', '').strip().lower().rstrip('.')
    if not raw or len(raw) > 190:
        raise OASTRuntimeError('oast_not_configured', 'OAST_PUBLIC_DNS_DOMAIN is not configured.', 503)
    labels = raw.split('.')
    if len(labels) < 2 or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise OASTRuntimeError('oast_not_configured', 'OAST_PUBLIC_DNS_DOMAIN must be a valid FQDN.', 503)
    return raw


def _session_token(session_id: UUID, request_fingerprint: str) -> str:
    payload = f'{session_id}:{request_fingerprint}:{OAST_POLICY_VERSION}'.encode('ascii')
    digest = hmac.new(_signing_key(), payload, hashlib.sha256).digest()
    return base64.b32encode(digest).decode('ascii').rstrip('=').lower()


def _callback_contract(session: GovernedOASTSession) -> dict[str, str]:
    token = _session_token(session.id, session.request_fingerprint)
    if not hmac.compare_digest(_sha256_text(token), session.token_sha256):
        raise OASTRuntimeError(
            'oast_key_drift',
            'OAST token signing key no longer matches this active session.',
            503,
        )
    return {
        'http_url': f'{_http_callback_base()}/{session.id}/{token}',
        'dns_name': f'{token}.{session.id.hex}.{_dns_domain()}',
    }


def _project_access(project_id: str, user_id: str) -> Project | None:
    return (
        Project.objects.filter(pk=project_id)
        .filter(Q(owner_id=user_id) | Q(members__id=user_id))
        .distinct()
        .first()
    )


def _require_current_authorization(
    asset: Asset,
    authorization_id: str,
    expected_target: str,
) -> AssetAuthorization:
    latest = (
        AssetAuthorization.objects.select_for_update()
        .filter(asset=asset)
        .order_by('-created_at', '-id')
        .first()
    )
    if latest is None or str(latest.id) != str(authorization_id):
        raise OASTRuntimeError(
            'authorization_superseded',
            'OAST session requires the latest asset authorization decision.',
            409,
        )
    if latest.asset_identity_snapshot != asset.id:
        raise OASTRuntimeError(
            'authorization_identity_mismatch',
            'Authorization decision is not bound to the current asset identity.',
            409,
        )
    if latest.authorized is not True or not latest.is_currently_valid:
        raise OASTRuntimeError(
            'authorization_invalid',
            'Authorization decision is not currently valid.',
            403,
        )
    current_target = asset_target(asset)
    if not current_target or current_target != latest.target_snapshot:
        raise OASTRuntimeError(
            'authorization_target_drift',
            'Asset target no longer matches the authorization snapshot.',
            409,
        )
    if expected_target and current_target != expected_target:
        raise OASTRuntimeError(
            'target_mismatch',
            'Requested OAST target does not match the authorization snapshot.',
            409,
        )
    return latest


def _normalize_execution_id(value: str) -> str:
    execution_id = str(value or '').strip()
    if not execution_id or len(execution_id) > 128 or any(ch in execution_id for ch in '\r\n\x00'):
        raise OASTRuntimeError('invalid_execution_id', 'execution_id must be a non-empty bounded identifier.', 422)
    return execution_id


def _normalize_source_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _session_payload(session: GovernedOASTSession) -> dict[str, Any]:
    callbacks = _callback_contract(session)
    return {
        'id': str(session.id),
        'project_id': str(session.project_id),
        'asset_id': str(session.asset_id),
        'scan_id': str(session.scan_id) if session.scan_id else None,
        'authorization_decision_id': str(session.authorization_decision_id),
        'execution_id': session.execution_id,
        'target': session.target_snapshot,
        'expires_at': session.expires_at.isoformat(),
        'max_interactions': session.max_interactions,
        'policy_version': session.policy_version,
        'callbacks': callbacks,
    }


@transaction.atomic
def create_oast_session(
    *,
    user_id: str,
    project_id: str,
    asset_id: str,
    authorization_decision_id: str,
    execution_id: str,
    idempotency_key: str,
    target: str = '',
    scan_id: str | None = None,
    ttl_seconds: int = 300,
    max_interactions: int = 8,
) -> dict[str, Any]:
    if not _IDEMPOTENCY_RE.fullmatch(str(idempotency_key or '')):
        raise OASTRuntimeError(
            'invalid_idempotency_key',
            'idempotency_key must be 16-128 URL-safe characters.',
            422,
        )
    try:
        ttl = int(ttl_seconds)
        interaction_limit = int(max_interactions)
    except (TypeError, ValueError) as exc:
        raise OASTRuntimeError('invalid_limits', 'OAST limits must be integers.', 422) from exc
    if not _MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS:
        raise OASTRuntimeError(
            'invalid_ttl',
            f'ttl_seconds must be between {_MIN_TTL_SECONDS} and {_MAX_TTL_SECONDS}.',
            422,
        )
    if not 1 <= interaction_limit <= _MAX_INTERACTIONS:
        raise OASTRuntimeError(
            'invalid_interaction_limit',
            f'max_interactions must be between 1 and {_MAX_INTERACTIONS}.',
            422,
        )

    project = _project_access(project_id, user_id)
    if project is None:
        raise OASTRuntimeError('project_not_found', 'Project not found.', 404)
    asset = (
        Asset.objects.select_for_update()
        .filter(pk=asset_id, project=project, is_active=True)
        .first()
    )
    if asset is None:
        raise OASTRuntimeError('asset_not_found', 'Active asset not found in project.', 404)

    expected_target = str(target or '').strip() or asset_target(asset)
    decision = _require_current_authorization(
        asset,
        authorization_decision_id,
        expected_target,
    )
    execution = _normalize_execution_id(execution_id)

    scan = None
    if scan_id:
        scan = (
            Scan.objects.select_for_update()
            .filter(pk=scan_id, project=project, asset=asset)
            .first()
        )
        if scan is None:
            raise OASTRuntimeError('scan_not_found', 'Bound scan not found.', 404)
        if str(scan.authorization_decision_id or '') != str(decision.id):
            raise OASTRuntimeError(
                'scan_authorization_mismatch',
                'Scan is not bound to the OAST authorization decision.',
                409,
            )
        scan_execution = str(scan.execution_correlation_id or scan.id)
        if execution != scan_execution:
            raise OASTRuntimeError(
                'scan_execution_mismatch',
                'execution_id does not match the bound scan execution.',
                409,
            )
        if scan.status == Scan.Status.CANCELLED:
            raise OASTRuntimeError('scan_cancelled', 'Cancelled scan cannot create OAST callbacks.', 409)

    fingerprint_payload = {
        'actor_id': str(user_id),
        'project_id': str(project.id),
        'asset_id': str(asset.id),
        'scan_id': str(scan.id) if scan else '',
        'authorization_decision_id': str(decision.id),
        'execution_id': execution,
        'target': decision.target_snapshot,
        'idempotency_key': str(idempotency_key),
        'policy_version': OAST_POLICY_VERSION,
    }
    request_fingerprint = _sha256_text(_canonical_json(fingerprint_payload))
    session_id = uuid5(OAST_NAMESPACE, f'session:{request_fingerprint}')
    token = _session_token(session_id, request_fingerprint)
    token_sha256 = _sha256_text(token)

    existing = GovernedOASTSession.objects.filter(pk=session_id).first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise OASTRuntimeError(
                'session_identity_collision',
                'OAST session identity collision detected.',
                409,
            )
        return _session_payload(existing)

    expires_at = timezone.now() + timedelta(seconds=ttl)
    try:
        with transaction.atomic():
            session = GovernedOASTSession.objects.create(
                id=session_id,
                project=project,
                asset=asset,
                scan=scan,
                authorization_decision=decision,
                created_by_id=user_id,
                target_snapshot=decision.target_snapshot,
                execution_id=execution,
                request_fingerprint=request_fingerprint,
                token_sha256=token_sha256,
                expires_at=expires_at,
                max_interactions=interaction_limit,
                policy_version=OAST_POLICY_VERSION,
            )
    except IntegrityError as exc:
        concurrent = GovernedOASTSession.objects.filter(
            request_fingerprint=request_fingerprint,
        ).first()
        if concurrent is None:
            raise OASTRuntimeError(
                'session_commit_conflict',
                'OAST session could not be committed idempotently.',
                409,
            ) from exc
        session = concurrent

    append_audit(
        user_id=user_id,
        action=AuditLog.Action.API_REQUEST,
        result=AuditLog.Result.SUCCESS,
        resource_type='GovernedOASTSession',
        resource_id=str(session.id),
        resource_repr=f'Governed OAST session for asset {asset.id}',
        changes={'created': True},
        metadata={
            'event': 'oast_session_created',
            'project_id': str(project.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id) if scan else None,
            'authorization_decision_id': str(decision.id),
            'execution_id': execution,
            'target_sha256': _sha256_text(decision.target_snapshot),
            'expires_at': session.expires_at.isoformat(),
            'max_interactions': session.max_interactions,
            'policy_version': session.policy_version,
        },
        ip_address='0.0.0.0',
    )
    return _session_payload(session)


def _load_callback_session(session_id: str, token: str) -> GovernedOASTSession:
    try:
        session_uuid = UUID(str(session_id))
    except ValueError as exc:
        raise OASTRuntimeError('invalid_callback', 'Invalid OAST callback identity.', 404) from exc
    session = (
        GovernedOASTSession.objects.select_related(
            'asset',
            'project',
            'scan',
            'authorization_decision',
            'created_by',
        )
        .filter(pk=session_uuid)
        .first()
    )
    if session is None:
        raise OASTRuntimeError('invalid_callback', 'Invalid OAST callback identity.', 404)
    expected = _session_token(session.id, session.request_fingerprint)
    if not hmac.compare_digest(token, expected):
        raise OASTRuntimeError('invalid_callback', 'Invalid OAST callback identity.', 404)
    if not hmac.compare_digest(session.token_sha256, _sha256_text(token)):
        raise OASTRuntimeError('invalid_callback', 'Invalid OAST callback identity.', 404)
    if timezone.now() >= session.expires_at:
        raise OASTRuntimeError('callback_expired', 'OAST callback session has expired.', 410)
    return session


def _revalidate_session_authorization(session: GovernedOASTSession) -> None:
    asset = Asset.objects.select_for_update().get(pk=session.asset_id)
    _require_current_authorization(
        asset,
        str(session.authorization_decision_id),
        session.target_snapshot,
    )
    if session.scan_id:
        scan = Scan.objects.select_for_update().get(pk=session.scan_id)
        if scan.status == Scan.Status.CANCELLED:
            raise OASTRuntimeError('scan_cancelled', 'Bound scan has been cancelled.', 410)
        if str(scan.authorization_decision_id or '') != str(session.authorization_decision_id):
            raise OASTRuntimeError(
                'scan_authorization_mismatch',
                'Bound scan authorization changed.',
                409,
            )
        if str(scan.execution_correlation_id or scan.id) != session.execution_id:
            raise OASTRuntimeError(
                'scan_execution_mismatch',
                'Bound scan execution identity changed.',
                409,
            )


def _safe_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (headers or {}).items():
        name = str(key).strip().lower()
        if name not in _SAFE_HTTP_HEADERS:
            continue
        text = str(value).replace('\r', ' ').replace('\n', ' ')[:512]
        safe[name] = text
    return safe


def _interaction_fingerprint(
    *,
    session: GovernedOASTSession,
    protocol: str,
    source_ip: str | None,
    request_method: str,
    payload_sha256: str,
    metadata: Mapping[str, Any],
) -> str:
    return _sha256_text(_canonical_json({
        'session_id': str(session.id),
        'protocol': protocol,
        'source_ip': source_ip or '',
        'request_method': request_method,
        'payload_sha256': payload_sha256,
        'metadata': dict(metadata),
    }))


@transaction.atomic
def _persist_interaction(
    *,
    session: GovernedOASTSession,
    protocol: str,
    source_ip: str | None,
    request_method: str = '',
    payload: bytes = b'',
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    locked = GovernedOASTSession.objects.select_for_update().get(pk=session.pk)
    if timezone.now() >= locked.expires_at:
        raise OASTRuntimeError('callback_expired', 'OAST callback session has expired.', 410)
    _revalidate_session_authorization(locked)

    source = _normalize_source_ip(source_ip)
    payload_bytes = bytes(payload or b'')
    if len(payload_bytes) > _MAX_BODY_BYTES:
        raise OASTRuntimeError('payload_too_large', 'OAST callback payload exceeds the bounded limit.', 413)
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else ''
    safe_metadata = dict(metadata or {})
    fingerprint = _interaction_fingerprint(
        session=locked,
        protocol=protocol,
        source_ip=source,
        request_method=request_method,
        payload_sha256=payload_sha256,
        metadata=safe_metadata,
    )

    duplicate = (
        GovernedOASTInteraction.objects.select_related('evidence')
        .filter(session=locked, fingerprint=fingerprint)
        .first()
    )
    if duplicate is not None:
        return {
            'accepted': True,
            'duplicate': True,
            'interaction_id': str(duplicate.id),
            'evidence_id': str(duplicate.evidence_id),
            'protocol': duplicate.protocol,
        }

    if locked.interactions.count() >= locked.max_interactions:
        raise OASTRuntimeError(
            'interaction_limit_reached',
            'OAST callback interaction limit has been reached.',
            429,
        )

    interaction_id = uuid5(OAST_NAMESPACE, f'interaction:{locked.id}:{fingerprint}')
    evidence_uuid = evidence_id(
        'oast_interaction',
        str(interaction_id),
        'oast',
        f'oast_{protocol}_callback',
    )
    observation = {
        'schema': 'aegis.governed-oast-interaction.v1',
        'session_id': str(locked.id),
        'interaction_id': str(interaction_id),
        'project_id': str(locked.project_id),
        'asset_id': str(locked.asset_id),
        'scan_id': str(locked.scan_id) if locked.scan_id else None,
        'authorization_decision_id': str(locked.authorization_decision_id),
        'execution_id': locked.execution_id,
        'target_sha256': _sha256_text(locked.target_snapshot),
        'protocol': protocol,
        'source_ip': source,
        'request_method': request_method,
        'payload_sha256': payload_sha256,
        'payload_size': len(payload_bytes),
        'metadata': safe_metadata,
        'policy_version': locked.policy_version,
    }
    raw_output = _canonical_json(observation)

    try:
        with transaction.atomic():
            evidence = Evidence.objects.create(
                id=evidence_uuid,
                scan=locked.scan,
                asset=locked.asset,
                source='oast',
                evidence_type=f'oast_{protocol}_callback',
                raw_output=raw_output,
                metadata={
                    'oast_session_id': str(locked.id),
                    'oast_interaction_id': str(interaction_id),
                    'project_id': str(locked.project_id),
                    'authorization_decision_id': str(locked.authorization_decision_id),
                    'execution_id': locked.execution_id,
                    'protocol': protocol,
                    'policy_version': locked.policy_version,
                    'authoritative_oast_evidence': True,
                },
                collected_by=locked.created_by,
            )
            interaction = GovernedOASTInteraction.objects.create(
                id=interaction_id,
                session=locked,
                evidence=evidence,
                protocol=protocol,
                fingerprint=fingerprint,
                source_ip=source,
                request_method=request_method,
                payload_sha256=payload_sha256,
                payload_size=len(payload_bytes),
                metadata=safe_metadata,
            )
    except IntegrityError as exc:
        concurrent = (
            GovernedOASTInteraction.objects.select_related('evidence')
            .filter(session=locked, fingerprint=fingerprint)
            .first()
        )
        if concurrent is None:
            raise OASTRuntimeError(
                'interaction_commit_conflict',
                'OAST interaction could not be committed idempotently.',
                409,
            ) from exc
        return {
            'accepted': True,
            'duplicate': True,
            'interaction_id': str(concurrent.id),
            'evidence_id': str(concurrent.evidence_id),
            'protocol': concurrent.protocol,
        }

    append_audit(
        user=locked.created_by,
        action=AuditLog.Action.API_REQUEST,
        result=AuditLog.Result.SUCCESS,
        resource_type='GovernedOASTInteraction',
        resource_id=str(interaction.id),
        resource_repr=f'Governed OAST {protocol.upper()} callback',
        changes={'accepted': True, 'duplicate': False},
        metadata={
            'event': 'oast_callback_accepted',
            'session_id': str(locked.id),
            'project_id': str(locked.project_id),
            'asset_id': str(locked.asset_id),
            'authorization_decision_id': str(locked.authorization_decision_id),
            'execution_id': locked.execution_id,
            'protocol': protocol,
            'evidence_id': str(evidence.id),
            'evidence_sha256': evidence.sha256,
            'interaction_fingerprint': fingerprint,
        },
        ip_address=source or '0.0.0.0',
    )
    return {
        'accepted': True,
        'duplicate': False,
        'interaction_id': str(interaction.id),
        'evidence_id': str(evidence.id),
        'protocol': protocol,
    }


def ingest_http_callback(
    *,
    session_id: str,
    token: str,
    source_ip: str | None,
    method: str,
    query_string: str = '',
    headers: Mapping[str, Any] | None = None,
    body: bytes = b'',
) -> dict[str, Any]:
    verb = str(method or '').upper()
    if verb not in {'GET', 'HEAD', 'POST'}:
        raise OASTRuntimeError('method_not_allowed', 'OAST HTTP collector only accepts GET, HEAD and POST.', 405)
    raw_query = str(query_string or '')
    if len(raw_query.encode('utf-8', errors='replace')) > _MAX_QUERY_BYTES:
        raise OASTRuntimeError('query_too_large', 'OAST callback query exceeds the bounded limit.', 413)
    session = _load_callback_session(session_id, token)
    metadata = {
        'headers': _safe_headers(headers),
        'query_length': len(raw_query),
        'query_sha256': _sha256_text(raw_query) if raw_query else '',
    }
    return _persist_interaction(
        session=session,
        protocol=GovernedOASTInteraction.Protocol.HTTP,
        source_ip=source_ip,
        request_method=verb,
        payload=body,
        metadata=metadata,
    )


def _parse_dns_callback_name(qname: str) -> tuple[str, str]:
    raw = str(qname or '').strip().lower().rstrip('.')
    domain = _dns_domain()
    suffix = '.' + domain
    if not raw.endswith(suffix):
        raise OASTRuntimeError('invalid_callback', 'DNS callback is outside the configured OAST domain.', 404)
    prefix = raw[:-len(suffix)]
    labels = prefix.split('.')
    if len(labels) != 2:
        raise OASTRuntimeError('invalid_callback', 'DNS callback identity is malformed.', 404)
    token, session_hex = labels
    if len(token) != 52 or not re.fullmatch(r'[a-z2-7]{52}', token):
        raise OASTRuntimeError('invalid_callback', 'DNS callback token is malformed.', 404)
    if not re.fullmatch(r'[0-9a-f]{32}', session_hex):
        raise OASTRuntimeError('invalid_callback', 'DNS callback session identity is malformed.', 404)
    return str(UUID(hex=session_hex)), token


def ingest_dns_callback(
    *,
    qname: str,
    source_ip: str | None,
    qtype: int,
) -> dict[str, Any]:
    session_id, token = _parse_dns_callback_name(qname)
    session = _load_callback_session(session_id, token)
    qtype_value = max(0, min(int(qtype), 65535))
    metadata = {
        'qname_sha256': _sha256_text(str(qname).lower().rstrip('.')),
        'qtype': qtype_value,
    }
    return _persist_interaction(
        session=session,
        protocol=GovernedOASTInteraction.Protocol.DNS,
        source_ip=source_ip,
        metadata=metadata,
    )


def get_oast_session(*, session_id: str, user_id: str) -> dict[str, Any]:
    try:
        session_uuid = UUID(str(session_id))
    except ValueError as exc:
        raise OASTRuntimeError('session_not_found', 'OAST session not found.', 404) from exc
    session = (
        GovernedOASTSession.objects.select_related('project')
        .filter(pk=session_uuid)
        .filter(Q(project__owner_id=user_id) | Q(project__members__id=user_id))
        .distinct()
        .first()
    )
    if session is None:
        raise OASTRuntimeError('session_not_found', 'OAST session not found.', 404)
    payload = _session_payload(session)
    payload['expired'] = timezone.now() >= session.expires_at
    payload['interactions'] = [
        {
            'id': str(item.id),
            'protocol': item.protocol,
            'evidence_id': str(item.evidence_id),
            'observed_at': item.observed_at.isoformat(),
            'payload_sha256': item.payload_sha256,
            'payload_size': item.payload_size,
        }
        for item in session.interactions.select_related('evidence').all()[: session.max_interactions]
    ]
    return payload


def resolve_ssrf_oast_evidence(
    *,
    session_id: str,
    execution_id: str,
    target: str,
) -> dict[str, Any]:
    try:
        session_uuid = UUID(str(session_id))
    except ValueError:
        return {'confirmed': False, 'reason': 'invalid_oast_session_id'}
    session = (
        GovernedOASTSession.objects.select_related('asset', 'authorization_decision', 'scan')
        .filter(pk=session_uuid)
        .first()
    )
    if session is None:
        return {'confirmed': False, 'reason': 'oast_session_not_found'}
    if session.execution_id != str(execution_id or '').strip():
        return {'confirmed': False, 'reason': 'oast_execution_mismatch'}
    if session.target_snapshot != str(target or '').strip():
        return {'confirmed': False, 'reason': 'oast_target_mismatch'}
    try:
        with transaction.atomic():
            locked = GovernedOASTSession.objects.select_for_update().get(pk=session.pk)
            _revalidate_session_authorization(locked)
    except (OASTRuntimeError, Asset.DoesNotExist, Scan.DoesNotExist):
        return {'confirmed': False, 'reason': 'oast_authorization_not_current'}

    interactions = list(
        session.interactions.select_related('evidence').order_by('observed_at', 'id')[: session.max_interactions]
    )
    if not interactions:
        return {'confirmed': False, 'reason': 'oast_callback_not_observed'}
    proof_payload = {
        'session_id': str(session.id),
        'execution_id': session.execution_id,
        'target_sha256': _sha256_text(session.target_snapshot),
        'interaction_ids': [str(item.id) for item in interactions],
        'evidence_ids': [str(item.evidence_id) for item in interactions],
        'protocols': sorted({item.protocol for item in interactions}),
        'callback_count': len(interactions),
    }
    proof_hmac = hmac.new(
        _signing_key(),
        ('ssrf-oast-proof:' + _canonical_json(proof_payload)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return {
        'confirmed': True,
        'reason': 'authoritative_oast_callback_observed',
        **proof_payload,
        'proof_hmac': proof_hmac,
    }


def verify_ssrf_oast_proof(payload: Mapping[str, Any]) -> bool:
    try:
        proof_payload = {
            'session_id': str(payload['session_id']),
            'execution_id': str(payload['execution_id']),
            'target_sha256': str(payload['target_sha256']),
            'interaction_ids': [str(item) for item in payload['interaction_ids']],
            'evidence_ids': [str(item) for item in payload['evidence_ids']],
            'protocols': sorted(str(item) for item in payload['protocols']),
            'callback_count': int(payload['callback_count']),
        }
        supplied = str(payload['proof_hmac'])
    except (KeyError, TypeError, ValueError):
        return False
    if (
        not proof_payload['session_id']
        or not proof_payload['execution_id']
        or len(proof_payload['target_sha256']) != 64
        or not proof_payload['interaction_ids']
        or not proof_payload['evidence_ids']
        or len(proof_payload['interaction_ids']) != len(proof_payload['evidence_ids'])
        or proof_payload['callback_count'] != len(proof_payload['interaction_ids'])
        or any(protocol not in {'dns', 'http'} for protocol in proof_payload['protocols'])
        or len(supplied) != 64
    ):
        return False
    expected = hmac.new(
        _signing_key(),
        ('ssrf-oast-proof:' + _canonical_json(proof_payload)).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(supplied, expected)


__all__ = [
    'OASTRuntimeError',
    'create_oast_session',
    'get_oast_session',
    'ingest_dns_callback',
    'ingest_http_callback',
    'resolve_ssrf_oast_evidence',
    'verify_ssrf_oast_proof',
]
