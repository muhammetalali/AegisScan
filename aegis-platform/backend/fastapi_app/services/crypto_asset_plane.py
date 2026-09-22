from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Any, Iterable

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from django_project.assets.models import Asset, AssetAuthorization
from django_project.projects.models import Project, ProjectMembership
from django_project.scans.models import Scan
from enterprise.crypto_asset_models import CryptographicAssetRecord, CryptographicInventorySnapshot
from enterprise.models import Organization, OrganizationMembership, TenantProject

from .audit_writer import add_audit_entry


CRYPTO_POLICY_VERSION = 'crypto-asset-cbom.v1'
CBOM_SCHEMA = 'aegis.cbom.v1'

_FORBIDDEN_FIELDS = {
    'private_key',
    'private_key_pem',
    'key_material',
    'secret',
    'secret_value',
    'password',
    'token',
    'raw_pem',
    'raw_certificate',
}
_ALLOWED_KINDS = {value for value, _label in CryptographicAssetRecord.Kind.choices}
_WEAK_ALGORITHMS = {'md5', 'sha1', 'rc4', 'des', '3des', 'tripledes'}
_DEPRECATED_PROTOCOLS = {'ssl2', 'ssl3', 'tls1.0', 'tls1.1'}
_QUANTUM_VULNERABLE = {'rsa', 'ecdsa', 'ecdh', 'ecc', 'dh', 'dsa'}
_QUANTUM_RESISTANT = {'ml-kem', 'ml-dsa', 'slh-dsa', 'kyber', 'dilithium', 'sphincs+'}


class CryptoAssetError(ValueError):
    pass


class CryptoAssetAuthorizationError(CryptoAssetError):
    pass


@dataclass(frozen=True)
class CryptoSnapshotResult:
    snapshot: CryptographicInventorySnapshot
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


def _text(value: Any, maximum: int) -> str:
    value = ' '.join(str(value or '').split())
    if len(value) > maximum or any(ch in value for ch in '\r\n\x00'):
        raise CryptoAssetError('Cryptographic inventory text field is invalid.')
    return value


def _dt(value: Any) -> datetime | None:
    if value in (None, ''):
        return None
    parsed = value if isinstance(value, datetime) else parse_datetime(str(value))
    if parsed is None:
        raise CryptoAssetError('Cryptographic inventory timestamp is invalid.')
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt_timezone.utc)
    return parsed


def _assert_no_secret_material(value: Any, path: str = 'record') -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if normalized in _FORBIDDEN_FIELDS:
                raise CryptoAssetError(f'{path}.{normalized} is forbidden; raw cryptographic secret material must never be persisted.')
            _assert_no_secret_material(item, f'{path}.{normalized}')
    elif isinstance(value, list):
        for index, item in enumerate(value[:500]):
            _assert_no_secret_material(item, f'{path}[{index}]')


def _security_state(*, algorithm: str, key_size: int | None, protocol: str, not_after: datetime | None) -> str:
    now = timezone.now()
    if not_after is not None and not_after <= now:
        return CryptographicAssetRecord.SecurityState.EXPIRED
    algo = algorithm.strip().lower().replace('_', '-')
    proto = protocol.strip().lower()
    if proto in _DEPRECATED_PROTOCOLS:
        return CryptographicAssetRecord.SecurityState.DEPRECATED
    if algo in _WEAK_ALGORITHMS:
        return CryptographicAssetRecord.SecurityState.DEPRECATED
    if algo == 'rsa' and key_size is not None and key_size < 2048:
        return CryptographicAssetRecord.SecurityState.WEAK
    if algo in {'', 'unknown'} and not protocol:
        return CryptographicAssetRecord.SecurityState.UNKNOWN
    return CryptographicAssetRecord.SecurityState.ACCEPTABLE


def _quantum_state(algorithm: str, metadata: dict[str, Any]) -> str:
    algo = algorithm.strip().lower().replace('_', '-')
    components = {
        str(item).strip().lower().replace('_', '-')
        for item in (metadata.get('hybrid_components') or [])
        if str(item).strip()
    }
    if components and components.intersection(_QUANTUM_VULNERABLE) and components.intersection(_QUANTUM_RESISTANT):
        return CryptographicAssetRecord.QuantumState.HYBRID
    if algo in _QUANTUM_RESISTANT:
        return CryptographicAssetRecord.QuantumState.RESISTANT
    if algo in _QUANTUM_VULNERABLE or algo.startswith('rsa') or algo.startswith('ec'):
        return CryptographicAssetRecord.QuantumState.VULNERABLE
    return CryptographicAssetRecord.QuantumState.UNKNOWN


def _normalize_record(raw: dict[str, Any], ordinal: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CryptoAssetError('Each cryptographic inventory record must be an object.')
    _assert_no_secret_material(raw)

    kind = str(raw.get('kind') or '').strip().lower()
    if kind not in _ALLOWED_KINDS:
        raise CryptoAssetError('Unsupported cryptographic asset kind.')
    name = _text(raw.get('name'), 255)
    if not name:
        raise CryptoAssetError('Cryptographic asset name is required.')

    algorithm = _text(raw.get('algorithm'), 128)
    protocol = _text(raw.get('protocol'), 64)
    version = _text(raw.get('version'), 64)
    curve = _text(raw.get('curve'), 128)
    issuer = _text(raw.get('issuer'), 500)
    subject = _text(raw.get('subject'), 500)

    key_size = raw.get('key_size')
    if key_size in (None, ''):
        normalized_key_size = None
    else:
        try:
            normalized_key_size = int(key_size)
        except (TypeError, ValueError) as exc:
            raise CryptoAssetError('key_size must be an integer.') from exc
        if normalized_key_size < 1 or normalized_key_size > 65536:
            raise CryptoAssetError('key_size is outside accepted bounds.')

    not_before = _dt(raw.get('not_before'))
    not_after = _dt(raw.get('not_after'))
    if not_before and not_after and not_after <= not_before:
        raise CryptoAssetError('not_after must be later than not_before.')

    metadata = raw.get('metadata') or {}
    if not isinstance(metadata, dict):
        raise CryptoAssetError('metadata must be an object.')
    _assert_no_secret_material(metadata, 'record.metadata')
    safe_metadata = json.loads(_canonical(metadata).decode('utf-8'))

    normalized = {
        'ordinal': ordinal,
        'kind': kind,
        'name': name,
        'algorithm': algorithm,
        'key_size': normalized_key_size,
        'curve': curve,
        'protocol': protocol,
        'version': version,
        'issuer': issuer,
        'subject': subject,
        'not_before': not_before.isoformat() if not_before else None,
        'not_after': not_after.isoformat() if not_after else None,
        'metadata': safe_metadata,
    }
    normalized['security_state'] = _security_state(
        algorithm=algorithm,
        key_size=normalized_key_size,
        protocol=protocol,
        not_after=not_after,
    )
    normalized['quantum_state'] = _quantum_state(algorithm, safe_metadata)
    normalized['fingerprint_sha256'] = _sha({
        key: value for key, value in normalized.items() if key != 'ordinal'
    })
    return normalized


def _risk_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    security_counts: dict[str, int] = {}
    quantum_counts: dict[str, int] = {}
    for item in records:
        security_counts[item['security_state']] = security_counts.get(item['security_state'], 0) + 1
        quantum_counts[item['quantum_state']] = quantum_counts.get(item['quantum_state'], 0) + 1
    return {
        'schema': 'aegis.crypto-risk-summary.v1',
        'record_count': len(records),
        'security_states': dict(sorted(security_counts.items())),
        'quantum_states': dict(sorted(quantum_counts.items())),
        'weak_or_deprecated_count': sum(
            security_counts.get(name, 0)
            for name in ('weak', 'deprecated', 'expired')
        ),
        'quantum_vulnerable_count': quantum_counts.get('vulnerable', 0),
        'quantum_resistant_count': quantum_counts.get('resistant', 0),
        'hybrid_count': quantum_counts.get('hybrid', 0),
    }


def _cbom(*, project_id: str, asset_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    components = [
        {
            key: value
            for key, value in item.items()
            if key != 'ordinal'
        }
        for item in sorted(records, key=lambda row: (row['kind'], row['name'], row['fingerprint_sha256']))
    ]
    return {
        'schema': CBOM_SCHEMA,
        'project_id': project_id,
        'asset_id': asset_id,
        'components': components,
    }


def _drift(previous: CryptographicInventorySnapshot | None, records: list[dict[str, Any]]) -> dict[str, Any]:
    current = {item['fingerprint_sha256'] for item in records}
    if previous is None:
        return {
            'schema': 'aegis.crypto-drift.v1',
            'baseline': True,
            'added': sorted(current),
            'removed': [],
            'changed': False,
        }
    previous_set = set(previous.records.values_list('fingerprint_sha256', flat=True))
    added = sorted(current - previous_set)
    removed = sorted(previous_set - current)
    return {
        'schema': 'aegis.crypto-drift.v1',
        'baseline': False,
        'added': added,
        'removed': removed,
        'changed': bool(added or removed),
        'predecessor_id': str(previous.id),
    }


def _lock_context(
    *,
    project_id: str,
    asset_id: str,
    authorization_id: str,
    actor_id: str,
    scan_id: str | None,
) -> tuple[Organization, Project, Asset, AssetAuthorization, Scan | None]:
    identity = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if identity is None:
        raise CryptoAssetAuthorizationError('Project is not bound to an active enterprise tenant.')

    organization = (
        Organization.objects.select_for_update()
        .filter(pk=identity['organization_id'], is_active=True)
        .first()
    )
    if organization is None:
        raise CryptoAssetAuthorizationError('Enterprise tenant is inactive.')

    link = (
        TenantProject.objects.select_for_update(of=('self',))
        .filter(pk=identity['id'], organization_id=organization.id, project_id=project_id)
        .first()
    )
    if link is None:
        raise CryptoAssetAuthorizationError('Tenant/project binding changed during inventory commit.')

    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise CryptoAssetAuthorizationError('Project was not found.')

    project_allowed = str(project.owner_id) == str(actor_id) or ProjectMembership.objects.filter(
        project=project,
        user_id=actor_id,
        role__in=[ProjectMembership.Role.OWNER, ProjectMembership.Role.ADMIN, ProjectMembership.Role.MEMBER],
    ).exists()
    if not project_allowed:
        raise CryptoAssetAuthorizationError('Actor has no project access.')

    org_allowed = OrganizationMembership.objects.filter(
        organization=organization,
        user_id=actor_id,
        is_active=True,
    ).exists()
    if not org_allowed:
        raise CryptoAssetAuthorizationError('Actor has no active enterprise membership.')

    asset = Asset.objects.select_for_update().filter(pk=asset_id, project=project).first()
    if asset is None:
        raise CryptoAssetAuthorizationError('Asset was not found in the governed project.')

    decision = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(pk=authorization_id, asset=asset)
        .first()
    )
    if decision is None:
        raise CryptoAssetAuthorizationError('Asset authorization decision was not found.')

    latest = (
        AssetAuthorization.objects.select_for_update(of=('self',))
        .filter(asset=asset)
        .order_by('-created_at', '-id')
        .first()
    )
    now = timezone.now()
    if (
        latest is None
        or latest.id != decision.id
        or decision.authorized is not True
        or decision.valid_from > now
        or (decision.expires_at and decision.expires_at <= now)
    ):
        raise CryptoAssetAuthorizationError('Asset authorization decision is not currently admissible.')

    scan = None
    if scan_id:
        scan = Scan.objects.select_for_update(of=('self',)).filter(
            pk=scan_id,
            project=project,
            asset=asset,
        ).first()
        if scan is None:
            raise CryptoAssetAuthorizationError('Scan lineage does not match the governed asset.')

    return organization, project, asset, decision, scan


@transaction.atomic
def record_crypto_inventory(
    *,
    project_id: str,
    asset_id: str,
    authorization_id: str,
    actor_id: str,
    records: Iterable[dict[str, Any]],
    source_type: str,
    scan_id: str | None = None,
) -> CryptoSnapshotResult:
    source = _text(source_type, 64)
    if not source:
        raise CryptoAssetError('source_type is required.')

    normalized = [_normalize_record(item, index) for index, item in enumerate(list(records), start=1)]
    if not normalized:
        raise CryptoAssetError('Cryptographic inventory must contain at least one record.')
    if len(normalized) > 5000:
        raise CryptoAssetError('Cryptographic inventory exceeds the 5000-record limit.')

    fingerprints = [item['fingerprint_sha256'] for item in normalized]
    if len(fingerprints) != len(set(fingerprints)):
        raise CryptoAssetError('Cryptographic inventory contains duplicate records.')

    organization, project, asset, decision, scan = _lock_context(
        project_id=str(project_id),
        asset_id=str(asset_id),
        authorization_id=str(authorization_id),
        actor_id=str(actor_id),
        scan_id=str(scan_id) if scan_id else None,
    )

    previous = (
        CryptographicInventorySnapshot.objects.select_for_update()
        .filter(project=project, asset=asset)
        .order_by('-snapshot_version', '-created_at', '-id')
        .first()
    )

    inventory_projection = [
        {key: value for key, value in item.items() if key != 'ordinal'}
        for item in sorted(normalized, key=lambda row: row['fingerprint_sha256'])
    ]
    inventory_sha256 = _sha(inventory_projection)
    cbom = _cbom(project_id=str(project.id), asset_id=str(asset.id), records=normalized)
    cbom_sha256 = _sha(cbom)

    if (
        previous is not None
        and previous.inventory_sha256 == inventory_sha256
        and previous.cbom_sha256 == cbom_sha256
        and previous.authorization_decision_id == decision.id
        and previous.source_type == source
    ):
        return CryptoSnapshotResult(snapshot=previous, replayed=True)

    next_version = int(previous.snapshot_version) + 1 if previous else 1
    drift = _drift(previous, normalized)
    risk_summary = _risk_summary(normalized)
    request_fingerprint = _sha({
        'organization_id': str(organization.id),
        'project_id': str(project.id),
        'asset_id': str(asset.id),
        'scan_id': str(scan.id) if scan else '',
        'authorization_id': str(decision.id),
        'actor_id': str(actor_id),
        'source_type': source,
        'snapshot_version': next_version,
        'inventory_sha256': inventory_sha256,
        'cbom_sha256': cbom_sha256,
        'predecessor_id': str(previous.id) if previous else '',
        'policy_version': CRYPTO_POLICY_VERSION,
    })

    replay = CryptographicInventorySnapshot.objects.filter(request_fingerprint=request_fingerprint).first()
    if replay is not None:
        return CryptoSnapshotResult(snapshot=replay, replayed=True)

    snapshot = CryptographicInventorySnapshot.objects.create(
        organization=organization,
        project=project,
        asset=asset,
        scan=scan,
        authorization_decision=decision,
        predecessor=previous,
        captured_by_id=actor_id,
        snapshot_version=next_version,
        source_type=source,
        inventory_sha256=inventory_sha256,
        cbom=cbom,
        cbom_sha256=cbom_sha256,
        risk_summary=risk_summary,
        drift=drift,
        request_fingerprint=request_fingerprint,
        policy_version=CRYPTO_POLICY_VERSION,
    )

    for item in normalized:
        CryptographicAssetRecord.objects.create(
            snapshot=snapshot,
            ordinal=item['ordinal'],
            kind=item['kind'],
            name=item['name'],
            algorithm=item['algorithm'],
            key_size=item['key_size'],
            curve=item['curve'],
            protocol=item['protocol'],
            version=item['version'],
            issuer=item['issuer'],
            subject=item['subject'],
            not_before=_dt(item['not_before']),
            not_after=_dt(item['not_after']),
            security_state=item['security_state'],
            quantum_state=item['quantum_state'],
            fingerprint_sha256=item['fingerprint_sha256'],
            metadata=item['metadata'],
        )

    add_audit_entry(
        user=str(actor_id),
        action='crypto_asset.inventory.commit',
        target=str(snapshot.id),
        project=str(project.id),
        resource_type='cryptographic_inventory_snapshot',
        resource_repr=f'{asset.id}:v{next_version}',
        metadata={
            'organization_id': str(organization.id),
            'asset_id': str(asset.id),
            'scan_id': str(scan.id) if scan else '',
            'authorization_decision_id': str(decision.id),
            'snapshot_version': next_version,
            'inventory_sha256': inventory_sha256,
            'cbom_sha256': cbom_sha256,
            'record_count': len(normalized),
            'drift_changed': bool(drift.get('changed')),
            'policy_version': CRYPTO_POLICY_VERSION,
        },
    )
    return CryptoSnapshotResult(snapshot=snapshot, replayed=False)
