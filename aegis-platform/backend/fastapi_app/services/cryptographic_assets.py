from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from django.db import transaction
from django.utils import timezone

from django_project.assets.models import Asset
from django_project.evidence.models import Evidence
from django_project.projects.models import Project
from django_project.scans.models import Scan
from enterprise.crypto_asset_models import CBOMArtifact, CryptographicAssetRecord, CryptographicInventorySnapshot
from enterprise.models import Organization, OrganizationMembership, TenantProject

from .audit_writer import add_audit_entry


POLICY_VERSION = 'crypto-asset-plane.v1'
CYCLONEDX_SPEC_VERSION = '1.7'
_ASSET_TYPES = {'algorithm', 'certificate', 'protocol', 'related-crypto-material'}
_PRIMITIVES = {
    'drbg', 'mac', 'block-cipher', 'stream-cipher', 'signature', 'hash', 'pke',
    'xof', 'kdf', 'key-agree', 'kem', 'ae', 'combiner', 'key-wrap', 'other', 'unknown',
}
_PROTOCOL_TYPES = {
    'tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'dtls', 'quic',
    'eap-aka', 'eap-aka-prime', 'prins', '5g-aka', 'other', 'unknown',
}
_MATERIAL_TYPES = {
    'private-key', 'public-key', 'secret-key', 'key', 'ciphertext', 'signature', 'digest',
    'initialization-vector', 'nonce', 'seed', 'salt', 'shared-secret', 'tag',
    'additional-data', 'password', 'credential', 'token', 'other', 'unknown',
}
_MATERIAL_STATES = {'pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed'}
_SHA_RE = re.compile(r'^[0-9a-f]{64}$')
_REF_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/@+\\-]{0,159}$')
_SECRET_KEYS = {
    'secret', 'password', 'private_key', 'privatekey', 'raw_value', 'raw_secret',
    'token_value', 'credential_value', 'plaintext', 'passphrase', 'key_material',
}


class CryptographicAssetError(ValueError):
    pass


class CryptographicAssetAuthorizationError(CryptographicAssetError):
    pass


class CryptographicAssetConflict(CryptographicAssetError):
    pass


@dataclass(frozen=True)
class CryptoInventoryResult:
    snapshot: CryptographicInventorySnapshot
    cbom: CBOMArtifact
    replayed: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode('utf-8')


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, *, field: str, maximum: int, required: bool = False) -> str:
    result = ' '.join(str(value or '').split())
    if required and not result:
        raise CryptographicAssetError(f'{field} is required.')
    if len(result) > maximum or any(ch in result for ch in '\r\n\x00'):
        raise CryptographicAssetError(f'{field} is invalid.')
    return result


def _datetime(value: Any, field: str) -> datetime | None:
    if value in (None, ''):
        return None
    if not isinstance(value, datetime) or timezone.is_naive(value):
        raise CryptographicAssetError(f'{field} must be a timezone-aware datetime.')
    return value


def _no_secret_material(value: Any, path: str = 'metadata') -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).strip().lower().replace('-', '_')
            if normalized in _SECRET_KEYS or any(fragment in normalized for fragment in ('private_key', 'raw_secret', 'token_value', 'credential_value')):
                raise CryptographicAssetError(f'{path}.{key} may not contain raw secret material.')
            _no_secret_material(nested, f'{path}.{key}')
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _no_secret_material(nested, f'{path}[{index}]')
    elif isinstance(value, str) and len(value) > 4096:
        raise CryptographicAssetError(f'{path} contains an oversized string.')


def _active_context(project_id: str, actor_id: str) -> tuple[Organization, Project]:
    link_id = (
        TenantProject.objects.filter(project_id=project_id, organization__is_active=True)
        .values('id', 'organization_id')
        .first()
    )
    if link_id is None:
        raise CryptographicAssetAuthorizationError('Project is not bound to an active enterprise tenant.')
    organization = Organization.objects.select_for_update().filter(
        pk=link_id['organization_id'], is_active=True
    ).first()
    if organization is None:
        raise CryptographicAssetAuthorizationError('Enterprise tenant is not active.')
    link = TenantProject.objects.select_for_update(of=('self',)).filter(
        pk=link_id['id'], project_id=project_id, organization=organization
    ).first()
    if link is None:
        raise CryptographicAssetAuthorizationError('Project tenant binding changed during inventory commit.')
    project = Project.objects.select_for_update().filter(pk=project_id).first()
    if project is None:
        raise CryptographicAssetAuthorizationError('Project was not found.')
    if str(project.owner_id) != str(actor_id) and not project.members.filter(pk=actor_id).exists():
        raise CryptographicAssetAuthorizationError('Actor does not have project inventory authority.')
    allowed_roles = {
        OrganizationMembership.Role.OWNER,
        OrganizationMembership.Role.ADMIN,
        OrganizationMembership.Role.MANAGER,
        OrganizationMembership.Role.ANALYST,
    }
    if not OrganizationMembership.objects.filter(
        organization=organization, user_id=actor_id, is_active=True, user__is_active=True, role__in=allowed_roles
    ).exists():
        raise CryptographicAssetAuthorizationError('Actor has no active enterprise inventory authority.')
    return organization, project


def _evidence_refs(
    *, project: Project, asset: Asset, scan: Scan | None, values: Iterable[Any] | None
) -> list[str]:
    refs = sorted({str(value).strip() for value in (values or []) if str(value).strip()})
    if not refs:
        raise CryptographicAssetError('Cryptographic inventory requires persisted source evidence.')
    if len(refs) > 128:
        raise CryptographicAssetError('At most 128 source evidence references are allowed.')
    rows = list(
        Evidence.objects.select_for_update(of=('self',))
        .select_related('scan', 'asset', 'finding')
        .filter(pk__in=refs)
    )
    by_id = {str(row.id): row for row in rows}
    if set(by_id) != set(refs):
        raise CryptographicAssetError('One or more source evidence references do not exist.')
    for ref in refs:
        row = by_id[ref]
        project_ids: set[str] = set()
        asset_ids: set[str] = set()
        if row.scan_id and row.scan is not None:
            project_ids.add(str(row.scan.project_id))
            if row.scan.asset_id:
                asset_ids.add(str(row.scan.asset_id))
        if row.asset_id and row.asset is not None:
            project_ids.add(str(row.asset.project_id))
            asset_ids.add(str(row.asset_id))
        if row.finding_id and row.finding is not None:
            project_ids.add(str(row.finding.project_id))
            if row.finding.asset_id:
                asset_ids.add(str(row.finding.asset_id))
        if not project_ids or project_ids != {str(project.id)}:
            raise CryptographicAssetAuthorizationError('Source evidence crossed the project boundary.')
        if str(asset.id) not in asset_ids:
            raise CryptographicAssetAuthorizationError('Source evidence is not bound to the requested asset.')
        if scan is not None and str(row.scan_id or '') != str(scan.id):
            raise CryptographicAssetAuthorizationError('Source evidence is not bound to the requested scan.')
        if not str(row.source or '').strip() or row.collected_at is None or row.collected_by_id is None:
            raise CryptographicAssetError('Source evidence is missing producer provenance.')
        digest = hashlib.sha256((row.raw_output or '').encode('utf-8', errors='replace')).hexdigest()
        if digest != row.sha256:
            raise CryptographicAssetConflict('Source evidence integrity verification failed.')
    return refs


def _relations(value: Any) -> list[dict[str, str]]:
    if value in (None, ''):
        return []
    if not isinstance(value, list):
        raise CryptographicAssetError('relationships must be a list.')
    result: list[dict[str, str]] = []
    for item in value[:128]:
        if not isinstance(item, dict):
            raise CryptographicAssetError('relationships entries must be objects.')
        relation = _text(item.get('type'), field='relationship.type', maximum=100, required=True)
        ref = _text(item.get('ref'), field='relationship.ref', maximum=160, required=True)
        if not _REF_RE.fullmatch(ref):
            raise CryptographicAssetError('relationship.ref contains unsupported characters.')
        entry = {'type': relation, 'ref': ref}
        if entry not in result:
            result.append(entry)
    return sorted(result, key=lambda item: (item['type'], item['ref']))


def _component(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CryptographicAssetError('Each cryptographic component must be an object.')
    _no_secret_material(raw)
    asset_type = _text(raw.get('asset_type'), field='asset_type', maximum=32, required=True).lower()
    if asset_type not in _ASSET_TYPES:
        raise CryptographicAssetError('Unsupported cryptographic asset_type.')
    name = _text(raw.get('name'), field='name', maximum=255, required=True)
    primitive = _text(raw.get('primitive'), field='primitive', maximum=64).lower()
    if primitive and primitive not in _PRIMITIVES:
        raise CryptographicAssetError('Unsupported CycloneDX cryptographic primitive.')
    protocol_type = _text(raw.get('protocol_type'), field='protocol_type', maximum=64).lower()
    if protocol_type and protocol_type not in _PROTOCOL_TYPES:
        raise CryptographicAssetError('Unsupported CycloneDX cryptographic protocol type.')
    material_type = _text(raw.get('material_type'), field='material_type', maximum=64).lower()
    if material_type and material_type not in _MATERIAL_TYPES:
        raise CryptographicAssetError('Unsupported CycloneDX related material type.')
    material_state = _text(raw.get('material_state'), field='material_state', maximum=64).lower()
    if material_state and material_state not in _MATERIAL_STATES:
        raise CryptographicAssetError('Unsupported cryptographic material state.')
    fingerprint = str(raw.get('fingerprint_sha256') or '').strip().lower()
    if fingerprint and not _SHA_RE.fullmatch(fingerprint):
        raise CryptographicAssetError('fingerprint_sha256 must be a lowercase SHA-256 digest.')
    key_size = raw.get('key_size')
    if key_size not in (None, ''):
        try:
            key_size = int(key_size)
        except (TypeError, ValueError) as exc:
            raise CryptographicAssetError('key_size must be an integer.') from exc
        if not 1 <= key_size <= 1_000_000:
            raise CryptographicAssetError('key_size is outside the accepted range.')
    else:
        key_size = None
    quantum = raw.get('nist_quantum_security_level')
    if quantum not in (None, ''):
        try:
            quantum = int(quantum)
        except (TypeError, ValueError) as exc:
            raise CryptographicAssetError('nist_quantum_security_level must be an integer.') from exc
        if not 0 <= quantum <= 6:
            raise CryptographicAssetError('nist_quantum_security_level must be between 0 and 6.')
    else:
        quantum = None
    metadata = raw.get('metadata') or {}
    if not isinstance(metadata, dict):
        raise CryptographicAssetError('metadata must be an object.')
    _no_secret_material(metadata)
    result = {
        'asset_type': asset_type,
        'name': name,
        'location': _text(raw.get('location'), field='location', maximum=500),
        'owner_ref': _text(raw.get('owner_ref'), field='owner_ref', maximum=255),
        'algorithm_family': _text(raw.get('algorithm_family'), field='algorithm_family', maximum=100),
        'primitive': primitive,
        'parameter_set': _text(raw.get('parameter_set'), field='parameter_set', maximum=120),
        'key_size': key_size,
        'curve': _text(raw.get('curve'), field='curve', maximum=120),
        'protocol_type': protocol_type,
        'protocol_version': _text(raw.get('protocol_version'), field='protocol_version', maximum=64),
        'material_type': material_type,
        'material_state': material_state,
        'protection_mechanism': _text(raw.get('protection_mechanism'), field='protection_mechanism', maximum=120),
        'fingerprint_sha256': fingerprint,
        'certificate_subject': _text(raw.get('certificate_subject'), field='certificate_subject', maximum=500),
        'certificate_issuer': _text(raw.get('certificate_issuer'), field='certificate_issuer', maximum=500),
        'certificate_serial': _text(raw.get('certificate_serial'), field='certificate_serial', maximum=255),
        'not_valid_before': _datetime(raw.get('not_valid_before'), 'not_valid_before'),
        'not_valid_after': _datetime(raw.get('not_valid_after'), 'not_valid_after'),
        'nist_quantum_security_level': quantum,
        'relationships': _relations(raw.get('relationships')),
        'metadata': json.loads(_canonical(metadata).decode('utf-8')),
    }
    requested_ref = _text(raw.get('component_ref'), field='component_ref', maximum=160)
    if requested_ref and not _REF_RE.fullmatch(requested_ref):
        raise CryptographicAssetError('component_ref contains unsupported characters.')
    identity = {
        'asset_type': asset_type, 'name': name, 'location': result['location'],
        'algorithm_family': result['algorithm_family'], 'protocol_type': protocol_type,
        'material_type': material_type, 'fingerprint_sha256': fingerprint,
    }
    result['component_ref'] = requested_ref or f'crypto-{_sha(identity)[:40]}'
    result['component_sha256'] = _sha({
        key: (value.isoformat() if isinstance(value, datetime) else value)
        for key, value in result.items() if key != 'component_sha256'
    })
    return result


def _components(values: Iterable[Any]) -> list[dict[str, Any]]:
    rows = [_component(item) for item in list(values)]
    if not rows:
        raise CryptographicAssetError('At least one cryptographic component is required.')
    if len(rows) > 5000:
        raise CryptographicAssetError('A single inventory may contain at most 5000 components.')
    refs = [row['component_ref'] for row in rows]
    if len(refs) != len(set(refs)):
        raise CryptographicAssetConflict('component_ref values must be unique within an inventory.')
    ref_set = set(refs)
    for row in rows:
        dangling = sorted({item['ref'] for item in row['relationships']} - ref_set)
        if dangling:
            raise CryptographicAssetError(f"Component {row['component_ref']} contains dangling relationships: {dangling}")
    return sorted(rows, key=lambda row: row['component_ref'])


def _drift(previous: CryptographicInventorySnapshot | None, current: list[dict[str, Any]]) -> dict[str, Any]:
    current_map = {row['component_ref']: row['component_sha256'] for row in current}
    if previous is None:
        return {'baseline': True, 'added': sorted(current_map), 'removed': [], 'changed': [], 'unchanged_count': 0}
    prior_map = {
        row.component_ref: row.component_sha256
        for row in previous.components.only('component_ref', 'component_sha256').all()
    }
    current_refs, prior_refs = set(current_map), set(prior_map)
    return {
        'baseline': False,
        'added': sorted(current_refs - prior_refs),
        'removed': sorted(prior_refs - current_refs),
        'changed': sorted(ref for ref in current_refs & prior_refs if current_map[ref] != prior_map[ref]),
        'unchanged_count': sum(1 for ref in current_refs & prior_refs if current_map[ref] == prior_map[ref]),
    }


def _crypto_properties(row: dict[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {'assetType': row['asset_type']}
    relations = row['relationships']
    if row['asset_type'] == 'algorithm':
        data: dict[str, Any] = {}
        for source, target in (
            ('primitive', 'primitive'), ('algorithm_family', 'algorithmFamily'),
            ('parameter_set', 'parameterSetIdentifier'), ('curve', 'curve'),
        ):
            if row[source]:
                data[target] = row[source]
        if row['nist_quantum_security_level'] is not None:
            data['nistQuantumSecurityLevel'] = row['nist_quantum_security_level']
        if relations:
            data['relatedCryptographicAssets'] = relations
        props['algorithmProperties'] = data
    elif row['asset_type'] == 'certificate':
        data = {}
        if row['certificate_serial']:
            data['serialNumber'] = row['certificate_serial']
        if row['certificate_subject']:
            data['subjectName'] = row['certificate_subject']
        if row['certificate_issuer']:
            data['issuerName'] = row['certificate_issuer']
        if row['not_valid_before']:
            data['notValidBefore'] = row['not_valid_before'].isoformat()
        if row['not_valid_after']:
            data['notValidAfter'] = row['not_valid_after'].isoformat()
        if relations:
            data['relatedCryptographicAssets'] = relations
        props['certificateProperties'] = data
    elif row['asset_type'] == 'protocol':
        data = {}
        if row['protocol_type']:
            data['type'] = row['protocol_type']
        if row['protocol_version']:
            data['version'] = row['protocol_version']
        if relations:
            data['relatedCryptographicAssets'] = relations
        props['protocolProperties'] = data
    else:
        data = {}
        if row['material_type']:
            data['type'] = row['material_type']
        if row['material_state']:
            data['state'] = row['material_state']
        if row['key_size'] is not None:
            data['size'] = row['key_size']
        if row['protection_mechanism']:
            data['securedBy'] = {'mechanism': row['protection_mechanism']}
        if row['fingerprint_sha256']:
            data['fingerprint'] = {'alg': 'SHA-256', 'content': row['fingerprint_sha256']}
        if relations:
            data['relatedCryptographicAssets'] = relations
        props['relatedCryptoMaterialProperties'] = data
    return props


def _cbom(snapshot: CryptographicInventorySnapshot, asset: Asset, rows: list[dict[str, Any]]) -> dict[str, Any]:
    components = []
    for row in rows:
        properties = [{'name': 'aegisscan:crypto:component-sha256', 'value': row['component_sha256']}]
        if row['location']:
            properties.append({'name': 'aegisscan:crypto:location', 'value': row['location']})
        if row['owner_ref']:
            properties.append({'name': 'aegisscan:crypto:owner-ref', 'value': row['owner_ref']})
        components.append({
            'type': 'cryptographic-asset',
            'bom-ref': row['component_ref'],
            'name': row['name'],
            'cryptoProperties': _crypto_properties(row),
            'properties': properties,
        })
    return {
        'bomFormat': 'CycloneDX',
        'specVersion': CYCLONEDX_SPEC_VERSION,
        'serialNumber': f'urn:uuid:{snapshot.id}',
        'version': int(snapshot.inventory_version),
        'metadata': {
            'timestamp': snapshot.created_at.isoformat(),
            'properties': [
                {'name': 'aegisscan:organization-id', 'value': str(snapshot.organization_id)},
                {'name': 'aegisscan:project-id', 'value': str(snapshot.project_id)},
                {'name': 'aegisscan:asset-id', 'value': str(snapshot.asset_id)},
                {'name': 'aegisscan:asset-name', 'value': asset.name},
                {'name': 'aegisscan:inventory-sha256', 'value': snapshot.inventory_sha256},
            ],
        },
        'components': components,
    }


@transaction.atomic
def record_cryptographic_inventory(
    *, project_id: str, asset_id: str, actor_id: str, source_kind: str,
    components: Iterable[Any], idempotency_key: str,
    source_ref: str = '', source_evidence_refs: Iterable[Any] | None = None,
    scan_id: str | None = None,
) -> CryptoInventoryResult:
    source = _text(source_kind, field='source_kind', maximum=64, required=True).lower()
    source_reference = _text(source_ref, field='source_ref', maximum=255)
    idem = _text(idempotency_key, field='idempotency_key', maximum=128, required=True)
    normalized = _components(components)
    inventory_sha256 = _sha([
        {key: (value.isoformat() if isinstance(value, datetime) else value) for key, value in row.items()}
        for row in normalized
    ])
    organization, project = _active_context(str(project_id), str(actor_id))
    asset = Asset.objects.select_for_update().filter(pk=asset_id, project=project, is_active=True).first()
    if asset is None:
        raise CryptographicAssetAuthorizationError('Cryptographic inventory asset was not found in the project.')
    scan = None
    if scan_id:
        scan = Scan.objects.select_for_update(of=('self',)).filter(pk=scan_id, project=project, asset=asset).first()
        if scan is None:
            raise CryptographicAssetAuthorizationError('Source scan is not bound to the requested project and asset.')
    evidence_refs = _evidence_refs(project=project, asset=asset, scan=scan, values=source_evidence_refs)
    request_fingerprint = _sha({
        'organization_id': str(organization.id), 'project_id': str(project.id),
        'asset_id': str(asset.id), 'scan_id': str(scan.id) if scan else '',
        'actor_id': str(actor_id), 'source_kind': source, 'source_ref': source_reference,
        'source_evidence_refs': evidence_refs, 'inventory_sha256': inventory_sha256,
        'idempotency_key': idem, 'policy_version': POLICY_VERSION,
    })
    existing = CryptographicInventorySnapshot.objects.filter(
        organization=organization, idempotency_key=idem
    ).select_related('cbom').first()
    if existing is not None:
        if existing.request_fingerprint != request_fingerprint:
            raise CryptographicAssetConflict('Inventory idempotency key was already used for another payload.')
        return CryptoInventoryResult(snapshot=existing, cbom=existing.cbom, replayed=True)
    previous = (
        CryptographicInventorySnapshot.objects.select_for_update()
        .filter(asset=asset).order_by('-inventory_version', '-created_at', '-id').first()
    )
    drift = _drift(previous, normalized)
    version = int(previous.inventory_version) + 1 if previous else 1
    snapshot = CryptographicInventorySnapshot.objects.create(
        organization=organization, project=project, asset=asset, scan=scan, predecessor=previous,
        collected_by_id=actor_id, source_kind=source, source_ref=source_reference,
        source_evidence_refs=evidence_refs, idempotency_key=idem, inventory_version=version,
        component_count=len(normalized), inventory_sha256=inventory_sha256,
        drift_summary=drift, drift_sha256=_sha(drift),
        request_fingerprint=request_fingerprint, policy_version=POLICY_VERSION,
    )
    for row in normalized:
        CryptographicAssetRecord.objects.create(
            snapshot=snapshot,
            component_ref=row['component_ref'], asset_type=row['asset_type'], name=row['name'],
            location=row['location'], owner_ref=row['owner_ref'],
            algorithm_family=row['algorithm_family'], primitive=row['primitive'],
            parameter_set=row['parameter_set'], key_size=row['key_size'], curve=row['curve'],
            protocol_type=row['protocol_type'], protocol_version=row['protocol_version'],
            material_type=row['material_type'], material_state=row['material_state'],
            protection_mechanism=row['protection_mechanism'], fingerprint_sha256=row['fingerprint_sha256'],
            certificate_subject=row['certificate_subject'], certificate_issuer=row['certificate_issuer'],
            certificate_serial=row['certificate_serial'], not_valid_before=row['not_valid_before'],
            not_valid_after=row['not_valid_after'], nist_quantum_security_level=row['nist_quantum_security_level'],
            relationships=row['relationships'], metadata_snapshot=row['metadata'],
            component_sha256=row['component_sha256'],
        )
    snapshot.refresh_from_db()
    document = _cbom(snapshot, asset, normalized)
    cbom = CBOMArtifact.objects.create(
        snapshot=snapshot, generated_by_id=actor_id, format='cyclonedx-json',
        spec_version=CYCLONEDX_SPEC_VERSION, serial_number=f'urn:uuid:{snapshot.id}',
        document=document, document_sha256=_sha(document),
    )
    add_audit_entry(
        user=actor_id, action='crypto.inventory.commit', target=str(snapshot.id), project=str(project.id),
        resource_type='cryptographic_inventory_snapshot', resource_repr=f'{asset.name} crypto inventory v{version}',
        metadata={
            'organization_id': str(organization.id), 'asset_id': str(asset.id),
            'scan_id': str(scan.id) if scan else '', 'inventory_version': version,
            'inventory_sha256': inventory_sha256, 'drift_sha256': snapshot.drift_sha256,
            'cbom_sha256': cbom.document_sha256, 'cbom_spec_version': CYCLONEDX_SPEC_VERSION,
            'source_evidence_refs': evidence_refs, 'raw_secret_material_persisted': False,
            'policy_version': POLICY_VERSION,
        },
    )
    return CryptoInventoryResult(snapshot=snapshot, cbom=cbom, replayed=False)


def serialize_snapshot(snapshot: CryptographicInventorySnapshot, *, include_cbom: bool = False) -> dict[str, Any]:
    data = {
        'id': str(snapshot.id), 'organization_id': str(snapshot.organization_id),
        'project_id': str(snapshot.project_id), 'asset_id': str(snapshot.asset_id),
        'scan_id': str(snapshot.scan_id or ''), 'predecessor_id': str(snapshot.predecessor_id or ''),
        'source_kind': snapshot.source_kind, 'source_ref': snapshot.source_ref,
        'source_evidence_refs': snapshot.source_evidence_refs, 'inventory_version': snapshot.inventory_version,
        'component_count': snapshot.component_count, 'inventory_sha256': snapshot.inventory_sha256,
        'drift_summary': snapshot.drift_summary, 'drift_sha256': snapshot.drift_sha256,
        'request_fingerprint': snapshot.request_fingerprint, 'policy_version': snapshot.policy_version,
        'created_at': snapshot.created_at.isoformat(),
    }
    if include_cbom:
        cbom = snapshot.cbom
        data['cbom'] = {
            'id': str(cbom.id), 'format': cbom.format, 'spec_version': cbom.spec_version,
            'serial_number': cbom.serial_number, 'document_sha256': cbom.document_sha256,
            'document': cbom.document, 'created_at': cbom.created_at.isoformat(),
        }
    return data
