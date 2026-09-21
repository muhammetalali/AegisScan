from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


RACE_TOCTOU_POLICY_VERSION = 'agom-race-toctou.v1'
RACE_TOCTOU_LOCK_ORDER = (
    'organization',
    'tenant_project',
    'governed_request',
    'fresh_capability_manifest',
    'dynamic_evidence',
    'temporal_policy',
    'commit_capability_manifest',
    'domain_cas',
)


class RaceToctouProofError(ValueError):
    pass


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


@dataclass(frozen=True)
class RaceToctouProof:
    action_id: str
    organization_id: str
    project_id: str
    actor_id: str
    entity_type: str
    entity_id: str
    expected_version: int
    current_version: int
    request_fingerprint: str
    governed_request_id: str
    governed_request_fingerprint: str
    contract_fingerprint: str
    evaluation_policy_version: str
    gate_snapshot_sha256: str
    evidence_qualification_fingerprint: str
    temporal_evaluation_fingerprint: str
    proof_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            'policy_version': RACE_TOCTOU_POLICY_VERSION,
            'lock_order': list(RACE_TOCTOU_LOCK_ORDER),
            'action_id': self.action_id,
            'organization_id': self.organization_id,
            'project_id': self.project_id,
            'actor_id': self.actor_id,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'expected_version': self.expected_version,
            'current_version': self.current_version,
            'request_fingerprint': self.request_fingerprint,
            'governed_request_id': self.governed_request_id,
            'governed_request_fingerprint': self.governed_request_fingerprint,
            'contract_fingerprint': self.contract_fingerprint,
            'evaluation_policy_version': self.evaluation_policy_version,
            'gate_snapshot_sha256': self.gate_snapshot_sha256,
            'evidence_qualification_fingerprint': self.evidence_qualification_fingerprint,
            'temporal_evaluation_fingerprint': self.temporal_evaluation_fingerprint,
            'proof_sha256': self.proof_sha256,
        }


def _proof_material(
    *,
    action_id: str,
    organization_id: str,
    project_id: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    expected_version: int,
    current_version: int,
    request_fingerprint: str,
    governed_request_id: str,
    governed_request_fingerprint: str,
    contract_fingerprint: str,
    evaluation_policy_version: str,
    gate_snapshot_sha256: str,
    evidence_qualification_fingerprint: str,
    temporal_evaluation_fingerprint: str,
) -> dict[str, Any]:
    return {
        'policy_version': RACE_TOCTOU_POLICY_VERSION,
        'lock_order': list(RACE_TOCTOU_LOCK_ORDER),
        'action_id': str(action_id),
        'organization_id': str(organization_id),
        'project_id': str(project_id),
        'actor_id': str(actor_id),
        'entity_type': str(entity_type),
        'entity_id': str(entity_id),
        'expected_version': int(expected_version),
        'current_version': int(current_version),
        'request_fingerprint': str(request_fingerprint),
        'governed_request_id': str(governed_request_id or ''),
        'governed_request_fingerprint': str(governed_request_fingerprint or ''),
        'contract_fingerprint': str(contract_fingerprint),
        'evaluation_policy_version': str(evaluation_policy_version),
        'gate_snapshot_sha256': str(gate_snapshot_sha256),
        'evidence_qualification_fingerprint': str(evidence_qualification_fingerprint or ''),
        'temporal_evaluation_fingerprint': str(temporal_evaluation_fingerprint or ''),
    }


def build_race_toctou_proof(
    *,
    action_id: str,
    organization_id: str,
    project_id: str,
    actor_id: str,
    entity_type: str,
    entity_id: str,
    expected_version: int,
    current_version: int,
    request_fingerprint: str,
    governed_request_id: str,
    governed_request_fingerprint: str,
    contract_snapshot: dict[str, Any],
    evaluation_policy_version: str,
    gate_snapshot: list[dict[str, Any]],
    evidence_qualification_fingerprint: str = '',
    temporal_evaluation_fingerprint: str = '',
) -> RaceToctouProof:
    if int(expected_version) != int(current_version):
        raise RaceToctouProofError(
            f'Race/TOCTOU proof requires a fresh CAS version: expected {expected_version}, current {current_version}.'
        )
    contract_fingerprint = _sha({
        'contract_version': contract_snapshot.get('contract_version', ''),
        'contract': contract_snapshot.get('contract', {}),
    })
    gate_snapshot_sha256 = _sha(gate_snapshot)
    material = _proof_material(
        action_id=action_id,
        organization_id=organization_id,
        project_id=project_id,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        expected_version=expected_version,
        current_version=current_version,
        request_fingerprint=request_fingerprint,
        governed_request_id=governed_request_id,
        governed_request_fingerprint=governed_request_fingerprint,
        contract_fingerprint=contract_fingerprint,
        evaluation_policy_version=evaluation_policy_version,
        gate_snapshot_sha256=gate_snapshot_sha256,
        evidence_qualification_fingerprint=evidence_qualification_fingerprint,
        temporal_evaluation_fingerprint=temporal_evaluation_fingerprint,
    )
    return RaceToctouProof(
        action_id=str(action_id),
        organization_id=str(organization_id),
        project_id=str(project_id),
        actor_id=str(actor_id),
        entity_type=str(entity_type),
        entity_id=str(entity_id),
        expected_version=int(expected_version),
        current_version=int(current_version),
        request_fingerprint=str(request_fingerprint),
        governed_request_id=str(governed_request_id or ''),
        governed_request_fingerprint=str(governed_request_fingerprint or ''),
        contract_fingerprint=contract_fingerprint,
        evaluation_policy_version=str(evaluation_policy_version),
        gate_snapshot_sha256=gate_snapshot_sha256,
        evidence_qualification_fingerprint=str(evidence_qualification_fingerprint or ''),
        temporal_evaluation_fingerprint=str(temporal_evaluation_fingerprint or ''),
        proof_sha256=_sha(material),
    )


def verify_race_toctou_proof(proof: dict[str, Any]) -> bool:
    if str(proof.get('policy_version') or '') != RACE_TOCTOU_POLICY_VERSION:
        return False
    if list(proof.get('lock_order') or []) != list(RACE_TOCTOU_LOCK_ORDER):
        return False
    try:
        material = _proof_material(
            action_id=str(proof['action_id']),
            organization_id=str(proof['organization_id']),
            project_id=str(proof['project_id']),
            actor_id=str(proof['actor_id']),
            entity_type=str(proof['entity_type']),
            entity_id=str(proof['entity_id']),
            expected_version=int(proof['expected_version']),
            current_version=int(proof['current_version']),
            request_fingerprint=str(proof['request_fingerprint']),
            governed_request_id=str(proof.get('governed_request_id') or ''),
            governed_request_fingerprint=str(proof.get('governed_request_fingerprint') or ''),
            contract_fingerprint=str(proof['contract_fingerprint']),
            evaluation_policy_version=str(proof['evaluation_policy_version']),
            gate_snapshot_sha256=str(proof['gate_snapshot_sha256']),
            evidence_qualification_fingerprint=str(proof.get('evidence_qualification_fingerprint') or ''),
            temporal_evaluation_fingerprint=str(proof.get('temporal_evaluation_fingerprint') or ''),
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        int(material['expected_version']) == int(material['current_version'])
        and _sha(material) == str(proof.get('proof_sha256') or '')
    )
