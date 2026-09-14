from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
import hashlib
import json
from typing import Any, Literal

from .capability_registry import get_capability
from .wstg_capability_mapping import EXPECTED_GAPS, WSTGCapabilityMapping


EvidenceRole = Literal[
    'direct_observation',
    'supporting_observation',
    'supporting_context',
    'conditional_context',
]
MethodologyState = Literal[
    'observed',
    'manual_required',
    'blocked_native_gap',
    'inconclusive',
]

_SCHEMA = 'aegis.wstg-observation-lineage.v1'
_CLAIM_POLICY = 'observation-only'
_FINDING_AUTHORITY = 'governed-finding-confirmation'
_CLASSIFICATION_SEMANTICS: dict[str, tuple[EvidenceRole, MethodologyState]] = {
    'AUTO_EXISTING': ('direct_observation', 'observed'),
    'ASSISTED_EXISTING': ('supporting_observation', 'observed'),
    'MANUAL_GOVERNED': ('supporting_context', 'manual_required'),
    'GAP_NATIVE_SMALL': ('supporting_observation', 'observed'),
    'CONDITIONAL_NA': ('conditional_context', 'inconclusive'),
}


@dataclass(frozen=True)
class WSTGObservationLineageItem:
    wstg_id: str
    classification: str
    semantic_requirement_id: str
    evidence_role: EvidenceRole
    methodology_state: MethodologyState
    completion_claim_allowed: bool = False

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@lru_cache(maxsize=1)
def _reverse_registry_index() -> dict[str, tuple[WSTGObservationLineageItem, ...]]:
    mapping = WSTGCapabilityMapping()
    rows: dict[str, list[WSTGObservationLineageItem]] = {}

    for test in mapping.catalog.tests:
        requirement = mapping.resolve(test.id)[0]
        semantics = _CLASSIFICATION_SEMANTICS.get(test.classification)
        if semantics is None:
            raise ValueError(f'Unsupported WSTG classification for observation lineage: {test.classification}')
        evidence_role, methodology_state = semantics
        for binding in requirement.provider_bindings:
            if binding.kind != 'registry_capability':
                continue
            if test.classification == 'GAP_NATIVE_SMALL' and binding.ref != EXPECTED_GAPS.get(test.id):
                continue
            rows.setdefault(binding.ref, []).append(WSTGObservationLineageItem(
                wstg_id=test.id,
                classification=test.classification,
                semantic_requirement_id=requirement.id,
                evidence_role=evidence_role,
                methodology_state=methodology_state,
            ))

    return {
        capability_id: tuple(sorted(items, key=lambda item: item.wstg_id))
        for capability_id, items in rows.items()
    }


def wstg_observation_lineage(capability_id: str) -> dict[str, Any]:
    """Return trusted methodology lineage for one executed semantic capability.

    The payload is evidence provenance only. It never represents a WSTG pass/fail
    decision and never grants finding confirmation, closure, accepted-risk, or
    false-positive authority.
    """
    capability = get_capability(capability_id)
    items = _reverse_registry_index().get(capability.id, ())
    material = {
        'schema': _SCHEMA,
        'methodology': 'WSTG',
        'methodology_version': '4.2',
        'capability_id': capability.id,
        'claim_policy': _CLAIM_POLICY,
        'completion_claim_allowed': False,
        'finding_state_authority': _FINDING_AUTHORITY,
        'tests': [item.public_dict() for item in items],
    }
    fingerprint = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    ).hexdigest()
    return {**material, 'lineage_fingerprint': fingerprint}


def attach_wstg_evidence_metadata(metadata: dict[str, Any] | None, capability_id: str) -> dict[str, Any]:
    result = dict(metadata or {})
    lineage = wstg_observation_lineage(capability_id)
    if lineage['tests']:
        # Server-owned reserved field: scanner output can never author this value.
        result['wstg_lineage'] = lineage
    return result


def attach_wstg_finding_lineage(raw_data: dict[str, Any] | None, capability_id: str) -> dict[str, Any]:
    result = dict(raw_data or {})
    lineage = wstg_observation_lineage(capability_id)
    if lineage['tests']:
        # Overwrite the reserved key rather than trusting scanner-supplied JSON.
        result['_aegisscan_wstg'] = lineage
    return result
