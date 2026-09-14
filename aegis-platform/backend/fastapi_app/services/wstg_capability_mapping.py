"""Validated WSTG -> semantic capability mapping metadata.

This module never authorizes or executes a security test. It binds canonical WSTG
identities to stable semantic requirements, then verifies implementation references
against the existing Aegis capability registry or existing control-plane services.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .capability_registry import get_capability
from .wstg_catalog import PACK, WSTGCatalog

ProviderKind = Literal[
    'registry_capability', 'control_plane_service', 'governed_service', 'planned_native',
]
Availability = Literal['existing', 'governed_manual', 'planned_native', 'conditional']

EXPECTED_GAPS = {
    'WSTG-v42-CONF-06': 'web.http-method-policy',
    'WSTG-v42-INPV-04': 'web.duplicate-parameter-semantics',
    'WSTG-v42-INPV-19': 'web.ssrf-canary-validation',
    'WSTG-v42-CRYP-01': 'tls.posture',
}
_BANNED_REQUIREMENT_TERMS = {
    'nmap', 'masscan', 'rustscan', 'nuclei', 'semgrep', 'httpx', 'katana', 'ffuf',
    'feroxbuster', 'gobuster', 'dirb', 'nikto', 'wafw00f', 'amass', 'subfinder',
}


class MappingModel(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)


class ProviderBinding(MappingModel):
    kind: ProviderKind
    ref: str = Field(min_length=3, max_length=160, pattern=r'^[A-Za-z0-9_.-]+$')


class CapabilityRequirement(MappingModel):
    id: str = Field(
        min_length=8,
        max_length=180,
        pattern=r'^(?:web|api)\.[a-z0-9]+(?:\.[a-z0-9][a-z0-9-]*)+$',
    )
    description: str = Field(min_length=3, max_length=256)
    availability: Availability
    provider_bindings: tuple[ProviderBinding, ...]

    @model_validator(mode='after')
    def validate_semantics(self):
        if any(term in self.id.split('.')[-1].split('-') for term in _BANNED_REQUIREMENT_TERMS):
            raise ValueError('Semantic requirement IDs must not encode implementation tool names')
        if not self.provider_bindings:
            raise ValueError('Capability requirement needs at least one provider binding')
        return self


class WSTGCapabilityMap(MappingModel):
    wstg_id: str = Field(pattern=r'^WSTG-v42-[A-Z]{4}-[0-9]{2}$')
    required_capability_ids: tuple[str, ...]

    @model_validator(mode='after')
    def validate_required_capabilities(self):
        if not self.required_capability_ids or len(set(self.required_capability_ids)) != len(self.required_capability_ids):
            raise ValueError('WSTG mapping requires unique semantic capability IDs')
        return self


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate mapping JSON key: {key}')
        result[key] = value
    return result


def _read_json(path: Path):
    raw = path.read_bytes()
    if len(raw) > 512_000:
        raise ValueError('WSTG mapping file exceeds size limit')
    return raw, json.loads(raw, object_pairs_hook=_unique_object)


class WSTGCapabilityMapping:
    """Read-only methodology binding; execution authority remains elsewhere."""

    def __init__(self, pack: Path = PACK):
        self.catalog = WSTGCatalog(pack)
        _, manifest = _read_json(pack / 'manifest.json')
        digests = manifest.get('capability_mapping_files')
        expected_files = {'capability_requirements.json', 'mappings.json'}
        if not isinstance(digests, dict) or set(digests) != expected_files:
            raise ValueError('Missing or unexpected WSTG capability mapping files')

        payloads = {}
        for name, digest in digests.items():
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError('Invalid WSTG capability mapping digest')
            raw, data = _read_json(pack / name)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError(f'WSTG capability mapping checksum mismatch: {name}')
            if not isinstance(data, list):
                raise ValueError('WSTG capability mapping records must be arrays')
            payloads[name] = data

        self.requirements = tuple(
            CapabilityRequirement.model_validate({
                **row,
                'provider_bindings': tuple(row.get('provider_bindings', ())),
            })
            for row in payloads['capability_requirements.json']
        )
        self.mappings = tuple(
            WSTGCapabilityMap.model_validate({
                **row,
                'required_capability_ids': tuple(row.get('required_capability_ids', ())),
            })
            for row in payloads['mappings.json']
        )
        self._requirements = self._index_unique(self.requirements, 'id')
        self._mappings = self._index_unique(self.mappings, 'wstg_id')
        self._validate_complete_mapping()
        self._validate_provider_bindings()
        self._validate_classification_contract()

    @staticmethod
    def _index_unique(records, field):
        result = {}
        for item in records:
            key = getattr(item, field)
            if key in result:
                raise ValueError(f'Duplicate WSTG capability mapping identity: {key}')
            result[key] = item
        return result

    def _validate_complete_mapping(self):
        official = {item.id for item in self.catalog.tests}
        if len(self.mappings) != 97 or set(self._mappings) != official:
            raise ValueError('WSTG capability mapping must cover exactly all 97 official tests')
        referenced = {
            requirement_id
            for mapping in self.mappings
            for requirement_id in mapping.required_capability_ids
        }
        if referenced != set(self._requirements):
            raise ValueError('Capability requirements must be referenced exactly by the official mapping set')

    def _validate_provider_bindings(self):
        for requirement in self.requirements:
            for binding in requirement.provider_bindings:
                if binding.kind == 'registry_capability':
                    get_capability(binding.ref)
                elif binding.kind in {'control_plane_service', 'governed_service'}:
                    if importlib.util.find_spec(binding.ref) is None:
                        raise ValueError(f'Unknown Aegis service provider: {binding.ref}')

    def _validate_classification_contract(self):
        for test in self.catalog.tests:
            mapping = self._mappings[test.id]
            requirements = tuple(self._requirements[item] for item in mapping.required_capability_ids)
            if len(requirements) != 1:
                raise ValueError(f'{test.id} must map to one canonical semantic requirement in PR-3')
            requirement = requirements[0]
            if test.classification in {'AUTO_EXISTING', 'ASSISTED_EXISTING'}:
                if requirement.availability != 'existing':
                    raise ValueError(f'{test.id} existing classification/provider mismatch')
                if any(item.kind == 'planned_native' for item in requirement.provider_bindings):
                    raise ValueError(f'{test.id} existing mapping cannot depend on a planned validator')
            elif test.classification == 'MANUAL_GOVERNED':
                if requirement.availability != 'governed_manual':
                    raise ValueError(f'{test.id} manual classification/provider mismatch')
                if not any(item.kind == 'governed_service' for item in requirement.provider_bindings):
                    raise ValueError(f'{test.id} manual mapping must retain governed execution')
            elif test.classification == 'GAP_NATIVE_SMALL':
                expected = EXPECTED_GAPS.get(test.id)
                planned = [item.ref for item in requirement.provider_bindings if item.kind == 'planned_native']
                if requirement.availability != 'planned_native' or planned != [expected]:
                    raise ValueError(f'{test.id} does not match the approved native gap')
            elif test.classification == 'CONDITIONAL_NA':
                if requirement.availability != 'conditional':
                    raise ValueError(f'{test.id} conditional applicability contract changed')

        actual_gap_ids = {
            test.id for test in self.catalog.tests if test.classification == 'GAP_NATIVE_SMALL'
        }
        if actual_gap_ids != set(EXPECTED_GAPS):
            raise ValueError('Approved native gap identity set changed')

    def resolve(self, wstg_id: str) -> tuple[CapabilityRequirement, ...]:
        canonical = self.catalog.resolve(wstg_id)
        mapping = self._mappings[canonical.id]
        return tuple(self._requirements[item] for item in mapping.required_capability_ids)
