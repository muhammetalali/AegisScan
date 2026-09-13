"""Independent contract proof for WSTG -> semantic capability mapping."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.wstg_capability_mapping import WSTGCapabilityMapping
from fastapi_app.services.wstg_catalog import PACK


def verify() -> dict:
    mapping = WSTGCapabilityMapping()
    availability = Counter(item.availability for item in mapping.requirements)
    providers = Counter(
        binding.kind
        for requirement in mapping.requirements
        for binding in requirement.provider_bindings
    )
    planned = sorted(
        {
            binding.ref
            for requirement in mapping.requirements
            for binding in requirement.provider_bindings
            if binding.kind == 'planned_native'
        }
    )
    pairs = [
        (item.wstg_id, list(item.required_capability_ids))
        for item in mapping.mappings
    ]
    return {
        'proof_scope': (
            'WSTG identity -> semantic requirement -> existing provider reference only; '
            'no target authorization, dispatch, execution or finding projection'
        ),
        'official_tests_mapped': len(mapping.mappings),
        'semantic_requirements': len(mapping.requirements),
        'availability_counts': dict(sorted(availability.items())),
        'provider_binding_counts': dict(sorted(providers.items())),
        'approved_planned_native_gaps': planned,
        'mapping_digest': hashlib.sha256(
            json.dumps(pairs, separators=(',', ':')).encode()
        ).hexdigest(),
        'mapping_file_sha256': {
            name: hashlib.sha256((PACK / name).read_bytes()).hexdigest()
            for name in ('capability_requirements.json', 'mappings.json')
        },
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
