"""Independent exact-head proof for WSTG observation -> evidence -> finding lineage."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi_app.services.wstg_capability_mapping import WSTGCapabilityMapping
from fastapi_app.services.wstg_observation_lineage import wstg_observation_lineage


BACKEND_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_FILES = (
    'fastapi_app/tasks/native_capabilities.py',
    'fastapi_app/tasks/security_scan.py',
    'fastapi_app/tasks/advanced_scans.py',
    'fastapi_app/services/native_finding_projection.py',
    'fastapi_app/services/nmap_finding_ingestion.py',
)


def verify() -> dict:
    mapping = WSTGCapabilityMapping()
    expected: dict[str, set[str]] = {}
    classifications = Counter()

    for test in mapping.catalog.tests:
        requirement = mapping.resolve(test.id)[0]
        for binding in requirement.provider_bindings:
            if binding.kind != 'registry_capability':
                continue
            expected.setdefault(binding.ref, set()).add(test.id)
            classifications[test.classification] += 1

    fingerprints: dict[str, str] = {}
    for capability_id, expected_ids in sorted(expected.items()):
        payload = wstg_observation_lineage(capability_id)
        actual_ids = {item['wstg_id'] for item in payload['tests']}
        if actual_ids != expected_ids:
            raise ValueError(
                f'WSTG observation lineage mismatch for {capability_id}: '
                f'expected={sorted(expected_ids)} actual={sorted(actual_ids)}'
            )
        if payload['completion_claim_allowed'] is not False:
            raise ValueError(f'{capability_id} lineage incorrectly grants methodology completion')
        if payload['finding_state_authority'] != 'governed-finding-confirmation':
            raise ValueError(f'{capability_id} changed finding-state authority')
        if len(payload['lineage_fingerprint']) != 64:
            raise ValueError(f'{capability_id} lineage fingerprint is invalid')
        if any(item['completion_claim_allowed'] is not False for item in payload['tests']):
            raise ValueError(f'{capability_id} contains an authoritative WSTG claim')

        for item in payload['tests']:
            classification = item['classification']
            state = item['methodology_state']
            if classification == 'MANUAL_GOVERNED' and state != 'manual_required':
                raise ValueError('Manual-governed evidence became self-attesting')
            if classification == 'GAP_NATIVE_SMALL' and state != 'blocked_native_gap':
                raise ValueError('Native-gap evidence became executable completion')
            if classification == 'CONDITIONAL_NA' and state != 'inconclusive':
                raise ValueError('Conditional WSTG evidence bypassed applicability')
        fingerprints[capability_id] = payload['lineage_fingerprint']

    unmapped = wstg_observation_lineage('binary.checksec')
    if unmapped['tests']:
        raise ValueError('Unmapped capability invented WSTG coverage')

    integration = {}
    for relative in INTEGRATION_FILES:
        content = (BACKEND_ROOT / relative).read_text(encoding='utf-8')
        evidence_bound = 'attach_wstg_evidence_metadata' in content
        finding_bound = (
            'attach_wstg_finding_lineage' in content
            or relative.endswith('native_capabilities.py')
        )
        if not evidence_bound and relative.endswith('native_capabilities.py'):
            raise ValueError('Native scanner evidence is not bound to WSTG lineage')
        if relative.endswith(('native_finding_projection.py', 'nmap_finding_ingestion.py')) and not finding_bound:
            raise ValueError(f'Finding projection lacks WSTG lineage: {relative}')
        integration[relative] = {
            'evidence_bound': evidence_bound,
            'finding_bound': finding_bound,
        }

    return {
        'proof_scope': (
            'Executed semantic capability observation -> persisted Evidence/Finding provenance only; '
            'no WSTG pass/fail claim and no finding confirmation/closure/disposition authority'
        ),
        'registry_capabilities_with_wstg_lineage': len(expected),
        'registry_binding_occurrences_by_classification': dict(sorted(classifications.items())),
        'capability_lineage_fingerprints': fingerprints,
        'unmapped_capability_wstg_tests': len(unmapped['tests']),
        'integration_files': integration,
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
