#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi_app.services.execution_semantic_parity import compare_execution_semantics
from fastapi_app.services.native_output_enrichment import normalize_enriched_native_output

EXPECTED = {
    ('discovered-hostname', 'www.parity.test'),
    ('discovered-hostname', 'api.parity.test'),
    ('discovered-hostname', 'mail.parity.test'),
}


def _load(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict):
        raise AssertionError(f'{path} must contain a JSON object')
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--exact-head', required=True)
    args = parser.parse_args()

    legacy = _load(args.artifacts / 'legacy-execution.json')
    kali = _load(args.artifacts / 'kali-execution.json')
    runtime = _load(args.artifacts / 'kali-runtime-manifest.json')
    actual_hashes = _load(args.artifacts / 'kali-amass-artifact-hashes.json')

    for field in ('capability_id', 'target', 'options', 'tool'):
        assert legacy[field] == kali[field], (field, legacy[field], kali[field])
    assert legacy['capability_id'] == 'recon.amass'
    assert legacy['target'] == 'parity.test'
    assert legacy['options'] == {'timeout_minutes': 1}
    assert legacy['exit_code'] == 0
    assert kali['exit_code'] == 0

    capability = legacy['capability_id']
    legacy_normalized = normalize_enriched_native_output(capability, legacy['stdout'])
    kali_normalized = normalize_enriched_native_output(capability, kali['stdout'])
    assert legacy_normalized.get('count', 0) > 0, legacy_normalized
    assert kali_normalized.get('count', 0) > 0, kali_normalized

    def values(normalized: dict) -> set[tuple[str | None, str | None]]:
        return {
            (item.get('kind'), item.get('hostname'))
            for item in normalized['observations']
            if isinstance(item, dict)
        }

    legacy_values = values(legacy_normalized)
    kali_values = values(kali_normalized)
    assert EXPECTED <= legacy_values, (EXPECTED, legacy_values)
    assert EXPECTED <= kali_values, (EXPECTED, kali_values)

    report = compare_execution_semantics(
        capability_id=capability,
        legacy_normalized=legacy_normalized,
        candidate_normalized=kali_normalized,
    )
    assert report.semantic_equivalent is True, report.as_dict()
    assert report.mismatches == (), report.as_dict()

    profile_artifacts = runtime.get('profile_artifacts')
    assert isinstance(profile_artifacts, dict)
    for name in (
        'adapter.amass-v5',
        'binary.amass-v5',
        'patch.amass-v5-engine-auth',
    ):
        assert profile_artifacts.get(name) == actual_hashes.get(name), (
            name,
            profile_artifacts.get(name),
            actual_hashes.get(name),
        )

    routing = kali['runtime_provenance'].get('routing_decision')
    assert isinstance(routing, dict)
    assert routing.get('selected_provider') == 'kali'
    assert routing.get('parity_approved') is False
    assert routing.get('reason') == 'explicit-kali-mode'

    evidence = {
        'schema': 'aegis.recon-amass-v5-real-dual-run.v1',
        'exact_head': args.exact_head,
        'upstream_commit': '79299dce87b0085db0f2f4ef3e9c52cccb49f514',
        'fixture': 'isolated-hackertarget-https-v1',
        'fixture_endpoint': 'https://api.hackertarget.com/hostsearch/?q=parity.test',
        'network_external_egress': False,
        'engine_auth_proven': True,
        'engine_auth_token_captured': False,
        'capability_id': capability,
        'target': legacy['target'],
        'legacy_runtime': {
            'provider': 'legacy-native-worker',
            'tool': legacy['tool'],
            'tool_version': legacy['tool_version'],
            'artifact_hashes': legacy['artifact_hashes'],
        },
        'candidate_runtime': kali['runtime_provenance'],
        'candidate_tool_version': runtime['profile_tools']['amass']['version'],
        'candidate_artifact_hashes': actual_hashes,
        'legacy_normalized': legacy_normalized,
        'candidate_normalized': kali_normalized,
        'parity': report.as_dict(),
        'real_dual_run_proven': True,
        'raw_stdout_byte_equality_required': False,
        'production_promotion_performed': False,
        'default_provider': 'legacy',
        'm6_retirement_allowed': False,
    }
    output = args.artifacts / 'amass-v5-real-dual-run.json'
    output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report.as_dict(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
