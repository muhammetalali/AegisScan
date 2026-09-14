#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

BASE = Path('/opt/aegis-runner/runtime-manifest.json')
TOOLS = Path('/opt/aegis-runner/tool-manifest.json')
PROFILE_ARTIFACTS = {
    'web': {
        'wordlist.web-common': Path('/opt/aegis-wordlists/web-common.txt'),
    },
}


def _load(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict):
        raise SystemExit(f'{path} must contain a JSON object')
    return payload


def _sha256(path: Path) -> str:
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    profile = os.environ.get('AEGIS_RUNNER_PROFILE', '').strip()
    if not profile or profile == 'base':
        raise SystemExit('profile runtime manifest requires a non-base profile')
    base = _load(BASE)
    tool_manifest = _load(TOOLS)
    policy = tool_manifest.get('profiles', {}).get(profile)
    if not isinstance(policy, dict):
        raise SystemExit(f'unknown profile: {profile}')
    if profile == 'full' and policy.get('production_allowed') is not False:
        raise SystemExit('full profile must remain CI/lab-only')
    if tool_manifest.get('policy', {}).get('dispatch_state') != 'placement-only':
        raise SystemExit('profile tool manifest must retain placement-only public semantics during provider migration')

    provider_dispatch = policy.get('provider_dispatch')
    if provider_dispatch not in {None, 'semantic-only'}:
        raise SystemExit(f'unsupported provider_dispatch for profile {profile}: {provider_dispatch}')
    if profile != 'recon' and provider_dispatch is not None:
        raise SystemExit('provider dispatch is currently permitted only for the recon profile')
    dispatch_enabled = profile == 'recon' and provider_dispatch == 'semantic-only'

    tools = {}
    for name, metadata in sorted(tool_manifest.get('tools', {}).items()):
        if profile in metadata.get('profiles', []):
            tools[name] = {
                key: metadata[key]
                for key in ('version', 'commit', 'sha256', 'source')
                if key in metadata
            }

    artifacts = {}
    for name, path in PROFILE_ARTIFACTS.get(profile, {}).items():
        if not path.is_file():
            raise SystemExit(f'missing required profile artifact: {path}')
        artifacts[name] = _sha256(path)

    base['profile'] = profile
    base['dispatch_enabled'] = dispatch_enabled
    base['dispatch_state'] = 'semantic-recon-provider' if dispatch_enabled else 'accepted-no-dispatch'
    base['profile_tools'] = tools
    base['profile_artifacts'] = artifacts
    base['tool_manifest_digest'] = _sha256(TOOLS)
    base['profile_capabilities'] = list(policy.get('capabilities', []))
    BASE.write_text(json.dumps(base, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
