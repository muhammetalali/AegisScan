from __future__ import annotations

import json
from pathlib import Path

import pytest

from fastapi_app.services.capability_registry import CAPABILITIES
from fastapi_app.services.kali_profile_policy import CAPABILITY_PROFILE_MAP, PROFILES

KALI = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((KALI / 'tool-manifest.json').read_text(encoding='utf-8'))
DOCKERFILE = (KALI / 'Dockerfile.profiles').read_text(encoding='utf-8')
RECON_SERVICE = (KALI / 'runner' / 'recon_service.py').read_text(encoding='utf-8')


def test_manifest_capability_assignments_match_control_plane_exactly():
    manifest_map = {}
    for profile, policy in MANIFEST['profiles'].items():
        for capability_id in policy['capabilities']:
            assert capability_id not in manifest_map, capability_id
            manifest_map[capability_id] = profile
    assert manifest_map == CAPABILITY_PROFILE_MAP
    assert set(manifest_map) == set(CAPABILITIES)


def test_profiles_match_policy_and_full_is_never_production():
    assert MANIFEST['policy']['dispatch_state'] == 'placement-only'
    assert MANIFEST['policy']['arbitrary_shell'] is False
    assert MANIFEST['policy']['wstg_authority'] is False
    assert set(MANIFEST['profiles']) == set(PROFILES)
    for name, policy in PROFILES.items():
        assert MANIFEST['profiles'][name]['production_allowed'] is policy.production_allowed
    assert MANIFEST['profiles']['full']['production_allowed'] is False
    assert MANIFEST['profiles']['full']['capabilities'] == []
    assert 'full' not in CAPABILITY_PROFILE_MAP.values()


def test_recon_is_only_profile_with_semantic_provider_dispatch():
    assert MANIFEST['profiles']['recon']['provider_dispatch'] == 'semantic-only'
    for name, policy in MANIFEST['profiles'].items():
        if name != 'recon':
            assert 'provider_dispatch' not in policy, name
    recon_capabilities = set(MANIFEST['profiles']['recon']['capabilities'])
    assert recon_capabilities == {'recon.amass', 'recon.subfinder', 'recon.dnsenum', 'recon.fierce'}


def test_recon_service_is_packaged_only_in_recon_profile_and_has_no_shell_dispatch():
    recon_start = DOCKERFILE.index('FROM profile-common AS profile-recon')
    web_start = DOCKERFILE.index('FROM profile-common AS profile-web')
    recon_stage = DOCKERFILE[recon_start:web_start]
    before_recon = DOCKERFILE[:recon_start]
    after_recon = DOCKERFILE[web_start:]
    assert 'COPY aegis-platform/kali/runner/recon_service.py /opt/aegis-runner/recon_service.py' in recon_stage
    assert 'recon_service.py' not in before_recon
    assert 'recon_service.py' not in after_recon
    assert 'shell=True' not in RECON_SERVICE
    assert "payload.get('argv')" not in RECON_SERVICE
    assert "payload.get('binary')" not in RECON_SERVICE


def test_manifest_has_no_floating_tool_versions_or_duplicate_tool_families():
    forbidden = {'assetfinder', 'findomain', 'chaos', 'shosubgo', 'aquatone', 'hakrawler', 'urlfinder', 'dirsearch', 'sqlmap', 'commix', 'hydra'}
    assert forbidden.isdisjoint(MANIFEST['tools'])
    for name, tool in MANIFEST['tools'].items():
        assert tool['source'] in {'kali-apt', 'go', 'cargo', 'oci-stage', 'release-archive', 'git', 'pypi'}
        assert tool.get('profiles'), name
        assert set(tool['profiles']).issubset(PROFILES), name
        assert 'full' not in tool['profiles'], name
        if tool['source'] != 'git':
            assert tool.get('version'), name
            assert 'latest' not in str(tool.get('version', '')).lower()
        if tool['source'] == 'kali-apt':
            assert tool.get('package') and tool.get('version'), name
        if tool['source'] == 'release-archive':
            assert len(tool.get('sha256', '')) == 64, name
        if tool['source'] == 'git':
            assert len(tool.get('commit', '')) == 40, name


def test_tool_manifest_provenance_is_bound_to_profile_build_inputs():
    for name, tool in MANIFEST['tools'].items():
        source = tool['source']
        if source == 'kali-apt':
            assert f"{tool['package']}={tool['version']}" in DOCKERFILE, name
        elif source == 'go':
            assert f"{tool['module']}@{tool['version']}" in DOCKERFILE, name
        elif source == 'cargo':
            assert f"--version {tool['version']} {name}" in DOCKERFILE, name
        elif source == 'oci-stage':
            assert tool['image'] in DOCKERFILE, name
        elif source == 'release-archive':
            assert tool['version'] in DOCKERFILE, name
            assert tool['sha256'] in DOCKERFILE, name
        elif source == 'git':
            assert tool['commit'] in DOCKERFILE, name
        elif source == 'pypi':
            assert f"{name}=={tool['version']}" in DOCKERFILE, name
        else:  # pragma: no cover - source allowlist is asserted separately.
            raise AssertionError(f'unhandled tool source: {source}')


def test_browser_firefox_is_bound_to_immutable_archive_artifact():
    firefox = MANIFEST['tools']['firefox-esr']
    assert firefox['source'] == 'release-archive'
    assert firefox['url'].startswith(
        'https://snapshot.debian.org/archive/debian/20260820T235959Z/pool/'
    )
    assert firefox['url'] in DOCKERFILE
    assert f"--checksum=sha256:{firefox['sha256']}" in DOCKERFILE
    assert f"firefox-esr={firefox['version']}" not in DOCKERFILE
    assert "dpkg-query -W -f='${Version}' firefox-esr" in DOCKERFILE
    assert firefox['version'] in DOCKERFILE


def test_profile_dockerfile_has_no_install_everything_or_floating_latest():
    lowered = DOCKERFILE.lower()
    assert 'kali-linux-everything' not in lowered
    assert '@latest' not in lowered
    assert ':latest' not in lowered
    for profile in ('network', 'recon', 'web', 'api', 'browser', 'code', 'cloud', 'binary', 'crypto'):
        assert f'as profile-{profile}' in lowered
        assert f'io.aegisscan.runner.profile={profile}' in lowered


def test_base_digest_and_runner_version_are_bound_to_foundation():
    base = (KALI / 'Dockerfile.base').read_text(encoding='utf-8')
    assert MANIFEST['base_image_digest'] in base
    assert f'ARG AEGIS_RUNNER_VERSION={MANIFEST["runner_version"]}' in base


def test_unknown_profile_cannot_appear_silently():
    with pytest.raises(KeyError):
        _ = MANIFEST['profiles']['unregistered']
