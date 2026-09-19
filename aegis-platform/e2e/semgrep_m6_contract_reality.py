#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def _volume(service: dict, target: str) -> dict:
    matches = [item for item in service.get('volumes', []) if item.get('target') == target]
    if len(matches) != 1:
        raise AssertionError((target, matches))
    return matches[0]


def validate(path: Path) -> None:
    model = json.loads(path.read_text(encoding='utf-8'))
    scanner = model['services']['scanner_worker']
    provider = model['services']['kali_code']
    env = scanner['environment']
    build = scanner['build']

    assert build['target'] == 'production-no-legacy-recon', build
    assert str(build['args']['AEGIS_RETIRE_NMAP']) == '1', build
    assert str(build['args']['AEGIS_RETIRE_NUCLEI']) == '1', build
    assert str(build['args']['AEGIS_RETIRE_SEMGREP']) == '1', build
    assert env['AEGIS_SEMGREP_PROVIDER'] == 'default-kali', env
    assert env['AEGIS_SEMGREP_LEGACY_DISABLED'] == 'true', env
    assert str(env['AEGIS_KALI_SEMGREP_CANARY_BPS']) == '0', env
    assert env['AEGIS_KALI_CODE_URL'] == 'http://127.0.0.1:18771', env
    assert env['AEGIS_SEMGREP_WORKSPACE_ROOT'] == '/var/lib/aegis-semgrep', env

    scanner_workspace = _volume(scanner, '/var/lib/aegis-semgrep')
    provider_workspace = _volume(provider, '/var/lib/aegis-semgrep')
    assert scanner_workspace.get('read_only') in (False, None), scanner_workspace
    assert provider_workspace.get('read_only') is True, provider_workspace
    assert scanner_workspace['source'] == provider_workspace['source']

    assert scanner['depends_on']['kali_code']['condition'] == 'service_healthy'
    assert provider['network_mode'] == 'service:scanner_egress', provider
    assert provider['read_only'] is True, provider
    assert provider['cap_drop'] == ['ALL'], provider
    assert provider.get('cap_add') in (None, []), provider
    assert provider['security_opt'] == ['no-new-privileges:true'], provider
    assert provider['user'] == '10001:10001', provider
    assert provider['pids_limit'] == 128, provider
    assert int(provider['mem_limit']) == 805306368, provider
    assert float(provider['cpus']) == 1.0, provider
    assert provider.get('ports') in (None, []), provider
    penv = provider['environment']
    assert penv['AEGIS_CODE_LISTEN_HOST'] == '127.0.0.1', penv
    assert str(penv['AEGIS_CODE_LISTEN_PORT']) == '18771', penv
    assert penv['AEGIS_CODE_WORKSPACE_ROOT'] == '/var/lib/aegis-semgrep', penv
    assert penv['AEGIS_KALI_CODE_AUTH_TOKEN'] == env['AEGIS_KALI_CODE_AUTH_TOKEN']


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f'usage: {sys.argv[0]} <production.json> <override.json>')
    for raw in sys.argv[1:]:
        validate(Path(raw))
    print('CODE_SEMGREP_M6_PRODUCTION_CONTRACT_PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
