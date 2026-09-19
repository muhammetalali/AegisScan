#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def validate(path: Path) -> None:
    model = json.loads(path.read_text(encoding='utf-8'))
    scanner = model['services']['scanner_worker']
    provider = model['services']['kali_masscan']
    env = scanner['environment']
    build = scanner['build']

    assert build['target'] == 'production-no-legacy-recon', build
    for name in ('AEGIS_RETIRE_NMAP', 'AEGIS_RETIRE_NUCLEI', 'AEGIS_RETIRE_SEMGREP', 'AEGIS_RETIRE_MASSCAN'):
        assert str(build['args'][name]) == '1', (name, build)

    assert env['AEGIS_MASSCAN_PROVIDER'] == 'default-kali', env
    assert env['AEGIS_MASSCAN_LEGACY_DISABLED'] == 'true', env
    assert str(env['AEGIS_KALI_MASSCAN_CANARY_BPS']) == '0', env
    assert env['AEGIS_KALI_MASSCAN_URL'] == 'http://127.0.0.1:18767', env
    assert scanner['depends_on']['kali_masscan']['condition'] == 'service_healthy'

    assert provider['network_mode'] == 'service:scanner_egress', provider
    assert provider['read_only'] is True, provider
    assert provider['cap_drop'] == ['ALL'], provider
    assert provider['cap_add'] == ['NET_RAW'], provider
    assert provider['security_opt'] == ['no-new-privileges:true'], provider
    assert provider['user'] == '0:0', provider
    assert provider['pids_limit'] == 128, provider
    assert int(provider['mem_limit']) == 536870912, provider
    assert float(provider['cpus']) == 1.0, provider
    assert provider.get('ports') in (None, []), provider
    assert provider.get('profiles') in (None, []), provider

    penv = provider['environment']
    assert penv['AEGIS_MASSCAN_LISTEN_HOST'] == '127.0.0.1', penv
    assert str(penv['AEGIS_MASSCAN_LISTEN_PORT']) == '18767', penv
    assert penv['AEGIS_KALI_MASSCAN_AUTH_TOKEN'] == env['AEGIS_KALI_MASSCAN_AUTH_TOKEN']
    assert provider['image'] == env['AEGIS_KALI_MASSCAN_IMAGE']


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f'usage: {sys.argv[0]} <production.json> <override.json>')
    for raw in sys.argv[1:]:
        validate(Path(raw))
    print('NETWORK_MASSCAN_M6_PRODUCTION_CONTRACT_PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
