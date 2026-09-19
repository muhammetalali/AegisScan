from __future__ import annotations

import json
import sys
from pathlib import Path


def validate(path: str, expected_mode: str) -> None:
    model = json.loads(Path(path).read_text(encoding='utf-8'))
    scanner = model['services']['scanner_worker']
    provider = model['services']['kali_masscan']
    env = scanner['environment']

    assert env['AEGIS_MASSCAN_PROVIDER'] == expected_mode, env
    assert str(env['AEGIS_KALI_MASSCAN_CANARY_BPS']) == '0', env
    assert env['AEGIS_KALI_MASSCAN_URL'] == 'http://127.0.0.1:18767', env
    assert 'AEGIS_MASSCAN_LEGACY_DISABLED' not in env, env
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
    assert provider['environment']['AEGIS_MASSCAN_LISTEN_HOST'] == '127.0.0.1', provider
    assert str(provider['environment']['AEGIS_MASSCAN_LISTEN_PORT']) == '18767', provider


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit('usage: masscan_default_kali_contract.py DEFAULT_JSON ROLLBACK_JSON')
    validate(sys.argv[1], 'default-kali')
    validate(sys.argv[2], 'legacy')
    print('NETWORK_MASSCAN_M5_DEPLOYMENT_PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
