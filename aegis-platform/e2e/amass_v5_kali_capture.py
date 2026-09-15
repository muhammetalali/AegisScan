#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi_app.services.kali_recon_provider import execute_kali_recon, recon_provider_decision


def main() -> int:
    capability = os.environ.get('AEGIS_AMASS_CAPABILITY', 'recon.amass')
    target = os.environ.get('AEGIS_AMASS_TARGET', 'parity.test')
    artifact_dir = Path(os.environ.get('AEGIS_ARTIFACT_DIR', '/artifacts'))
    artifact_dir.mkdir(parents=True, exist_ok=True)

    decision = recon_provider_decision(capability)
    assert decision.selected_provider == 'kali', decision
    assert decision.parity_approved is False, decision
    assert decision.reason == 'explicit-kali-mode', decision

    result = execute_kali_recon(
        capability_id=capability,
        target=target,
        options={'timeout_minutes': 1},
        timeout_seconds=150,
        execution_ref='amass-v5-parity-real',
        authorization_ref='authorization:amass-v5-parity-reality',
        scope_ref='project:amass-v5-parity:asset:parity-test',
        state_getter=None,
        poll_interval=0.1,
    )
    if result['exit_code'] != 0:
        raise SystemExit(
            f"Kali Amass failed: exit={result['exit_code']} stderr={result['stderr'][:4000]}"
        )

    runtime = result['runtime']
    runtime['routing_decision'] = decision.as_dict()
    assert runtime['provider'] == 'aegis-kali-recon'
    assert runtime['profile'] == 'recon'
    assert runtime['provenance_authority'] == 'control-plane-deployment-pins'
    assert runtime['image_digest'] == os.environ['AEGIS_KALI_RECON_EXPECTED_IMAGE_DIGEST']

    payload = {
        'backend': 'kali',
        'capability_id': capability,
        'target': result['target'],
        'options': {'timeout_minutes': 1},
        'tool': result['tool'],
        'exit_code': result['exit_code'],
        'stdout': result['stdout'],
        'stderr': result['stderr'],
        'runtime_provenance': runtime,
    }
    (artifact_dir / 'kali-execution.json').write_text(
        json.dumps(payload, sort_keys=True) + '\n', encoding='utf-8'
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
