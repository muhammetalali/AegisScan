#!/usr/bin/env python3
"""Fail-closed policy checks for the fully resolved production Compose model."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


INTERNAL_SERVICES = {'postgres', 'redis', 'django', 'fastapi', 'celery_worker', 'celery_beat', 'frontend'}
HARDENED_SERVICES = {'django', 'fastapi', 'celery_worker', 'celery_beat'}


def validate(model: dict) -> list[str]:
    failures: list[str] = []
    services = model.get('services') if isinstance(model, dict) else None
    if not isinstance(services, dict):
        return ['Resolved Compose document has no services mapping']
    scan_target = services.get('scan_target')
    if scan_target is not None and 'ci-only' not in (scan_target.get('profiles') or []):
        failures.append('CI-only scan_target is active in the default production model')
    for name in INTERNAL_SERVICES:
        service = services.get(name, {})
        if service.get('ports'):
            failures.append(f'{name} publishes a host port in production')
        for volume in service.get('volumes') or []:
            source = volume.get('source') if isinstance(volume, dict) else str(volume).split(':', 1)[0]
            if str(source).startswith('.') or str(source).startswith('/'):
                failures.append(f'{name} uses host bind mount {source!r} in production')
    for name in HARDENED_SERVICES:
        service = services.get(name, {})
        if service.get('read_only') is not True:
            failures.append(f'{name} root filesystem is not read-only')
        security_opt = service.get('security_opt') or []
        if not any(str(item).lower() == 'no-new-privileges:true' for item in security_opt):
            failures.append(f'{name} does not enforce no-new-privileges')
        cap_drop = {str(item).upper() for item in service.get('cap_drop') or []}
        if 'ALL' not in cap_drop:
            failures.append(f'{name} does not drop all ambient Linux capabilities')
    postgres = services.get('postgres', {})
    password = (postgres.get('environment') or {}).get('POSTGRES_PASSWORD', '')
    if not password or password == 'change-me':
        failures.append('Production PostgreSQL password is missing or uses the development default')
    for name in ('fastapi', 'celery_worker', 'celery_beat'):
        allowed = str((services.get(name, {}).get('environment') or {}).get('AUTHORIZED_SCAN_TARGETS', '')).strip()
        if not allowed or allowed == 'aegis-scan-target':
            failures.append(f'{name} uses an absent or CI fixture authorization scope')
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('compose_json', type=Path)
    args = parser.parse_args()
    model = json.loads(args.compose_json.read_text(encoding='utf-8'))
    failures = validate(model)
    print(json.dumps({'policy': 'production-compose-v1', 'failures': failures}, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
