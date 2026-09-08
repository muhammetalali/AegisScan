#!/usr/bin/env python3
"""Fail-closed policy checks for the fully resolved production Compose model."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


INTERNAL_SERVICES = {
    'postgres', 'redis', 'django', 'fastapi', 'celery_worker', 'scanner_worker',
    'scanner_egress', 'celery_beat', 'frontend',
}
HARDENED_SERVICES = {'django', 'fastapi', 'celery_worker', 'scanner_worker', 'scanner_egress', 'celery_beat'}
_TRUTHY = {'1', 'true', 'yes', 'on'}


def _tokens(value) -> set[str]:
    if isinstance(value, list):
        return {str(item).upper() for item in value}
    if value in (None, ''):
        return set()
    return {str(value).upper()}


def _command_text(service: dict) -> str:
    value = service.get('command', '')
    if isinstance(value, list):
        return ' '.join(str(item) for item in value)
    return str(value)


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
        cap_drop = _tokens(service.get('cap_drop'))
        if 'ALL' not in cap_drop:
            failures.append(f'{name} does not drop all ambient Linux capabilities')

    postgres = services.get('postgres', {})
    password = (postgres.get('environment') or {}).get('POSTGRES_PASSWORD', '')
    if not password or password == 'change-me':
        failures.append('Production PostgreSQL password is missing or uses the development default')

    for name in ('fastapi', 'celery_worker', 'scanner_worker', 'celery_beat'):
        environment = services.get(name, {}).get('environment') or {}
        allowed = str(environment.get('AUTHORIZED_SCAN_TARGETS', '')).strip()
        if not allowed or allowed == 'aegis-scan-target':
            failures.append(f'{name} uses an absent or CI fixture authorization scope')
        allow_single_label = str(environment.get('ALLOW_SINGLE_LABEL_SCAN_TARGETS', '')).strip().lower()
        if allow_single_label in _TRUTHY:
            failures.append(f'{name} enables single-label scanner targets in production')

    general_worker = services.get('celery_worker', {})
    general_caps = _tokens(general_worker.get('cap_add'))
    if {'NET_RAW', 'NET_ADMIN'} & general_caps:
        failures.append('general celery_worker retains scanner network capabilities')
    if '-Q default' not in _command_text(general_worker):
        failures.append('general celery_worker is not pinned to the default queue')

    scanner_worker = services.get('scanner_worker', {})
    scanner_caps = _tokens(scanner_worker.get('cap_add'))
    if 'NET_RAW' not in scanner_caps:
        failures.append('scanner_worker lacks the minimum NET_RAW capability required by packet scanners')
    if 'NET_ADMIN' in scanner_caps:
        failures.append('scanner_worker must not receive NET_ADMIN; egress policy belongs to scanner_egress')
    if scanner_worker.get('network_mode') != 'service:scanner_egress':
        failures.append('scanner_worker does not share the scanner_egress network namespace')
    if '-Q scanners' not in _command_text(scanner_worker):
        failures.append('scanner_worker is not pinned to the scanners queue')

    egress = services.get('scanner_egress', {})
    egress_caps = _tokens(egress.get('cap_add'))
    if 'NET_ADMIN' not in egress_caps:
        failures.append('scanner_egress lacks NET_ADMIN required to install kernel egress policy')
    if 'NET_RAW' in egress_caps:
        failures.append('scanner_egress should not receive NET_RAW')
    egress_env = egress.get('environment') or {}
    private_targets = str(egress_env.get('SCANNER_EGRESS_PRIVATE_TARGETS', '')).strip()
    if 'aegis-scan-target' in {item.strip() for item in private_targets.split(',') if item.strip()}:
        failures.append('scanner_egress enables the CI scan target in production')

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('compose_json', type=Path)
    args = parser.parse_args()
    model = json.loads(args.compose_json.read_text(encoding='utf-8'))
    failures = validate(model)
    print(json.dumps({'policy': 'production-compose-v3', 'failures': failures}, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
