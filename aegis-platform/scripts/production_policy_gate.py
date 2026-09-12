#!/usr/bin/env python3
"""Fail-closed policy checks for the fully resolved production Compose model."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


INTERNAL_SERVICES = {
    'postgres', 'redis', 'django', 'fastapi', 'celery_worker', 'scanner_worker',
    'browser_worker', 'scanner_egress', 'celery_beat', 'frontend', 'backup',
}
HARDENED_SERVICES = {'django', 'fastapi', 'celery_worker', 'scanner_worker', 'browser_worker', 'scanner_egress', 'celery_beat', 'backup'}
NO_NEW_PRIVILEGES_SERVICES = HARDENED_SERVICES - {'scanner_worker'}
_TRUTHY = {'1', 'true', 'yes', 'on'}
_SCANNER_BOOTSTRAP_CAPS = {'NET_RAW', 'SETUID', 'SETGID', 'SETPCAP'}
_BACKUP_SECRET_TARGETS = {'/run/secrets/s3-credentials.json', '/run/secrets/encryption.key'}


def _tokens(value) -> set[str]:
    if isinstance(value, list):
        return {str(item).upper() for item in value}
    if value in (None, ''):
        return set()
    return {str(value).upper()}


def _security_opts(service: dict) -> list[str]:
    value = service.get('security_opt') or []
    if isinstance(value, list):
        return [str(item).lower() for item in value]
    return [str(value).lower()]


def _has_no_new_privileges(service: dict) -> bool:
    return any(item == 'no-new-privileges:true' for item in _security_opts(service))


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
            if isinstance(volume, dict):
                source = volume.get('source')
                target = str(volume.get('target') or '')
                volume_type = str(volume.get('type') or '')
                read_only = bool(volume.get('read_only'))
            else:
                parts = str(volume).split(':')
                source = parts[0]
                target = parts[1] if len(parts) > 1 else ''
                volume_type = 'bind' if str(source).startswith(('.', '/')) else 'volume'
                read_only = len(parts) > 2 and parts[2] == 'ro'
            if str(source).startswith('.') or str(source).startswith('/'):
                allowed_backup_secret = (
                    name == 'backup'
                    and volume_type == 'bind'
                    and target in _BACKUP_SECRET_TARGETS
                    and read_only
                )
                if not allowed_backup_secret:
                    failures.append(f'{name} uses host bind mount {source!r} in production')
    for name in HARDENED_SERVICES:
        service = services.get(name, {})
        if service.get('read_only') is not True:
            failures.append(f'{name} root filesystem is not read-only')
        if name in NO_NEW_PRIVILEGES_SERVICES and not _has_no_new_privileges(service):
            failures.append(f'{name} does not enforce no-new-privileges')
        cap_drop = _tokens(service.get('cap_drop'))
        if 'ALL' not in cap_drop:
            failures.append(f'{name} does not drop all ambient Linux capabilities')

    postgres = services.get('postgres', {})
    password = (postgres.get('environment') or {}).get('POSTGRES_PASSWORD', '')
    if not password or password == 'change-me':
        failures.append('Production PostgreSQL password is missing or uses the development default')

    for name in ('fastapi', 'celery_worker', 'scanner_worker', 'browser_worker', 'celery_beat'):
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

    browser_worker = services.get('browser_worker', {})
    browser_caps = _tokens(browser_worker.get('cap_add'))
    if browser_caps:
        failures.append('browser_worker must not receive Linux capabilities')
    if str(browser_worker.get('user', '')).strip() in {'', '0', '0:0', 'root'}:
        failures.append('browser_worker must run as a non-root uid/gid')
    if browser_worker.get('network_mode') != 'service:scanner_egress':
        failures.append('browser_worker does not share the scanner_egress network namespace')
    if '-Q browser' not in _command_text(browser_worker):
        failures.append('browser_worker is not pinned to the browser queue')
    if not _has_no_new_privileges(browser_worker):
        failures.append('browser_worker does not enforce no-new-privileges')

    browser_env = browser_worker.get('environment') or {}
    for required in (
        'SECRET_KEY', 'JWT_SECRET_KEY', 'DATABASE_URL', 'REDIS_URL',
        'CELERY_BROKER_URL', 'CELERY_RESULT_BACKEND', 'CREDENTIAL_VAULT_KEYS',
        'CREDENTIAL_FINGERPRINT_KEY',
    ):
        if not str(browser_env.get(required, '')).strip():
            failures.append(f'browser_worker is missing required production runtime variable {required}')

    scanner_worker = services.get('scanner_worker', {})
    scanner_caps = _tokens(scanner_worker.get('cap_add'))
    if scanner_caps != _SCANNER_BOOTSTRAP_CAPS:
        failures.append(
            'scanner_worker bootstrap capabilities must be exactly '
            'NET_RAW,SETUID,SETGID,SETPCAP before the non-root handoff'
        )
    if 'NET_ADMIN' in scanner_caps:
        failures.append('scanner_worker must not receive NET_ADMIN; egress policy belongs to scanner_egress')
    if _has_no_new_privileges(scanner_worker):
        failures.append(
            'scanner_worker cannot enforce no-new-privileges before the bounded '
            'CAP_NET_RAW ambient handoff; runtime gates must verify the final non-root process'
        )
    if str(scanner_worker.get('user', '')) not in {'0', '0:0'}:
        failures.append('scanner_worker must start the bounded capability handoff as uid 0')
    if scanner_worker.get('network_mode') != 'service:scanner_egress':
        failures.append('scanner_worker does not share the scanner_egress network namespace')
    if 'scanner-worker-entrypoint.sh' not in _command_text(scanner_worker):
        failures.append('scanner_worker does not use the audited non-root capability handoff launcher')

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

    backup = services.get('backup', {})
    if backup:
        if str(backup.get('user', '')).strip() in {'', '0', '0:0', 'root'}:
            failures.append('backup service must run as a non-root uid/gid')
        environment = backup.get('environment') or {}
        if str(environment.get('AEGIS_BACKUP_KEEP_LOCAL_PLAINTEXT', '')).strip().lower() not in {'false', '0', 'no', 'off'}:
            failures.append('backup service must delete local plaintext after remote commit')
        if str(environment.get('AEGIS_BACKUP_REQUIRE_VERSIONING', '')).strip().lower() not in _TRUTHY:
            failures.append('backup service must require remote bucket versioning')
        if not str(environment.get('AEGIS_BACKUP_S3_ENDPOINT', '')).strip():
            failures.append('backup service is missing AEGIS_BACKUP_S3_ENDPOINT')
        networks = set((backup.get('networks') or {}).keys()) if isinstance(backup.get('networks'), dict) else set(backup.get('networks') or [])
        if networks != {'backup_db', 'backup_egress'}:
            failures.append('backup service must attach only to backup_db and backup_egress networks')
        model_networks = model.get('networks') or {}
        if (model_networks.get('backup_db') or {}).get('internal') is not True:
            failures.append('backup_db network must be internal')
        if (model_networks.get('backup_egress') or {}).get('internal') is True:
            failures.append('backup_egress network must permit remote object-storage egress')
        postgres_networks = services.get('postgres', {}).get('networks') or {}
        postgres_network_names = set(postgres_networks.keys()) if isinstance(postgres_networks, dict) else set(postgres_networks)
        if 'backup_db' not in postgres_network_names:
            failures.append('postgres service must join the isolated backup_db network')
        secret_targets = set()
        for volume in backup.get('volumes') or []:
            if isinstance(volume, dict):
                if str(volume.get('type') or '') == 'bind' and volume.get('read_only') is True:
                    secret_targets.add(str(volume.get('target') or ''))
        if secret_targets != _BACKUP_SECRET_TARGETS:
            failures.append('backup service must mount exactly the two audited read-only secret files')

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('compose_json', type=Path)
    args = parser.parse_args()
    model = json.loads(args.compose_json.read_text(encoding='utf-8'))
    failures = validate(model)
    print(json.dumps({'policy': 'production-compose-v4', 'failures': failures}, indent=2))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
