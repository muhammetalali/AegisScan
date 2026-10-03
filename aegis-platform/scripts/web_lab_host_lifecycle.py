"""Trusted host-only Web Lab lifecycle orchestration.

This operator tool owns Docker creation/removal. Application workers never
receive a Docker socket. Database lifecycle transitions are delegated to the
internal Django management authority and are fail-closed/idempotent.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

CONTAINER_RE = re.compile(r'^aegis-web-lab-[0-9a-f]{12}$')
IMAGE_RE = re.compile(r'^sha256:[0-9a-f]{64}$')
CONTROL_RE = re.compile(r'^(?:aegis-django|aegis-burp-p5-control|aegis-burp-p6-control)$')
NETWORK_RE = re.compile(r'^(?:aegis-burp-p2-egress|aegis-web-lab-egress-[0-9a-f]{12})$')
IDEM_RE = re.compile(r'^[A-Za-z0-9._:-]{1,96}$')


class LifecycleHostError(RuntimeError):
    pass


def _run(args, *, input_text=None, check=True):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, timeout=120,
    )
    if check and result.returncode:
        message = (result.stderr or result.stdout or '').strip()
        raise LifecycleHostError(f'Command failed ({result.returncode}): {message[:1200]}')
    return result


def _docker_json(args, *, allow_missing=False):
    result = _run(['docker', *args], check=False)
    if result.returncode:
        if allow_missing:
            return None
        raise LifecycleHostError((result.stderr or result.stdout or 'Docker inspection failed').strip())
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise LifecycleHostError('Docker returned malformed JSON.') from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise LifecycleHostError('Docker inspection returned an unexpected object.')
    return payload[0]


def _validate_common(args):
    if not CONTROL_RE.fullmatch(args.control_container):
        raise LifecycleHostError('Unapproved lifecycle control container.')
    control = _docker_json(['inspect', args.control_container])
    if not control.get('State', {}).get('Running'):
        raise LifecycleHostError('Lifecycle control container is not running.')
    if not isinstance(args.control_workdir, str) or not args.control_workdir.startswith('/'):
        raise LifecycleHostError('Control workdir must be an absolute container path.')


def _management(args, action, values, *, stdin=None):
    command = [
        'docker', 'exec', '-i', '-w', args.control_workdir,
        args.control_container, 'python', 'manage.py', 'web_lab_lifecycle', action,
    ]
    for key, value in values:
        if value is None:
            continue
        command.extend(['--' + key.replace('_', '-'), str(value)])
    result = _run(command, input_text=stdin)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise LifecycleHostError('Lifecycle authority returned no result.')
    try:
        payload = json.loads(lines[-1])
    except ValueError as exc:
        raise LifecycleHostError('Lifecycle authority returned malformed JSON.') from exc
    if not isinstance(payload, (dict, list)):
        raise LifecycleHostError('Lifecycle authority returned an unexpected payload.')
    return payload


def _container_record(name):
    if not isinstance(name, str) or not CONTAINER_RE.fullmatch(name):
        raise LifecycleHostError('Registered Web Lab container name is invalid.')
    return _docker_json(['inspect', name], allow_missing=True)


def _assert_registered_identity(row, record):
    if record is None:
        return
    actual_name = str(record.get('Name') or '').lstrip('/')
    actual_id = str(record.get('Id') or '')
    if actual_name != row['container_name'] or actual_id != row['container_id']:
        raise LifecycleHostError('Container name was reused or identity drifted; refusing host mutation.')


def _remove_registered(row):
    record = _container_record(row['container_name'])
    if record is None:
        return False
    _assert_registered_identity(row, record)
    _run(['docker', 'rm', '-f', row['container_name']])
    return True


def _wait_target(container, timeout=20):
    deadline = time.monotonic() + timeout
    code = (
        "import urllib.request;"
        "r=urllib.request.build_opener(urllib.request.ProxyHandler({}))."
        "open('http://127.0.0.1:18081/health',timeout=2);"
        "assert r.status==200"
    )
    while time.monotonic() < deadline:
        record = _container_record(container)
        if record is None or not record.get('State', {}).get('Running'):
            break
        result = _run(['docker', 'exec', container, 'python', '-c', code], check=False)
        if result.returncode == 0:
            return
        time.sleep(0.5)
    record = _container_record(container)
    state = record.get('State', {}) if record else {}
    raise LifecycleHostError(
        f'Web Lab target did not become ready: status={state.get("Status")} exit={state.get("ExitCode")}')


def _validate_provision_inputs(args):
    if not IMAGE_RE.fullmatch(args.image_id):
        raise LifecycleHostError('Fixture image must be an immutable sha256 image ID.')
    if not NETWORK_RE.fullmatch(args.network_container):
        raise LifecycleHostError('Unapproved Web Lab network namespace container.')
    if args.variant not in {'vulnerable', 'patched'}:
        raise LifecycleHostError('Unsupported Web Lab variant.')
    if not IDEM_RE.fullmatch(args.idempotency_key):
        raise LifecycleHostError('Invalid host lifecycle idempotency key.')
    if not Path(args.fixture_source).is_file():
        raise LifecycleHostError('Trusted fixture source file is unavailable.')
    image = _docker_json(['image', 'inspect', args.image_id])
    if image.get('Id') != args.image_id:
        raise LifecycleHostError('Fixture image identity changed.')
    network = _docker_json(['inspect', args.network_container])
    if not network.get('State', {}).get('Running'):
        raise LifecycleHostError('Web Lab network namespace container is not running.')


def provision(args, *, supersedes=None, key=None):
    _validate_common(args)
    _validate_provision_inputs(args)
    instance_ref = str(uuid.uuid4())
    container_name = 'aegis-web-lab-' + uuid.uuid4().hex[:12]
    idem = key or args.idempotency_key
    if not IDEM_RE.fullmatch(idem):
        raise LifecycleHostError('Invalid provision idempotency key.')
    created = False
    try:
        result = _run([
            'docker', 'create', '--name', container_name,
            '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true',
            '--user', '10001:10001', '--restart', 'no',
            '--memory', '256m', '--cpus', '1', '--pids-limit', '128',
            '--network', 'container:' + args.network_container,
            '--label', 'aegis.web-lab.lifecycle=v1',
            '--env', 'AEGIS_LAB_INSTANCE_REF=' + instance_ref,
            '--env', 'AEGIS_LAB_VARIANT=' + args.variant,
            args.image_id,
        ])
        container_id = result.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', container_id):
            raise LifecycleHostError('Docker returned an invalid container identity.')
        created = True
        _run(['docker', 'start', container_name])
        _wait_target(container_name)

        with tempfile.TemporaryDirectory(prefix='aegis-web-lab-inspect-') as tmp:
            output = Path(tmp) / 'inspection.json'
            inspector = Path(__file__).with_name('inspect_web_lab_runtime.py')
            inspected = _run([
                sys.executable, str(inspector), '--container', container_name,
                '--expected-image-id', args.image_id,
                '--fixture-source', args.fixture_source, '--output', str(output),
            ])
            if 'WEB_LAB_RUNTIME_INSPECTION=PASS' not in inspected.stdout:
                raise LifecycleHostError('Trusted runtime inspection did not report PASS.')
            inspection_text = output.read_text()
        row = _management(args, 'provision', [
            ('actor_id', args.actor_id), ('asset_id', args.asset_id),
            ('lab_definition_id', args.lab_definition_id),
            ('container_name', container_name), ('ttl_seconds', args.ttl_seconds),
            ('idempotency_key', idem), ('supersedes_instance_id', supersedes),
        ], stdin=inspection_text)
        if row.get('container_id') != container_id or row.get('container_name') != container_name:
            raise LifecycleHostError('Committed lifecycle identity differs from the created container.')
        return {'action': 'provision', 'status': 'ready', 'instance': row}
    except Exception:
        if created:
            record = _container_record(container_name)
            if record is not None and str(record.get('Id') or '') == locals().get('container_id', ''):
                _run(['docker', 'rm', '-f', container_name], check=False)
        raise


def _host_status(args, instance_id):
    proof = _management(args, 'verify-chain', [
        ('actor_id', args.actor_id), ('instance_id', instance_id),
    ])
    if proof.get('status') != 'pass':
        raise LifecycleHostError('Lifecycle hash-chain verification did not pass.')
    return _management(args, 'host-status', [
        ('actor_id', args.actor_id), ('instance_id', instance_id),
    ])


def reset(args):
    _validate_common(args)
    if not IDEM_RE.fullmatch(args.idempotency_key):
        raise LifecycleHostError('Invalid reset idempotency key.')
    previous = _host_status(args, args.instance_id)
    _remove_registered(previous)
    cleaned = _management(args, 'cleanup', [
        ('actor_id', args.actor_id), ('instance_id', args.instance_id),
        ('observed_container_id', previous['container_id']), ('reason', 'reset'),
        ('idempotency_key', args.idempotency_key + ':cleanup'),
    ])
    result = provision(args, supersedes=args.instance_id, key=args.idempotency_key + ':provision')
    return {'action': 'reset', 'cleaned': cleaned, 'replacement': result['instance']}


def expire(args, instance_id=None, key=None):
    _validate_common(args)
    instance_id = instance_id or args.instance_id
    idem = key or args.idempotency_key
    previous = _host_status(args, instance_id)
    expired = _management(args, 'expire', [
        ('actor_id', args.actor_id), ('instance_id', instance_id),
        ('idempotency_key', idem + ':expire'),
    ])
    _remove_registered(previous)
    cleaned = _management(args, 'cleanup', [
        ('actor_id', args.actor_id), ('instance_id', instance_id),
        ('observed_container_id', previous['container_id']), ('reason', 'expired'),
        ('idempotency_key', idem + ':cleanup'),
    ])
    return {'action': 'expire', 'expired': expired, 'cleaned': cleaned}


def cleanup(args):
    _validate_common(args)
    previous = _host_status(args, args.instance_id)
    _remove_registered(previous)
    cleaned = _management(args, 'cleanup', [
        ('actor_id', args.actor_id), ('instance_id', args.instance_id),
        ('observed_container_id', previous['container_id']), ('reason', 'manual'),
        ('idempotency_key', args.idempotency_key),
    ])
    return {'action': 'cleanup', 'cleaned': cleaned}


def status(args):
    _validate_common(args)
    row = _host_status(args, args.instance_id)
    record = _container_record(row['container_name'])
    _assert_registered_identity(row, record)
    return {
        'action': 'status', 'instance': row,
        'runtime': {
            'container_present': record is not None,
            'container_running': bool(record and record.get('State', {}).get('Running')),
            'identity_matches': record is None or str(record.get('Id') or '') == row['container_id'],
        },
    }


def reconcile(args):
    _validate_common(args)
    row = _host_status(args, args.instance_id)
    record = _container_record(row['container_name'])
    _assert_registered_identity(row, record)
    if row['status'] == 'cleaned':
        if record is not None:
            _remove_registered(row)
        return {'action': 'reconcile', 'status': 'already_cleaned', 'instance': row}
    if record is not None and record.get('State', {}).get('Running'):
        return {'action': 'reconcile', 'status': 'healthy', 'instance': row}
    if record is not None:
        _remove_registered(row)
    if row['status'] == 'expired':
        cleaned = _management(args, 'cleanup', [
            ('actor_id', args.actor_id), ('instance_id', args.instance_id),
            ('observed_container_id', row['container_id']), ('reason', 'expired'),
            ('idempotency_key', args.idempotency_key + ':cleanup'),
        ])
        return {'action': 'reconcile', 'status': 'expired_cleaned', 'instance': cleaned}
    if row['status'] == 'ready':
        failed = _management(args, 'fail', [
            ('actor_id', args.actor_id), ('instance_id', args.instance_id),
            ('observed_container_id', row['container_id']), ('failure_code', 'runtime.not_running'),
            ('idempotency_key', args.idempotency_key + ':fail'),
        ])
        cleaned = _management(args, 'cleanup', [
            ('actor_id', args.actor_id), ('instance_id', args.instance_id),
            ('observed_container_id', row['container_id']), ('reason', 'failed'),
            ('idempotency_key', args.idempotency_key + ':cleanup'),
        ])
        return {'action': 'reconcile', 'status': 'failed_cleaned', 'failed': failed, 'cleaned': cleaned}
    if row['status'] == 'failed':
        cleaned = _management(args, 'cleanup', [
            ('actor_id', args.actor_id), ('instance_id', args.instance_id),
            ('observed_container_id', row['container_id']), ('reason', 'failed'),
            ('idempotency_key', args.idempotency_key + ':cleanup'),
        ])
        return {'action': 'reconcile', 'status': 'failed_cleaned', 'cleaned': cleaned}
    raise LifecycleHostError('Unsupported lifecycle state during reconciliation.')


def reap(args):
    _validate_common(args)
    due = _management(args, 'due', [
        ('actor_id', args.actor_id), ('project_id', args.project_id), ('limit', args.limit),
    ])
    results = []
    for row in due:
        key = 'p5-reap-' + row['lifecycle_ref']
        proxy = argparse.Namespace(**vars(args))
        proxy.instance_id = row['lifecycle_ref']
        proxy.idempotency_key = key
        results.append(expire(proxy, instance_id=row['lifecycle_ref'], key=key))
    return {'action': 'reap', 'due_count': len(due), 'results': results}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--control-container', required=True)
    p.add_argument('--control-workdir', default='/app')
    p.add_argument('--actor-id', required=True)
    sub = p.add_subparsers(dest='action', required=True)

    def idem(sp):
        sp.add_argument('--idempotency-key', required=True)

    provision_p = sub.add_parser('provision')
    provision_p.add_argument('--asset-id', required=True)
    provision_p.add_argument('--lab-definition-id', default='bac-orders-v1')
    provision_p.add_argument('--variant', choices=['vulnerable', 'patched'], required=True)
    provision_p.add_argument('--ttl-seconds', type=int, default=1800)
    provision_p.add_argument('--image-id', required=True)
    provision_p.add_argument('--fixture-source', required=True)
    provision_p.add_argument('--network-container', required=True)
    idem(provision_p)

    reset_p = sub.add_parser('reset')
    reset_p.add_argument('--instance-id', required=True)
    reset_p.add_argument('--asset-id', required=True)
    reset_p.add_argument('--lab-definition-id', default='bac-orders-v1')
    reset_p.add_argument('--variant', choices=['vulnerable', 'patched'], required=True)
    reset_p.add_argument('--ttl-seconds', type=int, default=1800)
    reset_p.add_argument('--image-id', required=True)
    reset_p.add_argument('--fixture-source', required=True)
    reset_p.add_argument('--network-container', required=True)
    idem(reset_p)

    for action in ('expire', 'cleanup', 'reconcile'):
        sp = sub.add_parser(action)
        sp.add_argument('--instance-id', required=True)
        idem(sp)

    status_p = sub.add_parser('status')
    status_p.add_argument('--instance-id', required=True)

    reap_p = sub.add_parser('reap')
    reap_p.add_argument('--project-id', required=True)
    reap_p.add_argument('--limit', type=int, default=100)
    return p


def main():
    args = parser().parse_args()
    try:
        handler = {
            'provision': provision, 'reset': reset, 'expire': expire,
            'cleanup': cleanup, 'status': status, 'reconcile': reconcile, 'reap': reap,
        }[args.action]
        result = handler(args)
    except LifecycleHostError as exc:
        print(json.dumps({'status': 'error', 'error': str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
