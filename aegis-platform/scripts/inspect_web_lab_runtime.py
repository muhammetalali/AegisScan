"""Trusted host-only inspection of a sealed BAC fixture; no signing key here.

Run with a trusted expected image ID from the fixture build. Register the
result through the internal provisioner using the existing evidence HMAC key.
Never expose this inspector or the signing function as an HTTP endpoint.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

COMMAND = ['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', '18081', '--no-access-log']


def docker(args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Trusted fixture inspection failed: ' + str(result.returncode))
    return result.stdout


def inspect_runtime(container, expected_image, expected_revision):
    if (not re.fullmatch(r'aegis-burp-p4-target-[a-z0-9-]{1,40}', container)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', expected_image)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_revision)):
        raise ValueError('Use a dedicated P4 target and immutable image/source IDs')
    record = json.loads(docker(['inspect', container]))[0]
    config, host = record['Config'], record['HostConfig']
    if (not record['State']['Running'] or record['Image'] != expected_image
            or not host['ReadonlyRootfs'] or host['Privileged'] or record['Mounts']
            or config['User'] != '10001:10001' or config['WorkingDir'] != '/fixture'
            or config['Entrypoint'] != ['python'] or config['Cmd'] != COMMAND
            or host.get('CapAdd') or host.get('CapDrop') != ['ALL']
            or 'no-new-privileges' not in ','.join(host.get('SecurityOpt') or [])
            or not host['NetworkMode'].startswith('container:') or host.get('PortBindings')):
        raise RuntimeError('Fixture must be the trusted sealed image with no source mounts or exposed ports')
    env = dict(item.split('=', 1) for item in config['Env'])
    instance = str(uuid.UUID(env['AEGIS_LAB_INSTANCE_REF']))
    variant = env['AEGIS_LAB_VARIANT']
    if variant not in {'vulnerable', 'patched'} or env.get('PYTHONPATH') != '/fixture':
        raise RuntimeError('Unexpected fixture process configuration')
    nonce = 'inspector-' + uuid.uuid4().hex
    code = ("import hashlib,json,pathlib,urllib.request; "
            "r=urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:18081/__lab__/identity?nonce=" + nonce + "',timeout=5); "
            "v=json.loads(r.read(8192)); "
            "print(json.dumps({'revision':hashlib.sha256(pathlib.Path('/fixture/app.py').read_bytes()).hexdigest(),'identity':v}))")
    observation = json.loads(docker(['exec', container, 'python', '-c', code]))
    identity = observation['identity']
    if (set(identity) != {'instance_ref', 'process_ref', 'fixture_revision', 'variant', 'nonce'}
            or observation['revision'] != expected_revision or identity['fixture_revision'] != expected_revision
            or identity['instance_ref'] != instance or identity['variant'] != variant or identity['nonce'] != nonce):
        raise RuntimeError('Live process does not match independently inspected sealed fixture')
    process = str(uuid.UUID(identity['process_ref']))
    return {'target': 'http://127.0.0.1:18081', 'instance_ref': instance, 'process_ref': process,
            'fixture_revision': expected_revision, 'variant': variant,
            'image_id': expected_image, 'container_id': record['Id'], 'inspected_at': time.time()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--expected-image-id', required=True)
    parser.add_argument('--fixture-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    expected = hashlib.sha256(args.fixture_source.read_bytes()).hexdigest()
    result = inspect_runtime(args.container, args.expected_image_id, expected)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('WEB_LAB_RUNTIME_INSPECTION=PASS')


if __name__ == '__main__':
    main()
