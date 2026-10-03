"""Verify an embedded Burp producer in a fully retired scanner image offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import secrets
import subprocess
import uuid

MODULES = (
    'fastapi_app/services/burp_mcp_transport.py',
    'fastapi_app/services/burp_http_probe.py',
    'fastapi_app/tasks/burp_mcp.py',
    'fastapi_app/celery_app.py',
    'scripts/burp_mcp_sse_probe.py',
    'requirements.txt',
)

IMAGE_CHECK = '''
import hashlib,importlib.util,importlib.metadata,json,os,pathlib,shutil,sys
expected=json.load(sys.stdin)
actual={name:hashlib.sha256((pathlib.Path('/app')/name).read_bytes()).hexdigest() for name in expected}
assert actual==expected, 'Embedded source differs from exact checkout'
retired=['nmap','nping','ncat','ndiff','masscan','nuclei','semgrep','pysemgrep','amass','aegis-amass-runtime','subfinder','dnsenum','fierce']
assert all(shutil.which(name) is None for name in retired), 'Retired executable remains reachable'
assert importlib.util.find_spec('semgrep') is None, 'Retired Python package remains importable'
assert not pathlib.Path('/opt/nuclei-templates').exists()
assert not pathlib.Path('/app/.env').exists()
from fastapi_app.celery_app import celery_app,SCANNER_QUEUE,SCANNER_TASK_ROUTES
from fastapi_app.tasks.burp_mcp import run_burp_mcp_probe
from celery import current_app
assert current_app._get_current_object() is celery_app
assert run_burp_mcp_probe.app is celery_app
assert celery_app.main=='aegisscan'
assert SCANNER_QUEUE=='scanners'
assert SCANNER_TASK_ROUTES[run_burp_mcp_probe.name]=={'queue':'scanners'}
assert celery_app.amqp.router.route({},run_burp_mcp_probe.name)['queue'].name=='scanners'
assert run_burp_mcp_probe.max_retries==0
assert os.getuid()==10001
print(json.dumps({'module_hashes':actual,'retired_commands_absent':retired,
                 'semgrep_package_absent':True,'nuclei_templates_absent':True,
                 'image_env_file_absent':True,'canonical_app':'aegisscan',
                 'task_app_identity_matches':True,'resolved_queue':'scanners',
                 'max_retries':0,'uid':os.getuid(),
                 'python_version':sys.version.split()[0],
                 'httpx_version':importlib.metadata.version('httpx')}))
'''


def docker(args: list[str], *, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(['docker', *args], input=stdin, text=True,
                          capture_output=True, timeout=90)


def inspect(kind: str, reference: str) -> dict:
    result = docker([kind, 'inspect', reference])
    if result.returncode:
        raise RuntimeError(f'Cannot inspect {kind}')
    return json.loads(result.stdout)[0]


def verify(image: str, head: str, source_root: pathlib.Path) -> dict:
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise ValueError('Expected an exact commit SHA')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9./:@_-]{0,255}', image):
        raise ValueError('Invalid image reference')
    artifact = inspect('image', image)
    if (artifact['Config'].get('Labels') or {}).get('org.opencontainers.image.revision') != head:
        raise RuntimeError('Image revision differs from exact checkout')
    if artifact['Config'].get('User') != '10001:10001':
        raise RuntimeError('Scanner image must use UID/GID 10001')
    expected = {name: hashlib.sha256((source_root / name).read_bytes()).hexdigest()
                for name in MODULES}
    name = 'aegis-burp-release-check-' + uuid.uuid4().hex[:12]
    command = ['run', '-i', '--name', name, '--network', 'none',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--memory', '512m', '--cpus', '1', '--pids-limit', '128',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m',
               '-e', 'PYTHONPATH=/app', '-e', 'DEBUG=False',
               '-e', 'SECRET_KEY=' + secrets.token_urlsafe(48),
               '-e', 'JWT_SECRET_KEY=' + secrets.token_urlsafe(48),
               '-e', 'DATABASE_URL=postgresql://p2-import:p2-import@127.0.0.1:9/p2-import',
               '--entrypoint', 'python', artifact['Id'], '-c', IMAGE_CHECK]
    try:
        result = docker(command, stdin=json.dumps(expected))
        if result.returncode:
            # Never include the command: it contains disposable startup keys.
            raise RuntimeError('Offline source, retirement or producer verification failed')
        container = inspect('container', name)
        if container['Mounts']:
            raise RuntimeError('Verification must have no source mounts')
        if container['HostConfig']['NetworkMode'] != 'none':
            raise RuntimeError('Offline verification must have no network')
        if not container['HostConfig']['ReadonlyRootfs']:
            raise RuntimeError('Verification root filesystem must be read-only')
        proof = json.loads(result.stdout)
        return {'schema': 'aegis.burp-scanner-image-check.v1', 'head': head,
                'scope': 'embedded_source_retirement_and_producer',
                'image_id': artifact['Id'], 'image_size_bytes': artifact['Size'],
                'source_mounts': [], 'network_mode': 'none', 'offline_checks': proof,
                'live_burp_tested': False, 'lab_solved': False,
                'production_provider_approved': False}
    finally:
        cleanup = docker(['rm', '-f', '-v', name])
        if cleanup.returncode and 'No such container' not in cleanup.stderr:
            raise RuntimeError('Could not remove the isolated verification container')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--source-root', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        proof = verify(args.image, args.expected_head, args.source_root)
    except RuntimeError as exc:
        print('BURP_SCANNER_IMAGE_OFFLINE_CHECKS=FAIL: ' + str(exc))
        return 1
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        print('BURP_SCANNER_IMAGE_OFFLINE_CHECKS=FAIL')
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + '\n')
    print('BURP_SCANNER_IMAGE_OFFLINE_CHECKS=PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
