"""Exercise the workflow's real shell expansion at the Docker boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


WORKFLOW = Path(__file__).parents[1] / '.github/workflows/kubernetes-security-reality.yml'


def analyzer_command():
    workflow = yaml.safe_load(WORKFLOW.read_text())
    step = next(step for step in workflow['jobs']['kubernetes-security-reality']['steps']
                if step.get('name') == 'Run packaged analyzer against real cluster')
    # Run the actual multiline Docker command, with only output redirection removed.
    return step['run'].split('docker run', 1)[1].split(' > /tmp/kubernetes-container-result.json', 1)[0]


@pytest.fixture
def docker_boundary(tmp_path):
    docker = tmp_path / 'docker'
    docker.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=f'{tmp_path}:{os.environ["PATH"]}',
               AEGIS_KUBE_TARGET='https://127.0.0.1:41287')
    env.pop('AUTHORIZED_SCAN_TARGETS', None)
    return env


def test_packaged_analyzer_receives_explicit_restricted_scope(docker_boundary):
    docker_boundary['AUTHORIZED_SCAN_TARGETS'] = '127.0.0.1/32'
    result = subprocess.run(['bash', '-eu', '-c', 'docker run' + analyzer_command()],
                            env=docker_boundary, capture_output=True, text=True, check=True)
    args = json.loads(result.stdout)
    assert '--env' in args
    assert args[args.index('--env') + 1] == 'AUTHORIZED_SCAN_TARGETS=127.0.0.1/32'
    assert args[-3:] == ['https://127.0.0.1:41287', '--kubeconfig', '/tmp/aegis-kubeconfig']
    assert '/tmp/aegis-container.kubeconfig:/tmp/aegis-kubeconfig:ro' in args


@pytest.mark.parametrize('scope', [None, ''])
def test_packaged_analyzer_missing_scope_fails_before_docker(docker_boundary, scope):
    if scope is not None:
        docker_boundary['AUTHORIZED_SCAN_TARGETS'] = scope
    result = subprocess.run(['bash', '-eu', '-c', 'docker run' + analyzer_command()],
                            env=docker_boundary, capture_output=True, text=True)
    assert result.returncode != 0
    assert not result.stdout
    assert 'AUTHORIZED_SCAN_TARGETS' in result.stderr


def test_cleanup_removes_container_owned_kubeconfig_with_required_privilege():
    workflow = yaml.safe_load(WORKFLOW.read_text())
    cleanup = next(step for step in workflow['jobs']['kubernetes-security-reality']['steps']
                   if step.get('name') == 'Cleanup real worker and cluster')
    assert cleanup['if'] == 'always()'
    assert 'sudo rm -f -- /tmp/aegis-container.kubeconfig' in cleanup['run'].splitlines()


@pytest.mark.parametrize('reply,expected', [
    ({'kubernetes-reality@ci': {'ok': 'pong'}}, 0),
    ({}, 1),
    ({'other-worker@ci': {'ok': 'pong'}}, 1),
    ({'kubernetes-reality@ci': {'error': 'unavailable'}}, 1),
])
def test_worker_readiness_uses_complete_celery_reply(tmp_path, reply, expected):
    # Exercise the installed Celery CLI and its real output handling. Only the
    # broker response is replaced; this is not a live-worker integration test.
    (tmp_path / 'celery_app.py').write_text(
        'from celery import Celery\ncelery_app = Celery("probe", broker="memory://")\n'
    )
    executable = tmp_path / 'celery'
    executable.write_text(
        f'#!{sys.executable}\n'
        'from celery.bin.celery import celery\n'
        'from unittest.mock import patch\n'
        'import time\n'
        'def response(self, command, **kwargs):\n'
        f'    replies = {reply!r}\n'
        '    if self.callback and replies:\n'
        '        self.callback(replies)\n'
        '        time.sleep(0.1)\n'
        '    return replies\n'
        'with patch("celery.app.control.Inspect._request", response):\n'
        '    celery.main()\n'
    )
    executable.chmod(0o755)
    workflow = yaml.safe_load(WORKFLOW.read_text())
    job = workflow['jobs']['kubernetes-security-reality']
    step = next(s for s in job['steps'] if s.get('name') == 'Start real scanner Celery worker')
    condition = step['run'].split('if celery ', 1)[1].split('; then', 1)[0]
    condition = condition.replace('/tmp/kubernetes-worker-ping', str(tmp_path / 'ping'))
    env = dict(os.environ, PATH=f'{tmp_path}:{Path(sys.executable).parent}:{os.environ["PATH"]}',
               AEGIS_CELERY_NODE='kubernetes-reality@ci')
    result = subprocess.run(['bash', '-euo', 'pipefail', '-c', 'celery ' + condition],
                            env=env, capture_output=True, text=True)
    assert (result.returncode == 0) == (expected == 0), result.stderr
