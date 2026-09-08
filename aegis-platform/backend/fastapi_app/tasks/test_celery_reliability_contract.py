from __future__ import annotations

import subprocess
import sys
from textwrap import dedent

from fastapi_app.celery_app import SCANNER_QUEUE, SCANNER_TASK_ROUTES, celery_app


def test_celery_worker_loss_redelivery_contract():
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.task_track_started is True
    assert celery_app.conf.worker_prefetch_multiplier == 1


def test_scanner_tasks_are_routed_to_dedicated_queue():
    expected = {
        'fastapi_app.tasks.security_scan.run_nmap_scan',
        'fastapi_app.tasks.security_scan.run_nuclei_scan',
        'fastapi_app.tasks.security_scan.validate_finding_task',
        'fastapi_app.tasks.advanced_scans.run_masscan_scan',
        'fastapi_app.tasks.advanced_scans.run_semgrep_scan',
        'fastapi_app.tasks.finding_validation.validate_finding_e2e',
        'fastapi_app.tasks.nmap_finding_validation.validate_nmap_finding_e2e',
    }
    assert set(SCANNER_TASK_ROUTES) == expected
    assert SCANNER_QUEUE == 'scanners'
    assert celery_app.conf.task_default_queue == 'default'
    for task_name in expected:
        assert celery_app.conf.task_routes[task_name]['queue'] == 'scanners'


def test_scanner_shared_task_bootstraps_canonical_producer_app():
    """Prove a clean web-style import cannot publish scanner work to a stray queue.

    This must run in a fresh interpreter. Importing ``celery_app`` in this pytest
    process before a task module would otherwise hide the exact production import
    ordering regression that the execution-plane queue split exposed.
    """
    probe = dedent(
        """
        from celery import current_app
        from fastapi_app.tasks.security_scan import run_nmap_scan

        assert current_app.main == 'aegisscan', current_app.main
        assert run_nmap_scan.app.main == 'aegisscan', run_nmap_scan.app.main
        route = run_nmap_scan.app.conf.task_routes[
            'fastapi_app.tasks.security_scan.run_nmap_scan'
        ]
        assert route['queue'] == 'scanners', route
        assert run_nmap_scan.app.conf.task_default_queue == 'default'
        print('SCANNER_PRODUCER_BINDING=PASS')
        """
    )
    result = subprocess.run(
        [sys.executable, '-c', probe],
        check=True,
        capture_output=True,
        text=True,
    )
    assert 'SCANNER_PRODUCER_BINDING=PASS' in result.stdout
