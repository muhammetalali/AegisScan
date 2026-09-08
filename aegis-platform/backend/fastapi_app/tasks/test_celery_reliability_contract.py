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
