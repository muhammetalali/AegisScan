from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


PATH = Path(__file__).parents[1] / 'aegis-platform/scripts/production_policy_gate.py'
SPEC = spec_from_file_location('production_policy_gate', PATH)
MODULE = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def hardened_service(**extra):
    return {'read_only': True, 'security_opt': ['no-new-privileges:true'], 'cap_drop': ['ALL'], **extra}


def valid_model():
    return {'services': {
        'nginx': {'ports': [{'published': '443', 'target': 443}]},
        'postgres': {'environment': {'POSTGRES_PASSWORD': 'non-default-secret'}},
        'redis': {}, 'frontend': {},
        'django': hardened_service(volumes=[{'type':'volume','source':'media_data'}]),
        'fastapi': hardened_service(environment={'AUTHORIZED_SCAN_TARGETS':'security.example'}),
        'celery_worker': hardened_service(
            environment={'AUTHORIZED_SCAN_TARGETS':'security.example'},
            command='celery -A fastapi_app.celery_app worker -Q default',
        ),
        'scanner_worker': hardened_service(
            environment={'AUTHORIZED_SCAN_TARGETS':'security.example'},
            command='celery -A fastapi_app.celery_app worker -Q scanners',
            network_mode='service:scanner_egress',
            cap_add=['NET_RAW'],
        ),
        'scanner_egress': hardened_service(
            cap_add=['NET_ADMIN'],
            environment={'SCANNER_EGRESS_PRIVATE_TARGETS':''},
        ),
        'celery_beat': hardened_service(environment={'AUTHORIZED_SCAN_TARGETS':'security.example'}),
    }}


def test_accepts_hardened_resolved_production_model():
    assert MODULE.validate(valid_model()) == []


def test_rejects_internal_ports_bind_mounts_fixture_scope_and_ci_target():
    model = valid_model()
    model['services']['scan_target'] = {}
    model['services']['postgres']['ports'] = [{'published':'5432','target':5432}]
    model['services']['django']['volumes'] = [{'type':'bind','source':'./backend'}]
    model['services']['fastapi']['environment']['AUTHORIZED_SCAN_TARGETS'] = 'aegis-scan-target'
    failures = MODULE.validate(model)
    assert any('scan_target' in item for item in failures)
    assert any('postgres publishes' in item for item in failures)
    assert any('bind mount' in item for item in failures)
    assert any('CI fixture' in item for item in failures)

    model['services']['scan_target'] = {'profiles': ['ci-only']}
    assert not any('scan_target is active' in item for item in MODULE.validate(model))


def test_rejects_scanner_privilege_or_namespace_regressions():
    model = valid_model()
    model['services']['celery_worker']['cap_add'] = ['NET_RAW']
    model['services']['scanner_worker']['cap_add'] = ['NET_RAW', 'NET_ADMIN']
    model['services']['scanner_worker']['network_mode'] = 'default'
    model['services']['scanner_egress']['cap_add'] = ['NET_RAW']
    model['services']['scanner_egress']['environment']['SCANNER_EGRESS_PRIVATE_TARGETS'] = 'aegis-scan-target'
    failures = MODULE.validate(model)
    assert any('general celery_worker retains' in item for item in failures)
    assert any('scanner_worker must not receive NET_ADMIN' in item for item in failures)
    assert any('does not share the scanner_egress' in item for item in failures)
    assert any('scanner_egress lacks NET_ADMIN' in item for item in failures)
    assert any('scanner_egress should not receive NET_RAW' in item for item in failures)
    assert any('CI scan target' in item for item in failures)


def test_rejects_queue_routing_regression():
    model = valid_model()
    model['services']['celery_worker']['command'] = 'celery -A fastapi_app.celery_app worker'
    model['services']['scanner_worker']['command'] = 'celery -A fastapi_app.celery_app worker'
    failures = MODULE.validate(model)
    assert any('default queue' in item for item in failures)
    assert any('scanners queue' in item for item in failures)


def test_backend_images_drop_root_before_runtime():
    root = Path(__file__).parents[1] / 'aegis-platform/backend'
    for name in ('Dockerfile.django', 'Dockerfile.fastapi'):
        dockerfile = (root / name).read_text(encoding='utf-8')
        assert 'USER 10001:10001' in dockerfile
        assert dockerfile.rfind('USER 10001:10001') < dockerfile.rfind('CMD ')


def test_scanner_file_capabilities_match_runtime_least_privilege_boundary():
    dockerfile = (
        Path(__file__).parents[1] / 'aegis-platform/backend/Dockerfile.django'
    ).read_text(encoding='utf-8')
    assert 'cap_net_admin' not in dockerfile
    assert dockerfile.count('setcap cap_net_raw+eip') == 2
    assert dockerfile.count("grep -q 'cap_net_raw=eip'") == 2


def test_scanner_egress_image_installs_kernel_policy_tooling():
    root = Path(__file__).parents[1] / 'aegis-platform/docker/scanner-egress'
    dockerfile = (root / 'Dockerfile').read_text(encoding='utf-8')
    entrypoint = (root / 'entrypoint.sh').read_text(encoding='utf-8')
    assert 'nftables' in dockerfile
    assert 'table netdev' in entrypoint
    assert 'hook egress' in entrypoint
    assert '169.254.0.0/16' in entrypoint
