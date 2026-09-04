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
        'celery_worker': hardened_service(environment={'AUTHORIZED_SCAN_TARGETS':'security.example'}),
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
    assert not any('scan_target' in item for item in MODULE.validate(model))


def test_backend_images_drop_root_before_runtime():
    root = Path(__file__).parents[1] / 'aegis-platform/backend'
    for name in ('Dockerfile.django', 'Dockerfile.fastapi'):
        dockerfile = (root / name).read_text(encoding='utf-8')
        assert 'USER 10001:10001' in dockerfile
        assert dockerfile.rfind('USER 10001:10001') < dockerfile.rfind('CMD ')
