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


def scanner_handoff_service(**extra):
    return {'read_only': True, 'cap_drop': ['ALL'], **extra}


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
        'scanner_worker': scanner_handoff_service(
            environment={'AUTHORIZED_SCAN_TARGETS':'security.example'},
            command='sh /app/scanner-worker-entrypoint.sh',
            user='0:0',
            network_mode='service:scanner_egress',
            cap_add=['NET_RAW', 'SETUID', 'SETGID', 'SETPCAP'],
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
    model['services']['scanner_worker']['cap_add'] = ['NET_RAW', 'NET_ADMIN', 'SETUID', 'SETGID', 'SETPCAP']
    model['services']['scanner_worker']['network_mode'] = 'default'
    model['services']['scanner_worker']['user'] = '10001:10001'
    model['services']['scanner_worker']['security_opt'] = ['no-new-privileges:true']
    model['services']['scanner_egress']['cap_add'] = ['NET_RAW']
    model['services']['scanner_egress']['environment']['SCANNER_EGRESS_PRIVATE_TARGETS'] = 'aegis-scan-target'
    failures = MODULE.validate(model)
    assert any('general celery_worker retains' in item for item in failures)
    assert any('bootstrap capabilities must be exactly' in item for item in failures)
    assert any('scanner_worker must not receive NET_ADMIN' in item for item in failures)
    assert any('cannot enforce no-new-privileges' in item for item in failures)
    assert any('bounded capability handoff as uid 0' in item for item in failures)
    assert any('does not share the scanner_egress' in item for item in failures)
    assert any('scanner_egress lacks NET_ADMIN' in item for item in failures)
    assert any('scanner_egress should not receive NET_RAW' in item for item in failures)
    assert any('CI scan target' in item for item in failures)


def test_rejects_queue_or_handoff_regression():
    model = valid_model()
    model['services']['celery_worker']['command'] = 'celery -A fastapi_app.celery_app worker'
    model['services']['scanner_worker']['command'] = 'celery -A fastapi_app.celery_app worker -Q scanners'
    failures = MODULE.validate(model)
    assert any('default queue' in item for item in failures)
    assert any('capability handoff launcher' in item for item in failures)


def test_backend_images_drop_root_before_default_runtime():
    root = Path(__file__).parents[1] / 'aegis-platform/backend'
    for name in ('Dockerfile.django', 'Dockerfile.fastapi'):
        dockerfile = (root / name).read_text(encoding='utf-8')
        assert 'USER 10001:10001' in dockerfile
        assert dockerfile.rfind('USER 10001:10001') < dockerfile.rfind('CMD ')


def test_scanner_binaries_do_not_depend_on_file_capability_escalation():
    dockerfile = (
        Path(__file__).parents[1] / 'aegis-platform/backend/Dockerfile.django'
    ).read_text(encoding='utf-8')
    assert 'cap_net_admin' not in dockerfile
    assert 'setcap cap_net_raw' not in dockerfile
    assert 'libpcap0.8' in dockerfile
    assert 'command -v capsh' in dockerfile
    assert 'test -z "$(getcap "$nmap_binary")"' in dockerfile
    assert 'test -z "$(getcap "$masscan_binary")"' in dockerfile


def test_scanner_handoff_ends_nonroot_with_only_net_raw_and_scanners_queue():
    entrypoint = (
        Path(__file__).parents[1] / 'aegis-platform/backend/scanner-worker-entrypoint.sh'
    ).read_text(encoding='utf-8')
    assert '--keep=1' in entrypoint
    assert '--caps=cap_setpcap,cap_setuid,cap_setgid,cap_net_raw+eip' in entrypoint
    assert '--inh=cap_net_raw' in entrypoint
    assert '--user=aegis' in entrypoint
    assert entrypoint.index('--addamb=cap_net_raw') < entrypoint.index('--drop=cap_setuid,cap_setgid,cap_setpcap')
    assert '--caps=cap_net_raw+eip' in entrypoint
    assert '-Q scanners' in entrypoint
    assert 'cap_net_admin' not in entrypoint


def test_external_black_box_proves_final_scanner_runtime_capabilities():
    workflow = (
        Path(__file__).parents[1] / '.github/workflows/external-black-box-e2e.yml'
    ).read_text(encoding='utf-8')
    assert 'scanner-runtime pid=' in workflow
    assert 'Uid' in workflow and 'Gid' in workflow
    assert 'CapEff' in workflow and 'CapAmb' in workflow
    assert 'CAP_NET_RAW' in workflow
    assert 'CAP_NET_ADMIN' in workflow
    assert 'CAP_SETUID' in workflow
    assert 'CAP_SETGID' in workflow
    assert 'CAP_SETPCAP' in workflow
    assert 'expected 10001' in workflow


def test_external_black_box_proves_shared_runtime_network_namespace():
    workflow = (
        Path(__file__).parents[1] / '.github/workflows/external-black-box-e2e.yml'
    ).read_text(encoding='utf-8')
    assert "docker inspect -f '{{.Id}}' aegis-scanner-egress" in workflow
    assert "docker inspect -f '{{.HostConfig.NetworkMode}}' aegis-scanner-worker" in workflow
    assert 'EXPECTED_NETWORK_MODE="container:$EGRESS_ID"' in workflow
    assert 'scanner_worker is not attached to the scanner_egress runtime namespace' in workflow


def test_scanner_egress_image_installs_kernel_policy_tooling():
    root = Path(__file__).parents[1] / 'aegis-platform/docker/scanner-egress'
    dockerfile = (root / 'Dockerfile').read_text(encoding='utf-8')
    entrypoint = (root / 'entrypoint.sh').read_text(encoding='utf-8')
    assert 'nftables' in dockerfile
    assert 'iproute2' in dockerfile
    assert 'table netdev' in entrypoint
    assert 'hook egress' in entrypoint
    assert '169.254.0.0/16' in entrypoint
    promisc = 'ip link set "$IFACE" promisc on'
    policy_install = 'nft delete table netdev "$TABLE"'
    assert promisc in entrypoint
    assert entrypoint.index(promisc) < entrypoint.index(policy_install)
