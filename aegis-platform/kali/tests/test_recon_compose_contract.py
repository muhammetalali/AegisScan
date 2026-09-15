from __future__ import annotations

from pathlib import Path

COMPOSE = (Path(__file__).resolve().parents[2] / 'docker-compose.yml').read_text(encoding='utf-8')
SCANNER_EGRESS = (
    Path(__file__).resolve().parents[2] / 'docker' / 'scanner-egress' / 'entrypoint.sh'
).read_text(encoding='utf-8')


def _service_block(name: str, next_name: str) -> str:
    start = COMPOSE.index(f'  {name}:')
    end = COMPOSE.index(f'  {next_name}:', start)
    return COMPOSE[start:end]


def test_kali_recon_compose_boundary_is_isolated_and_loopback_shared():
    block = _service_block('kali_recon', 'browser_worker')
    assert 'profiles: [kali-recon]' in block
    assert 'user: "10001:10001"' in block
    assert 'network_mode: "service:scanner_egress"' in block
    assert 'cap_drop: [ALL]' in block
    assert 'no-new-privileges:true' in block
    assert 'read_only: true' in block
    assert 'AEGIS_RECON_LISTEN_HOST: 127.0.0.1' in block
    assert 'AEGIS_KALI_RECON_AUTH_TOKEN: ${AEGIS_KALI_RECON_AUTH_TOKEN:-}' in block
    assert 'env_file:' not in block
    assert 'ports:' not in block
    assert 'cap_add:' not in block
    assert 'docker.sock' not in block
    assert 'DATABASE_URL' not in block
    assert 'DJANGO_SETTINGS_MODULE' not in block
    assert 'POSTGRES_' not in block
    assert 'redis:' not in block
    assert 'django:' not in block


def test_scanner_worker_provider_selection_is_explicit_and_fail_closed():
    block = _service_block('scanner_worker', 'kali_recon')
    assert 'AEGIS_RECON_PROVIDER: ${AEGIS_RECON_PROVIDER:-legacy}' in block
    assert 'AEGIS_KALI_RECON_URL: ${AEGIS_KALI_RECON_URL:-http://127.0.0.1:18765}' in block
    assert 'AEGIS_KALI_RECON_AUTH_TOKEN: ${AEGIS_KALI_RECON_AUTH_TOKEN:-}' in block
    assert 'kali_recon:' not in block


def test_browser_worker_overrides_recon_provider_auth_token_to_empty():
    block = _service_block('browser_worker', 'celery_beat')
    assert 'AEGIS_KALI_RECON_AUTH_TOKEN: ""' in block


def test_frontend_has_no_self_dependency_cycle():
    block = _service_block('frontend', 'nginx')
    depends = block.split('depends_on:', 1)[1]
    assert '      frontend:' not in depends
    assert '      django: {condition: service_started}' in depends
    assert '      fastapi: {condition: service_healthy}' in depends


def test_scanner_egress_keeps_amass_engine_port_loopback_only():
    assert "type filter hook ingress device" in SCANNER_EGRESS
    assert 'nft add rule netdev "$TABLE" "$INGRESS_CHAIN" tcp dport 4000 counter drop' in SCANNER_EGRESS
