import importlib.util
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "aegis-platform/scripts/render_alertmanager_config.py"
ENTRYPOINT = ROOT / "aegis-platform/docker/alertmanager/entrypoint.sh"
MONITORING_COMPOSE = ROOT / "aegis-platform/docker-compose.monitoring.yml"
SPEC = importlib.util.spec_from_file_location("render_alertmanager_config", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def _template(tmp_path: Path) -> Path:
    template = tmp_path / "template"
    template.write_text(
        "receivers:\n  - name: aegis-production\n__ALERT_WEBHOOK_CONFIG__\n",
        encoding="utf-8",
    )
    return template


def test_renderer_external_webhook_is_private_and_safe(tmp_path):
    template = _template(tmp_path)
    output = tmp_path / "alertmanager.yml"
    MODULE.render(template, output, "https://alerts.example.com/aegis")
    rendered = output.read_text()
    assert 'url: "https://alerts.example.com/aegis"' in rendered
    assert "webhook_configs:" in rendered
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_renderer_supports_internal_only_alertmanager_without_external_webhook(tmp_path):
    template = _template(tmp_path)
    output = tmp_path / "alertmanager.yml"
    MODULE.render(template, output, "")
    rendered = output.read_text()
    assert "name: aegis-production" in rendered
    assert "webhook_configs:" not in rendered
    assert "internal Alertmanager control plane" in rendered
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "url",
    [
        "http://alerts.example.com/hook",
        "https://user:pass@alerts.example.com/hook",
        "file:///tmp/x",
        "https://127.0.0.1/hook",
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/hook",
        "https://alerts.example.com/hook\nsecond-line",
    ],
)
def test_renderer_rejects_unsafe_production_destinations(tmp_path, url):
    with pytest.raises(ValueError):
        MODULE.render(_template(tmp_path), tmp_path / "out", url)


def test_renderer_allows_http_only_for_explicit_loopback_tests(tmp_path):
    template = _template(tmp_path)
    output = tmp_path / "out"
    MODULE.render(
        template,
        output,
        "http://127.0.0.1:8080/aegis",
        allow_http=True,
    )
    assert "http://127.0.0.1:8080/aegis" in output.read_text()

    network_output = tmp_path / "network-out"
    MODULE.render(
        template,
        network_output,
        "http://alert-receiver:8080/aegis",
        allow_http=True,
    )
    assert "http://alert-receiver:8080/aegis" in network_output.read_text()
    with pytest.raises(ValueError):
        MODULE.render(
            template,
            tmp_path / "bad",
            "http://alerts.example.com/aegis",
            allow_http=True,
        )



def test_renderer_adds_bearer_credentials_file_for_authenticated_internal_receiver(tmp_path):
    output = tmp_path / "alertmanager.yml"
    MODULE.render(
        _template(tmp_path),
        output,
        "https://security.example.com:8443/_aegis/alerts",
        authorization_credentials_file="/run/secrets/alert-receiver-token",
    )
    rendered = output.read_text(encoding="utf-8")
    assert "http_config:" in rendered
    assert "authorization:" in rendered
    assert "type: Bearer" in rendered
    assert 'credentials_file: "/run/secrets/alert-receiver-token"' in rendered


def test_renderer_rejects_relative_authorization_credentials_file(tmp_path):
    with pytest.raises(ValueError, match="absolute safe path"):
        MODULE.render(
            _template(tmp_path),
            tmp_path / "out",
            "https://security.example.com:8443/_aegis/alerts",
            authorization_credentials_file="relative-token",
        )

def test_alertmanager_entrypoint_combines_public_and_enterprise_ca_trust():
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    compose = MONITORING_COMPOSE.read_text(encoding="utf-8")
    assert 'AEGIS_ENTERPRISE_CA_BUNDLE' in entrypoint
    assert 'cat /etc/ssl/certs/ca-certificates.crt "$enterprise_ca" > /tmp/aegis-ca-bundle.pem' in entrypoint
    assert 'export SSL_CERT_FILE=/tmp/aegis-ca-bundle.pem' in entrypoint
    assert 'AEGIS_ENTERPRISE_CA_BUNDLE: /run/aegis/enterprise-ca.pem' in compose
    assert '${AEGIS_ENTERPRISE_CA_HOST_BUNDLE:-/dev/null}:/run/aegis/enterprise-ca.pem:ro' in compose
    assert 'token_file=/run/secrets/alert-receiver-token' in entrypoint
    assert '${AEGIS_ALERT_RECEIVER_TOKEN_FILE:-/dev/null}:/run/secrets/alert-receiver-token:ro' in compose
    assert 'alert_receiver:' in compose


def test_internal_alert_delivery_network_is_isolated_and_receiver_fails_closed():
    compose = MONITORING_COMPOSE.read_text(encoding="utf-8")
    assert "alert_delivery_v2:\n    internal: true" in compose
    assert 'AEGIS_ALERT_RECEIVER_ALLOW_STANDBY: ${AEGIS_ALERT_RECEIVER_ALLOW_STANDBY:-false}' in compose
    assert "8443:8443" not in compose
