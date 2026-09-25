import importlib.util
import stat
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "aegis-platform/scripts/render_alertmanager_config.py"
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
