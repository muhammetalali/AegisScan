import importlib.util
import stat
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "aegis-platform/scripts/render_alertmanager_config.py"
SPEC = importlib.util.spec_from_file_location("render_alertmanager_config", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_renderer_is_fail_closed_and_secret_file_is_private(tmp_path):
    template = tmp_path / "template"
    output = tmp_path / "alertmanager.yml"
    template.write_text("url: '__ALERT_WEBHOOK_URL__'\n")
    MODULE.render(template, output, "https://alerts.example.com/aegis")
    assert "https://alerts.example.com/aegis" in output.read_text()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("url", ["", "http://alerts.example.com/hook", "https://user:pass@alerts.example.com/hook", "file:///tmp/x"])
def test_renderer_rejects_unsafe_production_destinations(tmp_path, url):
    template = tmp_path / "template"
    template.write_text("__ALERT_WEBHOOK_URL__")
    with pytest.raises(ValueError):
        MODULE.render(template, tmp_path / "out", url)
