from __future__ import annotations

from aegis.core.config_manager import ConfigManager


def test_optional_environment_placeholders_resolve_without_warning(tmp_path, caplog):
    path = tmp_path / 'config.yaml'
    path.write_text('integrations:\n  slack_webhook: ${AEGIS_SLACK_WEBHOOK:-}\n', encoding='utf-8')

    config = ConfigManager(str(path))

    assert config.get('integrations.slack_webhook') == ''
    assert 'متغير بيئة غير معرّف' not in caplog.text


def test_new_config_keeps_secret_placeholder_on_disk(monkeypatch, tmp_path):
    path = tmp_path / 'config.yaml'
    monkeypatch.setenv('AEGIS_SLACK_WEBHOOK', 'https://secret.example.invalid/hook')

    config = ConfigManager(str(path))

    assert config.get('integrations.slack_webhook') == 'https://secret.example.invalid/hook'
    saved = path.read_text(encoding='utf-8')
    assert 'https://secret.example.invalid/hook' not in saved
    assert '${AEGIS_SLACK_WEBHOOK:-}' in saved
