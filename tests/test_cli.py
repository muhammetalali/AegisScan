from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aegis import __version__
from aegis.cli.main import app


runner = CliRunner()


def test_version_reports_build_identity_without_false_readiness():
    result = runner.invoke(app, ['version'])

    assert result.exit_code == 0
    assert f'Aegis v{__version__}' in result.output
    assert 'READY' not in result.output
    assert 'المنصة مكتملة' not in result.output
    assert 'لا يعلن أمر الإصدار الجاهزية الإنتاجية' in result.output


def test_init_creates_real_local_project_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ['init'])

    assert result.exit_code == 0
    assert Path('config.yaml').is_file()
    assert Path('aegis/plugins').is_dir()
    assert Path('reports').is_dir()


def test_status_initializes_database_and_reports_real_zero_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ['status'])

    assert result.exit_code == 0
    assert 'حالة Aegis' in result.output
    assert 'المشاريع' in result.output
    assert '0' in result.output


def test_findings_empty_database_is_explicit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ['findings'])

    assert result.exit_code == 0
    assert 'لا ثغرات مطابقة' in result.output


def test_scan_and_validate_reject_missing_targets():
    scan_result = runner.invoke(app, ['local-scan', '--no-external', '--no-analysis'])
    validation_result = runner.invoke(app, ['local-validate', '--no-external', '--no-analysis', '--no-validation'])

    assert scan_result.exit_code == 1
    assert validation_result.exit_code == 1
    assert 'حدّد --code أو --url على الأقل' in scan_result.output
    assert 'حدّد --code أو --url على الأقل' in validation_result.output


def test_platform_status_requires_canonical_connection_credentials(monkeypatch):
    for key in ('AEGIS_PLATFORM_URL', 'AEGIS_EMAIL', 'AEGIS_PASSWORD'):
        monkeypatch.delenv(key, raising=False)
    result = runner.invoke(app, ['platform-status'])
    assert result.exit_code == 2
    assert 'AEGIS_PLATFORM_URL' in result.output


def test_platform_status_reports_only_authenticated_platform_state(monkeypatch):
    class Client:
        def __init__(self, base_url):
            assert base_url == 'https://platform.example'

        def authenticated_status(self, email, password):
            assert (email, password) == ('operator@example.test', 'secret')
            return {'ready': {'ready': True}, 'health': {'status': 'healthy'}, 'authenticated': True, 'project_count': 3, 'source': 'platform-api'}

    monkeypatch.setattr('aegis.cli.main.PlatformClient', Client)
    result = runner.invoke(app, ['platform-status', '--base-url', 'https://platform.example', '--email', 'operator@example.test', '--password', 'secret', '--json'])
    assert result.exit_code == 0
    assert 'platform-api' in result.output
    assert 'project_count' in result.output
