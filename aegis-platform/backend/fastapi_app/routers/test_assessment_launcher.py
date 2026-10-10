from __future__ import annotations

import io
import socket
import zipfile
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from django_project.assets import signals as asset_signals
from fastapi_app.routers import assessment_launcher as launcher
from fastapi_app.services.dynamic_egress import DynamicEgressError, _non_global_network, authorize_dynamic_egress
from fastapi_app.services.scanner_adapters import validate_code_target


def _dns(address: str):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return (family, socket.SOCK_STREAM, 6, '', sockaddr)


@pytest.mark.django_db
def test_primary_company_owner_can_prepare_another_users_project_without_membership(settings):
    from django_project.users.models import User
    from django_project.projects.models import Project, ProjectMembership
    primary = User.objects.create_superuser(
        email='primary-launcher@example.invalid', password='Test-Password-456!',
    )
    other = User.objects.create_user(
        email='project-launcher@example.invalid', password='Test-Password-789!',
    )
    settings.AEGIS_PRIMARY_OWNER_EMAIL = primary.email
    project = Project.objects.create(name='Company-wide authorization', slug='launcher-owner-access', owner=other)
    assert not ProjectMembership.objects.filter(project=project, user=primary).exists()

    assert launcher._project_for_launcher(str(project.id), str(primary.id)).pk == project.pk


@pytest.mark.django_db
def test_delegated_staff_cannot_bypass_its_project_membership_scope(settings):
    from django_project.users.models import User, UserRole
    from django_project.projects.models import Project, ProjectMembership
    settings.AEGIS_PRIMARY_OWNER_EMAIL = 'separate-owner@example.invalid'
    project_owner = User.objects.create_user(
        email='project-owner@example.invalid', password='Test-Password-012!',
    )
    delegated = User.objects.create_user(
        email='delegated-manager@example.invalid', password='Test-Password-345!',
        is_staff=True, role=UserRole.SUPER_ADMIN, is_superuser=False,
    )
    project = Project.objects.create(name='Delegated project policy', slug='launcher-delegated-policy', owner=project_owner)
    with pytest.raises(HTTPException, match='Project membership is required') as denied:
        launcher._project_for_launcher(str(project.id), str(delegated.id))
    assert denied.value.status_code == 403
    ProjectMembership.objects.create(project=project, user=delegated)
    assert launcher._project_for_launcher(str(project.id), str(delegated.id)).pk == project.pk


def test_launcher_normalizes_network_and_ip_targets():
    asset_type, target, config = launcher._normalize_target('network', '192.168.49.33/24')
    assert asset_type == 'network_range'
    assert target == '192.168.49.0/24'
    assert config == {'cidr': '192.168.49.0/24'}

    asset_type, target, config = launcher._normalize_target('ip', '192.168.49.10')
    assert asset_type == 'ip_address'
    assert target == '192.168.49.10'
    assert config == {'ip': '192.168.49.10'}


def test_launcher_url_defaults_https_and_pins_dns(monkeypatch):
    monkeypatch.setattr(
        launcher.socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [_dns('192.168.49.20')],
    )
    asset_type, target, config = launcher._normalize_target('url', 'internal.example/app')
    assert asset_type == 'website'
    assert target == 'https://internal.example/app'
    assert config['url'] == target
    assert config['resolved_ips'] == ['192.168.49.20']


def test_launcher_rejects_unresolvable_url(monkeypatch):
    def fail(*_args, **_kwargs):
        raise socket.gaierror('synthetic failure')

    monkeypatch.setattr(launcher.socket, 'getaddrinfo', fail)
    with pytest.raises(HTTPException, match='Target DNS resolution failed'):
        launcher._normalize_target('url', 'internal.example')


def test_file_asset_has_semgrep_execution_plan():
    planned = launcher._capability_plan(SimpleNamespace(type='file'), 'standard')
    assert 'code.semgrep' in planned['recommended_capabilities']


def test_safe_zip_extract_rejects_path_traversal(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('../escape.py', 'print("bad")')
    with pytest.raises(HTTPException, match='unsafe path'):
        launcher._safe_extract_zip(stream.getvalue(), tmp_path)


def test_safe_zip_extracts_regular_source(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('src/app.py', 'print("ok")')
    root = launcher._safe_extract_zip(stream.getvalue(), tmp_path)
    assert (root / 'src' / 'app.py').read_text() == 'print("ok")'


def test_validate_code_target_accepts_regular_file_and_rejects_symlink(tmp_path):
    source = tmp_path / 'app.py'
    source.write_text('print("ok")')
    assert validate_code_target(str(source)) == str(source.resolve())

    link = tmp_path / 'alias.py'
    link.symlink_to(source)
    with pytest.raises(ValueError, match='symlink'):
        validate_code_target(str(link))


def test_dynamic_egress_only_materializes_non_global_destinations():
    assert _non_global_network('192.168.49.0/24') == '192.168.49.0/24'
    assert _non_global_network('10.20.30.40') == '10.20.30.40'
    assert _non_global_network('93.184.216.34') is None


def test_scope_mode_defaults_to_governed_authorization(monkeypatch):
    monkeypatch.delenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', raising=False)
    monkeypatch.delenv('AEGIS_SCAN_SCOPE_MODE', raising=False)
    assert launcher._scope_mode() == 'asset-authorization'


def test_scope_mode_rejects_unknown_values(monkeypatch):
    monkeypatch.setenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', 'anything-goes')
    with pytest.raises(HTTPException, match='Assessment Launcher scope mode is invalid'):
        launcher._scope_mode()


def test_single_operator_lab_mode_routes_through_governance_service(monkeypatch):
    monkeypatch.setenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', 'single-operator-lab')
    monkeypatch.setattr(launcher, '_current_authorization', lambda _asset: None)
    monkeypatch.setattr(launcher, 'asset_authorization_version', lambda _asset: 7)

    decision = SimpleNamespace(
        id='decision-1',
        authorized=True,
        target_snapshot='192.168.49.10',
        actor_id='owner-1',
    )
    calls = {}

    def govern(**kwargs):
        calls.update(kwargs)
        return SimpleNamespace(decision=decision)

    monkeypatch.setattr(launcher, 'govern_asset_authorization', govern)
    asset = SimpleNamespace(id='asset-1', project_id='project-1')

    result = launcher._ensure_authorization(asset, 'owner-1')

    assert result['state'] == 'authorized'
    assert result['source'] == 'single-operator-lab'
    assert result['decision'] is decision
    assert calls['asset_id'] == 'asset-1'
    assert calls['project_id'] == 'project-1'
    assert calls['actor_id'] == 'owner-1'
    assert calls['expected_version'] == 7
    assert calls['authorized'] is True



def test_governed_launcher_reuses_request_identity_for_same_actor_asset_and_version(monkeypatch):
    monkeypatch.setenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', 'asset-authorization')
    monkeypatch.setattr(launcher, '_current_authorization', lambda _asset: None)
    monkeypatch.setattr(launcher, 'asset_authorization_version', lambda _asset: 11)
    calls = []

    def submit(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(request=SimpleNamespace(id='request-1'), replayed=len(calls) > 1)

    monkeypatch.setattr(launcher, 'create_governed_action_request', submit)
    monkeypatch.setattr(
        launcher, 'governed_action_request_view',
        lambda result: {'request_id': result.request.id, 'replayed': result.replayed},
    )
    asset = SimpleNamespace(id='asset-1', project_id='project-1')
    first = launcher._ensure_authorization(asset, 'owner-1')
    again = launcher._ensure_authorization(asset, 'owner-1')

    assert first['state'] == 'pending'
    assert again['state'] == 'pending'
    assert first['request']['request_id'] == again['request']['request_id']
    assert calls[0]['idempotency_key'] == calls[1]['idempotency_key']
    assert calls[0]['expected_version'] == calls[1]['expected_version'] == 11
    assert calls[0]['idempotency_key'].startswith('assessment-launcher-authorization:')
    assert len(calls[0]['idempotency_key']) <= 128
    assert first['request']['replayed'] is False
    assert again['request']['replayed'] is True


def test_governed_launcher_changes_request_identity_for_different_actor_or_version(monkeypatch):
    monkeypatch.setenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', 'asset-authorization')
    monkeypatch.setattr(launcher, '_current_authorization', lambda _asset: None)
    version = [5]
    monkeypatch.setattr(launcher, 'asset_authorization_version', lambda _asset: version[0])
    keys = []
    def submit(**kwargs):
        keys.append(kwargs['idempotency_key'])
        return SimpleNamespace(request=SimpleNamespace(id='request'), replayed=False)
    monkeypatch.setattr(launcher, 'create_governed_action_request', submit)
    monkeypatch.setattr(launcher, 'governed_action_request_view', lambda _result: {})
    asset = SimpleNamespace(id='asset-1', project_id='project-1')
    launcher._ensure_authorization(asset, 'owner-1')
    launcher._ensure_authorization(asset, 'owner-2')
    version[0] = 6
    launcher._ensure_authorization(asset, 'owner-1')
    assert len(set(keys)) == 3


def test_dynamic_egress_configured_controller_fails_closed_without_control_root(monkeypatch):
    monkeypatch.setenv('AEGIS_SCANNER_EGRESS_CONTROL_URL', 'http://127.0.0.1:18780')
    monkeypatch.delenv('AEGIS_SCANNER_EGRESS_CONTROL_ROOT', raising=False)
    monkeypatch.setenv('JWT_SECRET_KEY', 'must-not-be-used-for-egress')
    with pytest.raises(DynamicEgressError, match='AEGIS_SCANNER_EGRESS_CONTROL_ROOT'):
        authorize_dynamic_egress(['192.168.49.10'])


def test_dynamic_egress_unconfigured_runtime_uses_existing_scope_boundary(monkeypatch):
    monkeypatch.delenv('AEGIS_SCANNER_EGRESS_CONTROL_URL', raising=False)
    monkeypatch.delenv('AEGIS_SCANNER_EGRESS_CONTROL_ROOT', raising=False)
    authorize_dynamic_egress(['192.168.49.10'])


def test_dynamic_egress_public_target_needs_no_control_root(monkeypatch):
    monkeypatch.delenv('AEGIS_SCANNER_EGRESS_CONTROL_URL', raising=False)
    monkeypatch.delenv('AEGIS_SCANNER_EGRESS_CONTROL_ROOT', raising=False)
    monkeypatch.setenv('JWT_SECRET_KEY', 'must-not-be-used-for-egress')
    authorize_dynamic_egress(['93.184.216.34'])


def test_launcher_mode_overrides_global_governed_scope(monkeypatch):
    monkeypatch.setenv('AEGIS_SCAN_SCOPE_MODE', 'asset-authorization')
    monkeypatch.setenv('AEGIS_ASSESSMENT_LAUNCHER_MODE', 'single-operator-lab')
    assert launcher._scope_mode() == 'single-operator-lab'

def test_deleted_file_asset_cleanup_removes_only_managed_upload_bucket(tmp_path, monkeypatch):
    root = tmp_path / "uploads"
    bucket = root / ("a" * 32)
    content = bucket / "content"
    content.mkdir(parents=True)
    source = content / "safe.py"
    source.write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_SEMGREP_UPLOAD_ROOT", str(root))
    instance = SimpleNamespace(type="file", configuration={"path": str(source)})

    asset_signals.cleanup_managed_file_upload(sender=None, instance=instance)

    assert not bucket.exists()
    assert root.exists()


def test_deleted_file_asset_cleanup_rejects_path_outside_managed_root(tmp_path, monkeypatch):
    root = tmp_path / "uploads"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('keep')\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_SEMGREP_UPLOAD_ROOT", str(root))
    instance = SimpleNamespace(type="file", configuration={"path": str(outside)})

    asset_signals.cleanup_managed_file_upload(sender=None, instance=instance)

    assert outside.exists()


def test_deleted_file_asset_cleanup_rejects_unmanaged_bucket_name(tmp_path, monkeypatch):
    root = tmp_path / "uploads"
    bucket = root / "not-a-managed-upload"
    content = bucket / "content"
    content.mkdir(parents=True)
    source = content / "safe.py"
    source.write_text("print('keep')\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_SEMGREP_UPLOAD_ROOT", str(root))
    instance = SimpleNamespace(type="file", configuration={"path": str(source)})

    asset_signals.cleanup_managed_file_upload(sender=None, instance=instance)

    assert bucket.exists()

def test_safe_zip_extract_rejects_untrusted_symlink(tmp_path):
    stream = io.BytesIO()
    info = zipfile.ZipInfo('src/link.py')
    info.create_system = 3
    info.external_attr = (0o120777 << 16)
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr(info, 'outside-file')
    with pytest.raises(HTTPException, match='symlinks are not supported') as exc:
        launcher._safe_extract_zip(stream.getvalue(), tmp_path)
    assert exc.value.status_code == 422


def test_safe_zip_extract_caps_declared_uncompressed_size(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, '_MAX_ZIP_BYTES', 16)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('src/fixture.py', b'x' * 17)
    with pytest.raises(HTTPException, match='expands beyond') as exc:
        launcher._safe_extract_zip(stream.getvalue(), tmp_path)
    assert exc.value.status_code == 413


def test_safe_zip_extract_rejects_empty_directory_only_archive(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('folder/', b'')
    with pytest.raises(HTTPException, match='no regular files') as exc:
        launcher._safe_extract_zip(stream.getvalue(), tmp_path)
    assert exc.value.status_code == 422
