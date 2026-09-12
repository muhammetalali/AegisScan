from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import socket
import ssl
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from django.contrib.auth import get_user_model

from django_project.assets.models import Asset, AssetAuthorization
from django_project.evidence.models import Evidence, ValidationRun
from django_project.projects.models import Project, ProjectMembership
from django_project.scans.models import Scan
from django_project.vulnerabilities.models import Vulnerability
from fastapi_app.services import offensive_validation as service
from fastapi_app.services import scope_authorization


@pytest.fixture
def web_target():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.respond()

        def do_GET(self):
            self.respond()

        def respond(self):
            requests.append((self.command, self.path, self.headers.get('Host')))
            parsed = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if parsed.path == '/redirect' and 'next' in params:
                self.send_response(302)
                self.send_header('Location', params['next'][0])
            else:
                self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Set-Cookie', 'session=private-response-cookie')
            self.end_headers()
            if self.command == 'GET':
                marker = params.get('aegis_validation_token', [''])[0]
                body = f'<pre>{html.escape(marker)} private-response-secret</pre>'
                self.wfile.write(body.encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def finding(db, web_target, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', '127.0.0.1/32')
    user = get_user_model().objects.create_user(email='validation@example.test', password='Validation-123!')
    project = Project.objects.create(name='Validation', slug='validation', owner=user)
    url = f'{web_target[0]}/search'
    asset = Asset.objects.create(project=project, name='Lab', slug='lab', type=Asset.Type.WEBSITE, owner=user, configuration={'url': url})
    decision = AssetAuthorization.objects.create(asset=asset, actor=user, authorized=True, target_snapshot=url, reason='Local HTTP fixture')
    scan = Scan.objects.create(project=project, asset=asset, name='Browser scan', scan_type=Scan.Type.URL, engines=['browser-security'], initiated_by=user, authorization_decision=decision)
    return Vulnerability.objects.create(scan=scan, project=project, asset=asset, title='Reflected XSS candidate', description='Input reflection candidate', severity='high', status='accepted_risk', confidence='unverified', cwe_id='CWE-79', url=f'{url}?password=private-query-secret#private-fragment', parameter='q', source_engine='browser-security')


def redirect_finding(finding, web_target):
    url = f'{web_target[0]}/redirect'
    finding.asset.configuration = {'url': url}
    finding.asset.save(update_fields=['configuration'])
    AssetAuthorization.objects.create(asset=finding.asset, actor=finding.scan.initiated_by, authorized=True, target_snapshot=url, reason='Local redirect fixture')
    finding.url = url
    finding.title = 'Open redirect candidate'
    finding.cwe_id = 'CWE-601'
    finding.parameter = 'next'
    finding.save(update_fields=['url', 'title', 'cwe_id', 'parameter'])
    return finding


def test_real_http_reflection_is_inconclusive_and_raw_material_is_not_stored(finding, web_target):
    result = service.run_offensive_validation(finding=finding)
    assert result['status'] == 'completed'
    assert result['exploitability']['state'] == 'inconclusive'
    assert result['probes'][1]['observation_confirmed'] is True
    assert result['probes'][1]['exploitability_proven'] is False
    assert [request[0] for request in web_target[1]] == ['HEAD', 'GET']
    run = ValidationRun.objects.get(pk=result['validation_run_id'])
    evidence = Evidence.objects.get(pk=result['evidence_id'])
    assert run.authorization_decision_id is not None
    assert evidence.sha256 == hashlib.sha256(evidence.raw_output.encode()).hexdigest()
    persisted = json.dumps([run.result, run.error_message, evidence.raw_output, evidence.metadata])
    marker = urllib.parse.parse_qs(urllib.parse.urlsplit(web_target[1][1][1]).query)['aegis_validation_token'][0]
    for secret in ('private-response-secret', 'private-response-cookie', 'private-query-secret', 'private-fragment', marker):
        assert secret not in persisted
    finding.refresh_from_db()
    assert finding.confidence == 'unverified'
    assert finding.status == 'accepted_risk'
    assert finding.verified_evidence_count == 0
    assert finding.exploitability == 0


def test_real_redirect_confirms_only_the_random_controlled_location_without_following(finding, web_target):
    finding = redirect_finding(finding, web_target)
    result = service.run_offensive_validation(finding=finding)
    assert result['exploitability']['state'] == 'confirmed'
    assert result['probes'][1]['status'] == 302
    assert len(web_target[1]) == 2
    finding.refresh_from_db()
    assert finding.status == 'accepted_risk'
    assert finding.confidence == 'confirmed'
    assert finding.verified_evidence_count == 1
    run = ValidationRun.objects.get(pk=result['validation_run_id'])
    evidence = Evidence.objects.get(pk=result['evidence_id'])
    original_hash = evidence.sha256
    replay = service.run_offensive_validation(finding=finding, validation_run=run)
    assert replay == result
    assert len(web_target[1]) == 2
    assert Evidence.objects.filter(source=service.ENGINE).count() == 1
    evidence.refresh_from_db()
    assert evidence.sha256 == original_hash


def test_static_redirect_is_not_false_confirmation(finding, web_target):
    finding = redirect_finding(finding, web_target)
    result = service.run_offensive_validation(finding=finding, http_client=lambda probe: service.HTTPProbeResponse(302, {'location': 'https://aegis-validation.invalid/static'}, '', probe.url))
    assert result['exploitability']['state'] == 'not_reproduced'


@pytest.mark.parametrize('actor_type', ['outsider', 'viewer', 'inactive'])
def test_actor_authorization_is_checked_before_network_or_persistence(finding, web_target, actor_type):
    actor = get_user_model().objects.create_user(email='other@example.test', password='Other-123!', is_active=actor_type != 'inactive')
    if actor_type != 'outsider':
        ProjectMembership.objects.create(project=finding.project, user=actor, role='viewer' if actor_type == 'viewer' else 'member')
    with pytest.raises(PermissionError):
        service.run_offensive_validation(finding=finding, actor=actor)
    assert not web_target[1]
    assert not ValidationRun.objects.exists()
    assert not Evidence.objects.exists()


def test_revoked_grant_blocks_before_network(finding, web_target):
    AssetAuthorization.objects.create(asset=finding.asset, actor=finding.scan.initiated_by, authorized=False, target_snapshot=finding.asset.configuration['url'], reason='Revoked')
    with pytest.raises(PermissionError):
        service.run_offensive_validation(finding=finding)
    assert not web_target[1]
    assert not ValidationRun.objects.exists()


def test_other_endpoint_on_an_allowed_host_is_not_authorized(finding, web_target):
    finding.url = f'{web_target[0]}/other-endpoint'
    finding.save(update_fields=['url'])
    with pytest.raises(PermissionError, match='endpoint'):
        service.run_offensive_validation(finding=finding)
    assert not web_target[1]


def test_unscoped_destination_is_blocked_before_persistence(finding, monkeypatch, web_target):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'approved.example')
    with pytest.raises(ValueError, match='outside the server-side authorized scan scope'):
        service.run_offensive_validation(finding=finding)
    assert not ValidationRun.objects.exists()
    assert not web_target[1]


def test_revocation_after_first_request_blocks_next_request_and_evidence(finding, web_target):
    def revoke(probe):
        response = service._default_http_client(probe)
        AssetAuthorization.objects.create(asset=finding.asset, actor=finding.scan.initiated_by, authorized=False, target_snapshot=finding.asset.configuration['url'], reason='Revoked mid-execution')
        return response

    result = service.run_offensive_validation(finding=finding, http_client=revoke)
    assert result['status'] == 'failed'
    assert len(web_target[1]) == 1
    assert not Evidence.objects.exists()
    assert ValidationRun.objects.get(pk=result['validation_run_id']).status == 'failed'
    finding.refresh_from_db()
    assert finding.status == 'accepted_risk'
    assert finding.confidence == 'unverified'


def test_cancellation_is_terminal_during_execution(finding, web_target):
    def cancel(probe):
        response = service._default_http_client(probe)
        ValidationRun.objects.filter(finding=finding).update(status='cancelled')
        return response

    result = service.run_offensive_validation(finding=finding, http_client=cancel)
    assert result['status'] == 'cancelled'
    assert len(web_target[1]) == 1
    assert not Evidence.objects.exists()
    run = ValidationRun.objects.get(pk=result['validation_run_id'])
    service.run_offensive_validation(finding=finding, validation_run=run)
    assert len(web_target[1]) == 1


def test_probe_error_is_failed_and_does_not_persist_exception_secrets(finding):
    def fail(probe):
        raise OSError('private-error-secret ' + probe.url)

    result = service.run_offensive_validation(finding=finding, http_client=fail)
    run = ValidationRun.objects.get(pk=result['validation_run_id'])
    assert run.status == 'failed'
    assert run.result['exploitability']['state'] == 'inconclusive'
    assert 'private-error-secret' not in json.dumps([run.result, run.error_message])
    finding.refresh_from_db()
    assert finding.confidence == 'unverified'


def test_partial_transport_failure_does_not_claim_completion(finding):
    def partial(probe):
        if probe.method == 'HEAD':
            return service.HTTPProbeResponse(200, {}, '', probe.url)
        raise TimeoutError('target timed out')

    result = service.run_offensive_validation(finding=finding, http_client=partial)
    assert result['status'] == 'failed'
    assert ValidationRun.objects.get(pk=result['validation_run_id']).status == 'failed'


@pytest.mark.parametrize('linked_evidence', [False, True])
def test_browser_transport_requires_matching_stored_evidence_and_makes_no_request(finding, web_target, linked_evidence):
    affected = f'{web_target[0]}/login'
    finding.cwe_id = 'CWE-319'
    finding.title = 'Form submits over cleartext HTTP'
    finding.raw_data = {'rule_id': 'browser.insecure-form-action', 'affected_urls': [affected]}
    finding.save(update_fields=['cwe_id', 'title', 'raw_data'])
    if linked_evidence:
        Evidence.objects.create(scan=finding.scan, asset=finding.asset, source='browser-security', raw_output=json.dumps({'schema': 'aegis.browser-security.v1', 'target_url': finding.asset.configuration['url'], 'observations': [{'kind': 'browser-dom-security-snapshot', 'insecure_form_actions': [affected]}]}))
    result = service.run_offensive_validation(finding=finding)
    assert result['exploitability']['state'] == ('confirmed' if linked_evidence else 'inconclusive')
    assert bool(result['probes'][0]['source_evidence_id']) == linked_evidence
    assert not web_target[1]


def test_a_validation_run_from_another_finding_is_not_reused(finding, web_target):
    run = ValidationRun.objects.create(user=finding.scan.initiated_by, target_type='url', target_value=finding.url, scope='test', engines=[service.ENGINE])
    with pytest.raises(PermissionError, match='identity'):
        service.run_offensive_validation(finding=finding, validation_run=run)
    run.refresh_from_db()
    assert run.status == 'queued'
    assert not web_target[1]


def test_http_connection_pins_checked_ip_preserves_host_and_ignores_proxy(web_target, monkeypatch):
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'app.example,127.0.0.1/32')
    monkeypatch.setenv('http_proxy', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setattr(scope_authorization, '_resolve_host_addresses', lambda host: (ipaddress.ip_address('127.0.0.1'),))

    def unexpected_dns(*args, **kwargs):
        raise AssertionError('HTTP transport must not resolve the hostname again')

    monkeypatch.setattr(socket, 'getaddrinfo', unexpected_dns)
    port = urllib.parse.urlsplit(web_target[0]).port
    probe = service.ProbeRequest('http-reachability', 'HEAD', f'http://app.example:{port}/search')
    assert service._default_http_client(probe).status == 200
    assert web_target[1][0][2] == f'app.example:{port}'


def test_live_session_payload_is_rejected_before_persistence(finding, web_target):
    finding.raw_data = {'payload': 'meterpreter reverse shell'}
    finding.save(update_fields=['raw_data'])
    with pytest.raises(ValueError, match='Live shell/session payloads'):
        service.run_offensive_validation(finding=finding)
    assert not ValidationRun.objects.exists()
    assert not web_target[1]


@pytest.mark.parametrize(('trusted', 'host'), [(False, 'app.example'), (True, 'app.example'), (True, 'wrong.example')])
def test_pinned_https_validates_certificate_and_original_hostname(tmp_path, monkeypatch, trusted, host):
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=app.example', '-addext', 'subjectAltName=DNS:app.example', '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('AUTHORIZED_SCAN_TARGETS', 'app.example,wrong.example,127.0.0.1/32')
    monkeypatch.setattr(scope_authorization, '_resolve_host_addresses', lambda value: (ipaddress.ip_address('127.0.0.1'),))
    if trusted:
        client_context = ssl.create_default_context(cafile=str(cert))
        monkeypatch.setattr(service.ssl, 'create_default_context', lambda: client_context)
    try:
        probe = service.ProbeRequest('http-reachability', 'HEAD', f'https://{host}:{server.server_port}/')
        if trusted and host == 'app.example':
            assert service._default_http_client(probe).status == 200
        else:
            with pytest.raises(ssl.SSLCertVerificationError):
                service._default_http_client(probe)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
