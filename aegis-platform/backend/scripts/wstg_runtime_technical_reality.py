from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import tempfile
from threading import Thread

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fastapi_app.services.web_messaging_semantics import assess_web_messaging
from fastapi_app.services.wstg_native_capabilities import run_wstg_internal_capability


class _RealityHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        return

    def _send(self, status: int, body: bytes = b'', *, allow: str | None = None) -> None:
        self.send_response(status)
        if allow is not None:
            self.send_header('Allow', allow)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        if self.command != 'HEAD' and body:
            self.wfile.write(body)

    def do_OPTIONS(self):
        self._send(204, allow='GET, HEAD, OPTIONS')

    def do_HEAD(self):
        self._send(200)

    def do_GET(self):
        body = self.path.encode('utf-8', errors='replace')
        self._send(200, body)


def _start_server(context: ssl.SSLContext | None = None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), _RealityHandler)
    if context is not None:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _issue_local_tls_material(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Aegis WSTG Runtime Reality CA')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / 'ca.pem'
    cert_path = directory / 'server.pem'
    key_path = directory / 'server.key'
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    return ca_path, cert_path, key_path


def _observation(result):
    payload = json.loads(result.stdout)
    rows = payload.get('observations')
    assert isinstance(rows, list) and len(rows) == 1, payload
    assert isinstance(rows[0], dict), payload
    return rows[0]


def main() -> int:
    previous_targets = os.environ.get('AUTHORIZED_SCAN_TARGETS')
    previous_ca = os.environ.get('SSL_CERT_FILE')
    http_server = None
    https_server = None
    try:
        os.environ['AUTHORIZED_SCAN_TARGETS'] = '127.0.0.1/32'

        http_server, _ = _start_server()
        http_target = f'http://127.0.0.1:{http_server.server_port}/probe?existing=1'

        method = _observation(
            run_wstg_internal_capability('web.http-method-policy', http_target, {})
        )
        assert method['wstg_id'] == 'WSTG-CONF-06'
        assert method['unsafe_methods_sent'] is False
        assert set(method['statuses']) == {'OPTIONS', 'HEAD', 'GET'}
        assert method['allow_methods'] == ['GET', 'HEAD', 'OPTIONS']

        hpp = _observation(
            run_wstg_internal_capability('web.duplicate-parameter-semantics', http_target, {})
        )
        assert hpp['wstg_id'] == 'WSTG-INPV-04'
        assert hpp['order_sensitive_observed'] is True
        assert hpp['request_method'] == 'GET'

        ssrf = _observation(
            run_wstg_internal_capability('web.ssrf-canary-validation', http_target, {})
        )
        assert ssrf['wstg_id'] == 'WSTG-INPV-19'
        assert ssrf['abstained'] is True
        assert ssrf['callback_attempted'] is False
        assert ssrf['ssrf_confirmed'] is False

        with tempfile.TemporaryDirectory(prefix='aegis-wstg-runtime-reality-') as tmp:
            directory = Path(tmp)
            ca_path, cert_path, key_path = _issue_local_tls_material(directory)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            tls_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            os.environ['SSL_CERT_FILE'] = str(ca_path)
            https_server, _ = _start_server(tls_context)
            https_target = f'https://127.0.0.1:{https_server.server_port}/'

            tls = _observation(
                run_wstg_internal_capability('tls.posture', https_target, {})
            )
            assert tls['wstg_id'] == 'WSTG-CRYP-01'
            assert tls['certificate_hostname_verified'] is True
            assert tls['resolved_ip'] == '127.0.0.1'
            assert str(tls['tls_version']).startswith('TLSv')

        messaging = assess_web_messaging(
            [
                {
                    'direction': 'send',
                    'peer_origin': '*',
                    'data_type': 'object',
                    'data_keys': ['action'],
                    'payload': 'must-not-be-retained',
                },
                {
                    'direction': 'receive',
                    'peer_origin': 'https://partner.example.test',
                    'data_type': 'string',
                    'data_keys': [],
                },
            ],
            target_origin='https://app.example.test',
            listener_count=1,
            sent_count=1,
            received_count=1,
        )
        assert messaging['wstg_id'] == 'WSTG-CLNT-11'
        assert messaging['observation_only'] is True
        assert messaging['final_decision'] is False
        assert messaging['origin_validation_confirmed'] is False
        assert messaging['payload_values_captured'] is False
        assert 'must-not-be-retained' not in json.dumps(messaging, sort_keys=True)

        report = {
            'schema': 'aegis.wstg-runtime-technical-reality.v1',
            'scope': 'runtime-only',
            'methodology_cutover_performed': False,
            'capabilities': {
                'WSTG-CONF-06': {
                    'runtime': 'proven',
                    'unsafe_methods_sent': False,
                    'allow_methods': method['allow_methods'],
                },
                'WSTG-INPV-04': {
                    'runtime': 'proven',
                    'order_sensitive_observed': hpp['order_sensitive_observed'],
                },
                'WSTG-INPV-19': {
                    'runtime': 'pre-oast-abstention-proven',
                    'callback_attempted': False,
                    'ssrf_confirmed': False,
                },
                'WSTG-CRYP-01': {
                    'runtime': 'proven',
                    'tls_version': tls['tls_version'],
                    'certificate_hostname_verified': True,
                },
                'WSTG-CLNT-11': {
                    'runtime': 'observation-semantics-proven',
                    'payload_values_captured': False,
                    'origin_validation_confirmed': False,
                },
            },
        }
        print(json.dumps(report, sort_keys=True, separators=(',', ':')))
        return 0
    finally:
        for server in (https_server, http_server):
            if server is not None:
                server.shutdown()
                server.server_close()
        if previous_targets is None:
            os.environ.pop('AUTHORIZED_SCAN_TARGETS', None)
        else:
            os.environ['AUTHORIZED_SCAN_TARGETS'] = previous_targets
        if previous_ca is None:
            os.environ.pop('SSL_CERT_FILE', None)
        else:
            os.environ['SSL_CERT_FILE'] = previous_ca


if __name__ == '__main__':
    raise SystemExit(main())
