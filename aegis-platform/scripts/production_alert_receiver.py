#!/usr/bin/env python3
"""Minimal authenticated production receiver for Alertmanager webhooks."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import stat
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 1024 * 1024
MAX_ALERTS = 512
MAX_AUDIT_BYTES = 64 * 1024 * 1024
DEFAULT_TOKEN_FILE = Path('/run/secrets/alert-receiver-token')
DEFAULT_AUDIT_FILE = Path('/var/lib/aegis-alert-receiver/events.jsonl')


class ReceiverConfigError(RuntimeError):
    pass


def _private_token(path: Path) -> bytes:
    if not path.is_absolute() or not path.is_file():
        raise ReceiverConfigError('alert receiver token file must be an existing absolute path')
    info = path.stat()
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ReceiverConfigError('alert receiver token file must be mode 0600 or stricter')
    token = path.read_bytes().strip()
    if len(token) < 32 or len(token) > 512 or any(ch in token for ch in b'\r\n\x00'):
        raise ReceiverConfigError('alert receiver token has invalid length or control characters')
    return token


def _safe_label_set(alerts: list[object], name: str) -> list[str]:
    values: set[str] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        labels = alert.get('labels')
        if not isinstance(labels, dict):
            continue
        value = str(labels.get(name, '')).strip()
        if value and len(value) <= 256 and all(ord(ch) >= 32 and ord(ch) != 127 for ch in value):
            values.add(value)
    return sorted(values)[:64]


class ReceiverState:
    def __init__(self, token: bytes | None, audit_file: Path) -> None:
        self.token = token
        self.audit_file = audit_file
        self.lock = threading.Lock()
        self.events_total = 0
        self.unauthorized_total = 0
        self.rejected_total = 0
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        audit_file.parent.chmod(0o700)

    def record(self, payload: dict[str, object], raw: bytes) -> None:
        alerts = payload.get('alerts', [])
        assert isinstance(alerts, list)
        record = {
            'schema': 'aegisscan.alert-receiver-event.v1',
            'received_at': datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
            'status': str(payload.get('status', ''))[:32],
            'receiver': str(payload.get('receiver', ''))[:128],
            'alert_count': len(alerts),
            'alertnames': _safe_label_set(alerts, 'alertname'),
            'services': _safe_label_set(alerts, 'service'),
            'severities': _safe_label_set(alerts, 'severity'),
            'release_shas': _safe_label_set(alerts, 'release_sha'),
            'payload_sha256': hashlib.sha256(raw).hexdigest(),
        }
        line = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')
        with self.lock:
            if self.audit_file.exists() and self.audit_file.stat().st_size + len(line) > MAX_AUDIT_BYTES:
                rotated = self.audit_file.with_name(self.audit_file.name + '.1')
                try:
                    rotated.unlink()
                except FileNotFoundError:
                    pass
                os.replace(self.audit_file, rotated)
                os.chmod(rotated, 0o600)
            fd = os.open(self.audit_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.chmod(self.audit_file, 0o600)
                with os.fdopen(fd, 'ab', buffering=0, closefd=False) as stream:
                    stream.write(line)
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
            self.events_total += 1


class Receiver(BaseHTTPRequestHandler):
    state: ReceiverState
    server_version = 'AegisAlertReceiver'
    sys_version = ''

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

    def _text(self, status: int, body: str, content_type: str) -> None:
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == '/ready':
            self._text(200, '{"status":"ready"}\n', 'application/json')
            return
        if self.path == '/metrics':
            with self.state.lock:
                body = (
                    f'aegis_alert_receiver_events_total {self.state.events_total}\n'
                    f'aegis_alert_receiver_unauthorized_total {self.state.unauthorized_total}\n'
                    f'aegis_alert_receiver_rejected_total {self.state.rejected_total}\n'
                )
            self._text(200, body, 'text/plain; version=0.0.4')
            return
        self._empty(404)

    def do_POST(self) -> None:
        if self.path != '/alert':
            self._empty(404)
            return
        authorization = self.headers.get('Authorization', '')
        if self.state.token is None:
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(503)
            return
        expected = b'Bearer ' + self.state.token
        if not hmac.compare_digest(authorization.encode('utf-8', 'ignore'), expected):
            with self.state.lock:
                self.state.unauthorized_total += 1
            self._empty(401)
            return
        if self.headers.get('Content-Type', '').split(';', 1)[0].strip().lower() != 'application/json':
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(415)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(413)
            return
        raw = self.rfile.read(length)
        if len(raw) != length:
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(400)
            return
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if not isinstance(payload, dict):
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(400)
            return
        alerts = payload.get('alerts')
        if not isinstance(alerts, list) or not alerts or len(alerts) > MAX_ALERTS:
            with self.state.lock:
                self.state.rejected_total += 1
            self._empty(400)
            return
        try:
            self.state.record(payload, raw)
        except OSError:
            self._empty(503)
            return
        self._empty(202)

    def log_message(self, _fmt: str, *_args: object) -> None:
        return


def serve(host: str, port: int, token_file: Path, audit_file: Path, *, allow_standby: bool = False) -> None:
    if host not in {'0.0.0.0', '127.0.0.1'}:
        raise ReceiverConfigError('alert receiver bind host is not allowed')
    if port < 1 or port > 65535:
        raise ReceiverConfigError('alert receiver port is invalid')
    try:
        token = _private_token(token_file)
    except ReceiverConfigError:
        if not allow_standby:
            raise
        token = None
    state = ReceiverState(token, audit_file)
    Receiver.state = state
    server = ThreadingHTTPServer((host, port), Receiver)
    server.daemon_threads = True
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default=os.environ.get('AEGIS_ALERT_RECEIVER_HOST', '0.0.0.0'))
    parser.add_argument('--port', type=int, default=int(os.environ.get('AEGIS_ALERT_RECEIVER_PORT', '8080')))
    parser.add_argument('--token-file', type=Path, default=Path(os.environ.get('AEGIS_ALERT_RECEIVER_TOKEN_FILE', str(DEFAULT_TOKEN_FILE))))
    parser.add_argument('--audit-file', type=Path, default=Path(os.environ.get('AEGIS_ALERT_RECEIVER_AUDIT_FILE', str(DEFAULT_AUDIT_FILE))))
    args = parser.parse_args()
    allow_standby = os.environ.get('AEGIS_ALERT_RECEIVER_ALLOW_STANDBY', 'false').strip().lower() in {'1','true','yes','on'}
    try:
        serve(args.host, args.port, args.token_file, args.audit_file, allow_standby=allow_standby)
    except ReceiverConfigError as exc:
        print(json.dumps({'schema':'aegisscan.alert-receiver.v1','status':'failed','error':str(exc)}, sort_keys=True), file=os.sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
