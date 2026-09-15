#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REAL_AMASS = '/usr/local/libexec/amass-real'
LOCK_PATH = '/tmp/aegis-amass-v5.lock'
WORKDIR_PREFIX = 'aegis-amass-v5-'
ENGINE_HOST = '127.0.0.1'
ENGINE_PORT = 4000
ENGINE_URL = f'http://{ENGINE_HOST}:{ENGINE_PORT}'
ENGINE_AUTH_HEADER = 'X-Aegis-Amass-Token'
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
)
_TOKEN_RE = re.compile(r'^[a-f0-9]{64}$')


class AdapterError(RuntimeError):
    pass


def _canonical_domain(value: str) -> str:
    target = str(value or '').strip().lower().rstrip('.')
    if not _DOMAIN_RE.fullmatch(target):
        raise AdapterError('Amass adapter target must be a canonical domain name')
    return target


def _managed_enum_request(argv: list[str]) -> tuple[str, int] | None:
    if argv in (['-version'], ['--version']):
        return None
    if not argv or argv[0] != 'enum':
        raise AdapterError('Amass adapter permits only the governed enum contract and version queries')
    if len(argv) != 6 or argv[1] != '-passive' or argv[2] != '-d' or argv[4] != '-timeout':
        raise AdapterError('Amass enum command does not match the governed production contract')
    target = _canonical_domain(argv[3])
    try:
        timeout_minutes = int(argv[5])
    except ValueError as exc:
        raise AdapterError('Amass timeout must be an integer') from exc
    if timeout_minutes < 1 or timeout_minutes > 30:
        raise AdapterError('Amass timeout must be between 1 and 30 minutes')
    return target, timeout_minutes


def _new_engine_token() -> str:
    token = secrets.token_hex(32)
    if not _TOKEN_RE.fullmatch(token):
        raise AdapterError('Failed to generate a valid Amass engine authentication token')
    return token


def _minimal_environment(root: Path) -> dict[str, str]:
    home = root / 'home'
    cache = root / 'cache'
    config = root / 'config'
    temp = root / 'tmp'
    for path in (home, cache, config, temp):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        'HOME': str(home),
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'NO_COLOR': '1',
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'TMPDIR': str(temp),
        'XDG_CACHE_HOME': str(cache),
        'XDG_CONFIG_HOME': str(config),
    }
    for key in ('SSL_CERT_FILE', 'SSL_CERT_DIR'):
        value = os.environ.get(key, '').strip()
        if value:
            environment[key] = value
    return environment


def _port_open() -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex((ENGINE_HOST, ENGINE_PORT)) == 0
    finally:
        sock.close()


def _health_ok(token: str) -> bool:
    if not _TOKEN_RE.fullmatch(token):
        return False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        ENGINE_URL + '/api/v1/health',
        method='GET',
        headers={
            'Accept': 'application/json',
            ENGINE_AUTH_HEADER: token,
        },
    )
    try:
        with opener.open(request, timeout=0.5) as response:
            raw = response.read(4097)
            if response.status != 200 or len(raw) > 4096:
                return False
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return False
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict)


def _wait_for_engine(
    process: subprocess.Popen[bytes],
    token: str,
    timeout_seconds: float = 12.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AdapterError(f'Amass engine exited before becoming healthy (exit={process.returncode})')
        if _health_ok(token):
            return
        time.sleep(0.1)
    raise AdapterError('Amass engine did not become healthy within the startup deadline')


def _stop_engine(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_for_port_close(timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _port_open():
            return
        time.sleep(0.1)
    raise AdapterError('Amass engine listener remained reachable after shutdown')


def _cleanup_stale_workdirs() -> None:
    root = Path('/tmp')
    for path in root.glob(WORKDIR_PREFIX + '*'):
        try:
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)
        except OSError:
            continue


def _bounded_diagnostic(*parts: str) -> str:
    text = '\n'.join(part.strip() for part in parts if part and part.strip())
    raw = text.encode('utf-8', errors='replace')
    if len(raw) <= MAX_DIAGNOSTIC_BYTES:
        return text
    return raw[:MAX_DIAGNOSTIC_BYTES].decode('utf-8', errors='replace') + '\n[diagnostic truncated]'


def _run_command(
    argv: list[str],
    *,
    environment: dict[str, str],
    cwd: Path,
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            env=environment,
            cwd=str(cwd),
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterError(f'Amass subprocess exceeded its bounded deadline: {argv[1]}') from exc


def _run_managed_enum(target: str, timeout_minutes: int) -> int:
    if not Path(REAL_AMASS).is_file() or not os.access(REAL_AMASS, os.X_OK):
        raise AdapterError('Pinned Amass v5 runtime binary is unavailable')

    lock_fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    engine: subprocess.Popen[bytes] | None = None
    owned_listener = False
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AdapterError('Concurrent Amass execution is rejected because the v5 engine uses a fixed local port') from exc

        _cleanup_stale_workdirs()
        if _port_open():
            raise AdapterError('Pre-existing listener on Amass engine port 4000 detected; refusing cross-scan reuse')

        with tempfile.TemporaryDirectory(prefix=WORKDIR_PREFIX, dir='/tmp') as root_value:
            root = Path(root_value)
            os.chmod(root, 0o700)
            database = root / 'graph'
            logs = root / 'logs'
            database.mkdir(mode=0o700)
            logs.mkdir(mode=0o700)
            environment = _minimal_environment(root)
            engine_token = _new_engine_token()
            environment['AEGIS_AMASS_ENGINE_TOKEN'] = engine_token

            engine = subprocess.Popen(
                [REAL_AMASS, 'engine', '-silent', '-log-dir', str(logs)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                env=environment,
                cwd=str(root),
            )
            _wait_for_engine(engine, engine_token)
            owned_listener = True

            enum_result = _run_command(
                [
                    REAL_AMASS,
                    'enum',
                    '-passive',
                    '-d',
                    target,
                    '-timeout',
                    str(timeout_minutes),
                    '-dir',
                    str(database),
                    '-engine',
                    ENGINE_URL,
                    '-nocolor',
                ],
                environment=environment,
                cwd=root,
                timeout_seconds=(timeout_minutes * 60) + 20,
            )
            _stop_engine(engine)
            engine = None
            _wait_for_port_close()
            owned_listener = False

            if enum_result.returncode != 0:
                diagnostic = _bounded_diagnostic(enum_result.stderr, enum_result.stdout)
                raise AdapterError(
                    f'Amass enum failed with exit={enum_result.returncode}' +
                    (f': {diagnostic}' if diagnostic else '')
                )

            subs_result = _run_command(
                [
                    REAL_AMASS,
                    'subs',
                    '-names',
                    '-d',
                    target,
                    '-dir',
                    str(database),
                    '-nocolor',
                ],
                environment=environment,
                cwd=root,
                timeout_seconds=20,
            )
            if subs_result.returncode != 0:
                diagnostic = _bounded_diagnostic(subs_result.stderr, subs_result.stdout)
                raise AdapterError(
                    f'Amass subs extraction failed with exit={subs_result.returncode}' +
                    (f': {diagnostic}' if diagnostic else '')
                )

            output = subs_result.stdout.encode('utf-8', errors='replace')
            if len(output) > MAX_OUTPUT_BYTES:
                raise AdapterError('Amass discovered-name output exceeded the 2 MiB adapter limit')
            sys.stdout.write(subs_result.stdout)
            diagnostic = _bounded_diagnostic(enum_result.stderr, subs_result.stderr)
            if diagnostic:
                sys.stderr.write(diagnostic + ('\n' if not diagnostic.endswith('\n') else ''))
            return 0
    finally:
        _stop_engine(engine)
        if owned_listener:
            try:
                _wait_for_port_close()
            except AdapterError:
                pass
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        request = _managed_enum_request(args)
        if request is None:
            os.execv(REAL_AMASS, [REAL_AMASS, *args])
            raise AssertionError('os.execv returned unexpectedly')
        target, timeout_minutes = request
        return _run_managed_enum(target, timeout_minutes)
    except AdapterError as exc:
        print(f'aegis-amass-v5: {exc}', file=sys.stderr)
        return 70


if __name__ == '__main__':
    raise SystemExit(main())
