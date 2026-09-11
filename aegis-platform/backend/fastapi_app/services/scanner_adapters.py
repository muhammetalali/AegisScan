from __future__ import annotations

import ipaddress
import os
import re
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlparse

from .scope_authorization import require_authorized_target


@dataclass
class ScanResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str


class ScannerExecutionCancelled(RuntimeError):
    pass


_HOST_RE = re.compile(r'^[A-Za-z0-9.-]+$')
_URL_SCHEMES = {'http', 'https'}
_DEFAULT_NUCLEI_TEMPLATES = '/opt/nuclei-templates'


def validate_authorized_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > 253 or any(c in value for c in '\r\n\x00'):
        raise ValueError('Invalid scan target')
    if '://' not in value and '/' in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise ValueError('Invalid network scan target') from None
    parsed = urlparse(value if '://' in value else f'//{value}')
    if parsed.scheme and parsed.scheme not in _URL_SCHEMES:
        raise ValueError('Unsupported target URL scheme')
    host = parsed.hostname or value
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.fullmatch(host) or host.startswith('.') or host.endswith('.'):
            raise ValueError('Invalid scan target')
    return host


def validate_authorized_web_target(target: str) -> str:
    value = target.strip()
    parsed = urlparse(value)
    if parsed.scheme not in _URL_SCHEMES or not parsed.hostname:
        raise ValueError('A web scan requires an http/https URL')
    validate_authorized_target(parsed.hostname)
    return value


def validate_code_target(target: str) -> str:
    value = target.strip()
    if not value or '\x00' in value:
        raise ValueError('Invalid code scan target')
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise ValueError(f'Code scan target does not exist: {path}')
    if not path.is_dir():
        raise ValueError('Code scan target must be a directory')
    return str(path)


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def _run_controlled(
    argv: Sequence[str],
    *,
    tool: str,
    target: str,
    timeout: int,
    state_getter: Callable[[], str],
    poll_interval: float = 1.0,
) -> ScanResult:
    process = subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout
    paused = False
    try:
        while True:
            state = str(state_getter())
            if state == 'cancelled':
                _terminate_process_group(process)
                raise ScannerExecutionCancelled(f'{tool} execution cancelled')
            if state == 'paused' and not paused and process.poll() is None:
                os.killpg(process.pid, signal.SIGSTOP)
                paused = True
            elif state != 'paused' and paused and process.poll() is None:
                os.killpg(process.pid, signal.SIGCONT)
                paused = False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                raise subprocess.TimeoutExpired(list(argv), timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(poll_interval, remaining))
                return ScanResult(tool, target, process.returncode or 0, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        if process.poll() is None:
            _terminate_process_group(process)
        raise


def run_nmap(target: str, timeout: int = 300, state_getter: Callable[[], str] | None = None) -> ScanResult:
    host = validate_authorized_target(target)
    require_authorized_target(host, resolve_dns=True)
    executable = shutil.which('nmap')
    if not executable:
        raise RuntimeError('Nmap is not installed on the worker')
    argv = [executable, '-Pn', '-sV', '-oX', '-', '--', host]
    if state_getter is not None:
        return _run_controlled(argv, tool='nmap', target=host, timeout=timeout, state_getter=state_getter)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return ScanResult('nmap', host, completed.returncode, completed.stdout, completed.stderr)


def run_masscan(target: str, ports: str = '1-65535', rate: int = 1000, timeout: int = 300, state_getter: Callable[[], str] | None = None) -> ScanResult:
    host = validate_authorized_target(target)
    require_authorized_target(host, resolve_dns=True)
    if rate <= 0:
        raise ValueError('Masscan rate must be positive')
    executable = shutil.which('masscan')
    if not executable:
        raise RuntimeError('Masscan is not installed on the worker')
    argv = [executable, host, '-p', ports, '--rate', str(rate), '--output-format', 'json', '--output-filename', '-']
    if state_getter is not None:
        return _run_controlled(argv, tool='masscan', target=host, timeout=timeout, state_getter=state_getter)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return ScanResult('masscan', host, completed.returncode, completed.stdout, completed.stderr)


def run_nuclei(target: str, timeout: int = 600, state_getter: Callable[[], str] | None = None) -> ScanResult:
    url = validate_authorized_web_target(target)
    require_authorized_target(url, url=True, resolve_dns=True)
    executable = shutil.which('nuclei')
    if not executable:
        raise RuntimeError('Nuclei is not installed on the worker')

    templates_dir = os.getenv('NUCLEI_TEMPLATES_DIR', _DEFAULT_NUCLEI_TEMPLATES)
    templates_path = Path(templates_dir)
    if not templates_path.is_dir():
        raise RuntimeError(f'Nuclei templates directory is missing: {templates_dir}')

    # Nuclei supports -dr/--disable-redirects. Redirects are disabled so an
    # authorized URL cannot pivot the scanner to a different egress target.
    argv = [executable, '-u', url, '-t', str(templates_path), '-jsonl', '-silent', '-no-color', '-dr']
    if state_getter is not None:
        return _run_controlled(argv, tool='nuclei', target=url, timeout=timeout, state_getter=state_getter)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return ScanResult('nuclei', url, completed.returncode, completed.stdout, completed.stderr)


def run_semgrep(target: str, timeout: int = 600, state_getter: Callable[[], str] | None = None) -> ScanResult:
    path = validate_code_target(target)
    executable = shutil.which('semgrep')
    if not executable:
        raise RuntimeError('Semgrep is not installed on the worker')
    argv = [executable, '--config', os.getenv('SEMGREP_CONFIG', 'auto'), '--json', '--error', '--no-git-ignore', path]
    if state_getter is not None:
        return _run_controlled(argv, tool='semgrep', target=path, timeout=timeout, state_getter=state_getter)
    completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return ScanResult('semgrep', path, completed.returncode, completed.stdout, completed.stderr)
