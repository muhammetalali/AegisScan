from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ScanResult:
    tool: str
    target: str
    exit_code: int
    stdout: str
    stderr: str


_HOST_RE = re.compile(r'^[A-Za-z0-9.-]+$')
_URL_SCHEMES = {'http', 'https'}


def validate_authorized_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > 253 or any(c in value for c in '\r\n\x00'):
        raise ValueError('Invalid scan target')
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


def run_nmap(target: str, timeout: int = 300) -> ScanResult:
    host = validate_authorized_target(target)
    executable = shutil.which('nmap')
    if not executable:
        raise RuntimeError('Nmap is not installed on the worker')
    completed = subprocess.run(
        [executable, '-sV', '-oX', '-', '--', host],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return ScanResult('nmap', host, completed.returncode, completed.stdout, completed.stderr)


def run_nuclei(target: str, timeout: int = 600) -> ScanResult:
    url = validate_authorized_web_target(target)
    executable = shutil.which('nuclei')
    if not executable:
        raise RuntimeError('Nuclei is not installed on the worker')
    completed = subprocess.run(
        [executable, '-u', url, '-jsonl', '-silent', '-no-color'],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return ScanResult('nuclei', url, completed.returncode, completed.stdout, completed.stderr)
