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


def validate_authorized_target(target: str) -> str:
    value = target.strip()
    if not value or len(value) > 253 or any(c in value for c in '\r\n\x00'):
        raise ValueError('Invalid scan target')
    parsed = urlparse(value if '://' in value else f'//{value}')
    host = parsed.hostname or value
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.fullmatch(host) or host.startswith('.') or host.endswith('.'):
            raise ValueError('Invalid scan target')
    return host


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
