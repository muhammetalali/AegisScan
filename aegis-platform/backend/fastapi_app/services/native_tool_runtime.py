from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal

from .scanner_adapters import ScanResult, validate_authorized_target, validate_authorized_web_target
from .scope_authorization import require_authorized_target

TargetKind = Literal['host', 'network', 'url', 'path', 'image']


class NativeExecutionCancelled(RuntimeError):
    pass


@dataclass(frozen=True)
class OptionSpec:
    flag: str | None
    kind: Literal['str', 'int', 'bool', 'choice'] = 'str'
    default: Any = None
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class NativeToolSpec:
    capability_id: str
    binary: str
    category: str
    description: str
    scan_type: str
    asset_types: tuple[str, ...]
    risk: str
    target_kind: TargetKind
    target_flag: str | None = None
    target_suffix: str = ''
    prefix_args: tuple[str, ...] = ()
    suffix_args: tuple[str, ...] = ()
    options: tuple[tuple[str, OptionSpec], ...] = ()
    timeout: int = 600

    @property
    def option_map(self) -> dict[str, OptionSpec]:
        return dict(self.options)


NATIVE_TOOL_SPECS: dict[str, NativeToolSpec] = {
    'network.rustscan': NativeToolSpec('network.rustscan', 'rustscan', 'network-reconnaissance', 'Fast authorized TCP discovery with service handoff.', 'ip', ('ip_address', 'domain'), 'active-medium', 'host', '-a', suffix_args=('--', '-sV'), timeout=420),
    'network.nbtscan-host': NativeToolSpec('network.nbtscan-host', 'nbtscan', 'network-reconnaissance', 'NetBIOS name discovery for an authorized host.', 'ip', ('ip_address',), 'active-low', 'host', None, timeout=180),
    'network.nbtscan-range': NativeToolSpec('network.nbtscan-range', 'nbtscan', 'network-reconnaissance', 'NetBIOS name discovery across an authorized network range.', 'network', ('network_range',), 'active-low', 'network', None, timeout=300),
    'recon.amass': NativeToolSpec('recon.amass', 'amass', 'asset-discovery', 'Passive DNS and subdomain enumeration.', 'ip', ('domain',), 'passive', 'host', '-d', prefix_args=('enum', '-passive'), timeout=900),
    'recon.subfinder': NativeToolSpec('recon.subfinder', 'subfinder', 'asset-discovery', 'Passive subdomain enumeration.', 'ip', ('domain',), 'passive', 'host', '-d', suffix_args=('-silent',), timeout=600),
    'recon.dnsenum': NativeToolSpec('recon.dnsenum', 'dnsenum', 'dns-reconnaissance', 'Authorized DNS enumeration.', 'ip', ('domain',), 'active-low', 'host', None, timeout=600),
    'recon.fierce': NativeToolSpec('recon.fierce', 'fierce', 'dns-reconnaissance', 'Authorized DNS discovery and hostname enumeration.', 'ip', ('domain',), 'active-low', 'host', '--domain', timeout=600),
    'web.httpx': NativeToolSpec('web.httpx', 'httpx', 'web-discovery', 'HTTP service probing and metadata collection.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', '-u', suffix_args=('-json', '-silent'), timeout=600),
    'web.katana': NativeToolSpec('web.katana', 'katana', 'web-discovery', 'Web crawling and endpoint discovery.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', '-u', suffix_args=('-jsonl', '-silent'), options=(('depth', OptionSpec('-d', 'int', 3, 1, 5)),), timeout=900),
    'web.gobuster': NativeToolSpec('web.gobuster', 'gobuster', 'content-discovery', 'Directory and content discovery against an authorized web asset.', 'url', ('website',), 'active-medium', 'url', '-u', prefix_args=('dir',), options=(('wordlist', OptionSpec('-w', 'str', '/opt/aegis-wordlists/web-common.txt')), ('threads', OptionSpec('-t', 'int', 10, 1, 50))), timeout=1200),
    'web.dirb': NativeToolSpec('web.dirb', 'dirb', 'content-discovery', 'Bounded dictionary-driven web content discovery.', 'url', ('website',), 'active-medium', 'url', None, options=(('wordlist', OptionSpec(None, 'str', '/opt/aegis-wordlists/web-common.txt')),), suffix_args=('-S',), timeout=1200),
    'web.feroxbuster': NativeToolSpec('web.feroxbuster', 'feroxbuster', 'content-discovery', 'Recursive content discovery against an authorized web asset.', 'url', ('website',), 'active-medium', 'url', '-u', suffix_args=('--json', '--silent'), options=(('threads', OptionSpec('-t', 'int', 10, 1, 50)),), timeout=1200),
    'web.ffuf': NativeToolSpec('web.ffuf', 'ffuf', 'content-discovery', 'Wordlist-driven endpoint discovery.', 'url', ('website', 'api_endpoint'), 'active-medium', 'url', '-u', target_suffix='/FUZZ', suffix_args=('-of', 'json', '-o', '/dev/stdout'), options=(('wordlist', OptionSpec('-w', 'str', '/opt/aegis-wordlists/web-common.txt')), ('threads', OptionSpec('-t', 'int', 20, 1, 50))), timeout=1200),
    'web.nikto': NativeToolSpec('web.nikto', 'nikto', 'web-vulnerability-assessment', 'Web server misconfiguration and exposure assessment.', 'url', ('website',), 'active-medium', 'url', '-h', suffix_args=('-Format', 'json', '-output', '/dev/stdout'), timeout=1200),
    'web.waf-detection': NativeToolSpec('web.waf-detection', 'wafw00f', 'web-fingerprinting', 'Web application firewall fingerprinting.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=300),
    'container.trivy-image': NativeToolSpec('container.trivy-image', 'trivy', 'container-security', 'Container image vulnerability and misconfiguration assessment.', 'docker', ('docker_image',), 'passive', 'image', None, prefix_args=('image', '--format', 'json', '--quiet'), timeout=1800),
    'code.checkov': NativeToolSpec('code.checkov', 'checkov', 'iac-security', 'Infrastructure-as-code policy and misconfiguration analysis.', 'code', ('source_code', 'repository'), 'passive', 'path', '-d', suffix_args=('-o', 'json', '--quiet'), timeout=1200),
    'code.terrascan': NativeToolSpec('code.terrascan', 'terrascan', 'iac-security', 'Infrastructure-as-code security policy analysis.', 'code', ('source_code', 'repository'), 'passive', 'path', '-d', prefix_args=('scan',), suffix_args=('-o', 'json'), timeout=1200),
    'code.trufflehog': NativeToolSpec('code.trufflehog', 'trufflehog', 'secret-detection', 'Repository and filesystem secret discovery.', 'code', ('source_code', 'repository'), 'passive', 'path', None, prefix_args=('filesystem',), suffix_args=('--json', '--no-update'), timeout=1200),
    'binary.checksec': NativeToolSpec('binary.checksec', 'checksec', 'binary-analysis', 'Executable hardening and mitigation inspection.', 'file', ('file',), 'passive', 'path', '--file', timeout=180),
    'binary.strings': NativeToolSpec('binary.strings', 'strings', 'binary-analysis', 'Printable string extraction for binary triage.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-a',), timeout=180),
    'binary.objdump': NativeToolSpec('binary.objdump', 'objdump', 'binary-analysis', 'Object file headers and metadata inspection.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-x',), timeout=300),
    'binary.readelf': NativeToolSpec('binary.readelf', 'readelf', 'binary-analysis', 'ELF headers, sections and program metadata inspection.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-a',), timeout=300),
    'binary.xxd': NativeToolSpec('binary.xxd', 'xxd', 'binary-analysis', 'Bounded hexadecimal dump for binary triage.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-g', '1', '-l', '65536'), timeout=180),
    'binary.gdb-metadata': NativeToolSpec('binary.gdb-metadata', 'gdb', 'binary-analysis', 'Non-interactive debugger metadata inspection with fixed commands.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-q', '-batch', '-ex', 'info files', '-ex', 'info functions'), timeout=300),
    'binary.binwalk': NativeToolSpec('binary.binwalk', 'binwalk', 'binary-analysis', 'Embedded file signature and firmware structure analysis.', 'file', ('file',), 'passive', 'path', None, timeout=600),
    'forensics.exiftool': NativeToolSpec('forensics.exiftool', 'exiftool', 'forensics', 'Metadata extraction for uploaded evidence and files.', 'file', ('file',), 'passive', 'path', None, prefix_args=('-json',), timeout=180),
}


def get_native_tool_spec(capability_id: str) -> NativeToolSpec:
    try:
        return NATIVE_TOOL_SPECS[capability_id]
    except KeyError as exc:
        raise ValueError(f'No native tool adapter for capability: {capability_id}') from exc


def validate_native_options(spec: NativeToolSpec, options: dict[str, Any]) -> dict[str, Any]:
    definitions = spec.option_map
    unknown = sorted(set(options) - set(definitions))
    if unknown:
        raise ValueError(f'Unsupported options for {spec.capability_id}: {unknown}')
    normalized: dict[str, Any] = {}
    for name, definition in definitions.items():
        value = options.get(name, definition.default)
        if value is None or value == '':
            continue
        if definition.kind == 'int':
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f'{name} must be an integer') from exc
            if definition.minimum is not None and value < definition.minimum:
                raise ValueError(f'{name} must be >= {definition.minimum}')
            if definition.maximum is not None and value > definition.maximum:
                raise ValueError(f'{name} must be <= {definition.maximum}')
        elif definition.kind == 'bool':
            if not isinstance(value, bool):
                raise ValueError(f'{name} must be a boolean')
        else:
            value = str(value).strip()
            if not value or len(value) > 2048 or any(ch in value for ch in '\r\n\x00'):
                raise ValueError(f'{name} is invalid')
            if definition.kind == 'choice' and value not in definition.choices:
                raise ValueError(f'{name} must be one of {definition.choices}')
            if name == 'wordlist':
                path = Path(value).expanduser().resolve()
                allowed_root = Path(os.getenv('AEGIS_WORDLIST_ROOT', '/opt/aegis-wordlists')).resolve()
                if allowed_root != path and allowed_root not in path.parents:
                    raise ValueError('wordlist must be inside AEGIS_WORDLIST_ROOT')
                value = str(path)
        normalized[name] = value
    return normalized


def _validated_target(spec: NativeToolSpec, target: str) -> str:
    if spec.target_kind == 'url':
        value = validate_authorized_web_target(target)
        require_authorized_target(value, url=True, resolve_dns=True)
        return value
    if spec.target_kind in {'host', 'network'}:
        value = validate_authorized_target(target)
        require_authorized_target(value, resolve_dns=True)
        return value
    if spec.target_kind == 'path':
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise ValueError(f'Asset path does not exist on the worker: {path}')
        return str(path)
    value = str(target).strip()
    if not value or len(value) > 1024 or any(ch in value for ch in '\r\n\x00'):
        raise ValueError('Invalid asset target')
    return value


def build_native_argv(spec: NativeToolSpec, target: str, options: dict[str, Any]) -> tuple[list[str], str]:
    executable = shutil.which(spec.binary)
    if not executable:
        raise RuntimeError(f'{spec.binary} is not installed on the scanner worker')
    target = _validated_target(spec, target)
    normalized = validate_native_options(spec, options)
    if 'wordlist' in normalized and not Path(str(normalized['wordlist'])).is_file():
        raise ValueError('wordlist does not exist on the scanner worker')
    command_target = target.rstrip('/') + spec.target_suffix if spec.target_suffix else target
    argv = [executable, *spec.prefix_args]
    if spec.target_flag:
        argv.extend([spec.target_flag, command_target])
    else:
        argv.append(command_target)
    for name, definition in spec.options:
        if name not in normalized:
            continue
        value = normalized[name]
        if definition.kind == 'bool':
            if value and definition.flag:
                argv.append(definition.flag)
        elif definition.flag:
            argv.extend([definition.flag, str(value)])
        else:
            argv.append(str(value))
    argv.extend(spec.suffix_args)
    return argv, target


def _terminate_process_group(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGCONT)
    except ProcessLookupError:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    except ProcessLookupError:
        pass


def run_native_tool(
    capability_id: str,
    target: str,
    options: dict[str, Any],
    state_getter: Callable[[], str] | None = None,
    poll_interval: float = 0.5,
) -> ScanResult:
    spec = get_native_tool_spec(capability_id)
    argv, canonical_target = build_native_argv(spec, target, options)
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        start_new_session=True,
        env={**os.environ, 'NO_COLOR': '1'},
    )
    deadline = time.monotonic() + spec.timeout
    paused = False
    while True:
        state = state_getter() if state_getter is not None else 'running'
        if state == 'cancelled':
            _terminate_process_group(process)
            raise NativeExecutionCancelled('Native capability execution cancelled')
        if state == 'paused' and not paused and process.poll() is None:
            os.killpg(process.pid, signal.SIGSTOP)
            paused = True
        elif state != 'paused' and paused and process.poll() is None:
            os.killpg(process.pid, signal.SIGCONT)
            paused = False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            raise subprocess.TimeoutExpired(argv, spec.timeout)
        try:
            stdout, stderr = process.communicate(timeout=min(poll_interval, remaining))
            return ScanResult(spec.binary, canonical_target, process.returncode or 0, stdout, stderr)
        except subprocess.TimeoutExpired:
            continue
