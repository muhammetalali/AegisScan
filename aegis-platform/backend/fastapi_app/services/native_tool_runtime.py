from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal

from .cloud_target import canonical_cloud_target
from .scanner_adapters import ScanResult, validate_authorized_target, validate_authorized_web_target
from .scope_authorization import require_authorized_target

TargetKind = Literal['host', 'network', 'url', 'path', 'image', 'cloud']
CredentialMode = Literal['none', 'curl-bearer-config', 'kubeconfig-file', 'cloud-credentials-file', 'browser-session-file']
CaptureMode = Literal['stdout', 'nikto-json-file']


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
    credential_mode: CredentialMode = 'none'
    credential_kinds: tuple[str, ...] = ()
    credential_required: bool = False
    capture_mode: CaptureMode = 'stdout'

    @property
    def option_map(self) -> dict[str, OptionSpec]:
        return dict(self.options)


NATIVE_TOOL_SPECS: dict[str, NativeToolSpec] = {
    'network.rustscan': NativeToolSpec('network.rustscan', 'rustscan', 'network-reconnaissance', 'Fast authorized TCP discovery with service handoff.', 'ip', ('ip_address', 'domain'), 'active-medium', 'host', '-a', options=(('ports', OptionSpec('-p', 'str', None)),), suffix_args=('--', '-sV'), timeout=420),
    'network.nbtscan-host': NativeToolSpec('network.nbtscan-host', 'nbtscan', 'network-reconnaissance', 'NetBIOS name discovery for an authorized host.', 'ip', ('ip_address',), 'active-low', 'host', None, timeout=180),
    'network.nbtscan-range': NativeToolSpec('network.nbtscan-range', 'nbtscan', 'network-reconnaissance', 'NetBIOS name discovery across an authorized network range.', 'network', ('network_range',), 'active-low', 'network', None, timeout=300),
    'recon.amass': NativeToolSpec('recon.amass', 'amass', 'asset-discovery', 'Passive DNS and subdomain enumeration.', 'ip', ('domain',), 'passive', 'host', '-d', prefix_args=('enum', '-passive'), options=(('timeout_minutes', OptionSpec('-timeout', 'int', 5, 1, 30)),), timeout=1830),
    'recon.subfinder': NativeToolSpec('recon.subfinder', 'subfinder', 'asset-discovery', 'Passive subdomain enumeration.', 'ip', ('domain',), 'passive', 'host', '-d', suffix_args=('-silent',), timeout=600),
    'recon.dnsenum': NativeToolSpec('recon.dnsenum', 'dnsenum', 'dns-reconnaissance', 'Authorized DNS enumeration.', 'ip', ('domain',), 'active-low', 'host', None, timeout=600),
    'recon.fierce': NativeToolSpec('recon.fierce', 'fierce', 'dns-reconnaissance', 'Authorized DNS discovery and hostname enumeration.', 'ip', ('domain',), 'active-low', 'host', '--domain', timeout=600),
    'web.httpx': NativeToolSpec('web.httpx', 'httpx', 'web-discovery', 'HTTP service probing and metadata collection.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', '-u', suffix_args=('-json', '-silent'), timeout=600),
    'web.katana': NativeToolSpec('web.katana', 'katana', 'web-discovery', 'Web crawling and endpoint discovery.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', '-u', suffix_args=('-jsonl', '-silent'), options=(('depth', OptionSpec('-d', 'int', 3, 1, 5)),), timeout=900),
    'web.security-headers': NativeToolSpec(
        'web.security-headers', 'curl', 'web-fingerprinting',
        'HTTP response header and redirect inspection for an authorized web asset.',
        'url', ('website', 'api_endpoint'), 'active-low', 'url', None,
        prefix_args=(
            '--head', '--location', '--max-redirs', '3', '--connect-timeout', '5',
            '--max-time', '20', '--silent', '--show-error', '--dump-header', '-',
            '--output', '/dev/null',
        ),
        timeout=120,
        credential_mode='curl-bearer-config',
        credential_kinds=('token', 'api_key', 'generic'),
    ),
    'browser.dom-snapshot': NativeToolSpec(
        'browser.dom-snapshot', 'aegis-browser-security', 'browser-security',
        'Headless browser DOM and browser-security posture snapshot for an authorized web asset.',
        'url', ('website',), 'active-low', 'url', None,
        options=(
            ('browser', OptionSpec('--browser', 'choice', 'auto', choices=('auto', 'chromium', 'firefox'))),
            ('virtual_time_budget_ms', OptionSpec('--virtual-time-budget-ms', 'int', 3000, 1000, 10000)),
            ('max_dom_bytes', OptionSpec('--max-dom-bytes', 'int', 262144, 65536, 1048576)),
        ),
        timeout=120,
    ),
    'browser.spa-discovery': NativeToolSpec(
        'browser.spa-discovery', 'aegis-browser-spa-discovery', 'browser-security',
        'Stateful Chromium CDP discovery of SPA routes, runtime HTTP APIs, GraphQL operations, WebSocket channels, browser storage metadata and client-side security signals.',
        'url', ('website',), 'active-low', 'url', None,
        options=(
            ('identity_ref', OptionSpec('--identity-ref', 'str', 'anonymous')),
            ('wait_ms', OptionSpec('--wait-ms', 'int', 4000, 1000, 15000)),
            ('max_events', OptionSpec('--max-events', 'int', 2000, 100, 5000)),
        ),
        timeout=180,
        credential_mode='browser-session-file',
        credential_kinds=('generic',),
    ),
    'web.gobuster': NativeToolSpec('web.gobuster', 'gobuster', 'content-discovery', 'Directory and content discovery against an authorized web asset.', 'url', ('website',), 'active-medium', 'url', '-u', prefix_args=('dir',), options=(('wordlist', OptionSpec('-w', 'str', '/opt/aegis-wordlists/web-common.txt')), ('threads', OptionSpec('-t', 'int', 10, 1, 50))), timeout=1200),
    'web.dirb': NativeToolSpec('web.dirb', 'dirb', 'content-discovery', 'Bounded dictionary-driven web content discovery.', 'url', ('website',), 'active-medium', 'url', None, options=(('wordlist', OptionSpec(None, 'str', '/opt/aegis-wordlists/web-common.txt')),), suffix_args=('-S',), timeout=1200),
    'web.feroxbuster': NativeToolSpec('web.feroxbuster', 'feroxbuster', 'content-discovery', 'Recursive content discovery against an authorized web asset.', 'url', ('website',), 'active-medium', 'url', '-u', suffix_args=('--json', '--silent', '--no-state'), options=(('wordlist', OptionSpec('-w', 'str', '/opt/aegis-wordlists/web-common.txt')), ('threads', OptionSpec('-t', 'int', 10, 1, 50)), ('depth', OptionSpec('-d', 'int', 2, 1, 4))), timeout=1200),
    'web.ffuf': NativeToolSpec('web.ffuf', 'ffuf', 'content-discovery', 'Wordlist-driven endpoint discovery.', 'url', ('website', 'api_endpoint'), 'active-medium', 'url', '-u', target_suffix='/FUZZ', suffix_args=('-of', 'json', '-o', '/dev/stdout'), options=(('wordlist', OptionSpec('-w', 'str', '/opt/aegis-wordlists/web-common.txt')), ('threads', OptionSpec('-t', 'int', 20, 1, 50))), timeout=1200),
    'web.nikto': NativeToolSpec('web.nikto', 'nikto', 'web-vulnerability-assessment', 'Web server misconfiguration and exposure assessment.', 'url', ('website',), 'active-medium', 'url', '-h', suffix_args=('-nocheck', '-nointeractive', '-Format', 'json'), timeout=1200, capture_mode='nikto-json-file'),
    'web.waf-detection': NativeToolSpec('web.waf-detection', 'wafw00f', 'web-fingerprinting', 'Web application firewall fingerprinting.', 'url', ('website', 'api_endpoint'), 'active-low', 'url', None, timeout=300),
    'container.trivy-image': NativeToolSpec('container.trivy-image', 'trivy', 'container-security', 'Container image vulnerability and misconfiguration assessment.', 'docker', ('docker_image',), 'passive', 'image', None, prefix_args=('image', '--format', 'json', '--quiet'), timeout=1800),
    'code.checkov': NativeToolSpec('code.checkov', 'checkov', 'iac-security', 'Infrastructure-as-code policy and misconfiguration analysis.', 'code', ('source_code', 'repository'), 'passive', 'path', '-d', suffix_args=('-o', 'json', '--quiet'), timeout=1200),
    'code.trivy-config': NativeToolSpec('code.trivy-config', 'trivy', 'iac-security', 'Maintained infrastructure-as-code misconfiguration analysis using the image-seeded Trivy checks bundle.', 'code', ('source_code', 'repository'), 'passive', 'path', None, prefix_args=('--cache-dir', '/opt/trivy-cache', 'config', '--format', 'json', '--quiet', '--skip-check-update', '--skip-version-check'), timeout=1200),
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
            if name == 'ports':
                if len(value) > 128 or any(ch not in '0123456789,' for ch in value):
                    raise ValueError('ports must be a comma-separated numeric port list')
                parts = value.split(',')
                if (
                    not parts
                    or any(not part or not part.isdigit() for part in parts)
                    or any(int(part) < 1 or int(part) > 65535 for part in parts)
                ):
                    raise ValueError('ports must contain integers between 1 and 65535')
                value = ','.join(str(int(part)) for part in parts)
            if name == 'identity_ref':
                if len(value) > 255:
                    raise ValueError('identity_ref must be at most 255 characters')
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
    if spec.target_kind == 'cloud':
        return canonical_cloud_target(target)
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


def effective_native_timeout(spec: NativeToolSpec, options: dict[str, Any]) -> int:
    """Return the process watchdog timeout after applying bounded tool-level limits."""
    normalized = validate_native_options(spec, options)
    timeout_minutes = normalized.get('timeout_minutes')
    if timeout_minutes is not None:
        requested = int(timeout_minutes) * 60 + 30
        return min(spec.timeout, requested)
    return spec.timeout


def _material_secret(material: Mapping[str, Any]) -> str:
    secret = str(material.get('secret') or '')
    if not secret or len(secret) > 8192 or any(ch in secret for ch in '\r\n\x00'):
        raise ValueError('Credential material is not valid for native runtime injection')
    return secret


def _multiline_material_secret(material: Mapping[str, Any]) -> str:
    secret = str(material.get('secret') or '')
    if not secret or '\x00' in secret or len(secret.encode('utf-8')) > 262144:
        raise ValueError('Kubeconfig credential material must be UTF-8 text no larger than 256 KiB')
    return secret


def _cloud_material_secret(material: Mapping[str, Any]) -> str:
    secret = str(material.get('secret') or '')
    if not secret or '\x00' in secret or len(secret.encode('utf-8')) > 65536:
        raise ValueError('Cloud credential material must be UTF-8 JSON no larger than 64 KiB')
    try:
        data = json.loads(secret)
    except json.JSONDecodeError as exc:
        raise ValueError('Cloud credential material must be valid JSON') from exc
    if not isinstance(data, dict):
        raise ValueError('Cloud credential material must be a JSON object')
    return secret


def _browser_session_material_secret(material: Mapping[str, Any]) -> str:
    secret = str(material.get('secret') or '')
    if not secret or '\x00' in secret or len(secret.encode('utf-8')) > 65536:
        raise ValueError('Browser session credential must be UTF-8 JSON no larger than 64 KiB')
    try:
        data = json.loads(secret)
    except json.JSONDecodeError as exc:
        raise ValueError('Browser session credential must be valid JSON') from exc
    if not isinstance(data, dict):
        raise ValueError('Browser session credential must be a JSON object')
    unknown = set(data) - {'headers', 'cookies', 'local_storage', 'session_storage'}
    if unknown:
        raise ValueError(f'Browser session credential contains unsupported fields: {sorted(unknown)}')
    return secret


def _curl_config_for_bearer(secret: str) -> str:
    escaped = secret.replace('\\', '\\\\').replace('"', '\\"')
    fd, path = tempfile.mkstemp(prefix='aegis-credential-', suffix='.curlrc')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(f'header = "Authorization: Bearer {escaped}"\n')
    return path


def _kubeconfig_file(secret: str) -> str:
    fd, path = tempfile.mkstemp(prefix='aegis-credential-', suffix='.kubeconfig')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(secret)
    return path


def _cloud_credentials_file(secret: str) -> str:
    fd, path = tempfile.mkstemp(prefix='aegis-credential-', suffix='.cloud.json')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(secret)
    return path


def _browser_session_file(secret: str) -> str:
    fd, path = tempfile.mkstemp(prefix='aegis-credential-', suffix='.browser-session.json')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(secret)
    return path


def _credential_runtime_args(
    spec: NativeToolSpec,
    credential_materials: tuple[Mapping[str, Any], ...],
) -> tuple[list[str], list[str]]:
    if not credential_materials:
        if spec.credential_required:
            raise ValueError(f'{spec.capability_id} requires credential-bound execution')
        return [], []
    if spec.credential_mode == 'none':
        raise ValueError(f'{spec.capability_id} does not support credential-bound execution')
    if spec.credential_mode == 'curl-bearer-config':
        if len(credential_materials) != 1:
            raise ValueError('curl bearer credential execution accepts exactly one credential reference')
        path = _curl_config_for_bearer(_material_secret(credential_materials[0]))
        return ['--config', path], [path]
    if spec.credential_mode == 'kubeconfig-file':
        if len(credential_materials) != 1:
            raise ValueError('kubeconfig execution accepts exactly one credential reference')
        material = credential_materials[0]
        if str(material.get('kind') or '') != 'kubeconfig':
            raise ValueError('kubeconfig execution requires a kubeconfig credential')
        path = _kubeconfig_file(_multiline_material_secret(material))
        return ['--kubeconfig', path], [path]
    if spec.credential_mode == 'cloud-credentials-file':
        if len(credential_materials) != 1:
            raise ValueError('cloud execution accepts exactly one credential reference')
        material = credential_materials[0]
        if str(material.get('kind') or '') != 'cloud_access_key':
            raise ValueError('cloud execution requires a cloud_access_key credential')
        path = _cloud_credentials_file(_cloud_material_secret(material))
        return ['--credentials-file', path], [path]
    if spec.credential_mode == 'browser-session-file':
        if len(credential_materials) != 1:
            raise ValueError('browser session execution accepts exactly one credential reference')
        material = credential_materials[0]
        if str(material.get('kind') or '') != 'generic':
            raise ValueError('browser session execution requires a generic credential containing the session JSON')
        path = _browser_session_file(_browser_session_material_secret(material))
        return ['--session-file', path], [path]
    raise ValueError(f'Unsupported credential execution mode: {spec.credential_mode}')


def _native_environment(spec: NativeToolSpec) -> dict[str, str]:
    environment = dict(os.environ)
    if spec.credential_mode == 'cloud-credentials-file':
        blocked = {
            'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN',
            'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_CONFIG_FILE',
            'AWS_WEB_IDENTITY_TOKEN_FILE', 'AWS_ROLE_ARN', 'AWS_ROLE_SESSION_NAME',
            'AZURE_CLIENT_ID', 'AZURE_TENANT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH',
            'AZURE_USERNAME', 'AZURE_PASSWORD', 'AZURE_SUBSCRIPTION_ID',
            'GOOGLE_APPLICATION_CREDENTIALS', 'GOOGLE_CLOUD_PROJECT', 'GCLOUD_PROJECT', 'CLOUDSDK_CONFIG',
        }
        for key in blocked:
            environment.pop(key, None)
    environment['NO_COLOR'] = '1'
    return environment


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
    credential_materials: tuple[Mapping[str, Any], ...] | None = None,
) -> ScanResult:
    spec = get_native_tool_spec(capability_id)
    execution_timeout = effective_native_timeout(spec, options)
    argv, canonical_target = build_native_argv(spec, target, options)
    cleanup_paths: list[str] = []
    cleanup_dirs: list[str] = []
    captured_report_path: str | None = None
    process: subprocess.Popen[str] | None = None
    try:
        credential_args, cleanup_paths = _credential_runtime_args(spec, tuple(credential_materials or ()))
        if credential_args:
            argv = [argv[0], *credential_args, *argv[1:]]
        if spec.capture_mode == 'nikto-json-file':
            report_dir = tempfile.mkdtemp(prefix='aegis-nikto-')
            os.chmod(report_dir, 0o700)
            cleanup_dirs.append(report_dir)
            report_prefix = str(Path(report_dir) / 'report')
            captured_report_path = f'{report_prefix}.json'
            argv.extend(['-output', report_prefix])
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,
            env=_native_environment(spec),
            umask=0o077 if captured_report_path is not None else -1,
        )
        deadline = time.monotonic() + execution_timeout
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
                raise subprocess.TimeoutExpired(argv, execution_timeout)
            try:
                stdout, stderr = process.communicate(timeout=min(poll_interval, remaining))
                if captured_report_path is not None:
                    report_path = Path(captured_report_path)
                    if not report_path.is_file() or report_path.stat().st_size <= 0:
                        raise RuntimeError('Nikto did not produce its required JSON report')
                    report = report_path.read_text(encoding='utf-8', errors='replace')
                    console = stdout.strip()
                    if console:
                        stderr = '\n'.join(part for part in (stderr.strip(), console) if part)
                    stdout = report
                return ScanResult(spec.binary, canonical_target, process.returncode or 0, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        if process is not None and process.poll() is None:
            _terminate_process_group(process)
        raise
    finally:
        for path in cleanup_paths:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass
        for directory in cleanup_dirs:
            shutil.rmtree(directory, ignore_errors=True)
