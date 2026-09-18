from __future__ import annotations

import os
import re
import sys
import urllib.parse


_TRUTHY = {'1', 'true', 'yes', 'on'}
_HEX64 = re.compile(r'^[a-f0-9]{64}$')
_COMMIT = re.compile(r'^[a-f0-9]{40}$')
_SHA256 = re.compile(r'^sha256:[a-f0-9]{64}$')
_RUNTIME_TEXT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:/@-]{0,254}$')
_PIN_NAMES = (
    'AEGIS_KALI_CODE_EXPECTED_BASE_IMAGE_DIGEST',
    'AEGIS_KALI_CODE_EXPECTED_TOOL_MANIFEST_DIGEST',
    'AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST',
    'AEGIS_KALI_CODE_EXPECTED_RUNTIME_MANIFEST_DIGEST',
)


def _truthy(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def _selected_image_digest(value: str) -> str | None:
    image = value.strip()
    if _SHA256.fullmatch(image):
        return image
    if '@' not in image:
        return None
    digest = image.rsplit('@', 1)[1]
    return digest if _SHA256.fullmatch(digest) else None


def validate(environment: dict[str, str]) -> list[str]:
    """Validate M6 Semgrep production invariants before scanner startup."""
    if not _truthy(environment.get('AEGIS_SEMGREP_LEGACY_DISABLED', '')):
        return []

    failures: list[str] = []
    if environment.get('AEGIS_SEMGREP_PROVIDER', '').strip().lower() != 'default-kali':
        failures.append('AEGIS_SEMGREP_PROVIDER must be default-kali after M6 Semgrep retirement')
    if environment.get('AEGIS_KALI_SEMGREP_CANARY_BPS', '').strip() != '0':
        failures.append('AEGIS_KALI_SEMGREP_CANARY_BPS must be exactly 0 after M6 Semgrep retirement')
    if environment.get('AEGIS_SEMGREP_WORKSPACE_ROOT', '').strip() != '/var/lib/aegis-semgrep':
        failures.append('AEGIS_SEMGREP_WORKSPACE_ROOT must be /var/lib/aegis-semgrep after M6 Semgrep retirement')

    parsed = urllib.parse.urlparse(environment.get('AEGIS_KALI_CODE_URL', '').strip())
    try:
        port = parsed.port
    except ValueError:
        port = None
    if (
        parsed.scheme != 'http'
        or parsed.hostname != '127.0.0.1'
        or parsed.username
        or parsed.password
        or parsed.path not in {'', '/'}
        or parsed.query
        or parsed.fragment
        or port is None
        or port < 1024
        or port > 65535
    ):
        failures.append('AEGIS_KALI_CODE_URL must be an explicit http://127.0.0.1 high-port endpoint')

    if not _HEX64.fullmatch(environment.get('AEGIS_KALI_CODE_AUTH_TOKEN', '').strip()):
        failures.append('AEGIS_KALI_CODE_AUTH_TOKEN must be a 64-character lowercase hexadecimal token')
    if not _RUNTIME_TEXT.fullmatch(environment.get('AEGIS_KALI_CODE_EXPECTED_RUNNER_VERSION', '').strip()):
        failures.append('AEGIS_KALI_CODE_EXPECTED_RUNNER_VERSION is required and invalid')
    if not _COMMIT.fullmatch(environment.get('AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT', '').strip()):
        failures.append('AEGIS_KALI_CODE_EXPECTED_BUILD_COMMIT must be a 40-character lowercase commit SHA')
    for name in _PIN_NAMES:
        if not _SHA256.fullmatch(environment.get(name, '').strip()):
            failures.append(f'{name} must be an immutable sha256 digest')

    expected_image = environment.get('AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST', '').strip()
    selected_image = _selected_image_digest(environment.get('AEGIS_KALI_CODE_IMAGE', ''))
    if selected_image is None:
        failures.append('AEGIS_KALI_CODE_IMAGE must be an immutable sha256 image ID or digest-qualified OCI reference')
    elif _SHA256.fullmatch(expected_image) and selected_image != expected_image:
        failures.append('AEGIS_KALI_CODE_IMAGE must match AEGIS_KALI_CODE_EXPECTED_IMAGE_DIGEST')
    return failures


def main() -> int:
    failures = validate(dict(os.environ))
    if failures:
        for failure in failures:
            print(f'Semgrep M6 production preflight: {failure}', file=sys.stderr)
        return 78
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
