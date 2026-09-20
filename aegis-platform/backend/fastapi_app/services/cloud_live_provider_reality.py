from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from fastapi_app.services.cloud_target import parse_cloud_target


PROOF_SCHEMA = 'aegis.cloud-live-provider-proof.v1'
RESULT_SCHEMA = 'aegis.cloud-security.v1'
_MAX_CREDENTIAL_BYTES = 65536
_MAX_RESULT_BYTES = 8 * 1024 * 1024
_SHA40 = re.compile(r'^[a-f0-9]{40}$')
_SENSITIVE_FIELDS = {
    'access_key_id',
    'secret_access_key',
    'session_token',
    'client_secret',
    'private_key',
    'private_key_id',
    'password',
}


class CloudLiveProviderProofError(RuntimeError):
    pass


def _read_private_credential(path: str) -> tuple[str, dict[str, Any]]:
    credential_path = Path(path)
    try:
        meta = credential_path.stat()
    except OSError as exc:
        raise CloudLiveProviderProofError('Live-provider credential file is not available') from exc
    if not stat.S_ISREG(meta.st_mode):
        raise CloudLiveProviderProofError('Live-provider credential path must be a regular file')
    if meta.st_size <= 0 or meta.st_size > _MAX_CREDENTIAL_BYTES:
        raise CloudLiveProviderProofError('Live-provider credential file must be between 1 byte and 64 KiB')
    if stat.S_IMODE(meta.st_mode) & 0o077:
        raise CloudLiveProviderProofError('Live-provider credential file must not be group/world accessible')
    try:
        raw = credential_path.read_text(encoding='utf-8')
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudLiveProviderProofError('Live-provider credential must contain valid UTF-8 JSON') from exc
    if not isinstance(data, dict):
        raise CloudLiveProviderProofError('Live-provider credential JSON must be an object')
    return raw, data


def _read_result(path: str) -> tuple[str, dict[str, Any]]:
    result_path = Path(path)
    try:
        meta = result_path.stat()
    except OSError as exc:
        raise CloudLiveProviderProofError('Live-provider result file is not available') from exc
    if not stat.S_ISREG(meta.st_mode) or meta.st_size <= 0 or meta.st_size > _MAX_RESULT_BYTES:
        raise CloudLiveProviderProofError('Live-provider result file has an invalid size or type')
    try:
        raw = result_path.read_text(encoding='utf-8')
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudLiveProviderProofError('Live-provider result must contain valid UTF-8 JSON') from exc
    if not isinstance(data, dict):
        raise CloudLiveProviderProofError('Live-provider result JSON must be an object')
    return raw, data


def _sensitive_values(value: Any, *, field: str = '') -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            values.extend(_sensitive_values(item, field=str(key).strip().lower()))
    elif isinstance(value, list):
        for item in value:
            values.extend(_sensitive_values(item, field=field))
    elif field in _SENSITIVE_FIELDS and value is not None:
        text = str(value)
        if text:
            values.append(text)
    return values


def validate_live_provider_result(
    *,
    provider: str,
    target: str,
    credential_path: str,
    result_path: str,
    source_sha: str = '',
) -> dict[str, Any]:
    expected_provider = provider.strip().lower()
    if expected_provider not in {'aws', 'azure', 'gcp'}:
        raise CloudLiveProviderProofError('Live-provider proof requires provider aws, azure, or gcp')

    parsed_target = parse_cloud_target(target)
    if parsed_target.provider != expected_provider:
        raise CloudLiveProviderProofError('Live-provider proof provider does not match target provider')

    credential_raw, credential = _read_private_credential(credential_path)
    if str(credential.get('provider') or '').strip().lower() != expected_provider:
        raise CloudLiveProviderProofError('Live-provider credential provider does not match requested provider')

    result_raw, result = _read_result(result_path)
    if result.get('schema') != RESULT_SCHEMA:
        raise CloudLiveProviderProofError('Live-provider result schema is not authoritative')
    if str(result.get('provider') or '').strip().lower() != expected_provider:
        raise CloudLiveProviderProofError('Live-provider result provider does not match requested provider')
    if str(result.get('target') or '').strip() != parsed_target.canonical:
        raise CloudLiveProviderProofError('Live-provider result target does not match authorized canonical target')

    observations = result.get('observations')
    if not isinstance(observations, list) or not observations or not isinstance(observations[0], dict):
        raise CloudLiveProviderProofError('Live-provider result is missing its authoritative summary observation')
    summary = observations[0]
    if summary.get('kind') != 'cloud-security-summary':
        raise CloudLiveProviderProofError('Live-provider first observation must be the cloud security summary')
    if summary.get('identity_verified') is not True:
        raise CloudLiveProviderProofError('Live-provider identity was not verified')
    if summary.get('read_only') is not True:
        raise CloudLiveProviderProofError('Live-provider collector did not prove read-only execution')
    if summary.get('ambient_credentials_used') is not False:
        raise CloudLiveProviderProofError('Live-provider collector used or could not exclude ambient credentials')
    if summary.get('credential_source') != 'vault-materialized-file':
        raise CloudLiveProviderProofError('Live-provider credential source is not the governed materialized-file path')

    if credential_raw and credential_raw in result_raw:
        raise CloudLiveProviderProofError('Live-provider result contains the complete credential document')
    for secret in _sensitive_values(credential):
        if len(secret) >= 4 and secret in result_raw:
            raise CloudLiveProviderProofError('Live-provider result contains credential material')

    source_sha = source_sha.strip().lower()
    if source_sha and not _SHA40.fullmatch(source_sha):
        raise CloudLiveProviderProofError('Live-provider source SHA must be a 40-character lowercase commit SHA')

    coverage_gaps = summary.get('coverage_gaps')
    if coverage_gaps is None:
        coverage_gaps = []
    if not isinstance(coverage_gaps, list):
        raise CloudLiveProviderProofError('Live-provider coverage gaps must be a list')

    finding_count = summary.get('finding_count', 0)
    if not isinstance(finding_count, int) or finding_count < 0:
        raise CloudLiveProviderProofError('Live-provider finding count must be a non-negative integer')

    return {
        'schema': PROOF_SCHEMA,
        'source_schema': RESULT_SCHEMA,
        'source_sha': source_sha,
        'provider': expected_provider,
        'target': parsed_target.canonical,
        'identity_verified': True,
        'read_only': True,
        'ambient_credentials_used': False,
        'credential_source': 'vault-materialized-file',
        'finding_count': finding_count,
        'coverage_gap_count': len(coverage_gaps),
        'result_sha256': hashlib.sha256(result_raw.encode('utf-8')).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Validate and reduce AegisScan live cloud-provider evidence.')
    parser.add_argument('--provider', required=True, choices=('aws', 'azure', 'gcp'))
    parser.add_argument('--target', required=True)
    parser.add_argument('--credential-file', required=True)
    parser.add_argument('--result-file', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-sha', default=os.getenv('GITHUB_SHA', ''))
    args = parser.parse_args()

    try:
        proof = validate_live_provider_result(
            provider=args.provider,
            target=args.target,
            credential_path=args.credential_file,
            result_path=args.result_file,
            source_sha=args.source_sha,
        )
    except Exception as exc:
        print(f'cloud-live-provider-proof-error: {exc}', file=os.sys.stderr)
        return 2

    output = Path(args.output)
    output.write_text(json.dumps(proof, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
