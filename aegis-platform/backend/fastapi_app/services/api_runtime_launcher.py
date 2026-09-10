#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

from fastapi_app.services.api_runtime_conformance import main as conformance_main
from fastapi_app.services.pinned_http import pinned_http_operation

_CURL_BEARER_RE = re.compile(r'^header\s*=\s*"Authorization:\s*Bearer\s+(.+)"\s*$')


def _extract_bearer_config(path: str) -> str:
    try:
        text = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        raise ValueError('credential config could not be read') from exc
    if len(text) > 16384 or '\x00' in text:
        raise ValueError('credential config is invalid')
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError('credential config must contain exactly one bearer header')
    match = _CURL_BEARER_RE.fullmatch(lines[0])
    if not match:
        raise ValueError('credential config is not an AegisScan bearer config')
    encoded = match.group(1)
    secret = encoded.replace('\\"', '"').replace('\\\\', '\\')
    if not secret or len(secret) > 8192 or any(ch in secret for ch in '\r\n\x00'):
        raise ValueError('credential material is invalid')
    return secret


def _write_secret(secret: str) -> str:
    fd, path = tempfile.mkstemp(prefix='aegis-api-runtime-', suffix='.credential')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(secret)
    return path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    config_path = ''
    if '--config' in args:
        index = args.index('--config')
        if index + 1 >= len(args):
            print('credential config path is missing', file=sys.stderr)
            return 2
        config_path = args[index + 1]
        del args[index:index + 2]

    secret_path = ''
    try:
        if config_path:
            secret = _extract_bearer_config(config_path)
            secret_path = _write_secret(secret)
            args.extend(['--credential-file', secret_path])
        if not args or args[0].startswith('-'):
            # Native runtime always supplies the authorized target first. Fail
            # closed rather than creating an unscoped multi-request pin.
            print('authorized target URL must be the first runtime argument', file=sys.stderr)
            return 2
        with pinned_http_operation(args[0]):
            return conformance_main(args)
    except ValueError as exc:
        print(str(exc)[:1000], file=sys.stderr)
        return 2
    finally:
        if secret_path:
            try:
                Path(secret_path).unlink(missing_ok=True)
            except OSError:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
