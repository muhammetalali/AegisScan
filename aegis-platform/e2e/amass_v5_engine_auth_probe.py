#!/usr/bin/env python3
from __future__ import annotations

import os
import urllib.error
import urllib.request

URL = 'http://127.0.0.1:4000/api/v1/health'
HEADER = 'X-Aegis-Amass-Token'


def _status(headers: dict[str, str]) -> int:
    request = urllib.request.Request(URL, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    token = os.environ['AEGIS_AMASS_ENGINE_TOKEN']
    assert len(token) == 64
    assert _status({}) == 401
    assert _status({HEADER: '0' * 64}) == 401
    assert _status({HEADER: token}) == 200
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
