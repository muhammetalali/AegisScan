"""Local live-Burp conformance probe; no Django, database, scan, or lab verdict."""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi_app.services.burp_http_probe import health_request_arguments, summarize_health_result
from fastapi_app.services.burp_mcp_transport import MCPTransportError, call_burp_sse


def loopback_origin(value: str) -> None:
    parsed = urlsplit(value)
    host = parsed.hostname or ''
    if host != 'localhost' and not ipaddress.ip_address(host).is_loopback:
        raise ValueError('Live preparation probe admits loopback only')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', default='http://127.0.0.1:9876/')
    parser.add_argument('--target', default='http://127.0.0.1:18081')
    parser.add_argument('--schema-sha256', default='')
    args = parser.parse_args()
    try:
        loopback_origin(args.endpoint)
        loopback_origin(args.target)
        call = call_burp_sse(endpoint=args.endpoint, provider_tool_name='send_http1_request',
                             arguments=health_request_arguments(args.target),
                             request_id='live-probe-' + uuid4().hex,
                             expected_schema_sha256=args.schema_sha256)
        summary = summarize_health_result({'mcp_result': call.result, 'transport_metadata': call.metadata})
        print(json.dumps({'schema': 'aegis.burp-live-probe.v1', 'source': 'configured-local-endpoint',
                          'claim_requires_official_runtime_provenance': True, **summary}, ensure_ascii=False))
        return 0 if summary['transport_probe_passed'] else 1
    except (MCPTransportError, ValueError) as exc:
        print(json.dumps({'schema': 'aegis.burp-live-probe.v1', 'transport_probe_passed': False,
                          'lab_solved': False, 'live_fixture_revision_verified': False,
                          'error_code': getattr(exc, 'code', 'invalid_probe_configuration'),
                          'message_ar': 'لم يثبت اتصال Burp الحي. تحقّق من تشغيل الإضافة والسماح للهدف المحلي المحدد.'},
                         ensure_ascii=False))
        return 1


if __name__ == '__main__':
    sys.exit(main())
