from __future__ import annotations

import argparse
import json
import os
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')
import django
django.setup()

from fastapi_app.main import app


def main() -> int:
    parser = argparse.ArgumentParser(description='Audit AegisScan API OpenAPI contract surface')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    schema = app.openapi()
    failures: list[str] = []
    operations = 0
    v1_paths = 0
    operation_ids: set[str] = set()
    for path, item in schema.get('paths', {}).items():
        for method, operation in item.items():
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete', 'options', 'head'}:
                continue
            operations += 1
            if path.startswith('/api/v1/'):
                v1_paths += 1
            operation_id = operation.get('operationId')
            if not operation_id:
                failures.append(f'{method.upper()} {path}: missing OpenAPI operationId')
            elif operation_id in operation_ids:
                failures.append(f'{method.upper()} {path}: duplicate operationId {operation_id}')
            else:
                operation_ids.add(operation_id)
            responses = operation.get('responses', {})
            if not responses:
                failures.append(f'{method.upper()} {path}: no OpenAPI responses declared')
            if '500' in responses:
                failures.append(f'{method.upper()} {path}: implicit 500 response leaked into contract')
    required = {
        '/api/v1/scans/',
        '/api/v1/scans/{scan_id}',
        '/api/v1/scans/{scan_id}/engine-executions',
        '/api/v1/scans/{scan_id}/progress',
        '/api/v1/scans/{scan_id}/cancel',
        '/api/v1/vulnerabilities/',
        '/api/v1/vulnerabilities/{vuln_id}/evidences',
        '/api/v1/evidence/',
        '/api/v1/system/metrics',
        '/api/v1/system/services',
        '/api/v1/attack-path/projects/{project_id}',
        '/api/v1/attack-path/projects/{project_id}/analyze',
        '/api/v1/intelligence/cve/{cve_id}',
        '/api/v1/validations/{validation_id}/compliance',
        '/api/v1/validations/{validation_id}/contract',
        '/api/v1/validation-contract',
        '/api/v1/investigation/projects/{project_id}',
        '/api/v1/reports/schedules',
        '/api/v1/reports/templates',
    }
    missing = sorted(required - set(schema.get('paths', {})))
    failures.extend(f'Missing contractual domain path: {path}' for path in missing)
    result = {'status': 'failed' if failures else 'passed', 'operations': operations, 'v1_paths': v1_paths, 'failures': failures}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
