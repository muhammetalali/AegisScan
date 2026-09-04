from __future__ import annotations

import pytest

from fastapi_app.contracts import UnifiedValidationOut
from fastapi_app.main import app


EXPECTED_ROUTES = {
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
    '/api/v1/intelligence/cve/{cve_id}',
    '/api/v1/intelligence/cve/{cve_id}/latest',
    '/api/v1/attack-path/projects/{project_id}',
    '/api/v1/attack-path/projects/{project_id}/analyze',
    '/api/v1/compliance/frameworks',
    '/api/v1/compliance/projects/{project_id}/dashboard',
    '/api/v1/validations/{validation_id}/compliance',
    '/api/v1/validation-contract',
    '/api/v1/validations/{validation_id}/contract',
    '/api/v1/digital-twin/projects/{project_id}/twins',
    '/api/v1/digital-twin/twins/{twin_id}/scenarios',
    '/api/v1/digital-twin/scenarios/{scenario_id}/simulate',
}


def test_domain_contract_routes_are_registered():
    registered = set(app.openapi().get('paths', {}))
    missing = sorted(EXPECTED_ROUTES - registered)
    assert not missing, f'Missing API contract routes: {missing}'


def test_unified_validation_contract_is_strict_and_versioned():
    schema = UnifiedValidationOut.model_json_schema()
    assert schema['properties']['contract_version']['const'] == '1.0'
    assert schema['additionalProperties'] is False
