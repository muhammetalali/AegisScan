"""Exact-head closure proof for WSTG UI + reporting surfaces."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
BACKEND = ROOT / 'aegis-platform' / 'backend'
FRONTEND = ROOT / 'aegis-platform' / 'frontend'
sys.path.insert(0, str(BACKEND))

from fastapi_app.main import app
from fastapi_app.routers.reports import SUPPORTED_REPORT_TYPES
from fastapi_app.routers.wstg import WSTGProjectCoverage, WSTGTestCoverage
from fastapi_app.services.wstg_catalog import WSTGCatalog


def verify() -> dict:
    catalog = WSTGCatalog()
    if len(catalog.tests) != 97:
        raise ValueError('WSTG canonical catalog must contain exactly 97 tests')

    paths = set(app.openapi().get('paths', {}))
    coverage_path = '/api/v1/wstg/projects/{project_id}/coverage'
    if coverage_path not in paths:
        raise ValueError('WSTG coverage API is not registered in OpenAPI')

    project_schema = WSTGProjectCoverage.model_json_schema()
    test_schema = WSTGTestCoverage.model_json_schema()
    if project_schema.get('additionalProperties') is not False:
        raise ValueError('WSTG project coverage response must reject unknown fields')
    state_enum = (
        test_schema.get('properties', {})
        .get('state', {})
        .get('enum', [])
    )
    if {'passed', 'failed'} & set(state_enum):
        raise ValueError('WSTG reporting surface must not expose pass/fail planner authority')

    if 'wstg' not in SUPPORTED_REPORT_TYPES:
        raise ValueError('WSTG report type is not enabled')

    app_source = (FRONTEND / 'src' / 'App.tsx').read_text(encoding='utf-8')
    layout_source = (FRONTEND / 'src' / 'components' / 'layout' / 'Layout.tsx').read_text(encoding='utf-8')
    page_source = (FRONTEND / 'src' / 'pages' / 'assurance' / 'WSTGCoveragePage.tsx').read_text(encoding='utf-8')
    reports_source = (FRONTEND / 'src' / 'pages' / 'reports' / 'Reports.tsx').read_text(encoding='utf-8')
    evidence_source = (FRONTEND / 'src' / 'pages' / 'evidence' / 'Evidence.tsx').read_text(encoding='utf-8')
    contracts_source = (FRONTEND / 'src' / 'contracts' / 'api.ts').read_text(encoding='utf-8')

    checks = {
        'protected_route': 'path="/wstg"' in app_source,
        'navigation': "href: '/wstg'" in layout_source,
        'central_transport': "apiHelpers.get<unknown>(`/wstg/projects/${projectId}/coverage`)" in page_source,
        'strict_contract': 'WSTGProjectCoverageSchema' in contracts_source and '.strict()' in contracts_source,
        'report_type': '<option value="wstg">wstg</option>' in reports_source,
        'evidence_lineage_surface': 'wstgLineageCount' in evidence_source,
        'no_direct_fetch': 'fetch(' not in page_source,
        'no_direct_axios': 'axios.' not in page_source,
        'observation_only_copy': 'observation only' in page_source.lower(),
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise ValueError(f'WSTG UI/reporting closure checks failed: {failed}')

    return {
        'proof_scope': (
            'WSTG v4.2 observation coverage UI + project-scoped read API + '
            'persisted report integration; no security pass/fail or finding-state authority'
        ),
        'canonical_tests': len(catalog.tests),
        'coverage_api': coverage_path,
        'report_type': 'wstg',
        'completion_claim_allowed': False,
        'finding_state_authority': 'governed-finding-confirmation',
        'frontend_route': '/wstg',
        'checks': checks,
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
