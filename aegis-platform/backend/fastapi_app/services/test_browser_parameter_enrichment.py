from __future__ import annotations

import json

from fastapi_app.services.browser_parameter_enrichment import (
    analyze_javascript_source,
    build_hidden_parameter_probe_plan,
    probe_plan_request_count,
)


def test_js_analyzer_returns_names_and_redacted_same_origin_endpoints_only():
    source = r"""
    const queryParams = new URLSearchParams(location.search);
    queryParams.get('previewMode');
    const formData = new FormData();
    formData.append('clientHint', 'never-persist-this-value');
    fetch('/api/profile?token=secret-value&view=full');
    fetch('https://other.example.test/outside?leak=secret');
    const dormant = '/api/internal-preview?previewMode=secret-preview';
    """
    result = analyze_javascript_source(
        source,
        script_url='https://app.example.test/static/app.js',
        target_origin='https://app.example.test',
    )
    rendered = json.dumps(result, sort_keys=True)

    assert {'previewMode', 'clientHint', 'token', 'view'} <= set(result['parameter_names'])
    assert 'https://app.example.test/api/profile?token=*&view=*' in result['endpoint_candidates']
    assert 'https://app.example.test/api/internal-preview?previewMode=*' in result['endpoint_candidates']
    assert not any('other.example.test' in value for value in result['endpoint_candidates'])
    assert 'never-persist-this-value' not in rendered
    assert 'secret-value' not in rendered
    assert 'secret-preview' not in rendered


def test_js_analyzer_refuses_cross_origin_script_source():
    result = analyze_javascript_source(
        "fetch('/api/private?hidden=secret')",
        script_url='https://cdn.example.net/app.js',
        target_origin='https://app.example.test',
    )
    assert result == {'parameter_names': [], 'endpoint_candidates': []}


def test_hidden_parameter_probe_plan_is_head_budgeted_and_skips_sensitive_and_stateful():
    plan = build_hidden_parameter_probe_plan(
        [
            'https://app.example.test/api/profile?view=*',
            'https://app.example.test/logout',
            'https://outside.example.test/api/profile',
        ],
        ['previewMode', 'clientHint', 'token', 'password', 'view'],
        target_origin='https://app.example.test',
        max_requests=4,
    )

    assert len(plan) == 1
    assert plan[0]['endpoint'] == 'https://app.example.test/api/profile'
    assert plan[0]['parameter_names'] == ['clientHint', 'previewMode']
    assert probe_plan_request_count(plan) == 3
    assert probe_plan_request_count(plan) <= 4


def test_hidden_parameter_probe_plan_never_exceeds_hard_request_budget():
    plan = build_hidden_parameter_probe_plan(
        [
            'https://app.example.test/api/a',
            'https://app.example.test/api/b',
            'https://app.example.test/api/c',
        ],
        [f'candidate{i}' for i in range(20)],
        target_origin='https://app.example.test',
        max_requests=7,
    )
    assert probe_plan_request_count(plan) <= 7
    assert all(len(item['parameter_names']) <= 4 for item in plan)
