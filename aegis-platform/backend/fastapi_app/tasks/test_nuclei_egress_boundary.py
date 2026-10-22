from __future__ import annotations

from fastapi_app.tasks import finding_validation


def test_nuclei_finding_revalidation_uses_attested_provider_and_exact_template(monkeypatch):
    recorded = {}

    def execute(**kwargs):
        recorded.update(kwargs)
        return {'exit_code': 0, 'stdout': '{"template-id":"fixture"}\n', 'stderr': ''}

    monkeypatch.setattr(finding_validation, 'execute_kali_nuclei', execute)
    state_getter = lambda: 'running'
    result = finding_validation._run_nuclei_template(
        'https://approved.example',
        '/opt/nuclei-templates/http/cves/exact.yaml',
        timeout=15,
        authorization_ref='authorization:1',
        scope_ref='project:p1:asset:a1',
        execution_ref='validation:v1:nuclei',
        state_getter=state_getter,
    )
    assert result == (0, '{"template-id":"fixture"}\n', '')
    assert recorded == {
        'target': 'https://approved.example',
        'template_path': '/opt/nuclei-templates/http/cves/exact.yaml',
        'timeout_seconds': 15,
        'authorization_ref': 'authorization:1',
        'scope_ref': 'project:p1:asset:a1',
        'execution_ref': 'validation:v1:nuclei',
        'state_getter': state_getter,
    }
