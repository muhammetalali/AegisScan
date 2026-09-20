import asyncio
from types import SimpleNamespace
from uuid import uuid4

from starlette.requests import Request

from fastapi_app.routers import remediation as remediation_router
from fastapi_app.routers.remediation import RemediationCloseRequest, RemediationValidationRequest
from fastapi_app.services.remediation_lifecycle import RemediationState, get_state
from django_project.evidence.models import ValidationRun


def test_remediation_state_without_run():
    assert get_state(None) == RemediationState.NOT_REQUESTED


def test_remediation_state_tracks_queued_validation():
    validation = SimpleNamespace(
        status=ValidationRun.Status.QUEUED,
        result={},
    )
    assert get_state(validation) == RemediationState.REQUESTED


def test_remediation_state_tracks_running_validation():
    validation = SimpleNamespace(
        status=ValidationRun.Status.RUNNING,
        result={},
    )
    assert get_state(validation) == RemediationState.VALIDATING


def test_remediation_state_tracks_completed_result_with_finding():
    validation = SimpleNamespace(
        status=ValidationRun.Status.COMPLETED,
        result={"finding_present": True},
    )
    assert get_state(validation) == RemediationState.NOT_FIXED


def test_remediation_state_tracks_completed_result_without_finding():
    validation = SimpleNamespace(
        status=ValidationRun.Status.COMPLETED,
        result={"finding_present": False},
    )
    assert get_state(validation) == RemediationState.VALIDATION_PASSED


def test_remediation_state_tracks_failed_validation():
    validation = SimpleNamespace(
        status=ValidationRun.Status.FAILED,
        result={},
    )
    assert get_state(validation) == RemediationState.FAILED


def test_remediation_state_tracks_cancelled_validation():
    validation = SimpleNamespace(
        status=ValidationRun.Status.CANCELLED,
        result={},
    )
    assert get_state(validation) == RemediationState.CANCELLED


def test_remediation_state_uses_persisted_state_when_present():
    validation = SimpleNamespace(
        status=ValidationRun.Status.COMPLETED,
        result={"remediation_state": RemediationState.VERIFIED},
    )
    assert get_state(validation) == RemediationState.VERIFIED


def test_remediation_request_requires_explicit_authorization():
    request = RemediationValidationRequest()
    assert request.authorized is False
    assert RemediationValidationRequest(authorized=True).authorized is True



def test_legacy_remediation_close_delegates_to_governed_finding_close(monkeypatch):
    vuln_id = uuid4()
    project_id = uuid4()
    user_id = uuid4()
    validation_id = uuid4()
    execution_id = uuid4()
    captured = {}

    finding = SimpleNamespace(project_id=project_id, status='in_progress')
    validation = SimpleNamespace(
        id=validation_id,
        status=ValidationRun.Status.COMPLETED,
        result={'remediation_state': RemediationState.VERIFIED},
    )

    async def fake_get_finding(_vuln_id, _user_id):
        return finding

    async def fake_latest_run(_vuln_id, _user_id):
        return validation

    def fake_execute(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            execution=SimpleNamespace(
                id=execution_id,
                result_payload={
                    'status': 'fixed',
                    'version': 12,
                    'validation_id': str(validation_id),
                },
            ),
            replayed=False,
        )

    def forbidden_transition(*_args, **_kwargs):
        raise AssertionError('legacy remediation close must not call generic transition')

    monkeypatch.setattr(remediation_router, '_get_finding', fake_get_finding)
    monkeypatch.setattr(remediation_router, '_latest_run', fake_latest_run)
    monkeypatch.setattr(remediation_router, 'execute_governed_action', fake_execute)
    monkeypatch.setattr(remediation_router, 'transition', forbidden_transition)

    request = Request({
        'type': 'http',
        'method': 'POST',
        'path': '/remediation/close',
        'headers': [(b'user-agent', b'a4-reality')],
        'client': ('127.0.0.1', 45678),
        'scheme': 'http',
        'server': ('testserver', 80),
        'query_string': b'',
    })
    result = asyncio.run(
        remediation_router.close_remediation(
            vuln_id,
            RemediationCloseRequest(expected_version=11, idempotency_key='a4-remediation-close'),
            request,
            user={'user_id': str(user_id)},
        )
    )

    assert captured['action_id'] == 'finding.close'
    assert captured['entity_type'] == 'finding'
    assert captured['entity_id'] == str(vuln_id)
    assert captured['project_id'] == str(project_id)
    assert captured['expected_version'] == 11
    assert captured['idempotency_key'] == 'a4-remediation-close'
    assert captured['parameters'] == {}
    assert result['execution_id'] == str(execution_id)
    assert result['version'] == 12
    assert result['vulnerability_status'] == 'fixed'
