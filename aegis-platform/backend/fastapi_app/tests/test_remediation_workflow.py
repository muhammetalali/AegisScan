from types import SimpleNamespace

from fastapi_app.routers.remediation import RemediationValidationRequest
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
