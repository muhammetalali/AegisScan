from types import SimpleNamespace

from fastapi_app.routers.remediation import RemediationValidationRequest, _state
from django_project.evidence.models import ValidationRun


def test_remediation_state_without_run():
    assert _state(None) == 'not_requested'


def test_remediation_state_tracks_active_validation():
    for status in (ValidationRun.Status.QUEUED, ValidationRun.Status.RUNNING):
        validation = SimpleNamespace(status=status, result={})
        assert _state(validation) == 'validating'


def test_remediation_state_tracks_result():
    assert _state(SimpleNamespace(status=ValidationRun.Status.COMPLETED, result={'finding_present': False})) == 'verified'
    assert _state(SimpleNamespace(status=ValidationRun.Status.COMPLETED, result={'finding_present': True})) == 'not_fixed'
    assert _state(SimpleNamespace(status=ValidationRun.Status.FAILED, result={})) == 'validation_failed'
    assert _state(SimpleNamespace(status=ValidationRun.Status.CANCELLED, result={})) == 'cancelled'


def test_remediation_request_requires_explicit_authorization():
    request = RemediationValidationRequest()
    assert request.authorized is False
    assert RemediationValidationRequest(authorized=True).authorized is True
