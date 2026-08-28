import pytest

from fastapi_app.services.remediation_validation import RemediationValidationSuite


def test_compare_scores_reports_real_delta():
    result = RemediationValidationSuite.compare_scores(75, 92)
    assert result["before"] == 75
    assert result["after"] == 92
    assert result["improvement"] == 17
    assert result["delta"] == 17
    assert result["regressed"] is False


def test_validate_blocks_without_approval():
    result = RemediationValidationSuite().validate({}, {"policy": lambda _: True})
    assert result["blocked"] is True
    assert result["passed"] is False

@pytest.mark.asyncio
async def test_workspace_validation_requires_authorized_scope(tmp_path):
    suite = RemediationValidationSuite()
    with pytest.raises(PermissionError):
        await suite.validate_workspace(
            {"approval_id": "ap-1", "authorized": False, "workspace": str(tmp_path)},
            tools=["semgrep"],
        )
