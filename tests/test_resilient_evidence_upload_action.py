from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]
ACTION = ROOT / ".github/actions/resilient-evidence-upload/action.yml"
PRODUCTION_EVIDENCE_WORKFLOWS = (
    ROOT / ".github/workflows/production-resilience-acceptance.yml",
    ROOT / ".github/workflows/production-live-deploy.yml",
    ROOT / ".github/workflows/production-final-governance.yml",
)


def test_resilient_evidence_upload_is_bounded_current_and_fail_closed():
    data = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert data["runs"]["using"] == "composite"
    steps = data["runs"]["steps"]

    uploads = [step for step in steps if step.get("uses") == "actions/upload-artifact@v7"]
    assert len(uploads) == 3
    assert uploads[0]["id"] == "upload_1"
    assert uploads[0]["continue-on-error"] is True
    assert uploads[1]["id"] == "upload_2"
    assert uploads[1]["continue-on-error"] is True
    assert uploads[2]["id"] == "upload_3"
    assert "continue-on-error" not in uploads[2]

    for upload in uploads:
        assert upload["with"]["if-no-files-found"] == "error"
        assert upload["with"]["overwrite"] is True

    assert uploads[1]["if"] == "steps.upload_1.outcome == 'failure'"
    assert uploads[2]["if"] == (
        "steps.upload_1.outcome == 'failure' && steps.upload_2.outcome == 'failure'"
    )

    text = ACTION.read_text(encoding="utf-8")
    assert "sleep 10" in text
    assert "sleep 30" in text
    assert "all bounded artifact upload attempts failed" in text
    assert "artifact-digest" in text
    assert "AEGISSCAN_EVIDENCE_UPLOAD=PASS" in text
    assert "actions/upload-artifact@v4" not in text


def test_all_production_evidence_workflows_use_shared_resilient_uploader():
    for workflow in PRODUCTION_EVIDENCE_WORKFLOWS:
        text = workflow.read_text(encoding="utf-8")
        assert "uses: ./.github/actions/resilient-evidence-upload" in text, workflow
        assert "actions/upload-artifact@v4" not in text, workflow
        assert "if-no-files-found: error" not in text.split(
            "uses: ./.github/actions/resilient-evidence-upload", 1
        )[1].split("retention-days: 90", 1)[0]
