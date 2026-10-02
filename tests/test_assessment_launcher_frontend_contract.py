from pathlib import Path


LAUNCHER = Path("aegis-platform/frontend/src/pages/assessments/AssessmentLauncher.tsx")


def test_file_assessment_upload_is_multipart():
    source = LAUNCHER.read_text(encoding="utf-8")
    marker = "api.post<Prepared>('/assessment-launcher/file'"
    start = source.index(marker)
    request = source[start:start + 320]

    assert "form" in request
    assert "timeout:120000" in request
    assert "headers:{'Content-Type':'multipart/form-data'}" in request


def test_file_assessment_upload_does_not_rely_on_json_default_header():
    source = LAUNCHER.read_text(encoding="utf-8")
    marker = "api.post<Prepared>('/assessment-launcher/file'"
    start = source.index(marker)
    request = source[start:start + 320]

    assert "Content-Type':'application/json" not in request
