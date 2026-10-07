from pathlib import Path

ROOT = Path(__file__).parents[1]

def test_launcher_uses_project_membership_instead_of_owner_staff_only():
    source = (ROOT / "aegis-platform/backend/fastapi_app/routers/assessment_launcher.py").read_text()
    block = source[source.index("def _project_for_launcher"):source.index("def _normalize_web_target")]
    assert "ProjectMembership.objects.filter(project=project, user_id=user_id).exists()" in block
    assert "Assessment Launcher is available to the project owner or staff." not in block

def test_launcher_copy_hides_governance_friction():
    source = (ROOT / "aegis-platform/frontend/src/pages/assessments/AssessmentLauncher.tsx").read_text()
    assert "Ready to run · setup is automatic" in source
    assert "Project access verified automatically" in source
    assert "Bind target to project" in source
    assert "Open required private path automatically" in source
    assert "Single-operator lab · scope activates automatically" not in source
