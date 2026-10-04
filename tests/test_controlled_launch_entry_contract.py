from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "aegis-platform" / "frontend" / "src"


def read(relative: str) -> str:
    return (FRONTEND / relative).read_text(encoding="utf-8")


def test_general_assessment_entry_routes_to_existing_launcher_without_replacing_it():
    app = read("App.tsx")
    entry = read("pages/assessments/AssessmentEntry.tsx")
    launcher = read("pages/assessments/AssessmentLauncher.tsx")

    assert 'path="/assess"' in app
    assert 'path="/projects/:id/assess"' in app
    assert "navigate(`/projects/${encodeURIComponent(selectedProject.id)}/assess`)" in entry
    assert "id:'url' as Mode" in launcher
    assert "id:'file' as Mode" in launcher
    assert "'/assessment-launcher/file'" in launcher
    assert "'/assessment-launcher/prepare'" in launcher


def test_global_navigation_uses_assessment_entry_while_finding_validation_remains_specific():
    layout = read("components/layout/Layout.tsx")
    palette = read("components/layout/CommandPalette.tsx")
    dashboard = read("pages/Dashboard.tsx")
    projects = read("pages/projects/Projects.tsx")
    findings = read("pages/vulnerabilities/Vulnerabilities.tsx")
    assets = read("pages/assets/Assets.tsx")

    assert "name: 'New Assessment', href: '/assess'" in layout
    assert "label:'New Assessment',href:'/assess'" in palette
    assert "t('New assessment'), '/assess'" in dashboard
    assert 'to="/assess"' in projects
    assert "/validations/new?finding_id=" in findings
    assert "/projects/${encodeURIComponent(selected.project_id)}/assess" in assets
    assert "/validations/new?asset_id=" not in assets
