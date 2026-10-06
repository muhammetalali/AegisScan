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


def test_reports_use_canonical_collection_path_without_insecure_redirect() -> None:
    reports = read("pages/reports/Reports.tsx")

    assert "apiHelpers.get<Report[]>('/reports/?limit=100')" in reports
    assert "apiHelpers.get<Report[]>('/reports?limit=100')" not in reports

def test_production_black_box_proves_governed_url_assessment_launcher() -> None:
    e2e = (ROOT / "aegis-platform" / "e2e" / "external_black_box_e2e.py").read_text(encoding="utf-8")

    assert "if not CAPACITY_MODE:" in e2e
    assert "'Assessment Launcher URL prepare',{201}" in e2e
    assert "'mode':'url'" in e2e
    assert "launcher_scope_mode=='single-operator-lab'" in e2e
    assert "CONTROLLED_LAUNCH_URL_AUTH=AUTOMATIC" in e2e
    assert "launcher_scope_mode=='asset-authorization'" in e2e
    assert "CONTROLLED_LAUNCH_URL_AUTH=PENDING" in e2e
    assert "CONTROLLED_LAUNCH_URL_PREPARE=PASS" in e2e
    assert "'Execute governed Assessment Launcher URL authorization',{200}" in e2e
    assert "'Assessment Launcher URL authorized re-prepare',{201}" in e2e
    assert "'web.httpx' not in launcher_caps" in e2e
    assert "f'{API_V1}/capabilities/web.httpx/execute'" in e2e
    assert "'Assessment Launcher URL web.httpx execution',{202}" in e2e
    assert "CONTROLLED_LAUNCH_URL_EXECUTION=PASS" in e2e

def test_black_box_proves_governed_file_assessment_and_deactivation_guard() -> None:
    e2e = (ROOT / "aegis-platform" / "e2e" / "external_black_box_e2e.py").read_text(encoding="utf-8")

    assert "AEGIS_E2E_FILE_ACCEPTANCE" in e2e
    assert "AEGIS_E2E_FILE_REQUIRE_FINDING" in e2e
    assert "'Assessment Launcher file prepare',{201}" in e2e
    assert "'code.semgrep'" in e2e
    assert "CONTROLLED_LAUNCH_FILE_AUTH=AUTOMATIC" in e2e
    assert "CONTROLLED_LAUNCH_FILE_AUTH=PENDING" in e2e
    assert "CONTROLLED_LAUNCH_FILE_PREPARE=PASS" in e2e
    assert "'Assessment Launcher file Semgrep execution',{202}" in e2e
    assert "CONTROLLED_LAUNCH_FILE_EXECUTION=PASS" in e2e
    assert "CONTROLLED_LAUNCH_FILE_FINDING=PASS" in e2e
    assert "'Deactivate file assessment asset',{200}" in e2e
    assert "'Reject inactive file assessment execution',{404}" in e2e
    assert "CONTROLLED_LAUNCH_FILE_DEACTIVATION_GUARD=PASS" in e2e
