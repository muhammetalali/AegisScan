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


def test_asset_scan_uses_existing_governed_capability_planner():
    asset_page = (ROOT / 'aegis-platform/frontend/src/pages/assets/Assets.tsx').read_text()
    scan_page = (ROOT / 'aegis-platform/frontend/src/pages/scans/ScanPage.tsx').read_text()
    assert 'navigate(`/scan?project_id=${encodeURIComponent(asset.project_id)}&asset_id=${encodeURIComponent(asset.id)}`)' in asset_page
    assert "apiHelpers.post<any>('/scans/'" not in asset_page
    assert "useSearchParams" in scan_page
    assert "useState(requestedProjectId)" in scan_page
    assert "useState(requestedAssetId)" in scan_page
    assert 'apiContractPaths.capabilityPlan(assetId)' in scan_page
    assert 'apiContractPaths.capabilityExecute(capabilityId)' in scan_page


def test_asset_deletion_requires_explicit_confirmation():
    asset_page = (ROOT / 'aegis-platform/frontend/src/pages/assets/Assets.tsx').read_text()
    assert "window.confirm(t('Delete this asset?'))" in asset_page
    assert 'onClick={()=>deleteMutation.mutate(asset.id)}' not in asset_page
