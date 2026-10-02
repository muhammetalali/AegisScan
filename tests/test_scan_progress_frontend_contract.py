from pathlib import Path


SCAN_PROGRESS = Path("aegis-platform/frontend/src/pages/scans/ScanProgress.tsx")


def test_partial_scan_is_terminal_and_exposes_results():
    source = SCAN_PROGRESS.read_text(encoding="utf-8")

    assert "const partial=display.status==='partial'" in source
    assert "const terminal=completed||partial||failed" in source
    assert "{!terminal&&<>" in source
    assert "{(completed||partial)&&<button onClick={()=>navigate(`/scan/${id}/results`)}" in source


def test_partial_scan_uses_warning_tone_instead_of_spinner():
    source = SCAN_PROGRESS.read_text(encoding="utf-8")

    assert 'partial?<CheckCircle2 className="h-3.5 w-3.5 text-amber-500"/>' in source
    assert "partial?'bg-amber-500'" in source
