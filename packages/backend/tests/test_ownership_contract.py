from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FASTAPI_ROOT = REPO_ROOT / "backend" / "fastapi_app"
DJANGO_ROOT = REPO_ROOT / "backend" / "django_project"

DURABLE_RESOURCES = ("assets", "scans", "vulnerabilities", "reports", "compliance", "audit")


def test_legacy_fastapi_crud_surfaces_do_not_exist():
    routers = FASTAPI_ROOT / "routers"
    for resource in DURABLE_RESOURCES:
        assert not (routers / f"{resource}.py").exists(), (
            f"FastAPI must not reintroduce a CRUD router for Django-owned resource: {resource}"
        )


def test_fastapi_main_does_not_register_durable_crud_routers():
    source = (FASTAPI_ROOT / "main.py").read_text(encoding="utf-8")
    for resource in DURABLE_RESOURCES:
        assert f"routers.{resource}" not in source
        assert f"{resource}.router" not in source


def test_django_owns_all_durable_resource_api_surfaces():
    for resource in DURABLE_RESOURCES:
        urls = DJANGO_ROOT / resource / "urls.py"
        assert urls.exists(), f"Missing Django API surface for owned resource: {resource}"


def test_django_root_registers_all_durable_resource_apis():
    source = (DJANGO_ROOT / "urls.py").read_text(encoding="utf-8")
    for resource in DURABLE_RESOURCES:
        assert f'include("{resource}.urls")' in source


def test_fastapi_scan_runtime_is_not_crud_ownership():
    source = (FASTAPI_ROOT / "main.py").read_text(encoding="utf-8")
    assert '"/api/v1/scans/{scan_id}/start"' in source
    assert '"/api/v1/scans/{scan_id}/pause"' in source
    assert '"/api/v1/scans/{scan_id}/resume"' in source
    assert '"/api/v1/scans/{scan_id}/cancel"' in source
    assert '"/api/v1/scans/{scan_id}/progress"' in source
