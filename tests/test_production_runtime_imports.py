"""Reality gates for the production Django/FastAPI application tree."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "aegis-platform" / "backend"


def _bootstrap_backend() -> None:
    backend = str(BACKEND_ROOT)
    repo = str(REPO_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    os.environ.setdefault("DEBUG", "0")


def _discover_modules() -> list[str]:
    modules: list[str] = []
    for root in (BACKEND_ROOT / "django_project", BACKEND_ROOT / "fastapi_app"):
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if path.name == "__init__.py" or path.name.startswith("test_"):
                continue
            if "migrations" in path.parts or "tests" in path.parts:
                continue
            modules.append(".".join(path.relative_to(BACKEND_ROOT).with_suffix("").parts))
    return sorted(set(modules))


def test_production_backend_modules_are_importable() -> None:
    _bootstrap_backend()
    import django

    django.setup()
    failures: list[str] = []
    for module_name in _discover_modules():
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            failures.append(f"{module_name}: {type(exc).__name__}: {exc}")
    assert not failures, "Production backend import failures:\n" + "\n".join(failures)


def test_global_exception_handler_handles_unexpected_exception() -> None:
    _bootstrap_backend()
    import django

    django.setup()
    from django.conf import settings
    from django.test import override_settings
    from django_project.core.exceptions import custom_exception_handler

    with override_settings(DEBUG=False):
        response = custom_exception_handler(RuntimeError("runtime-reality-gate"), {})
    assert response is not None
    assert response.status_code == 500
    assert response.data["error"]["message"] == "Internal server error"
    assert response.data["error"]["details"] == "An unexpected error occurred"
    assert settings.DEBUG is False


@pytest.mark.parametrize(
    ("target", "allowed", "expected"),
    [
        ("https://10.0.0.evil-external-host.com", ("https://10.0.0.",), False),
        ("https://10.0.0.10", ("https://10.0.0.10",), True),
        ("https://10.0.0.10/app/path", ("https://10.0.0.10",), True),
        ("https://10.0.0.100", ("https://10.0.0.10",), False),
    ],
)
def test_aepex_target_authorization_is_not_prefix_bypass(target: str, allowed: tuple[str, ...], expected: bool) -> None:
    _bootstrap_backend()
    from aegis.engines.offensive.aepex import AePEX

    subject = object.__new__(AePEX)
    subject.allowed_target_prefixes = allowed
    assert subject._target_allowed(target) is expected


def test_capability_registry_is_typed_and_fail_closed() -> None:
    _bootstrap_backend()
    from fastapi_app.services.capability_registry import (
        get_capability,
        list_capabilities,
        validate_capability_options,
    )
    from fastapi_app.services.native_packaging import PACKAGED_NATIVE_CAPABILITIES
    from fastapi_app.services.native_tool_runtime import NATIVE_TOOL_SPECS

    capabilities = {item.id: item for item in list_capabilities()}
    core = {"network.nmap", "network.masscan", "web.nuclei", "code.semgrep"}
    assert core <= set(capabilities)
    assert set(NATIVE_TOOL_SPECS) <= set(capabilities)
    assert PACKAGED_NATIVE_CAPABILITIES <= set(NATIVE_TOOL_SPECS)
    assert len(capabilities) >= 26
    assert all(item.authorization_required for item in capabilities.values())
    assert all(item.evidence_required for item in capabilities.values())
    assert all(item.execution_mode == "isolated-celery" for item in capabilities.values())
    assert all(capabilities[item].adapter == "native-cli" for item in NATIVE_TOOL_SPECS)
    assert get_capability("network.masscan").execution_mode == "isolated-celery"
    assert validate_capability_options(capabilities["network.masscan"], {"ports": "80,443", "rate": 2500}) == {
        "ports": "80,443",
        "rate": 2500,
    }
    assert validate_capability_options(capabilities["web.katana"], {"depth": 5}) == {"depth": 5}
    with pytest.raises(ValueError, match="Unsupported options"):
        validate_capability_options(capabilities["network.nmap"], {"arbitrary_flags": "-Pn --script anything"})
    with pytest.raises(ValueError, match="Unsupported options"):
        validate_capability_options(capabilities["web.katana"], {"additional_args": "anything"})
    with pytest.raises(ValueError, match="<= 5"):
        validate_capability_options(capabilities["web.katana"], {"depth": 50})
    with pytest.raises(ValueError, match="between 1 and 10000"):
        validate_capability_options(capabilities["network.masscan"], {"rate": 1000000})
    with pytest.raises(ValueError, match="Unknown capability"):
        get_capability("command.shell")


def test_native_cli_builds_argv_without_shell_strings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _bootstrap_backend()
    from fastapi_app.services.native_tool_runtime import build_native_argv, get_native_tool_spec

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"aegis")
    monkeypatch.setattr("fastapi_app.services.native_tool_runtime.shutil.which", lambda _: "/usr/bin/strings")
    argv, target = build_native_argv(get_native_tool_spec("binary.strings"), str(sample), {})
    assert argv == ["/usr/bin/strings", "-a", str(sample.resolve())]
    assert target == str(sample.resolve())
    assert all(isinstance(part, str) for part in argv)


def test_capability_planner_prefers_ready_tools_and_exposes_packaging_gaps() -> None:
    _bootstrap_backend()
    from fastapi_app.services.capability_planner import planning_summary

    web = planning_summary("website", "standard")
    assert web["ready"] >= 3
    assert web["pending_packaging"] >= 1
    ready = [item for item in web["plan"] if item["execution_ready"]]
    pending = [item for item in web["plan"] if not item["execution_ready"]]
    assert ready and pending
    assert max(item["order"] for item in ready) < min(item["order"] for item in pending)
    file_plan = planning_summary("file", "quick")
    assert file_plan["ready"] >= 6


def test_native_capability_task_is_routed_to_scanner_plane() -> None:
    _bootstrap_backend()
    from fastapi_app.celery_app import SCANNER_QUEUE, SCANNER_TASK_ROUTES

    route = SCANNER_TASK_ROUTES["fastapi_app.tasks.native_capabilities.run_native_capability_scan"]
    assert route == {"queue": SCANNER_QUEUE}


def test_capability_api_is_part_of_production_openapi_surface() -> None:
    _bootstrap_backend()
    import django

    django.setup()
    from fastapi_app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/capabilities/" in paths
    assert "/api/v1/capabilities/packaging" in paths
    assert "/api/v1/capabilities/plan/{asset_id}" in paths
    assert "/api/v1/capabilities/{capability_id}/execute" in paths
    execute = paths["/api/v1/capabilities/{capability_id}/execute"]["post"]
    assert execute["responses"]["202"]["description"] == "Successful Response"