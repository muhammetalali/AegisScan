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
