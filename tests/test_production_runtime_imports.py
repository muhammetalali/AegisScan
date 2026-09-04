"""Reality gates for the production Django/FastAPI application tree.

These tests deliberately exercise the real application packages under
``aegis-platform/backend`` rather than the legacy ``packages/backend`` tree.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


BACKEND_ROOT = Path(__file__).resolve().parents[1] / "aegis-platform" / "backend"


def _bootstrap_backend() -> None:
    backend = str(BACKEND_ROOT)
    if backend not in sys.path:
        sys.path.insert(0, backend)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
    os.environ.setdefault("DEBUG", "0")
    os.environ.setdefault("SECRET_KEY", "production-reality-gate-secret-key")
    os.environ.setdefault("JWT_SECRET_KEY", "production-reality-gate-jwt-secret-key")
    os.environ.setdefault("ALLOWED_HOSTS", "localhost,127.0.0.1")
    os.environ.setdefault("DATABASE_URL", "sqlite:///tmp/reality-gate.sqlite3")
    os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")


def _discover_modules() -> list[str]:
    roots = [BACKEND_ROOT / "django_project", BACKEND_ROOT / "fastapi_app"]
    modules: list[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            if path.name == "__init__.py" or path.name.startswith("test_"):
                continue
            if "migrations" in path.parts or "tests" in path.parts:
                continue
            relative = path.relative_to(BACKEND_ROOT).with_suffix("")
            modules.append(".".join(relative.parts))
    return sorted(set(modules))


def test_production_backend_modules_are_importable() -> None:
    _bootstrap_backend()
    import django

    django.setup()

    failures: list[str] = []
    for module_name in _discover_modules():
        try:
            importlib.import_module(module_name)
        except Exception as exc:  # pragma: no cover - failure payload is assertion output
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

    assert AePEX._target_allowed is not object  # keep method import explicit for this reality gate
    candidate = AePEX._parse_target(target)
    assert candidate is not None

    # Execute the same policy with a deliberately untrusted object-less instance.
    subject = object.__new__(AePEX)
    subject.allowed_target_prefixes = allowed
    assert subject._target_allowed(target) is expected
