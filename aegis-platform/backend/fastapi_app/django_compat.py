"""Django/FastAPI import compatibility for the unified backend.

The FastAPI routers historically imported Django apps both with and without the
``django_project`` package prefix.  Those are not interchangeable for Django:
loading the same model through two module names can create a second model class
outside the registered app.  This module ensures legacy imports resolve to the
already-registered Django modules instead of creating duplicate model modules.
"""

from __future__ import annotations

import importlib
import sys


_DJANGO_APPS = (
    "assets",
    "audit",
    "compliance",
    "evidence",
    "knowledge",
    "notifications",
    "projects",
    "scans",
    "system",
    "users",
    "vulnerabilities",
)


def install_django_import_aliases() -> None:
    """Register legacy top-level app/module aliases to canonical Django apps."""
    for app_name in _DJANGO_APPS:
        canonical_package = f"django_project.{app_name}"
        package = importlib.import_module(canonical_package)
        sys.modules.setdefault(app_name, package)

        # Eagerly alias models so ``app.models`` is the exact same module object
        # as ``django_project.app.models`` and Django sees one model class.
        models_name = f"{canonical_package}.models"
        models = importlib.import_module(models_name)
        sys.modules[ f"{app_name}.models" ] = models
