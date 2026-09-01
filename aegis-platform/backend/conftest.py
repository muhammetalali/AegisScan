"""Pytest bootstrap for the Django-backed AegisScan test suite."""

from __future__ import annotations

import os


# Ensure Django is configured before test modules import Django models.
# This is intentionally explicit so tests behave the same way when invoked
# directly with pytest, through Docker Compose, or from CI.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
