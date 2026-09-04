"""Pytest bootstrap and deterministic Django database cleanup for AegisScan."""

from __future__ import annotations

import os

import pytest
from django.db import connections


# Ensure Django is configured before test modules import Django models.
# This is intentionally explicit so tests behave the same way when invoked
# directly with pytest, through Docker Compose, or from CI.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")


@pytest.fixture(autouse=True)
def close_django_connections_after_test():
    """Close all Django DB connections after every test.

    FastAPI's TestClient can exercise Django from a worker thread. Calling
    close_all() in fixture teardown makes connection cleanup deterministic
    before pytest-django attempts to destroy the test database.
    """
    yield
    connections.close_all()
