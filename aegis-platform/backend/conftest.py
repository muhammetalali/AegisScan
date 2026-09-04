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
    """Close the current thread's Django DB connection after every test."""
    yield
    connections.close_all()


@pytest.fixture(scope="session", autouse=True)
def terminate_orphaned_test_database_sessions(django_db_setup):
    """Terminate cross-thread DB sessions before pytest-django drops the DB.

    FastAPI/Starlette may open Django ORM connections from worker threads that
    are not visible through Django's thread-local connection registry in the
    main pytest thread. pytest-django then cannot DROP DATABASE test_aegisdb.
    This fixture runs before the parent django_db_setup teardown and removes
    only sessions connected to the generated test database.
    """
    yield

    from django.db import connection
    import psycopg2

    settings = connection.settings_dict
    test_db_name = connection.vendor and settings.get("NAME")
    if not test_db_name:
        return

    params = {
        "dbname": "postgres",
        "user": settings.get("USER") or None,
        "password": settings.get("PASSWORD") or None,
        "host": settings.get("HOST") or "127.0.0.1",
        "port": settings.get("PORT") or 5432,
        "connect_timeout": 5,
    }

    maintenance = None
    try:
        maintenance = psycopg2.connect(**params)
        maintenance.autocommit = True
        with maintenance.cursor() as cursor:
            cursor.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s
                  AND pid <> pg_backend_pid()
                """,
                [test_db_name],
            )
    except (psycopg2.Error, OSError):
        # Database teardown is still owned by pytest-django. Do not mask the
        # actual test result if the maintenance connection is unavailable.
        pass
    finally:
        if maintenance is not None:
            maintenance.close()
