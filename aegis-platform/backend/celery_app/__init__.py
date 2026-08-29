"""Compatibility entrypoint for the canonical AegisScan Celery application.

The project previously maintained a second, legacy Celery application here.
That created duplicate configuration and referenced task modules that do not
exist in the repository.  The canonical application now lives in
``fastapi_app.celery_app`` and this module intentionally re-exports it so
existing ``celery -A celery_app`` commands continue to work.
"""

from fastapi_app.celery_app import celery_app

__all__ = ["celery_app"]
