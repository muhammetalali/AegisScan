"""Compatibility import for the single platform Celery application."""

from fastapi_app.celery_app import celery_app

__all__ = ["celery_app"]
