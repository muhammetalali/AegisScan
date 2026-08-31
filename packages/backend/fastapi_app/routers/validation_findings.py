"""Compatibility namespace for validation findings.

The canonical findings API is implemented in ``validation_runtime.py`` so
validation progress, results, findings, evidence, authorization, and
PostgreSQL persistence stay on one runtime path. ``main.py`` imports this
module as the named router surface; keeping an explicit module prevents an
import-time failure without introducing a second or fake findings registry.
"""

from fastapi import APIRouter

router = APIRouter()
