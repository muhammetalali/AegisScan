"""Compatibility module retained for import stability.

Validation findings are served exclusively by validation_runtime, which reads
PostgreSQL-backed Vulnerability records. No synthetic or process-local finding
store is exposed here.
"""

from fastapi import APIRouter

router = APIRouter()
