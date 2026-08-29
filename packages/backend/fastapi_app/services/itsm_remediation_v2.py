"""Backward-compatible import shim for the canonical ITSM remediation service.

The implementation lives in :mod:`itsm_remediation`; this module exists only so
older runtime imports remain compatible while callers migrate to the canonical path.
"""
from .itsm_remediation import *  # noqa: F401,F403
