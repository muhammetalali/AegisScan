"""Legacy task compatibility module.

All executable security tasks are owned by ``fastapi_app.tasks``.  This
module deliberately contains no simulated or hard-coded security results.
It re-exports the real scanner/validation tasks for callers that still use
the historical import path.
"""

from fastapi_app.tasks.security_scan import (
    run_nmap_scan,
    run_nuclei_scan,
    validate_finding_task,
)

__all__ = [
    "run_nmap_scan",
    "run_nuclei_scan",
    "validate_finding_task",
]
