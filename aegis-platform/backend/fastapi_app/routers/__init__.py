"""FastAPI router package registration."""

# Register governed finding-disposition routes onto the existing vulnerability
# router so both legacy and /api/v1 vulnerability prefixes inherit them.
from . import vulnerabilities as vulnerabilities
from . import finding_dispositions as finding_dispositions

vulnerabilities.router.include_router(finding_dispositions.router)

__all__ = ['vulnerabilities', 'finding_dispositions']
