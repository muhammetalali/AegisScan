from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from ..core.dependencies import get_current_user
from ..services.intelligence import IntelligenceFusion, IntelligenceFusionError

router = APIRouter()
_fusion = IntelligenceFusion()


@router.get('/cve/{cve_id}')
async def enrich_cve(cve_id: str, current_user=Depends(get_current_user)):
    try:
        result = _fusion.enrich_cve(cve_id, nvd_api_key=os.getenv('NVD_API_KEY'))
    except IntelligenceFusionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        'cve_id': result.cve_id,
        'confidence': result.confidence,
        'conflicts': result.conflicts,
        'recommendation': result.recommendation,
        'explanation': result.explanation,
        'sources': result.sources,
        'live': True,
    }
