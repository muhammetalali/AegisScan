from __future__ import annotations

import os

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException

from django_project.intelligence.models import IntelligenceEnrichment

from ..core.dependencies import get_current_user
from ..services.intelligence.fusion import IntelligenceFusion, IntelligenceFusionError

router = APIRouter()
_fusion = IntelligenceFusion()


@sync_to_async
def _persist(result, actor_id: str):
    return IntelligenceFusion.persist(result, actor_id=actor_id)


@router.get('/cve/{cve_id}')
async def enrich_cve(cve_id: str, current_user=Depends(get_current_user)):
    try:
        result = _fusion.enrich_cve(cve_id, nvd_api_key=os.getenv('NVD_API_KEY'))
    except IntelligenceFusionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    actor_id = str(current_user.get('user_id') or current_user.get('id'))
    try:
        snapshot = await _persist(result, actor_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail='Intelligence persistence failed') from exc
    return {
        'id': str(snapshot.id), 'cve_id': result.cve_id, 'confidence': result.confidence,
        'conflicts': result.conflicts, 'recommendation': result.recommendation,
        'explanation': result.explanation, 'sources': result.sources,
        'source_urls': result.source_urls, 'provider_failures': result.provider_failures,
        'live': True, 'persisted': True, 'observed_at': snapshot.observed_at.isoformat(),
        'snapshot_sha256': snapshot.snapshot_sha256,
    }


@sync_to_async
def _latest(cve_id: str, actor_id: str):
    return IntelligenceEnrichment.objects.filter(cve_id=cve_id.upper(), observed_by_id=actor_id).first()


@router.get('/cve/{cve_id}/latest')
async def latest_cve_enrichment(cve_id: str, current_user=Depends(get_current_user)):
    snapshot = await _latest(cve_id, str(current_user.get('user_id') or current_user.get('id')))
    if not snapshot:
        raise HTTPException(status_code=404, detail='No persisted intelligence observation found')
    return {
        'id': str(snapshot.id), 'cve_id': snapshot.cve_id, 'confidence': snapshot.confidence,
        'conflicts': snapshot.conflicts, 'recommendation': snapshot.recommendation,
        'explanation': snapshot.explanation, 'sources': snapshot.sources,
        'source_urls': snapshot.source_urls, 'provider_failures': snapshot.provider_failures,
        'live': False, 'persisted': True, 'observed_at': snapshot.observed_at.isoformat(),
        'snapshot_sha256': snapshot.snapshot_sha256,
    }
