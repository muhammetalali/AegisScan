from __future__ import annotations

import os
from collections import defaultdict
from datetime import timezone
from uuid import UUID

from asgiref.sync import sync_to_async
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.dependencies import get_current_user
from ..services.intelligence import IntelligenceFusion, IntelligenceFusionError
from evidence.models import Evidence, ValidationRun

router = APIRouter()
_fusion = IntelligenceFusion()


class AssuranceSummary(BaseModel):
    conflicts: int
    validations: int
    sources: int
    evidence_backed: int


@sync_to_async
def _conflicts(user_id: str, limit: int):
    runs = ValidationRun.objects.filter(user_id=user_id, status=ValidationRun.Status.COMPLETED, finding__isnull=False).order_by('-completed_at')
    grouped = defaultdict(list)
    for run in runs[:1000]:
        result = run.result if isinstance(run.result, dict) else {}
        if 'finding_present' in result:
            grouped[str(run.finding_id)].append(run)
    items = []
    for finding_id, history in grouped.items():
        observed = {bool((run.result or {}).get('finding_present')) for run in history}
        if len(observed) < 2:
            continue
        items.append({
            'finding_id': finding_id,
            'type': 'validation_conflict',
            'recommendation': 'Investigate the conflicting authorized validation results and rerun validation with the recorded scope.',
            'validations': [
                {
                    'id': str(run.id),
                    'finding_present': run.result.get('finding_present'),
                    'engine': (run.engines or [None])[0],
                    'evidence_id': str(run.result.get('evidence_id')) if run.result.get('evidence_id') else None,
                    'completed_at': run.completed_at.astimezone(timezone.utc).isoformat() if run.completed_at else None,
                }
                for run in history[:10]
            ],
        })
    return items[:limit]


@sync_to_async
def _summary_data(user_id: str):
    runs = list(ValidationRun.objects.filter(user_id=user_id, status=ValidationRun.Status.COMPLETED).order_by('-completed_at')[:1000])
    sources = {str(engine) for run in runs for engine in (run.engines or [])}
    evidence_backed = 0
    for run in runs:
        result = run.result if isinstance(run.result, dict) else {}
        evidence_id = result.get('evidence_id')
        if evidence_id and Evidence.objects.filter(pk=evidence_id, finding=run.finding).exists():
            evidence_backed += 1
    return {'validations': len(runs), 'sources': len(sources), 'evidence_backed': evidence_backed}


@router.get('/correlations/conflicts')
async def list_conflicts(limit: int = Query(100, ge=1, le=500), current_user=Depends(get_current_user)):
    items = await _conflicts(str(current_user.get('user_id')), limit)
    return {'items': items, 'total': len(items), 'source': 'postgresql'}


@router.get('/correlations/summary', response_model=AssuranceSummary)
async def correlation_summary(current_user=Depends(get_current_user)):
    user_id = str(current_user.get('user_id'))
    data = await _summary_data(user_id)
    conflicts = len(await _conflicts(user_id, 500))
    return {**data, 'conflicts': conflicts}


@router.get('/correlations/validations/{validation_id}')
async def validation_correlation(validation_id: UUID, current_user=Depends(get_current_user)):
    run = await sync_to_async(lambda: ValidationRun.objects.filter(id=validation_id, user_id=str(current_user.get('user_id'))).first())()
    if not run: raise HTTPException(status_code=404, detail='Validation not found')
    result = run.result if isinstance(run.result, dict) else {}
    evidence_id = result.get('evidence_id')
    evidence = await sync_to_async(lambda: Evidence.objects.filter(pk=evidence_id, finding=run.finding).first())() if evidence_id else None
    return {'validation_id':str(run.id),'finding_id':str(run.finding_id) if run.finding_id else None,'status':run.status,'engine':(run.engines or [None])[0],'finding_present':result.get('finding_present'),'evidence_id':str(evidence.id) if evidence else None,'evidence_valid':evidence is not None,'source':'postgresql'}


@router.get('/intelligence/cve/{cve_id}')
async def enrich_cve(cve_id: str, current_user=Depends(get_current_user)):
    try: result = _fusion.enrich_cve(cve_id, nvd_api_key=os.getenv('NVD_API_KEY'))
    except IntelligenceFusionError as exc: raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {'cve_id':result.cve_id,'confidence':result.confidence,'conflicts':result.conflicts,'recommendation':result.recommendation,'explanation':result.explanation,'sources':result.sources,'live':True}
