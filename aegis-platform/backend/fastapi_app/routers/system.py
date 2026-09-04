from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from typing import List, Optional

import httpx
import psutil
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ..core.config import settings

router = APIRouter()


class MetricResponse(BaseModel):
    metric_type: str
    value: float
    unit: str
    timestamp: str


class ServiceStatusResponse(BaseModel):
    service: str
    status: str
    latency_ms: float | None = None
    detail: str = ""


class SettingResponse(BaseModel):
    key: str
    value: str


class SettingUpdate(BaseModel):
    value: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _system_cpu_percent() -> float:
    return float(psutil.cpu_percent(interval=0.1))


def _system_memory_percent() -> float:
    return float(psutil.virtual_memory().percent)


def _disk_percent() -> float:
    return float(psutil.disk_usage(os.path.abspath(os.sep)).percent)


def _postgres_probe() -> str:
    try:
        import psycopg2
        conn = psycopg2.connect(settings.DATABASE_URL, connect_timeout=2)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        finally:
            conn.close()
        return "healthy"
    except Exception as exc:
        return f"unhealthy: {exc}"


def _redis_probe() -> str:
    try:
        import redis
        client = redis.from_url(settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        client.ping()
        return "healthy"
    except Exception as exc:
        return f"unhealthy: {exc}"


def _unsupported(operation: str) -> None:
    raise HTTPException(status_code=501, detail=f"{operation} is not supported by the current production backend")


@router.get('/metrics', response_model=List[MetricResponse])
async def get_metrics(
    metric_type: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    del since
    collectors = {
        'cpu_usage': _system_cpu_percent,
        'memory_usage': _system_memory_percent,
        'disk_usage': _disk_percent,
    }
    selected = [metric_type] if metric_type in collectors else list(collectors)
    limit_value = int(limit)
    return [
        {'metric_type': key, 'value': float(await asyncio.to_thread(collectors[key])), 'unit': '%', 'timestamp': _now()}
        for key in selected[:limit_value]
    ]


@router.get('/services', response_model=List[ServiceStatusResponse])
async def get_services():
    django_url = os.getenv('DJANGO_HEALTH_URL', 'http://django:8000/health/')
    fastapi_url = os.getenv('FASTAPI_HEALTH_URL', 'http://fastapi:8001/health')
    probes = await asyncio.gather(
        asyncio.to_thread(_postgres_probe),
        asyncio.to_thread(_redis_probe),
        asyncio.to_thread(_http_probe, django_url),
        asyncio.to_thread(_http_probe, fastapi_url),
    )
    names = ['postgresql', 'redis', 'django', 'fastapi']
    return [
        {'service': name, 'status': result if result == 'healthy' else 'unhealthy', 'detail': result}
        for name, result in zip(names, probes)
    ]


def _http_probe(url: str) -> str:
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get(url)
            response.raise_for_status()
        return 'healthy'
    except Exception as exc:
        return f'unhealthy: {exc}'


@router.get('/settings/{key}', response_model=SettingResponse)
async def get_setting(key: str):
    del key
    _unsupported('Settings management')


@router.patch('/settings/{key}', response_model=SettingResponse)
async def update_setting(key: str, update: SettingUpdate):
    del key, update
    _unsupported('Settings management')
