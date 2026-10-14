import asyncio
import os
import shutil
import time
from datetime import datetime, timezone
from typing import Annotated, List, Optional
from urllib.parse import urlparse

import psutil
import redis
from celery import current_app as celery_app
from fastapi import APIRouter, Query, Depends
from pydantic import BaseModel
from asgiref.sync import sync_to_async

from ..core.dependencies import require_permission

import requests

router = APIRouter()


class SettingResponse(BaseModel):
    id: str
    key: str
    name: str
    description: str
    category: str
    value: dict
    value_type: str
    is_sensitive: bool
    requires_restart: bool


class MetricResponse(BaseModel):
    metric_type: str
    value: float
    unit: str
    timestamp: str


class ServiceStatusResponse(BaseModel):
    service: str
    status: str
    host: str
    port: Optional[int] = None
    response_time_ms: float
    uptime_percentage: Optional[float] = None
    last_check: str
    detail: Optional[str] = None


class BackupResponse(BaseModel):
    id: str
    name: str
    backup_type: str
    storage: str
    status: str
    file_size: int
    created_at: str
    completed_at: Optional[str] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _system_cpu_percent() -> float:
    return round(float(psutil.cpu_percent(interval=0.1)), 2)


def _system_memory_percent() -> float:
    return round(float(psutil.virtual_memory().percent), 2)


def _disk_percent() -> float:
    usage = shutil.disk_usage(os.path.abspath(os.sep))
    return round((usage.used * 100 / usage.total) if usage.total else 0.0, 2)


def _redis_probe() -> tuple[str, str, int, float, Optional[str]]:
    started = time.perf_counter()
    raw = os.getenv('REDIS_URL', 'redis://redis:6379/0')
    parsed = urlparse(raw)
    host = parsed.hostname or 'redis'
    port = parsed.port or 6379
    client = redis.Redis.from_url(raw, socket_connect_timeout=2, socket_timeout=2)
    try:
        client.ping()
        return 'healthy', host, port, round((time.perf_counter() - started) * 1000, 2), None
    except Exception as exc:
        return 'unhealthy', host, port, round((time.perf_counter() - started) * 1000, 2), str(exc)[:200]
    finally:
        try:
            client.close()
        except Exception:
            pass


def _postgres_probe() -> tuple[str, str, int, float, Optional[str]]:
    started = time.perf_counter()
    raw = os.getenv('DATABASE_URL')
    parsed = urlparse(raw) if raw else None
    host = parsed.hostname if parsed else 'postgres'
    port = (parsed.port if parsed else None) or 5432
    try:
        import psycopg2

        conn = psycopg2.connect(raw, connect_timeout=2) if raw else psycopg2.connect(
            host=host,
            port=port,
            dbname=os.getenv('POSTGRES_DB', 'aegisdb'),
            user=os.getenv('POSTGRES_USER', 'aegis'),
            password=os.getenv('POSTGRES_PASSWORD', 'aegis'),
            connect_timeout=2,
        )
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT 1')
                cursor.fetchone()
        finally:
            conn.close()
        return 'healthy', host or 'postgres', port, round((time.perf_counter() - started) * 1000, 2), None
    except Exception as exc:
        return 'unhealthy', host or 'postgres', port, round((time.perf_counter() - started) * 1000, 2), str(exc)[:200]


def _celery_probe() -> tuple[str, str, Optional[int], float, Optional[str]]:
    started = time.perf_counter()
    broker = os.getenv('CELERY_BROKER_URL', os.getenv('REDIS_URL', 'redis://redis:6379/0'))
    parsed = urlparse(broker)
    host = parsed.hostname or 'redis'
    port = parsed.port or 6379
    try:
        inspector = celery_app.control.inspect(timeout=2)
        replies = inspector.ping() or {}
        if not replies:
            raise RuntimeError('No responding Celery workers')
        return 'healthy', host, port, round((time.perf_counter() - started) * 1000, 2), f'{len(replies)} worker(s) responding'
    except Exception as exc:
        return 'unhealthy', host, port, round((time.perf_counter() - started) * 1000, 2), str(exc)[:200]


def _http_probe(url: str, service: str) -> tuple[str, str, Optional[int], float, Optional[str]]:
    started = time.perf_counter()
    parsed = urlparse(url)
    host = parsed.hostname or service
    port = parsed.port
    try:
        response = requests.get(url, timeout=2)
        response.raise_for_status()
        return 'healthy', host, port, round((time.perf_counter() - started) * 1000, 2), None
    except Exception as exc:
        return 'unhealthy', host, port, round((time.perf_counter() - started) * 1000, 2), str(exc)[:200]


def _service(name: str, result: tuple[str, str, Optional[int], float, Optional[str]]) -> ServiceStatusResponse:
    status, host, port, response_ms, detail = result
    return ServiceStatusResponse(
        service=name,
        status=status,
        host=host,
        port=port,
        response_time_ms=response_ms,
        last_check=_now(),
        detail=detail,
        uptime_percentage=None,
    )


def _setting_response(obj) -> SettingResponse:
    # Never disclose stored credentials even to settings administrators.
    value = {} if obj.is_sensitive or obj.value_type == 'password' else obj.value
    return SettingResponse(
        id=str(obj.id), key=obj.key, name=obj.name, description=obj.description,
        category=obj.category,
        value=value if isinstance(value, dict) else {'value': value},
        value_type=obj.value_type, is_sensitive=obj.is_sensitive,
        requires_restart=obj.requires_restart,
    )


@sync_to_async
def _read_settings(category: Optional[str] = None) -> List[SettingResponse]:
    from django_project.system.models import SystemSettings
    records = SystemSettings.objects.order_by('category', 'order', 'key')
    if category:
        records = records.filter(category=category)
    return [_setting_response(obj) for obj in records[:500]]


@sync_to_async
def _read_setting(key: str) -> SettingResponse | None:
    from django_project.system.models import SystemSettings
    obj = SystemSettings.objects.filter(key=key).first()
    return _setting_response(obj) if obj else None


@router.get('/settings', response_model=List[SettingResponse])
async def list_settings(category: Optional[str] = None, user=Depends(require_permission('system.settings'))):
    return await _read_settings(category)


@router.get('/settings/{key}', response_model=SettingResponse)
async def get_setting(key: str, user=Depends(require_permission('system.settings'))):
    result = await _read_setting(key)
    if result is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail='Setting does not exist')
    return result


@router.get('/metrics', response_model=List[MetricResponse])
async def get_metrics(
    metric_type: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    user=Depends(require_permission('system.monitor')),
):
    del since
    limit_value = int(limit)
    collectors = {
        'cpu_usage': _system_cpu_percent,
        'memory_usage': _system_memory_percent,
        'disk_usage': _disk_percent,
    }
    selected = [metric_type] if metric_type in collectors else list(collectors)
    return [
        MetricResponse(
            metric_type=key,
            value=float(await asyncio.to_thread(collectors[key])),
            unit='%',
            timestamp=_now(),
        )
        for key in selected[:limit_value]
    ]


@router.get('/services', response_model=List[ServiceStatusResponse])
async def get_services(user=Depends(require_permission('system.monitor'))):
    django_url = os.getenv('DJANGO_HEALTH_URL', 'http://django:8000/health/')
    fastapi_url = os.getenv('FASTAPI_HEALTH_URL', 'http://fastapi:8001/health')
    probes = await asyncio.gather(
        asyncio.to_thread(_postgres_probe),
        asyncio.to_thread(_redis_probe),
        asyncio.to_thread(_celery_probe),
        asyncio.to_thread(_http_probe, fastapi_url, 'fastapi'),
        asyncio.to_thread(_http_probe, django_url, 'django'),
    )
    return [
        _service('postgresql', probes[0]),
        _service('redis', probes[1]),
        _service('celery_worker', probes[2]),
        _service('fastapi', probes[3]),
        _service('django', probes[4]),
    ]


@sync_to_async
def _read_backups() -> List[BackupResponse]:
    from django_project.system.models import Backup
    return [
        BackupResponse(
            id=str(obj.id), name=obj.name, backup_type=obj.backup_type,
            storage=obj.storage, status=obj.status, file_size=obj.file_size,
            created_at=obj.created_at.isoformat(),
            completed_at=obj.completed_at.isoformat() if obj.completed_at else None,
        )
        for obj in Backup.objects.order_by('-created_at')[:200]
    ]


@router.get('/backups', response_model=List[BackupResponse])
async def list_backups(user=Depends(require_permission('system.backup'))):
    return await _read_backups()


@sync_to_async
def _read_maintenance_windows() -> list[dict]:
    from django_project.system.models import MaintenanceWindow
    return [
        {
            'id': str(obj.id), 'name': obj.name,
            'start_time': obj.start_time.isoformat(),
            'end_time': obj.end_time.isoformat(),
            'affected_services': obj.affected_services,
        }
        for obj in MaintenanceWindow.objects.order_by('start_time')[:200]
    ]


@router.get('/maintenance-windows')
async def list_maintenance_windows(user=Depends(require_permission('system.settings'))):
    return await _read_maintenance_windows()


@sync_to_async
def _read_feature_flags() -> list[dict]:
    from django_project.system.models import FeatureFlag
    return [
        {
            'id': str(obj.id), 'key': obj.key, 'name': obj.name,
            'description': obj.description, 'enabled': obj.is_enabled,
            'rollout_percentage': obj.rollout_percentage,
        }
        for obj in FeatureFlag.objects.order_by('key')[:300]
    ]


@router.get('/feature-flags')
async def list_feature_flags(user=Depends(require_permission('system.settings'))):
    return await _read_feature_flags()
