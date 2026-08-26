from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

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

class SettingUpdate(BaseModel):
    value: dict

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
    uptime_percentage: float
    last_check: str

class BackupResponse(BaseModel):
    id: str
    name: str
    backup_type: str
    storage: str
    status: str
    file_size: int
    created_at: str
    completed_at: Optional[str] = None

class BackupCreate(BaseModel):
    name: str
    backup_type: str
    storage: str
    retention_days: int = 30

@router.get("/settings", response_model=List[SettingResponse])
async def list_settings(category: Optional[str] = None):
    return []

@router.get("/settings/{key}", response_model=SettingResponse)
async def get_setting(key: str):
    raise HTTPException(status_code=404, detail="Setting not found")

@router.patch("/settings/{key}", response_model=SettingResponse)
async def update_setting(key: str, update: SettingUpdate):
    raise HTTPException(status_code=404, detail="Setting not found")

@router.get("/metrics", response_model=List[MetricResponse])
async def get_metrics(
    metric_type: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 100,
):
    return [
        {"metric_type": "cpu_usage", "value": 45.2, "unit": "%", "timestamp": datetime.utcnow().isoformat()},
        {"metric_type": "memory_usage", "value": 62.5, "unit": "%", "timestamp": datetime.utcnow().isoformat()},
        {"metric_type": "disk_usage", "value": 35.0, "unit": "%", "timestamp": datetime.utcnow().isoformat()},
    ]

@router.get("/services", response_model=List[ServiceStatusResponse])
async def get_services():
    return [
        {"service": "postgresql", "status": "healthy", "host": "localhost", "port": 5432, "response_time_ms": 2.5, "uptime_percentage": 99.9, "last_check": datetime.utcnow().isoformat()},
        {"service": "redis", "status": "healthy", "host": "localhost", "port": 6379, "response_time_ms": 1.2, "uptime_percentage": 99.9, "last_check": datetime.utcnow().isoformat()},
        {"service": "celery_worker", "status": "healthy", "host": "localhost", "port": None, "response_time_ms": 5.0, "uptime_percentage": 99.5, "last_check": datetime.utcnow().isoformat()},
        {"service": "fastapi", "status": "healthy", "host": "localhost", "port": 8001, "response_time_ms": 15.0, "uptime_percentage": 99.9, "last_check": datetime.utcnow().isoformat()},
        {"service": "django", "status": "healthy", "host": "localhost", "port": 8000, "response_time_ms": 25.0, "uptime_percentage": 99.9, "last_check": datetime.utcnow().isoformat()},
    ]

@router.get("/backups", response_model=List[BackupResponse])
async def list_backups():
    return []

@router.post("/backups", response_model=BackupResponse, status_code=201)
async def create_backup(backup: BackupCreate):
    return BackupResponse(
        id="new-backup-id",
        name=backup.name,
        backup_type=backup.backup_type,
        storage=backup.storage,
        status="pending",
        file_size=0,
        created_at=datetime.utcnow().isoformat(),
    )

@router.post("/backups/{backup_id}/restore")
async def restore_backup(backup_id: str):
    return {"message": "Restore started", "restore_id": "new-restore-id"}

@router.get("/maintenance-windows")
async def list_maintenance_windows():
    return []

@router.post("/maintenance-windows")
async def create_maintenance_window(name: str, start_time: str, end_time: str, affected_services: List[str] = []):
    return {"id": "new-window-id", "message": "Maintenance window created"}

@router.get("/feature-flags")
async def list_feature_flags():
    return []

@router.post("/feature-flags")
async def create_feature_flag(key: str, name: str, description: str = "", enabled: bool = False):
    return {"id": "new-flag-id", "key": key, "enabled": enabled}