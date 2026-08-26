from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class AssetCreate(BaseModel):
    project_id: str
    name: str
    type: str
    description: str = ""
    environment: str = "development"
    criticality: str = "medium"
    configuration: dict = {}
    tags: List[str] = []

class AssetResponse(BaseModel):
    id: str
    project_id: str
    name: str
    slug: str
    type: str
    description: str
    environment: str
    criticality: str
    configuration: dict
    tags: List[str]
    is_active: bool
    scan_count: int
    last_scanned_at: Optional[str] = None
    created_at: str
    updated_at: str

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    configuration: Optional[dict] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None

@router.get("/", response_model=List[AssetResponse])
async def list_assets(
    project_id: Optional[str] = None,
    asset_type: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
):
    return []

@router.post("/", response_model=AssetResponse, status_code=201)
async def create_asset(asset: AssetCreate):
    return AssetResponse(
        id="new-asset-id",
        project_id=asset.project_id,
        name=asset.name,
        slug=asset.name.lower().replace(" ", "-"),
        type=asset.type,
        description=asset.description,
        environment=asset.environment,
        criticality=asset.criticality,
        configuration=asset.configuration,
        tags=asset.tags,
        is_active=True,
        scan_count=0,
        created_at=datetime.utcnow().isoformat(),
        updated_at=datetime.utcnow().isoformat(),
    )

@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str):
    raise HTTPException(status_code=404, detail="Asset not found")

@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, update: AssetUpdate):
    raise HTTPException(status_code=404, detail="Asset not found")

@router.delete("/{asset_id}")
async def delete_asset(asset_id: str):
    return {"message": "Asset deleted"}

@router.post("/{asset_id}/scan")
async def scan_asset(asset_id: str, scan_type: str = "full_validation", depth: str = "standard"):
    # TODO: Trigger scan for this asset
    return {"scan_id": "new-scan-id", "message": "Scan started"}

@router.get("/{asset_id}/technologies")
async def get_asset_technologies(asset_id: str):
    return []

@router.post("/{asset_id}/technologies")
async def add_technology(asset_id: str, name: str, version: str, category: str, confidence: float):
    return {"id": "new-tech-id"}

@router.get("/{asset_id}/relationships")
async def get_asset_relationships(asset_id: str):
    return []

@router.post("/{asset_id}/relationships")
async def add_relationship(asset_id: str, target_id: str, relationship_type: str):
    return {"id": "new-rel-id"}

@router.post("/bulk-import")
async def bulk_import_assets(project_id: str, file: UploadFile = File(...)):
    # TODO: Parse CSV/JSON and create assets
    return {"imported": 0, "errors": []}