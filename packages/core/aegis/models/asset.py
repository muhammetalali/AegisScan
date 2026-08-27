"""نموذج الأصول — Asset Model."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    SERVER = "server"
    DOMAIN = "domain"
    URL = "url"
    DATABASE = "database"
    FILE = "file"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    IDENTITY = "identity"
    NETWORK = "network"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Asset(BaseModel):
    """أصل رقمي موحد — يُستخدم لاحقاً في حساب المخاطر والرسم البياني."""

    id: str = Field(default_factory=lambda: f"asset_{uuid.uuid4().hex[:12]}")
    project_id: str = "default"
    name: str = Field(..., min_length=1)
    asset_type: AssetType = AssetType.UNKNOWN
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    tags: list = Field(default_factory=list)
    discovered_by: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
