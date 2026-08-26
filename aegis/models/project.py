"""نموذج المشروع — Project Model."""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ProjectType(str, Enum):
    WEB_APPLICATION = "web_application"
    MOBILE_APP = "mobile_app"
    API_SERVICE = "api_service"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    SOURCE_CODE = "source_code"
    NETWORK = "network"
    MIXED = "mixed"


class Project(BaseModel):
    """أعلى مستوى في التسلسل: Project → Scans → Evidences → Findings."""

    id: str = Field(default_factory=lambda: f"proj_{uuid.uuid4().hex[:12]}")
    name: str = Field(..., min_length=1, max_length=256)
    project_type: ProjectType = ProjectType.MIXED
    description: Optional[str] = None
    root_path: Optional[str] = None
    repo_url: Optional[str] = None
    languages: List[str] = Field(default_factory=list)
    scan_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
