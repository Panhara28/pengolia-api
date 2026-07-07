import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.owasp import OwaspCoverageStatus


class OWASPCategoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    code: str
    name: str
    description: str | None
    coverage_status: OwaspCoverageStatus
    recommended_checks_json: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime


class OWASPCoverageItem(BaseModel):
    code: str
    name: str
    coverage_status: OwaspCoverageStatus
    finding_count: int
