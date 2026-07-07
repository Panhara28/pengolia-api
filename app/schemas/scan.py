import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanStatus, ScanType


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    scan_type: ScanType = ScanType.PASSIVE_BASELINE
    selected_owasp_categories: list[str] | None = None
    authentication_config: dict[str, Any] | None = None
    safety_confirmed: bool = False


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_url: str
    scan_type: ScanType
    status: ScanStatus
    progress: int
    risk_score: float
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    zap_report_path: str | None
    error_message: str | None
    created_by: uuid.UUID
    safety_confirmed: bool
    created_at: datetime
    updated_at: datetime


class ScanCreateResponse(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    status: ScanStatus
    progress: int
    message: str = "Scan queued successfully"


class ScanLogEntry(BaseModel):
    timestamp: str
    level: str
    message: str


class ScanSummary(BaseModel):
    scan_id: uuid.UUID
    status: ScanStatus
    risk_score: float
    total_findings: int
    findings_by_severity: dict[str, int]
    duration_seconds: int | None
