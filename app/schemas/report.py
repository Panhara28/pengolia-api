import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.report import ReportFormat


class ReportGenerateRequest(BaseModel):
    scan_id: uuid.UUID
    name: str | None = None


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    name: str
    format: ReportFormat
    file_path: str
    executive_summary: str | None
    risk_score: float
    total_findings: int
    generated_by: uuid.UUID
    generated_at: datetime
    created_at: datetime
