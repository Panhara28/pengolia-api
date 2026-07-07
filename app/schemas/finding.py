import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.finding import FindingConfidence, FindingSeverity, FindingStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID
    title: str
    description: str | None
    severity: FindingSeverity
    confidence: FindingConfidence
    owasp_category: str | None
    affected_url: str | None
    evidence: str | None
    impact: str | None
    recommendation: str | None
    references_json: dict[str, Any] | None
    status: FindingStatus
    first_seen: datetime
    last_seen: datetime
    developer_notes: str | None
    false_positive_reason: str | None
    created_at: datetime
    updated_at: datetime


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    developer_notes: str | None = None
    false_positive_reason: str | None = None


class FalsePositiveRequest(BaseModel):
    reason: str


class DeveloperNoteRequest(BaseModel):
    note: str | None = None
