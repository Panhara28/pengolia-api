import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.project import Environment, ProjectStatus, RiskLevel


class ProjectCreate(BaseModel):
    name: str
    target_url: str
    environment: Environment = Environment.LOCAL
    owner_id: uuid.UUID | None = None
    description: str | None = None
    scope_confirmed: bool = False


class ProjectUpdate(BaseModel):
    name: str | None = None
    target_url: str | None = None
    environment: Environment | None = None
    description: str | None = None
    status: ProjectStatus | None = None
    allowed_domain: str | None = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    target_url: str
    environment: Environment
    owner_id: uuid.UUID
    description: str | None
    status: ProjectStatus
    risk_level: RiskLevel
    risk_score: float
    scope_confirmed: bool
    allowed_domain: str | None
    created_at: datetime
    updated_at: datetime


class ScopeConfirmRequest(BaseModel):
    confirmed: bool = Field(default=True)
