import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.tool import ToolStatus


class ToolRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    purpose: str | None
    status: ToolStatus
    version: str | None
    docker_image: str | None
    enabled: bool
    timeout_seconds: int
    config_json: dict[str, Any] | None
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ToolUpdate(BaseModel):
    enabled: bool | None = None
    timeout_seconds: int | None = None
    config_json: dict[str, Any] | None = None
    docker_image: str | None = None


class ToolTestConnectionResponse(BaseModel):
    status: ToolStatus
    detail: str
