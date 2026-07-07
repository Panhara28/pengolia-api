import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.scan import ScanType


class SettingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key: str
    value_json: dict[str, Any]
    description: str | None
    created_at: datetime
    updated_at: datetime


class SettingUpdate(BaseModel):
    key: str
    value_json: dict[str, Any]
    description: str | None = None


class SecurityScopeSettings(BaseModel):
    allow_localhost_targets: bool = True
    allow_private_ip_ranges: bool = True
    allow_approved_staging_domains: bool = True
    block_public_internet_targets: bool = True
    require_confirmation_before_active_scans: bool = True
    approved_domains: list[str] = []


class ScanDefaultSettings(BaseModel):
    default_scan_type: ScanType = ScanType.PASSIVE_BASELINE
    max_scan_duration_minutes: int = 30
    enable_passive_checks: bool = True
    enable_dependency_checks: bool = True
    enable_secret_scanning: bool = True
    auto_generate_report: bool = True
