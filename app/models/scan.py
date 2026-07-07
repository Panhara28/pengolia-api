import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import SoftDeleteMixin, TimestampMixin, UUIDPKMixin


class ScanType(str, enum.Enum):
    PASSIVE_BASELINE = "passive_baseline_scan"
    AUTHENTICATED = "authenticated_scan"
    API_SCAN = "api_scan"
    FULL_LOCAL_STAGING = "full_local_staging_scan"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(UUIDPKMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("projects.id"), nullable=False
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType, name="scan_type"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), nullable=False, default=ScanStatus.QUEUED
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    zap_report_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    raw_output_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=False
    )
    safety_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    selected_owasp_categories: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    authentication_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
