import enum
import uuid

from sqlalchemy import Boolean, Enum, Float, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.mixins import SoftDeleteMixin, TimestampMixin, UUIDPKMixin


class Environment(str, enum.Enum):
    LOCAL = "local"
    STAGING = "staging"
    QA = "qa"
    INTERNAL = "internal"


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Project(UUIDPKMixin, TimestampMixin, SoftDeleteMixin, Base):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="environment"), nullable=False, default=Environment.LOCAL
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus, name="project_status"), nullable=False, default=ProjectStatus.ACTIVE
    )
    risk_level: Mapped[RiskLevel] = mapped_column(
        Enum(RiskLevel, name="risk_level"), nullable=False, default=RiskLevel.LOW
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    scope_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allowed_domain: Mapped[str | None] = mapped_column(String(512), nullable=True)

    owner = relationship("User", back_populates="projects", foreign_keys=[owner_id])
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")
