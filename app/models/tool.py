import enum
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class ToolStatus(str, enum.Enum):
    CONNECTED = "connected"
    NOT_CONFIGURED = "not_configured"
    ERROR = "error"
    DISABLED = "disabled"


class ToolIntegration(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "tool_integrations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ToolStatus] = mapped_column(
        Enum(ToolStatus, name="tool_status"), nullable=False, default=ToolStatus.NOT_CONFIGURED
    )
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    docker_image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    config_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
