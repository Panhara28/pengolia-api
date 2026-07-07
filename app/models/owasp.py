import enum

from sqlalchemy import JSON, Enum, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.mixins import TimestampMixin, UUIDPKMixin


class OwaspCoverageStatus(str, enum.Enum):
    COVERED = "covered"
    PARTIAL = "partial"
    NOT_COVERED = "not_covered"


class OWASPCategory(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "owasp_categories"

    code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    coverage_status: Mapped[OwaspCoverageStatus] = mapped_column(
        Enum(OwaspCoverageStatus, name="owasp_coverage_status"),
        nullable=False,
        default=OwaspCoverageStatus.NOT_COVERED,
    )
    recommended_checks_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
