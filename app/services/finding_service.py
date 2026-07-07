import uuid
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.models.finding import Finding, FindingStatus
from app.models.user import User
from app.services.audit_service import log_action


def get_finding_or_404(db: Session, finding_id: uuid.UUID) -> Finding:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise NotFoundError("Finding")
    return finding


def upsert_finding_from_scan(db: Session, scan_id: uuid.UUID, project_id: uuid.UUID, data: dict) -> Finding:
    """Create or refresh a finding, deduping by (scan, affected_url, title)."""
    existing = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.affected_url == data.get("affected_url"),
            Finding.title == data.get("title"),
        )
        .one_or_none()
    )

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.evidence = data.get("evidence", existing.evidence)
        db.commit()
        db.refresh(existing)
        return existing

    finding = Finding(scan_id=scan_id, project_id=project_id, **data)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def _log_status_change(
    db: Session, finding: Finding, current_user: User, request: Request | None
) -> None:
    log_action(
        db,
        actor_id=current_user.id,
        action="finding.status_changed",
        resource_type="finding",
        resource_id=str(finding.id),
        metadata={"status": finding.status.value},
        request=request,
    )


def update_finding(
    db: Session,
    finding: Finding,
    payload,
    current_user: User | None = None,
    request: Request | None = None,
) -> Finding:
    data = payload.model_dump(exclude_unset=True)
    status_changed = "status" in data
    for field, value in data.items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)
    if status_changed and current_user:
        _log_status_change(db, finding, current_user, request)
    return finding


def mark_fixed(
    db: Session, finding: Finding, current_user: User, request: Request | None = None
) -> Finding:
    finding.status = FindingStatus.FIXED
    db.commit()
    db.refresh(finding)
    _log_status_change(db, finding, current_user, request)
    return finding


def mark_false_positive(
    db: Session,
    finding: Finding,
    reason: str,
    current_user: User,
    request: Request | None = None,
) -> Finding:
    finding.status = FindingStatus.FALSE_POSITIVE
    finding.false_positive_reason = reason
    db.commit()
    db.refresh(finding)
    _log_status_change(db, finding, current_user, request)
    return finding


def accept_risk(
    db: Session, finding: Finding, current_user: User, request: Request | None = None
) -> Finding:
    finding.status = FindingStatus.ACCEPTED_RISK
    db.commit()
    db.refresh(finding)
    _log_status_change(db, finding, current_user, request)
    return finding
