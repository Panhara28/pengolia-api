import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.permissions import require_role
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.user import User, UserRole
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.finding import FalsePositiveRequest, FindingRead, FindingUpdate
from app.services import finding_service

router = APIRouter(prefix="/findings", tags=["Findings"])

EDIT_ROLES = (UserRole.ADMIN, UserRole.SECURITY_ENGINEER, UserRole.DEVELOPER)


@router.get("", response_model=Page[FindingRead])
def list_findings(
    params: PageParams = Depends(),
    severity: FindingSeverity | None = None,
    status_filter: FindingStatus | None = None,
    owasp_category: str | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    first_seen_from: datetime | None = None,
    first_seen_to: datetime | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    stmt = select(Finding)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
    if owasp_category:
        stmt = stmt.where(Finding.owasp_category == owasp_category)
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if first_seen_from:
        stmt = stmt.where(Finding.first_seen >= first_seen_from)
    if first_seen_to:
        stmt = stmt.where(Finding.first_seen <= first_seen_to)
    if params.search:
        stmt = stmt.where(Finding.title.ilike(f"%{params.search}%"))
    stmt = stmt.order_by(Finding.first_seen.desc())

    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return finding_service.get_finding_or_404(db, finding_id)


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    finding = finding_service.get_finding_or_404(db, finding_id)
    return finding_service.update_finding(db, finding, payload, current_user, request)


@router.post("/{finding_id}/mark-fixed", response_model=FindingRead)
def mark_fixed(
    finding_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    finding = finding_service.get_finding_or_404(db, finding_id)
    return finding_service.mark_fixed(db, finding, current_user, request)


@router.post("/{finding_id}/mark-false-positive", response_model=FindingRead)
def mark_false_positive(
    finding_id: uuid.UUID,
    payload: FalsePositiveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*EDIT_ROLES)),
):
    finding = finding_service.get_finding_or_404(db, finding_id)
    return finding_service.mark_false_positive(db, finding, payload.reason, current_user, request)


@router.post("/{finding_id}/accept-risk", response_model=FindingRead)
def accept_risk(
    finding_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.SECURITY_ENGINEER)),
):
    finding = finding_service.get_finding_or_404(db, finding_id)
    return finding_service.accept_risk(db, finding, current_user, request)
