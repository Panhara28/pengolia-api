import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.scan import ScanCreate, ScanCreateResponse, ScanLogEntry, ScanRead, ScanSummary
from app.services import scan_service

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("", response_model=Page[ScanRead])
def list_scans(
    params: PageParams = Depends(),
    project_id: uuid.UUID | None = None,
    status_filter: ScanStatus | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    stmt = select(Scan).where(Scan.deleted_at.is_(None))
    if project_id:
        stmt = stmt.where(Scan.project_id == project_id)
    if status_filter:
        stmt = stmt.where(Scan.status == status_filter)
    stmt = stmt.order_by(Scan.created_at.desc())
    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)


@router.post("", response_model=ScanCreateResponse, status_code=202)
def create_scan(
    payload: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    scan = scan_service.create_scan(db, payload, current_user, request)
    return ScanCreateResponse(
        id=scan.id, project_id=scan.project_id, status=scan.status, progress=scan.progress
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return scan_service.get_scan_or_404(db, scan_id)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(
    scan_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    scan = scan_service.get_scan_or_404(db, scan_id)
    return scan_service.cancel_scan(db, scan, current_user, request)


@router.post("/{scan_id}/rerun", response_model=ScanCreateResponse, status_code=202)
def rerun_scan(
    scan_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    scan = scan_service.get_scan_or_404(db, scan_id)
    new_scan = scan_service.rerun_scan(db, scan, current_user, request)
    return ScanCreateResponse(
        id=new_scan.id,
        project_id=new_scan.project_id,
        status=new_scan.status,
        progress=new_scan.progress,
    )


@router.get("/{scan_id}/logs", response_model=list[ScanLogEntry])
def get_scan_logs(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    scan = scan_service.get_scan_or_404(db, scan_id)
    return scan_service.get_scan_logs(scan)


@router.get("/{scan_id}/summary", response_model=ScanSummary)
def get_scan_summary(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    scan = scan_service.get_scan_or_404(db, scan_id)
    return scan_service.get_scan_summary(db, scan)
