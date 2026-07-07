import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.core.permissions import require_role
from app.models.report import Report
from app.models.user import User, UserRole
from app.schemas.common import Page, PageParams, build_page, paginate
from app.schemas.report import ReportGenerateRequest, ReportRead
from app.services import report_service, scan_service
from app.services.audit_service import log_action

router = APIRouter(prefix="/reports", tags=["Reports"])

GENERATE_ROLES = (UserRole.ADMIN, UserRole.SECURITY_ENGINEER)


@router.get("", response_model=Page[ReportRead])
def list_reports(
    params: PageParams = Depends(),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    stmt = select(Report).order_by(Report.created_at.desc())
    items, total = paginate(db, stmt, params)
    return build_page(items, total, params)


@router.post("/generate", response_model=ReportRead, status_code=201)
def generate_report(
    payload: ReportGenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*GENERATE_ROLES)),
):
    scan = scan_service.get_scan_or_404(db, payload.scan_id)
    report = report_service.generate_report(db, scan, current_user, payload.name)
    log_action(
        db,
        actor_id=current_user.id,
        action="report.generated",
        resource_type="report",
        resource_id=str(report.id),
        request=request,
    )
    return report


@router.get("/{report_id}", response_model=ReportRead)
def get_report(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    return report_service.get_report_or_404(db, report_id)


@router.get("/{report_id}/download/pdf")
def download_pdf(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    report = report_service.get_report_or_404(db, report_id)
    path = report_service.resolve_download_path(report, "pdf")
    return FileResponse(path, media_type="application/pdf", filename=f"{report.name}.pdf")


@router.get("/{report_id}/download/html")
def download_html(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_active_user),
):
    report = report_service.get_report_or_404(db, report_id)
    path = report_service.resolve_download_path(report, "html")
    return FileResponse(path, media_type="text/html", filename=f"{report.name}.html")


@router.delete("/{report_id}", status_code=204)
def delete_report(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(*GENERATE_ROLES)),
):
    report = report_service.get_report_or_404(db, report_id)
    db.delete(report)
    db.commit()
