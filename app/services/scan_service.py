import uuid
from pathlib import Path

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    ForbiddenError,
    InvalidTargetError,
    NotFoundError,
    ScanAlreadyRunningError,
)
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User, UserRole
from app.schemas.scan import ScanLogEntry
from app.services import project_service, target_validator
from app.services.audit_service import log_action

ACTIVE_STATUSES = (ScanStatus.QUEUED, ScanStatus.RUNNING)

TASK_BY_SCAN_TYPE = {
    ScanType.PASSIVE_BASELINE: "run_zap_baseline_scan",
    ScanType.AUTHENTICATED: "run_authenticated_scan",
    ScanType.API_SCAN: "run_api_scan",
    ScanType.FULL_LOCAL_STAGING: "run_full_local_scan",
}


def _dispatch_scan_task(scan: Scan) -> None:
    from app.workers import scan_tasks

    task_name = TASK_BY_SCAN_TYPE[scan.scan_type]
    task = getattr(scan_tasks, task_name)
    task.delay(str(scan.id))


def create_scan(db: Session, payload, current_user: User, request: Request | None = None) -> Scan:
    project = project_service.get_project_or_404(db, payload.project_id)
    project_service.ensure_scope_confirmed(project)

    result = target_validator.validate_target_url(project.target_url, db=db)
    if not result.allowed:
        raise InvalidTargetError(result.reason)

    if payload.scan_type == ScanType.FULL_LOCAL_STAGING:
        if current_user.role not in (UserRole.ADMIN, UserRole.SECURITY_ENGINEER):
            raise ForbiddenError(
                "Full Local/Staging Scan requires the Admin or Security Engineer role"
            )
        if not payload.safety_confirmed:
            raise ForbiddenError(
                "Full Local/Staging Scan requires explicit safety confirmation"
            )

    existing_active = db.execute(
        select(Scan).where(Scan.project_id == project.id, Scan.status.in_(ACTIVE_STATUSES))
    ).scalars().first()
    if existing_active:
        raise ScanAlreadyRunningError()

    scan = Scan(
        project_id=project.id,
        target_url=result.normalized_url,
        scan_type=payload.scan_type,
        status=ScanStatus.QUEUED,
        created_by=current_user.id,
        safety_confirmed=payload.safety_confirmed,
        selected_owasp_categories=payload.selected_owasp_categories,
        authentication_config=payload.authentication_config,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_action(
        db,
        actor_id=current_user.id,
        action="scan.started",
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={"scan_type": scan.scan_type.value, "project_id": str(project.id)},
        request=request,
    )

    _dispatch_scan_task(scan)
    return scan


def get_scan_or_404(db: Session, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan or scan.deleted_at is not None:
        raise NotFoundError("Scan")
    return scan


def cancel_scan(db: Session, scan: Scan, current_user: User, request: Request | None = None) -> Scan:
    if scan.status not in ACTIVE_STATUSES:
        raise ForbiddenError("Only queued or running scans can be cancelled")

    scan.status = ScanStatus.CANCELLED
    db.commit()
    db.refresh(scan)

    log_action(
        db,
        actor_id=current_user.id,
        action="scan.cancelled",
        resource_type="scan",
        resource_id=str(scan.id),
        request=request,
    )
    return scan


def rerun_scan(db: Session, scan: Scan, current_user: User, request: Request | None = None) -> Scan:
    from app.schemas.scan import ScanCreate

    payload = ScanCreate(
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        selected_owasp_categories=scan.selected_owasp_categories,
        authentication_config=scan.authentication_config,
        safety_confirmed=scan.safety_confirmed,
    )
    return create_scan(db, payload, current_user, request)


def get_scan_logs(scan: Scan) -> list[ScanLogEntry]:
    log_path = Path(settings.SCAN_OUTPUT_DIR) / str(scan.id) / "scan.log"
    if not log_path.exists():
        return []

    entries = []
    for line in log_path.read_text().splitlines():
        parts = line.split(" | ", 2)
        if len(parts) == 3:
            entries.append(ScanLogEntry(timestamp=parts[0], level=parts[1], message=parts[2]))
        else:
            entries.append(ScanLogEntry(timestamp="", level="INFO", message=line))
    return entries


def get_scan_summary(db: Session, scan: Scan) -> dict:
    findings = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    by_severity: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.value
        by_severity[key] = by_severity.get(key, 0) + 1

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "total_findings": len(findings),
        "findings_by_severity": by_severity,
        "duration_seconds": scan.duration_seconds,
    }
