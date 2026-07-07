from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user
from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.owasp import OWASPCategory
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
def get_summary(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    total_projects = db.execute(
        select(func.count(Project.id)).where(Project.deleted_at.is_(None))
    ).scalar_one()
    total_scans = db.execute(select(func.count(Scan.id))).scalar_one()
    open_findings = db.execute(
        select(func.count(Finding.id)).where(Finding.status == FindingStatus.OPEN)
    ).scalar_one()
    critical_issues = db.execute(
        select(func.count(Finding.id)).where(
            Finding.status == FindingStatus.OPEN, Finding.severity == FindingSeverity.CRITICAL
        )
    ).scalar_one()
    last_scan = db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(1)).scalar_one_or_none()
    avg_risk_score = db.execute(select(func.avg(Scan.risk_score))).scalar_one()

    return {
        "total_projects": total_projects,
        "total_scans": total_scans,
        "open_findings": open_findings,
        "critical_issues": critical_issues,
        "last_scan_status": last_scan.status.value if last_scan else None,
        "average_risk_score": round(avg_risk_score, 2) if avg_risk_score else 0.0,
    }


@router.get("/recent-scans")
def get_recent_scans(
    limit: int = 10, db: Session = Depends(get_db), _: User = Depends(get_current_active_user)
):
    scans = db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).scalars().all()
    return [
        {
            "id": s.id,
            "project_id": s.project_id,
            "scan_type": s.scan_type.value,
            "status": s.status.value,
            "risk_score": s.risk_score,
            "created_at": s.created_at,
        }
        for s in scans
    ]


@router.get("/severity-distribution")
def get_severity_distribution(
    db: Session = Depends(get_db), _: User = Depends(get_current_active_user)
):
    rows = db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    ).all()
    distribution = {s.value: 0 for s in FindingSeverity}
    for severity, count in rows:
        distribution[severity.value] = count
    return distribution


@router.get("/owasp-coverage")
def get_owasp_coverage(db: Session = Depends(get_db), _: User = Depends(get_current_active_user)):
    categories = db.execute(select(OWASPCategory).order_by(OWASPCategory.code)).scalars().all()
    counts = dict(
        db.execute(
            select(Finding.owasp_category, func.count(Finding.id)).group_by(Finding.owasp_category)
        ).all()
    )
    return [
        {
            "code": c.code,
            "name": c.name,
            "coverage_status": c.coverage_status.value,
            "finding_count": counts.get(c.code, 0),
        }
        for c in categories
    ]


@router.get("/risk-trend")
def get_risk_trend(
    limit: int = 30, db: Session = Depends(get_db), _: User = Depends(get_current_active_user)
):
    scans = (
        db.execute(
            select(Scan)
            .where(Scan.status == ScanStatus.COMPLETED)
            .order_by(Scan.finished_at.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {"scan_id": s.id, "finished_at": s.finished_at, "risk_score": s.risk_score}
        for s in reversed(scans)
    ]
