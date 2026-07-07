from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.core.logging import get_logger

logger = get_logger(__name__)


@celery_app.task(name="generate_scan_report")
def generate_scan_report(scan_id: str) -> str | None:
    import uuid

    from app.models.scan import Scan
    from app.models.user import User
    from app.services import report_service

    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            logger.warning("generate_scan_report: scan %s not found", scan_id)
            return None

        generator = db.get(User, scan.created_by)
        report = report_service.generate_report(db, scan, generator)
        return str(report.id)
    finally:
        db.close()
