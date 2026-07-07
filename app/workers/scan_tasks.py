import os
import uuid
from datetime import datetime, timezone

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.core.scoring import calculate_risk_score, risk_level_for_score
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan, ScanStatus

logger = get_logger(__name__)


def _append_log(output_dir: str, level: str, message: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "scan.log")
    timestamp = datetime.now(timezone.utc).isoformat()
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(f"{timestamp} | {level} | {message}\n")


def _run_zap_backed_scan(scan_id: str, zap_runner) -> None:
    """Shared lifecycle for any scan type backed by a ZAP container run.

    zap_runner(target_url, output_dir) -> ZapRunResult
    """
    from app.services import finding_service, zap_service

    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if not scan:
            logger.warning("Scan %s not found", scan_id)
            return

        os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
        os.chmod(settings.SCAN_OUTPUT_DIR, 0o777)

        output_dir = os.path.join(settings.SCAN_OUTPUT_DIR, scan_id)
        os.makedirs(output_dir, exist_ok=True)
        # This directory (and the shared volume root above) is created here
        # (as root, inside this worker's own container) but written into by
        # the ZAP sibling container running as its own unprivileged "zap"
        # user -- open the permissions so cross-container/cross-uid writes
        # succeed regardless of uid mapping.
        os.chmod(output_dir, 0o777)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 10
        db.commit()
        _append_log(output_dir, "INFO", f"Scan {scan_id} started against {scan.target_url}")

        try:
            result = zap_runner(scan.target_url, scan_id, output_dir)
            scan.progress = 60
            db.commit()
            _append_log(output_dir, "INFO", f"ZAP container finished with exit code {result.exit_code}")
            if result.logs:
                for line in result.logs.splitlines()[-200:]:
                    _append_log(output_dir, "DEBUG", line)

            alerts = []
            if result.json_report_path:
                alerts = zap_service.parse_zap_json_report_file(result.json_report_path)
                scan.zap_report_path = result.json_report_path

            severities = []
            for alert in alerts:
                data = zap_service.convert_zap_alert_to_finding(alert)
                finding = finding_service.upsert_finding_from_scan(db, scan.id, scan.project_id, data)
                severities.append(finding.severity)

            risk_score = calculate_risk_score(severities)
            scan.risk_score = risk_score
            scan.progress = 100
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now(timezone.utc)
            scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds())
            db.commit()

            project = db.get(Project, scan.project_id)
            if project:
                project.risk_score = risk_score
                project.risk_level = risk_level_for_score(risk_score)
                db.commit()

            _append_log(output_dir, "INFO", f"Scan completed with {len(alerts)} finding(s), risk score {risk_score}")

        except Exception as exc:  # noqa: BLE001
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            _append_log(output_dir, "ERROR", f"Scan failed: {exc}")
            logger.exception("Scan %s failed", scan_id)
            return

        from app.workers.report_tasks import generate_scan_report

        generate_scan_report.delay(scan_id)
    finally:
        db.close()


@celery_app.task(name="run_zap_baseline_scan")
def run_zap_baseline_scan(scan_id: str) -> None:
    from app.services.zap_service import run_baseline_scan

    _run_zap_backed_scan(scan_id, run_baseline_scan)


@celery_app.task(name="run_authenticated_scan")
def run_authenticated_scan(scan_id: str) -> None:
    """Authenticated baseline scan. Uses the same passive ZAP baseline profile;
    authentication_config on the Scan record is reserved for a future
    login-context-aware scan profile."""
    from app.services.zap_service import run_baseline_scan

    _run_zap_backed_scan(scan_id, run_baseline_scan)


@celery_app.task(name="run_api_scan")
def run_api_scan(scan_id: str) -> None:
    from app.services.zap_service import run_api_scan as zap_run_api_scan

    def runner(target_url: str, scan_id: str, output_dir: str):
        return zap_run_api_scan(target_url, target_url, scan_id, output_dir)

    _run_zap_backed_scan(scan_id, runner)


@celery_app.task(name="run_full_local_scan")
def run_full_local_scan(scan_id: str) -> None:
    """Full Local/Staging Scan. Only reachable via scan_service.create_scan,
    which already enforces: Admin/Security Engineer role, explicit
    safety_confirmed=True, and a validated local/private/approved-staging
    target. No offensive/exploit modules are used here."""
    from app.services.zap_service import run_full_local_staging_scan

    _run_zap_backed_scan(scan_id, run_full_local_staging_scan)
