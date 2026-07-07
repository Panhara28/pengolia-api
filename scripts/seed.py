"""Seed the PentestFlow database with local development mock data.

Usage: python scripts/seed.py
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.finding import Finding, FindingConfidence, FindingSeverity, FindingStatus
from app.models.owasp import OWASPCategory, OwaspCoverageStatus
from app.models.project import Environment, Project, ProjectStatus, RiskLevel
from app.models.report import Report, ReportFormat
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.setting import Setting
from app.models.tool import ToolIntegration, ToolStatus
from app.models.user import User, UserRole
from app.services.owasp_mapper import OWASP_CATEGORIES, map_alert_name_to_category
from app.services.setting_service import SCAN_DEFAULTS_KEY, SECURITY_SCOPE_KEY
from app.schemas.setting import ScanDefaultSettings, SecurityScopeSettings

DEV_PASSWORD = "ChangeMe123!"

USERS = [
    ("admin@pentestflow.local", "Alex Admin", UserRole.ADMIN),
    ("security@pentestflow.local", "Sam Security", UserRole.SECURITY_ENGINEER),
    ("developer@pentestflow.local", "Dana Developer", UserRole.DEVELOPER),
    ("viewer@pentestflow.local", "Val Viewer", UserRole.VIEWER),
]

PROJECTS = [
    ("Local E-Commerce App", "http://localhost:3000", Environment.LOCAL),
    ("QA Banking Portal", "https://qa-bank.example.internal", Environment.QA),
    ("Staging HR System", "https://staging-hr.example.internal", Environment.STAGING),
    ("Local API Gateway", "http://localhost:8080", Environment.LOCAL),
]

TOOLS = [
    ("OWASP ZAP", "owasp-zap", "Passive/baseline web app scanning", "ghcr.io/zaproxy/zaproxy:stable", True),
    ("Trivy", "trivy", "Container & dependency vulnerability scanning", "aquasec/trivy:latest", False),
    ("OWASP Dependency-Check", "dependency-check", "Software composition analysis", None, False),
    ("Semgrep", "semgrep", "Static application security testing", "semgrep/semgrep:latest", False),
    ("Gitleaks", "gitleaks", "Secret scanning", "zricethezav/gitleaks:latest", False),
    ("Playwright", "playwright", "Authenticated scan session capture", None, False),
]

FINDINGS = [
    ("Missing Content Security Policy Header", FindingSeverity.MEDIUM),
    ("Cookie Missing Secure Flag", FindingSeverity.MEDIUM),
    ("Cookie Missing HttpOnly Flag", FindingSeverity.MEDIUM),
    ("Outdated React Dependency", FindingSeverity.HIGH),
    ("Missing X-Frame-Options Header", FindingSeverity.LOW),
    ("Verbose Error Message", FindingSeverity.LOW),
    ("Weak Password Policy", FindingSeverity.MEDIUM),
    ("Missing Rate Limiting on Login", FindingSeverity.HIGH),
    ("Insecure CORS Configuration", FindingSeverity.MEDIUM),
    ("Exposed Server Version Header", FindingSeverity.INFORMATIONAL),
    ("Missing Security Logging for Failed Login", FindingSeverity.LOW),
    ("API Endpoint Missing Authorization Check", FindingSeverity.CRITICAL),
]

REMEDIATION = {
    "Missing Content Security Policy Header": "Add a strict Content-Security-Policy header to all responses.",
    "Cookie Missing Secure Flag": "Set the Secure flag on all session cookies.",
    "Cookie Missing HttpOnly Flag": "Set the HttpOnly flag on all session cookies.",
    "Outdated React Dependency": "Update the dependency to the latest patched version.",
    "Missing X-Frame-Options Header": "Add X-Frame-Options: DENY or SAMEORIGIN.",
    "Verbose Error Message": "Return generic error messages to clients; log details server-side.",
    "Weak Password Policy": "Enforce a stronger password policy (length, complexity, breach checks).",
    "Missing Rate Limiting on Login": "Add rate limiting/backoff on authentication endpoints.",
    "Insecure CORS Configuration": "Restrict CORS to known, trusted origins.",
    "Exposed Server Version Header": "Suppress or mask the Server header.",
    "Missing Security Logging for Failed Login": "Log authentication failures for monitoring/alerting.",
    "API Endpoint Missing Authorization Check": "Add explicit authorization checks on the endpoint.",
}


def seed():
    db = SessionLocal()
    try:
        users = {}
        for email, full_name, role in USERS:
            user = db.query(User).filter(User.email == email).one_or_none()
            if not user:
                user = User(
                    email=email,
                    full_name=full_name,
                    hashed_password=hash_password(DEV_PASSWORD),
                    role=role,
                    is_active=True,
                )
                db.add(user)
                db.commit()
                db.refresh(user)
            users[email] = user
        print(f"Seeded {len(users)} users (password: {DEV_PASSWORD})")

        owner = users["security@pentestflow.local"]
        projects = {}
        for name, target_url, environment in PROJECTS:
            project = db.query(Project).filter(Project.name == name).one_or_none()
            if not project:
                project = Project(
                    name=name,
                    target_url=target_url,
                    environment=environment,
                    owner_id=owner.id,
                    description=f"Seeded project for {name}",
                    status=ProjectStatus.ACTIVE,
                    risk_level=RiskLevel.MEDIUM,
                    risk_score=35.0,
                    scope_confirmed=True,
                )
                db.add(project)
                db.commit()
                db.refresh(project)
            projects[name] = project
        print(f"Seeded {len(projects)} projects")

        for name, slug, purpose, docker_image, enabled in TOOLS:
            tool = db.query(ToolIntegration).filter(ToolIntegration.slug == slug).one_or_none()
            if not tool:
                db.add(
                    ToolIntegration(
                        name=name,
                        slug=slug,
                        purpose=purpose,
                        docker_image=docker_image,
                        enabled=enabled,
                        status=ToolStatus.NOT_CONFIGURED if not enabled else ToolStatus.CONNECTED,
                        timeout_seconds=900,
                    )
                )
        db.commit()
        print(f"Seeded {len(TOOLS)} tool integrations")

        for code, name in OWASP_CATEGORIES.items():
            category = db.query(OWASPCategory).filter(OWASPCategory.code == code).one_or_none()
            if not category:
                db.add(
                    OWASPCategory(
                        code=code,
                        name=name,
                        description=f"OWASP Top 10 category {code}: {name}",
                        coverage_status=OwaspCoverageStatus.PARTIAL,
                    )
                )
        db.commit()
        print(f"Seeded {len(OWASP_CATEGORIES)} OWASP categories")

        if not db.query(Setting).filter(Setting.key == SECURITY_SCOPE_KEY).one_or_none():
            db.add(
                Setting(
                    key=SECURITY_SCOPE_KEY,
                    value_json=SecurityScopeSettings(
                        approved_domains=["qa-bank.example.internal", "staging-hr.example.internal"]
                    ).model_dump(),
                    description="Controls which scan targets are considered in-scope.",
                )
            )
        if not db.query(Setting).filter(Setting.key == SCAN_DEFAULTS_KEY).one_or_none():
            db.add(
                Setting(
                    key=SCAN_DEFAULTS_KEY,
                    value_json=ScanDefaultSettings().model_dump(mode="json"),
                    description="Default parameters applied to newly created scans.",
                )
            )
        db.commit()
        print("Seeded settings")

        ecommerce = projects["Local E-Commerce App"]
        api_gateway = projects["Local API Gateway"]

        scan = db.query(Scan).filter(Scan.project_id == ecommerce.id).first()
        if not scan:
            now = datetime.now(timezone.utc)
            scan = Scan(
                project_id=ecommerce.id,
                target_url=ecommerce.target_url,
                scan_type=ScanType.PASSIVE_BASELINE,
                status=ScanStatus.COMPLETED,
                progress=100,
                risk_score=42.0,
                started_at=now - timedelta(minutes=5),
                finished_at=now,
                duration_seconds=300,
                created_by=owner.id,
                safety_confirmed=True,
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)

        scan2 = db.query(Scan).filter(Scan.project_id == api_gateway.id).first()
        if not scan2:
            now = datetime.now(timezone.utc)
            scan2 = Scan(
                project_id=api_gateway.id,
                target_url=api_gateway.target_url,
                scan_type=ScanType.API_SCAN,
                status=ScanStatus.COMPLETED,
                progress=100,
                risk_score=68.0,
                started_at=now - timedelta(minutes=8),
                finished_at=now,
                duration_seconds=480,
                created_by=owner.id,
                safety_confirmed=True,
            )
            db.add(scan2)
            db.commit()
            db.refresh(scan2)
        print("Seeded 2 scans")

        now = datetime.now(timezone.utc)
        scan_targets = [scan, scan, scan, scan2, scan, scan, scan2, scan2, scan, scan, scan2, scan2]
        created = 0
        for (title, severity), target_scan in zip(FINDINGS, scan_targets):
            existing = (
                db.query(Finding)
                .filter(Finding.scan_id == target_scan.id, Finding.title == title)
                .one_or_none()
            )
            if existing:
                continue
            db.add(
                Finding(
                    scan_id=target_scan.id,
                    project_id=target_scan.project_id,
                    title=title,
                    description=f"{title} was identified during automated scanning.",
                    severity=severity,
                    confidence=FindingConfidence.MEDIUM,
                    owasp_category=map_alert_name_to_category(title),
                    affected_url=target_scan.target_url,
                    evidence="See scan raw output for full request/response evidence.",
                    impact=f"Severity: {severity.value}",
                    recommendation=REMEDIATION[title],
                    references_json={"owasp": "https://owasp.org/Top10/"},
                    status=FindingStatus.OPEN,
                    first_seen=now,
                    last_seen=now,
                )
            )
            created += 1
        db.commit()
        print(f"Seeded {created} findings")

        if not db.query(Report).filter(Report.scan_id == scan.id).one_or_none():
            db.add(
                Report(
                    scan_id=scan.id,
                    project_id=scan.project_id,
                    name=f"{ecommerce.name} Security Report",
                    format=ReportFormat.HTML,
                    file_path=f"/app/reports/{scan.project_id}/seed-report.html",
                    executive_summary="Seeded example report for local development.",
                    risk_score=scan.risk_score,
                    total_findings=6,
                    generated_by=owner.id,
                    generated_at=now,
                )
            )
            db.commit()
        print("Seeded 1 report")

        print("Seed complete.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
