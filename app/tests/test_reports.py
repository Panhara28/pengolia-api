import os
from datetime import datetime, timezone

from app.core.config import settings
from app.models.finding import Finding, FindingConfidence, FindingSeverity, FindingStatus
from app.models.project import Environment, Project, ProjectStatus, RiskLevel
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User, UserRole
from app.services import report_service
from app.services.auth_service import register_user


def test_generate_report_creates_html_file(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "REPORT_OUTPUT_DIR", str(tmp_path))

    user = register_user(db_session, "reportowner@example.com", "Report Owner", "StrongPass123!")
    user.role = UserRole.SECURITY_ENGINEER
    db_session.commit()

    project = Project(
        name="Report Project",
        target_url="http://localhost:6000",
        environment=Environment.LOCAL,
        owner_id=user.id,
        status=ProjectStatus.ACTIVE,
        risk_level=RiskLevel.LOW,
        scope_confirmed=True,
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    scan = Scan(
        project_id=project.id,
        target_url=project.target_url,
        scan_type=ScanType.PASSIVE_BASELINE,
        status=ScanStatus.COMPLETED,
        created_by=user.id,
        risk_score=25.0,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    report = report_service.generate_report(db_session, scan, user)

    assert os.path.exists(report.file_path)
    assert report.file_path.endswith(".html")
    with open(report.file_path) as fh:
        content = fh.read()
    assert "Security Assessment Report" in content
    assert "Safety and Scope Statement" in content


def test_report_remediation_content_reflects_real_findings(db_session, tmp_path, monkeypatch):
    """Guards against the report regressing back to a static, generic
    remediation list -- the plan and executive summary must be derived from
    this scan's actual findings, including data (references, status) that
    exists on the model but was previously silently dropped from the report."""
    monkeypatch.setattr(settings, "REPORT_OUTPUT_DIR", str(tmp_path))

    user = register_user(db_session, "reportowner2@example.com", "Report Owner", "StrongPass123!")
    user.role = UserRole.SECURITY_ENGINEER
    db_session.commit()

    project = Project(
        name="Substantive Report Project",
        target_url="http://localhost:6001",
        environment=Environment.LOCAL,
        owner_id=user.id,
        status=ProjectStatus.ACTIVE,
        risk_level=RiskLevel.HIGH,
        scope_confirmed=True,
    )
    db_session.add(project)
    db_session.commit()
    db_session.refresh(project)

    scan = Scan(
        project_id=project.id,
        target_url=project.target_url,
        scan_type=ScanType.PASSIVE_BASELINE,
        status=ScanStatus.COMPLETED,
        created_by=user.id,
        risk_score=85.0,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        selected_owasp_categories=["A03"],
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    now = datetime.now(timezone.utc)
    finding = Finding(
        scan_id=scan.id,
        project_id=project.id,
        title="SQL Injection in /search",
        description="Unsanitized input reaches a database query.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.HIGH,
        owasp_category="A03",
        affected_url=f"{project.target_url}/search",
        evidence="' OR 1=1 --",
        impact="Full database read/write access.",
        recommendation="Use parameterized queries instead of string concatenation.",
        references_json={"reference": "https://owasp.org/sqli\nhttps://cwe.mitre.org/89", "cweid": "89", "wascid": "19"},
        status=FindingStatus.OPEN,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(finding)
    db_session.commit()

    report = report_service.generate_report(db_session, scan, user)

    with open(report.file_path) as fh:
        content = fh.read()

    # Remediation plan must contain the finding's real recommendation text,
    # not the old hardcoded generic bullet list.
    assert "Use parameterized queries instead of string concatenation." in content
    assert "Add missing security headers" not in content  # the old static bullet
    assert "remediate within 7 day(s)" in content  # critical-severity SLA

    # Data that previously existed on the model but was never rendered.
    assert "CWE-89" in content
    assert "WASC-19" in content
    assert "https://owasp.org/sqli" in content
    assert "open" in content.lower()  # finding status now shown

    # OWASP scope: A03 was selected, A01 was not.
    assert "In scope" in content
    assert "Out of scope" in content

    # Executive summary calls out the critical finding instead of a bare count.
    assert "critical" in report.executive_summary.lower()
