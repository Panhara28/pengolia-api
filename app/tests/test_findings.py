from datetime import datetime, timezone

from app.models.finding import Finding, FindingConfidence, FindingSeverity, FindingStatus
from app.models.project import Environment, Project, ProjectStatus, RiskLevel
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.user import User, UserRole
from app.tests.conftest import make_user_and_login


def _seed_finding(db_session, owner_id, severity, status=FindingStatus.OPEN, title="Test Finding"):
    project = Project(
        name=f"Findings Project {title}",
        target_url="http://localhost:7000",
        environment=Environment.LOCAL,
        owner_id=owner_id,
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
        created_by=owner_id,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    now = datetime.now(timezone.utc)
    finding = Finding(
        scan_id=scan.id,
        project_id=project.id,
        title=title,
        severity=severity,
        confidence=FindingConfidence.MEDIUM,
        owasp_category="A05",
        status=status,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)
    return finding


def test_filter_findings_by_severity(client, db_session):
    headers = make_user_and_login(client, "viewer1@example.com", "StrongPass123!", UserRole.VIEWER, db_session)
    user = db_session.query(User).filter(User.email == "viewer1@example.com").one()

    _seed_finding(db_session, user.id, FindingSeverity.CRITICAL, title="Critical One")
    _seed_finding(db_session, user.id, FindingSeverity.LOW, title="Low One")

    resp = client.get("/api/v1/findings", params={"severity": "critical"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "critical"


def test_filter_findings_by_status(client, db_session):
    headers = make_user_and_login(client, "viewer2@example.com", "StrongPass123!", UserRole.VIEWER, db_session)
    user = db_session.query(User).filter(User.email == "viewer2@example.com").one()

    _seed_finding(db_session, user.id, FindingSeverity.HIGH, status=FindingStatus.FIXED, title="Fixed One")
    _seed_finding(db_session, user.id, FindingSeverity.HIGH, status=FindingStatus.OPEN, title="Open One")

    resp = client.get("/api/v1/findings", params={"status_filter": "fixed"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "fixed"


def test_mark_finding_false_positive(client, db_session):
    headers = make_user_and_login(
        client, "sec9@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session
    )
    user = db_session.query(User).filter(User.email == "sec9@example.com").one()

    finding = _seed_finding(db_session, user.id, FindingSeverity.MEDIUM, title="FP Candidate")

    resp = client.post(
        f"/api/v1/findings/{finding.id}/mark-false-positive",
        json={"reason": "Not exploitable in this environment"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "false_positive"
