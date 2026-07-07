from app.models.user import UserRole
from app.tests.conftest import make_user_and_login


def _create_confirmed_project(client, headers, name="Scan Target", target_url="http://localhost:9000"):
    resp = client.post(
        "/api/v1/projects",
        json={
            "name": name,
            "target_url": target_url,
            "environment": "local",
            "scope_confirmed": True,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    return resp.json()["id"]


def test_create_baseline_scan_queued(client, db_session):
    headers = make_user_and_login(client, "sec4@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)
    project_id = _create_confirmed_project(client, headers)

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": project_id, "scan_type": "passive_baseline_scan"},
        headers=headers,
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "queued"
    assert body["project_id"] == project_id


def test_full_local_staging_scan_requires_safety_confirmation(client, db_session):
    headers = make_user_and_login(client, "sec5@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)
    project_id = _create_confirmed_project(client, headers, name="Full Scan Target", target_url="http://localhost:9100")

    resp = client.post(
        "/api/v1/scans",
        json={
            "project_id": project_id,
            "scan_type": "full_local_staging_scan",
            "safety_confirmed": False,
        },
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "FORBIDDEN"


def test_full_local_staging_scan_requires_privileged_role(client, db_session):
    sec_headers = make_user_and_login(
        client, "sec6@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session
    )
    project_id = _create_confirmed_project(client, sec_headers, name="Dev Scan Target", target_url="http://localhost:9200")

    dev_headers = make_user_and_login(client, "dev2@example.com", "StrongPass123!", UserRole.DEVELOPER, db_session)
    resp = client.post(
        "/api/v1/scans",
        json={
            "project_id": project_id,
            "scan_type": "full_local_staging_scan",
            "safety_confirmed": True,
        },
        headers=dev_headers,
    )
    assert resp.status_code == 403


def test_scan_blocked_without_scope_confirmation(client, db_session):
    headers = make_user_and_login(client, "sec7@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)

    project_resp = client.post(
        "/api/v1/projects",
        json={
            "name": "Unconfirmed Scope",
            "target_url": "http://localhost:9300",
            "environment": "local",
            "scope_confirmed": False,
        },
        headers=headers,
    )
    project_id = project_resp.json()["id"]

    resp = client.post(
        "/api/v1/scans",
        json={"project_id": project_id, "scan_type": "passive_baseline_scan"},
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["code"] == "SCOPE_NOT_CONFIRMED"


def test_duplicate_active_scan_blocked(client, db_session):
    headers = make_user_and_login(client, "sec8@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)
    project_id = _create_confirmed_project(client, headers, name="Dup Scan Target", target_url="http://localhost:9400")

    first = client.post(
        "/api/v1/scans",
        json={"project_id": project_id, "scan_type": "passive_baseline_scan"},
        headers=headers,
    )
    assert first.status_code == 202

    second = client.post(
        "/api/v1/scans",
        json={"project_id": project_id, "scan_type": "passive_baseline_scan"},
        headers=headers,
    )
    assert second.status_code == 409
    assert second.json()["code"] == "SCAN_ALREADY_RUNNING"
