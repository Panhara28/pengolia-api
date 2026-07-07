from app.models.user import UserRole
from app.tests.conftest import make_user_and_login


def test_create_project_localhost_allowed(client, db_session):
    headers = make_user_and_login(client, "sec1@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)

    resp = client.post(
        "/api/v1/projects",
        json={
            "name": "Local App",
            "target_url": "http://localhost:3000",
            "environment": "local",
            "scope_confirmed": True,
        },
        headers=headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["target_url"].startswith("http://localhost:3000")
    assert body["scope_confirmed"] is True


def test_create_project_public_target_blocked(client, db_session):
    headers = make_user_and_login(client, "sec2@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)

    resp = client.post(
        "/api/v1/projects",
        json={
            "name": "Public App",
            "target_url": "https://google.com",
            "environment": "local",
            "scope_confirmed": True,
        },
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["code"] == "INVALID_TARGET_URL"


def test_developer_cannot_create_project(client, db_session):
    headers = make_user_and_login(client, "dev1@example.com", "StrongPass123!", UserRole.DEVELOPER, db_session)

    resp = client.post(
        "/api/v1/projects",
        json={
            "name": "Should Fail",
            "target_url": "http://localhost:4000",
            "environment": "local",
            "scope_confirmed": True,
        },
        headers=headers,
    )
    assert resp.status_code == 403


def test_confirm_scope(client, db_session):
    headers = make_user_and_login(client, "sec3@example.com", "StrongPass123!", UserRole.SECURITY_ENGINEER, db_session)

    create_resp = client.post(
        "/api/v1/projects",
        json={
            "name": "Needs Confirm",
            "target_url": "http://127.0.0.1:5000",
            "environment": "local",
            "scope_confirmed": False,
        },
        headers=headers,
    )
    project_id = create_resp.json()["id"]
    assert create_resp.json()["scope_confirmed"] is False

    confirm_resp = client.post(
        f"/api/v1/projects/{project_id}/confirm-scope",
        json={"confirmed": True},
        headers=headers,
    )
    assert confirm_resp.status_code == 200
    assert confirm_resp.json()["scope_confirmed"] is True
