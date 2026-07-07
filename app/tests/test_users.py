from app.models.user import UserRole
from app.tests.conftest import make_user_and_login


def test_admin_can_create_user(client, db_session):
    admin_headers = make_user_and_login(client, "admin1@example.com", "StrongPass123!", UserRole.ADMIN, db_session)

    resp = client.post(
        "/api/v1/users",
        json={
            "email": "newmember@example.com",
            "full_name": "New Member",
            "password": "StrongPass123!",
            "role": "developer",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["email"] == "newmember@example.com"
    assert body["role"] == "developer"
    assert body["is_active"] is True

    # The created account can actually log in.
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "newmember@example.com", "password": "StrongPass123!"},
    )
    assert login_resp.status_code == 200


def test_create_user_duplicate_email_conflicts(client, db_session):
    admin_headers = make_user_and_login(client, "admin2@example.com", "StrongPass123!", UserRole.ADMIN, db_session)

    payload = {
        "email": "dupe@example.com",
        "full_name": "Dupe",
        "password": "StrongPass123!",
        "role": "viewer",
    }
    first = client.post("/api/v1/users", json=payload, headers=admin_headers)
    assert first.status_code == 201

    second = client.post("/api/v1/users", json=payload, headers=admin_headers)
    assert second.status_code == 409
    assert second.json()["code"] == "EMAIL_TAKEN"


def test_non_admin_cannot_create_user(client, db_session):
    dev_headers = make_user_and_login(client, "dev3@example.com", "StrongPass123!", UserRole.DEVELOPER, db_session)

    resp = client.post(
        "/api/v1/users",
        json={
            "email": "shouldfail@example.com",
            "full_name": "Should Fail",
            "password": "StrongPass123!",
            "role": "viewer",
        },
        headers=dev_headers,
    )
    assert resp.status_code == 403


def test_admin_can_update_another_users_role_and_active_status(client, db_session):
    admin_headers = make_user_and_login(client, "admin3@example.com", "StrongPass123!", UserRole.ADMIN, db_session)

    create_resp = client.post(
        "/api/v1/users",
        json={
            "email": "promote@example.com",
            "full_name": "Promote Me",
            "password": "StrongPass123!",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    user_id = create_resp.json()["id"]

    update_resp = client.patch(
        f"/api/v1/users/{user_id}",
        json={"role": "security_engineer", "is_active": False},
        headers=admin_headers,
    )
    assert update_resp.status_code == 200
    body = update_resp.json()
    assert body["role"] == "security_engineer"
    assert body["is_active"] is False


def test_admin_cannot_change_own_role(client, db_session):
    admin_headers = make_user_and_login(client, "admin4@example.com", "StrongPass123!", UserRole.ADMIN, db_session)

    me = client.get("/api/v1/auth/me", headers=admin_headers).json()

    resp = client.patch(
        f"/api/v1/users/{me['id']}",
        json={"role": "viewer"},
        headers=admin_headers,
    )
    assert resp.status_code == 403


def test_admin_cannot_deactivate_own_account(client, db_session):
    admin_headers = make_user_and_login(client, "admin5@example.com", "StrongPass123!", UserRole.ADMIN, db_session)

    me = client.get("/api/v1/auth/me", headers=admin_headers).json()

    resp = client.patch(
        f"/api/v1/users/{me['id']}",
        json={"is_active": False},
        headers=admin_headers,
    )
    assert resp.status_code == 403


def test_admin_can_list_users(client, db_session):
    admin_headers = make_user_and_login(client, "admin6@example.com", "StrongPass123!", UserRole.ADMIN, db_session)
    make_user_and_login(client, "listed@example.com", "StrongPass123!", UserRole.VIEWER, db_session)

    resp = client.get("/api/v1/users", headers=admin_headers)
    assert resp.status_code == 200
    emails = [u["email"] for u in resp.json()["items"]]
    assert "admin6@example.com" in emails
    assert "listed@example.com" in emails


def test_non_admin_cannot_list_users(client, db_session):
    viewer_headers = make_user_and_login(client, "viewer1@example.com", "StrongPass123!", UserRole.VIEWER, db_session)

    resp = client.get("/api/v1/users", headers=viewer_headers)
    assert resp.status_code == 403
